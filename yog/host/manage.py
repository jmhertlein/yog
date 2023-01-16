import logging
from os.path import dirname, join, isdir, isfile, basename

import docker
from docker.models.containers import Container
from paramiko import SSHClient, SSHException
from paramiko.ssh_exception import NoValidConnectionsError

from yog.host import necronomicon
from yog.host.docker_attrs import build_run_kwargs_dict, diff_container
from yog.host.necronomicon import Necronomicon
from yog.ssh_utils import check_call, ScopedProxiedRemoteSSHTunnel, compare_local_and_remote

log = logging.getLogger(__name__)


def apply_necronomicon(host: str, root_dir):
    ssh = SSHClient()
    ssh.load_system_host_keys()
    try:
        log.info(f"[{host}]")
        ssh.connect(host)
        apply_necronomicon_for_host(host, ssh, root_dir)
    except RuntimeError as e:
        log.error(f"{host} error: {e.__class__.__name__}: {str(e)}")
    except SSHException as e:
        log.error(f"{host} error: {e.__class__.__name__}: {str(e)}")
    except NoValidConnectionsError as e:
        log.error(f"{host} error: {e.__class__.__name__}: {str(e)}")
    finally:
        ssh.close()


def load_necronomicons_for_host(host: str, root_dir):
    necronomicon_paths = []
    cur = join(root_dir, "domains")
    if isfile(join(cur, "_.yml")):
        necronomicon_paths.append(join(cur, "_.yml"))

    for part in reversed(host.split(".")):
        if not isdir(cur):
            break
        if isfile(join(cur, f"{part}.yml")):
            necronomicon_paths.append(join(cur, f"{part}.yml"))
        cur = join(cur, part)

    return [necronomicon.loadfile(basename(p), p) for p in necronomicon_paths]


def apply_necronomicon_for_host(host: str, ssh: SSHClient, root_dir):
    necronomicons = load_necronomicons_for_host(host, root_dir)
    if not necronomicons:
        raise RuntimeError(f"No necronomicons found for {host}")

    necronomicons = [n.inflate(host, ssh) for n in necronomicons]

    for n in necronomicons:
        if n.files.files:
            apply_files_section(host, n, ssh, root_dir)
        if n.docker.containers:
            apply_docker_section(host, n)
        if n.cron.crons:
            apply_cron_section(host, n, ssh)


def apply_cron_section(host: str, n: Necronomicon, ssh: SSHClient):
    cronfile_lines = []
    line1_length = max([len(c.expr) for c in n.cron.crons])
    line2_length = max([len(c.user) for c in n.cron.crons])
    for cron in n.cron.crons:
        cronfile_lines.append(f"{cron.expr.ljust(line1_length, ' ')}\t{cron.user.ljust(line2_length, ' ')}\t{cron.command}")
    cronfile_body = "\n".join(cronfile_lines + [""])
    ok, expected, found = compare_local_and_remote(bytes(cronfile_body, "utf-8"), "/etc/cron.d/yog.cron", ssh)
    if not ok:
        log.info(f"[{host}][cron]: stale")
        log.info(f"Writing /etc/cron.d/yog.cron version {expected[:10]}")
        check_call(ssh, "sudo bash -c 'cat - > /etc/cron.d/yog.cron'", send_stdin=cronfile_body)
    else:
        log.info(f"[{host}][cron]: OK")


def apply_docker_section(host: str, n: Necronomicon):
    log.debug(f"Docker: {n.ident}")
    tunnels = []
    for tunnel_def in n.tunnels.tunnels:
        log.debug(f"Setting up tunnel {tunnel_def}")
        tunnel = ScopedProxiedRemoteSSHTunnel(
            host,
            tunnel_def.target_port,
            tunnel_def.host,
            "remote",
            force_random_port=tunnel_def.local_port)
        tunnels.append(tunnel)

    try:
        for tun in tunnels:
            tun.connect()
        with ScopedProxiedRemoteSSHTunnel(host, 4243) as tport:
            log.debug(f"Connecting docker client.... tcp://localhost:{tport}")
            client = docker.DockerClient(base_url=f"tcp://localhost:{tport}", version="auto")
            log.debug("Docker connected.")

            for desired_container in n.docker.containers:
                log.debug(desired_container)

                log.debug(f"PULL: {desired_container.image}@{desired_container.fingerprint}")

                cur = client.containers.list(all=True, filters={"name": desired_container.name})
                c: Container = cur[0] if len(cur) > 0 else None

                if c:
                    log.debug(f"Existing container {c.id} is {c.status}")
                    diffs = diff_container(c, desired_container)
                    if not diffs:
                        log.debug(f"{c.id} is image {c.image.id} which matches our target.")
                        log.info(f"[{host}][docker]: OK {desired_container.name}@{desired_container.fingerprint[7:13]}")
                        log.debug("Existing container matches our desired state. No need to kill it.")
                        continue

                    log.debug(f"[{host}][docker][{c.name}]: diffs:")
                    for diff in diffs:
                        log.debug(f"[{host}][docker][{c.name}]: {diff[0]}")
                        log.debug(f"[{host}][docker][{c.name}]: {diff[1]}")
                        log.debug(f"[{host}][docker][{c.name}]: {diff[2]}")

                    if c.status in ["running", "restarting"]:
                        log.debug(f"STOP {c.name}:{c.id}")
                        c.stop()
                    log.debug(f"RM: {c.name}:{c.id}")
                    c.remove()

                log.debug(f"RUN: {desired_container.image}@{desired_container.fingerprint}")
                log.info(f"[{host}][docker]: run {desired_container.name}")
                client.containers.run(**build_run_kwargs_dict(desired_container))

    finally:
        for tun in tunnels:
            try:
                tun.disconnect()
            except RuntimeError as e:
                log.warning("Error while disconnecting tunnel", exc_info=e)


def apply_files_section(host: str, n: Necronomicon, ssh: SSHClient, root_dir):
    log.debug(f"Files: {n.ident}")
    hupcmds = set()
    for f in n.files.files:
        with open(join(root_dir, "files", f.src)) as fin:
            content = fin.read()
        ok, _, _ = compare_local_and_remote(content.encode("utf-8"), f.dest, ssh, f.root)
        if ok:
            log.info(f"[{host}][files]: OK [{f.src}]")
        else:
            log.info(f"[{host}][files]: stale {f.src} -> {f.dest}")
            if f.hupcmd:
                hupcmds.add(f.hupcmd)

            if f.root:
                cmd_prefix = "sudo "
            else:
                cmd_prefix = ""

            check_call(ssh, f"{cmd_prefix}mkdir -p \"{dirname(f.dest)}\"")
            check_call(ssh, f"{cmd_prefix}bash -c 'cat - > \"{f.dest}\"'", send_stdin=content)
    for c in hupcmds:
        log.info(f"[{host}][files][hup]: {c}")
        check_call(ssh, c)
