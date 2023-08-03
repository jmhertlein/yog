import json
import logging
import typing as t
from paramiko.client import SSHClient
from yog.host.necronomicon import Necronomicon, PipXPackage
import yog.ssh_utils as ssh_utils
from urllib.parse import urlparse


log = logging.getLogger(__name__)


def apply_pipx_section(host: str, n: Necronomicon, ssh: SSHClient, root_dir):
    # sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install hert
    installed_versions = list_pkgs(ssh)

    needs_install: t.List[PipXPackage] = list()
    for pkg in n.pipx.packages:
        if pkg.name in installed_versions:
            if pkg.version == installed_versions[pkg.name]:
                log.info(f"[{host}][pipx]: OK [{pkg.name}]")
            else:
                needs_install.append(pkg)
                log.debug(f"pipx {pkg.name} wanted {pkg.version} but got {installed_versions[pkg.name]}")
                log.info(f"[{host}][pipx]: stale [{pkg.name}]")
        else:
            needs_install.append(pkg)
            log.info(f"[{host}][pipx]: stale [{pkg.name}]")

    for ipkg in needs_install:
        install_pkg(ssh, ipkg, n.pipx.extra_indices)


def cmd(args: t.List[str]) -> t.List[str]:
    cmd_preamble = [
        "sudo",
        "PIPX_HOME=/opt/pipx",
        "PIPX_BIN_DIR=/usr/local/bin",
        "pipx",
    ]

    return cmd_preamble + args


def list_pkgs(ssh: SSHClient) -> t.Dict[str, str]:
    lines = ssh_utils.check_stdout(ssh, cmd(["list", "--json"]))
    return get_packages_from_pipx_json("".join(lines))


def install_pkg(ssh: SSHClient, pkg: PipXPackage, extra_indices: t.List[str]):
    extra_index_hosts = [urlparse(u).hostname for u in extra_indices]
    install_cmd = cmd([
        "install",
        f"{pkg.name}=={pkg.version}",
        "--force",
        "--pip-args",
        f"--extra-index-url '{','.join(extra_indices)}' --trusted-host {','.join(extra_index_hosts)}"])

    ssh_utils.check_call(ssh, install_cmd)


def get_packages_from_pipx_json(raw_json: str) -> t.Dict[str, str]:
    """
    :param raw_json:
    :returns a map of package name -> package version
    """
    ret = dict()
    parsed_json = json.loads(raw_json)
    for name, venv in parsed_json["venvs"].items():
        main_pkg = venv["metadata"]["main_package"]
        pkg_name = main_pkg["package"]
        pkg_version = str(main_pkg["package_version"]).strip()
        ret[pkg_name] = pkg_version

    return ret
