import logging
import shlex

from paramiko.client import SSHClient

from yog.host.necronomicon import Necronomicon, SystemdUnit
import yog.ssh_utils as ssh_utils

log = logging.getLogger(__name__)


def apply_systemd_section(host: str, n: Necronomicon, ssh: SSHClient):
    if not n.systemd.units:
        return

    modified = []

    for u in n.systemd.units:
        fpath = render_unit_file_path(u)
        fcontent = render_unit_file(u)
        same, _, _ = ssh_utils.compare_local_and_remote(fcontent.encode("utf-8"), fpath, ssh, True)
        if not same:
            log.info(f"[{host}][systemd][units][{u.name}]: stale")
            ssh_utils.put(ssh, fpath, fcontent, user="root", group="root")
            modified.append(u)
        else:
            log.info(f"[{host}][systemd][units][{u.name}]: OK")

    if modified:
        ssh_utils.check_call(ssh, "sudo systemctl daemon-reload")
    for u in modified:
        log.info(f"[{host}][systemd][units][{u.name}]: restart")
        ssh_utils.check_call(ssh, f"sudo systemctl restart {shlex.quote(u.name)}")
        ssh_utils.check_call(ssh, f"sudo systemctl enable {shlex.quote(u.name)}")


def render_unit_file(desc: SystemdUnit) -> str:
    return f"""
[Unit]
Description={desc.description}
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=1
User={desc.user}
ExecStart={desc.cmd}

[Install]
WantedBy=multi-user.target
"""


def render_unit_file_path(desc: SystemdUnit) -> str:
    return f"/etc/systemd/system/{desc.name}.service"