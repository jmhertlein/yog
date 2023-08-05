import json
import typing as t
from paramiko.client import SSHClient
from yog.host.necronomicon import Necronomicon
import yog.ssh_utils as ssh_utils


def apply_pipx_section(host: str, n: Necronomicon, ssh: SSHClient, root_dir):
    # sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install hert --pip-args \"--extra-index-url 'https://pyrepo.hert/' --trusted-host pyrepo.hert\"
    pass


def cmd(args: t.List[str]) -> t.List[str]:
    cmd_preamble = [
        "sudo",
        "PIPX_HOME=/opt/pipx",
        "PIPX_BIN_DIR=/usr/local/bin",
        "pipx",
    ]

    return cmd_preamble + args


def list(ssh: SSHClient):
    lines = ssh_utils.check_stdout(ssh, cmd(["list"]))


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
        pkg_version = main_pkg["package_version"]
        ret[pkg_name] = pkg_version

    return ret
