import logging
import os.path
import subprocess

from yog.host.necronomicon import Necronomicon
from yog.host.utils import get_path_for_file, get_resource_root

log = logging.getLogger(__name__)


def apply_compose_section(host: str, n: Necronomicon, root_dir: str):
    log.info(f"[{host}][compose] up")
    env = os.environ.copy()
    env['DOCKER_HOST'] = f"ssh://{host}"
    env['YOG_RES_ROOT'] = get_resource_root(root_dir)

    for name, group in n.compose.groups.items():
        log.info(f"[{host}][compose][{name}] up")
        cmd = [
            "docker",
            "compose",
            "-f",
            get_path_for_file(group.compose_path, root_dir)
        ]
        if group.env_path:
            cmd.append("--env-file")
            cmd.append(get_path_for_file(group.env_path, root_dir))

        cmd.extend(["up", "--detach"])

        subprocess.check_call(cmd, env=env)
