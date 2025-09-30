import logging
import os.path
import subprocess

from yog.host.necronomicon import Necronomicon
from yog.host.utils import get_path_for_file

log = logging.getLogger(__name__)


def apply_compose_section(host: str, n: Necronomicon, root_dir: str):
    log.info(f"[{host}][compose] up")
    env = os.environ.copy()
    env['DOCKER_HOST'] = f"ssh://{host}"
    subprocess.check_call([
        "docker",
        "compose",
        "-f", get_path_for_file(n.compose.compose_file_path, root_dir),
        "up",
        "--detach",
    ], env=env)
