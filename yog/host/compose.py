import logging
import os.path
import subprocess

from yog.host.necronomicon import Necronomicon

log = logging.getLogger(__name__)


def apply_compose_section(host: str, n: Necronomicon, root_dir: str):
    log.info(f"[{host}][compose] up")
    subprocess.check_call([
        "docker",
        "compose",
        "-f", os.path.join(root_dir, n.compose.compose_file_path),
        "up",
    ], env={"DOCKER_HOST": f"ssh://{host}"})
