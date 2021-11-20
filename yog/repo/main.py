import logging
import os
import typing as t
import re
from argparse import ArgumentParser
import json

import yaml

from yog.git_utils import require_clean_work_tree
from subprocess import check_output
import docker
from dataclasses import dataclass

from yog.logging_utils import setup
from yog.ssh_utils import ScopedProxiedRemoteSSHTunnel

log = logging.getLogger(__name__)


@dataclass
class PushTarget:
    image_name: str
    dockerfile_path: str
    registry_url: str = None
    tunnel_host: str = None
    tunnel_port: int = 5000
    context_path: str = None


def push(target: str):
    with open("./yog-repo.conf", "r") as fin:
        obj = yaml.full_load(fin)
    targets = {target_name: PushTarget(**target_dict) for target_name, target_dict in obj.items()}

    push_target: PushTarget = targets[target]

    if push_target.context_path:
        os.chdir(push_target.context_path)

    if not require_clean_work_tree():
        raise RuntimeError("Your work tree is not clean.")

    revision = check_output(["git", "rev-parse", "HEAD"]).decode("utf-8").strip()

    if push_target.tunnel_host:
        log.info(f"Establishing tunnel to {push_target.tunnel_host}:{push_target.tunnel_port}")
        tunnel = ScopedProxiedRemoteSSHTunnel(push_target.tunnel_host, push_target.tunnel_port)
        tunnel_port = tunnel.connect()
    else:
        tunnel = None
        tunnel_port = None

    try:
        if push_target.tunnel_host:
            tag = f"localhost:{tunnel_port}/{push_target.image_name}:{revision}"
        elif push_target.registry_url:
            tag = f"{push_target.registry_url}/{push_target.image_name}:{revision}"
        else:
            tag = f"{push_target.image_name}:{revision}"
        log.info(f"tag: {tag}")

        client: docker.DockerClient = docker.DockerClient(base_url='unix://var/run/docker.sock')
        log.info(f"Dockerfile: {push_target.dockerfile_path}")

        log.info("Building...")
        client.images.build(path=".", dockerfile=push_target.dockerfile_path, rm=True, tag=tag)
        log.info("Pushing...")

        for line_raw in client.images.push(tag).splitlines():
            if "sha256" in line_raw:
                log.info(line_raw)
            line = json.loads(line_raw)
            if "error" in line:
                raise RuntimeError(str(line))
        log.info("Done.")

    finally:
        if tunnel:
            tunnel.disconnect()


def main():
    setup("yog")
    args = ArgumentParser()

    subparsers = args.add_subparsers(help="Subcommand arguments.", dest="subcommand")
    push_parser = subparsers.add_parser("push")
    push_parser.add_argument("target")
    push_parser.add_argument("--workdir", default=None)

    prune_parser = subparsers.add_parser("prune")

    opts = args.parse_args()
    log.info(f"Invoked with: {opts}")

    if opts.subcommand == "push":
        if opts.workdir:
            log.info(f"chdir: {opts.workdir}")
            os.chdir(opts.workdir)
        push(opts.target)
    else:
        log.error(f"Invalid command: {opts.subcommand}")





