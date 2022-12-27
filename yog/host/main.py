import logging
from argparse import ArgumentParser

from yog.host.manage import apply_necronomicon
from yog.logging_utils import setup


def main():
    log = setup("yog")
    args = ArgumentParser()
    args.add_argument("host")
    args.add_argument("--root-dir", default="./")

    opts = args.parse_args()
    log.debug(f"Invoked with: {opts}")
    apply_necronomicon(opts.host, opts.root_dir)