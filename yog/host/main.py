import logging
from argparse import ArgumentParser

from yog.host.manage import apply_necronomicon
from yog.logging_utils import setup


def main():

    args = ArgumentParser()
    args.add_argument("host")
    args.add_argument("--root-dir", default="./")
    args.add_argument("--debug", action="store_true")

    opts = args.parse_args()
    log = setup("yog", logging.DEBUG if opts.debug else logging.INFO)
    log.debug(f"Invoked with: {opts}")
    apply_necronomicon(opts.host, opts.root_dir)