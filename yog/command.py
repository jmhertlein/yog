import logging
from argparse import ArgumentParser

from yog.logging_utils import setup
from yog.host.pki import apply_cas


def ca_main():
    args = ArgumentParser()
    args.add_argument("--ident", default=None)
    args.add_argument("--root-dir", default="./")
    args.add_argument("--debug", action="store_true")

    opts = args.parse_args()
    log = setup("yog-ca", logging.DEBUG if opts.debug else logging.INFO)

    apply_cas(opts.ident, opts.root_dir)

