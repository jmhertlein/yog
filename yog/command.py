from argparse import ArgumentParser

from yog.logging_utils import setup
from yog.host.pki import apply_cas


def ca_main():
    log = setup("yog-ca")
    args = ArgumentParser()
    args.add_argument("--ident", default=None)
    args.add_argument("--root-dir", default="./")

    opts = args.parse_args()
    apply_cas(opts.ident, opts.root_dir)

