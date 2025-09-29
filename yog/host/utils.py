import os
from os.path import join

from paramiko import SSHClient
from yog.host import pki

from yog.host.necronomicon import File
from yog.host.pki_model import load_cas


def load_file_content(f: File, root_dir: str) -> bytes:
    if f.src.startswith("ca:"):
        ca_ident = f.src[len("ca:"):]
        matches = [ca for ca in load_cas(os.path.join(root_dir, "cas.yml")) if ca_ident == ca.ident]
        if not matches:
            raise ValueError(f"No such CA with ident {ca_ident}")
        ca = matches[0]
        ssh = SSHClient()
        ssh.load_system_host_keys()
        ssh.connect(ca.storage.host)
        try:
            trust = pki.KeyPairData.load(ssh, ca.storage.path)
        finally:
            ssh.close()

        return trust.raw_crt().body.encode("utf-8")

    with open(get_path_for_file(f.src, root_dir)) as fin:
        return fin.read().encode("utf-8")


def get_path_for_file(resource_path, root_dir):
    return os.path.join(root_dir, "files", resource_path)