import datetime
import logging
import os
import typing as t
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from paramiko.client import SSHClient

from yog.host.pki_model import CAEntry, load_cas
from yog.ssh_utils import mkdirp, cat, exists, put

log = logging.getLogger(__name__)

class KeyMaterial(t.NamedTuple):
    fname: str
    mattype: str
    body: str

class CAData(t.NamedTuple):
    model: CAEntry
    data: t.List[KeyMaterial]

    def crt(self) -> Certificate:
        return x509.load_pem_x509_certificate([e for e in self.data if e.mattype == "cert"][0].body.encode("utf-8"))



def _load_cadata(ssh: SSHClient, ca: CAEntry) -> CAData:
    mats = []
    for fname, mtype in [("key.pem.openssl", "private"), ("key.ssh", "private"),
                         ("key.pem.pkcs1.public", "public"), ("key.ssh.public", "public"), ("key.crt", "public")]:

        if exists(ssh, os.path.join(ca.storage.path, fname)):
            mats.append(
                KeyMaterial(
                    fname,
                    mtype,
                    cat(ssh, os.path.join(ca.storage.path, fname), mtype == "private")
                )
            )

    return CAData(ca, mats)


def _gen_ca(ca: CAEntry):
    private_key = ec.generate_private_key(
        curve = ec.SECP384R1(),
        backend=default_backend()
    )

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Yog-Sothoth'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Lovecraft'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'The Outer Gods'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Yog-Sothoth'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=365*ca.validity_years))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    material = CAData(ca, [
        KeyMaterial("key.pem.openssl", "private", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")),
        KeyMaterial("key.ssh", "private", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")),
        KeyMaterial("key.pem.pkcs1.public", "public",
            public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")),
        KeyMaterial("key.ssh.public", "public",
            public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
            ).decode("utf-8")),
        KeyMaterial("key.crt", "cert",
            certificate.public_bytes(
            encoding=serialization.Encoding.PEM,
            ).decode("utf-8")),
    ])

    return material




def apply_cas(ident: t.Optional[str], root_dir: str):
    cas = load_cas(os.path.join(root_dir, "cas.yml"))
    if ident:
        cas = [ca for ca in cas if ca.ident == ident]

    for ca in cas:
        _apply_ca(ca)

def _apply_ca(ca: CAEntry):
    ssh = SSHClient()
    ssh.load_system_host_keys()

    ssh.connect(ca.storage.host)
    try:
        _provision_hier(ssh, ca)
        cadata = _load_cadata(ssh, ca)
        if not cadata.data:
            _provision_ca(ssh, ca)
        else:
            log.info("CA is OK")
    finally:
        ssh.close()

def _provision_hier(ssh: SSHClient, ca: CAEntry):
    mkdirp(ssh, ca.storage.path, "root")


def _provision_ca(ssh: SSHClient, ca: CAEntry):
    log.info("Generating new CA...")
    cadata = _gen_ca(ca)
    for km in cadata.data:
        log.info(f"put {km.fname}")
        put(ssh, os.path.join(ca.storage.path, km.fname), km.body, "root", mode=("600" if km.mattype=="private" else "644"))

