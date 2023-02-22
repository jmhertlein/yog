import datetime
import logging
import os
import typing as t
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate, GeneralName
from cryptography.x509.oid import NameOID
from paramiko.client import SSHClient

from yog.host.necronomicon import CertEntry, Necronomicon
from yog.host.pki_model import CAEntry, load_cas
from yog.model_utils import HostPathStr
from yog.ssh_utils import mkdirp, cat, exists, put

log = logging.getLogger(__name__)

class KeyMaterial(t.NamedTuple):
    fname: str
    mattype: str
    body: str

class KeyPairData(t.NamedTuple):
    # model: CAEntry
    data: t.List[KeyMaterial]

    def raw_crt(self) -> KeyMaterial:
        return [e for e in self.data if e.mattype == "cert"][0]

    def crt(self) -> Certificate:
        return x509.load_pem_x509_certificate(self.raw_crt().body.encode("utf-8"))

    def private(self) -> EllipticCurvePrivateKey:
        return load_pem_private_key([e for e in self.data if e.mattype == "private" and e.fname.endswith(".pem.openssl")][0].body.encode("utf-8"), None)

    def cert_names(self) -> t.List[str]:
        e: x509.SubjectAlternativeName = self.crt().extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return e.get_values_for_type(x509.DNSName)

    def issuer_cn(self) -> str:
        return self.crt().issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value




def load_keypair_data(ssh: SSHClient, path: str) -> KeyPairData:
    mats = []
    for fname, mtype in [("key.pem.openssl", "private"), ("key.ssh", "private"),
                         ("key.pem.pkcs1.public", "public"), ("key.ssh.public", "public"), ("key.crt", "cert")]:
        if not exists(ssh, os.path.join(path, fname)):
            raise ValueError(f"Unable to load {path}")
        mats.append(
            KeyMaterial(
                fname,
                mtype,
                cat(ssh, os.path.join(path, fname), mtype == "private")
            )
        )

    return KeyPairData(mats)



def _gen_ca(ca: CAEntry):
    private_key = ec.generate_private_key(
        curve = ec.SECP384R1(),
        backend=default_backend()
    )

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca.ident),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca.ident),
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

    material = KeyPairData([
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


def _gen_cert(ce: CertEntry, ca_data: KeyPairData, ca: CAEntry):
    private_key = ec.generate_private_key(
        curve = ec.SECP384R1(),
        backend=default_backend()
    )

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ce.names[0]),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca.ident),
    ]))
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=365*ce.validity_years))
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(n) for n in ce.names]), critical=False
    )
    certificate = builder.sign(
        private_key=ca_data.private(), algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    material = KeyPairData([
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
        try:
            cadata = load_keypair_data(ssh, ca.storage.path)
        except ValueError:
            cadata = None
        if not cadata:
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


def apply_pki_section(host: str, n: Necronomicon, ssh: SSHClient, root_dir):
    cas = load_cas(os.path.join(root_dir, "cas.yml"))

    for ce in n.pki.certs:
        generate = False

        try:
            trust = load_keypair_data(ssh, ce.storage)
            cert: Certificate = trust.crt()
            expiry = cert.not_valid_after
            if (expiry - datetime.timedelta(days=365 * ce.refresh_at)) <= datetime.datetime.utcnow():
                generate = True
                log.debug("Expiry too soon")
            elif set(ce.names) != set(trust.cert_names()):
                generate = True
                log.debug("Set of names != cert names")
            elif trust.issuer_cn() != ce.authority:
                generate = True
                log.debug("Issuer CN != authority ident")
            elif expiry > (datetime.datetime.utcnow() + datetime.timedelta(days=365 * ce.validity_years)):
                generate = True
                log.debug("expiry too far out")
            elif cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != ce.names[0]:
                generate = True
                log.debug("CN != cert CN")
        except ValueError:
            generate = True
            log.debug("no cert found")

        if not generate:
            log.debug("No need to regenerate")
            continue

        root = [ca for ca in cas if ca.ident == ce.authority]
        if not root:
            raise ValueError(f"No such CA: {ce.authority}")
        ca = root[0]

        ssh_ca = SSHClient()
        ssh_ca.load_system_host_keys()
        ssh_ca.connect(ca.storage.host)
        try:
            ca_data = load_keypair_data(ssh_ca, ca.storage.path)
        finally:
            ssh_ca.close()

        trust_new = _gen_cert(ce, ca_data, ca)
        mkdirp(ssh, ce.storage, "root")
        for km in trust_new.data:
            log.info(f"put {km.fname}")
            put(ssh, os.path.join(ce.storage, km.fname), km.body, "root",
                mode=("600" if km.mattype == "private" else "644"))
