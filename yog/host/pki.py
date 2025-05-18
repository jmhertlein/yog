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
from yog.host.os_utils import Perms, Owner, RWXBits
from yog.host.pki_model import CAEntry, load_cas, parse_validity_period
from yog.ssh_utils import mkdirp, cat, exists, put, check_call, check_output, stat

log = logging.getLogger(__name__)

class KeyMaterial(t.NamedTuple):
    fname: str
    mattype: str
    body: str
    owner: t.Optional[Owner]
    perms: t.Optional[Perms]


class KeyPairDataItem(t.NamedTuple):
    field_name: str
    fname: str
    material_type: str

KEY_PAIR_DATA_ITEMS = [
    KeyPairDataItem("private_openssl", "key.pem.openssl", "private"),
    KeyPairDataItem("private_ssh", "key.ssh", "private"),
    KeyPairDataItem("public_pkcs", "key.pem.pkcs1.public", "public"),
    KeyPairDataItem("public_ssh", "key.ssh.public", "public"),
    KeyPairDataItem("certificate", "key.crt", "cert"),
]


class KeyPairData(t.NamedTuple):
    serial: uuid.UUID
    issuer_serial: uuid.UUID
    private_ssh: KeyMaterial
    private_openssl: KeyMaterial

    public_pkcs: KeyMaterial
    public_ssh: KeyMaterial

    certificate: KeyMaterial

    def materials(self) -> t.List[KeyMaterial]:
        return [self.private_ssh, self.private_openssl, self.public_ssh, self.public_pkcs, self.certificate]

    def raw_crt(self) -> KeyMaterial:
        return self.certificate

    def crt(self) -> Certificate:
        return x509.load_pem_x509_certificate(self.raw_crt().body.encode("utf-8"))

    def private(self) -> EllipticCurvePrivateKey:
        return load_pem_private_key(self.private_openssl.body.encode("utf-8"), None)

    def cert_names(self) -> t.List[str]:
        e: x509.SubjectAlternativeName = self.crt().extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return e.get_values_for_type(x509.DNSName)

    def issuer_cn(self) -> str:
        return self.crt().issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    def write(self, ssh: SSHClient, path: str, owner: t.Optional[Owner]=None, perms: t.Optional[Perms]=None):
        mkdirp(ssh, path, "root")
        for km in self.materials():
            put(ssh, os.path.join(path, km.fname), km.body,
                user=owner.user if owner else None,
                group=owner.group if owner else None,
                mode=("600" if km.mattype == "private" else perms.to_chmod_expr() if perms else "644"))
        put(ssh, os.path.join(path, "issuer_serial.txt"), str(self.issuer_serial), "root")
        put(ssh, os.path.join(path, "serial.txt"), str(self.serial), "root")

    @staticmethod
    def load(ssh: SSHClient, path: str) -> 'KeyPairData':
        serial_path = os.path.join(path, "serial.txt")
        issuer_serial_path = os.path.join(path, "issuer_serial.txt")
        if (not exists(ssh, issuer_serial_path)) or (not exists(ssh, serial_path)):
            raise ValueError(f"Unable to load {path} (missing serial file)")

        serial = uuid.UUID(cat(ssh, serial_path))
        issuer_serial = uuid.UUID(cat(ssh, issuer_serial_path))

        args = {}
        for i in KEY_PAIR_DATA_ITEMS:
            if not exists(ssh, os.path.join(path, i.fname)):
                raise ValueError(f"Unable to load {path} (missing key data)")
            args[i.field_name] = KeyMaterial(
                i.fname,
                i.material_type,
                cat(ssh, os.path.join(path, i.fname), i.material_type == "private"),
                *stat(ssh, os.path.join(path, i.fname))
            )

        return KeyPairData(serial, issuer_serial, **args) # TODO these Nones


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
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=parse_validity_period(ca.validity_period)))
    serial_no = uuid.uuid4()
    builder = builder.serial_number(int(serial_no))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    material = KeyPairData(
        serial_no,
        serial_no,
        KeyMaterial("key.ssh", "private", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8"), None, None),
        KeyMaterial("key.pem.openssl", "private", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"), None, None),
        KeyMaterial("key.pem.pkcs1.public", "public",
            public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8"), None, None),
        KeyMaterial("key.ssh.public", "public",
            public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
            ).decode("utf-8"), None, None),
        KeyMaterial("key.crt", "cert",
            certificate.public_bytes(
            encoding=serialization.Encoding.PEM,
            ).decode("utf-8"), None, None),
    )

    return material


def _gen_cert(ce: CertEntry, ca_data: KeyPairData, ca: CAEntry):
    private_key = ec.generate_private_key(
        curve = ec.SECP384R1(),
        backend=default_backend()
    )

    public_key = private_key.public_key()
    
    builder: x509.CertificateBuilder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ce.names[0]),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca.ident),
    ]))
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=parse_validity_period(ce.validity_period)))
    serial_no = uuid.uuid4()
    builder = builder.serial_number(int(serial_no))
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(n) for n in ce.names]), critical=False
    )
    certificate = builder.sign(
        private_key=ca_data.private(), algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    material = KeyPairData(
        serial_no,
        ca_data.issuer_serial,
        KeyMaterial("key.ssh", "private", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"), None, None),
        KeyMaterial("key.pem.openssl", "private", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8"), None, None),
        KeyMaterial("key.pem.pkcs1.public", "public",
            public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8"), None, None),
        KeyMaterial("key.ssh.public", "public",
            public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
            ).decode("utf-8"), None, None),
        KeyMaterial("key.crt", "cert",
            certificate.public_bytes(
            encoding=serialization.Encoding.PEM,
            ).decode("utf-8"), None, None),
    )

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
            cadata = KeyPairData.load(ssh, ca.storage.path)
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
    cadata.write(ssh, ca.storage.path)


def apply_pki_section(host: str, n: Necronomicon, ssh: SSHClient, root_dir):
    cas = load_cas(os.path.join(root_dir, "cas.yml"))

    hupcmds = set()

    for ce in n.pki.certs:
        generate = False

        root = [ca for ca in cas if ca.ident == ce.authority]
        if not root:
            raise ValueError(f"No such CA: {ce.authority}")
        ca = root[0]

        ssh_ca = SSHClient()
        ssh_ca.load_system_host_keys()
        ssh_ca.connect(ca.storage.host)
        try:
            ca_data = KeyPairData.load(ssh_ca, ca.storage.path)
        finally:
            ssh_ca.close()

        try:
            cur_trust = KeyPairData.load(ssh, ce.storage)
            cert: Certificate = cur_trust.crt()
            expiry = cert.not_valid_after_utc
            if (expiry - datetime.timedelta(days=parse_validity_period(ce.refresh_at_period))) <= datetime.datetime.now(datetime.timezone.utc):
                generate = True
                log.debug("Expiry too soon")
            elif set(ce.names) != set(cur_trust.cert_names()):
                generate = True
                log.debug("Set of names != cert names")
            elif cur_trust.issuer_cn() != ce.authority:
                generate = True
                log.debug("Issuer CN != authority ident")
            elif expiry > (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=parse_validity_period(ce.validity_period))):
                generate = True
                log.debug("expiry too far out")
            elif cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != ce.names[0]:
                generate = True
                log.debug("CN != cert CN")
            elif ca_data.serial != cur_trust.issuer_serial:
                generate = True
                log.debug("CA serial != cert issuer serial")
            elif ce.chown and any(Owner.from_str(ce.chown) != m.owner for m in cur_trust.materials() if m.mattype != "private"):
                generate = True
                log.debug("chown != current ownership")
            elif ce.chmod and any(Perms(*RWXBits.from_stat(ce.chmod)) != m.perms for m in cur_trust.materials() if m.mattype != "private"):
                generate = True
                log.debug("chmod != current perms")
        except ValueError:
            generate = True
            log.debug("no cert found")

        if not generate:
            log.info(f"[{host}][pki]: OK [{ce.storage}]")
            continue

        log.info(f"[{host}][pki]: stale [{ce.storage}]")

        trust_new = _gen_cert(ce, ca_data, ca)
        trust_new.write(ssh, ce.storage, None if not ce.chown else Owner.from_str(ce.chown), None if not ce.chmod else Perms(*RWXBits.from_stat(ce.chmod)))

        if ce.hupcmd:
            hupcmds.add(ce.hupcmd)

    for cmd in hupcmds:
        log.info(f"[{host}][pki][hup]: {cmd}")
        check_call(ssh, cmd)
