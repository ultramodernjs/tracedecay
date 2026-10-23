#!/usr/bin/env python3
"""Regenerate the Remote Brain TLS test chains before their leaves expire.

Run `python3 -I tests/fixtures/remote_tls/regenerate.py` from the repository.
Requires the Python `cryptography` package (`python3 -m pip install cryptography`).
No generator dependency is needed to run the Rust tests. Existing server keys
are test-only fixtures; fresh CA private keys remain in memory and are discarded.

Apple's platform TLS verifier rejects the former ten-year leaf certificates.
Leaves are backdated one day and valid for 397 days; roots remain valid for ten
years. The invalid variants retain their individual constraint violations.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import ipaddress


def regenerate(directory: Path) -> None:
    start = datetime.now(timezone.utc) - timedelta(days=1)

    def certificate(key, subject, issuer, issuer_key, *, ca, eku=None, ip=None):
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(start + timedelta(days=3650 if subject == issuer else 397))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=not ca,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=ca,
                    crl_sign=ca,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        )
        if eku is not None:
            builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        if ip is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip)), x509.DNSName("localhost")]),
                critical=False,
            )
        return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def name(common_name):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    def chain(prefix, root_name):
        server_key = serialization.load_pem_private_key((directory / f"{prefix}.key.pem").read_bytes(), password=None)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = name(root_name)
        root = certificate(ca_key, ca_name, ca_name, ca_key, ca=True)
        leaf_name = name("localhost")
        leaf = certificate(server_key, leaf_name, ca_name, ca_key, ca=False, eku=ExtendedKeyUsageOID.SERVER_AUTH, ip="127.0.0.1")
        (directory / f"{prefix}-root.crt.pem").write_bytes(root)
        (directory / f"{prefix}.crt.pem").write_bytes(leaf + root)
        return server_key, ca_key, ca_name, leaf_name, leaf, root

    server_key, ca_key, ca_name, leaf_name, leaf, root = chain("localhost", "TraceDecay Remote Brain Test Root A")
    (directory / "localhost-leaf.crt.pem").write_bytes(leaf)
    for filename, is_ca, eku, ip in [
        ("ca-true", True, ExtendedKeyUsageOID.SERVER_AUTH, "127.0.0.1"),
        ("client-auth-only", False, ExtendedKeyUsageOID.CLIENT_AUTH, "127.0.0.1"),
        ("wrong-ip", False, ExtendedKeyUsageOID.SERVER_AUTH, "127.0.0.2"),
    ]:
        variant = certificate(server_key, leaf_name, ca_name, ca_key, ca=is_ca, eku=eku, ip=ip)
        (directory / f"{filename}.crt.pem").write_bytes(variant + root)
    chain("alternate", "TraceDecay Remote Brain Test Root B")


if __name__ == "__main__":
    regenerate(Path(__file__).resolve().parent)
