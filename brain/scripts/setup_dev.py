import ipaddress
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    directory = root / "certs"
    if directory.exists() or (root / ".env").exists():
        raise SystemExit("Refusing to overwrite certs or .env")
    directory.mkdir(mode=0o700)
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "City Brain Local CA")])

    def builder(name: x509.Name, public_key: object) -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=30))
        )

    def save(name: str, key: object, certificate: x509.Certificate) -> None:
        key_path = directory / f"{name}.key"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        (directory / f"{name}.crt").write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )

    ca = (
        builder(ca_name, ca_key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    save("ca", ca_key, ca)
    for service in ("brain", "twin", "guardian"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service)])
        certificate = (
            builder(name, key.public_key())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.DNSName(service),
                        x509.DNSName("proxy"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        save(service, key, certificate)
    lines = [
        f"{role}_API_KEY={secrets.token_urlsafe(48)}" for role in ("BRAIN", "TWIN", "GUARDIAN")
    ]
    lines += [
        "BRAIN_BASE_URL=http://127.0.0.1:8000",
        "TWIN_BASE_URL=http://127.0.0.1:8001",
        "GUARDIAN_BASE_URL=http://127.0.0.1:8002",
    ]
    env = root / ".env"
    env.write_text("\n".join(lines) + "\n", encoding="utf-8")
    env.chmod(0o600)


if __name__ == "__main__":
    main()
