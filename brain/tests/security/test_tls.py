import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.core.config import Settings
from app.integration.http import client_context
from scripts import setup_dev


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("certificates")
    original = setup_dev.__file__
    try:
        setup_dev.__file__ = str(root / "scripts" / "setup_dev.py")
        setup_dev.main()
    finally:
        setup_dev.__file__ = original
    return root / "certs"


@pytest.mark.parametrize("mode", ["valid", "no_certificate", "untrusted_ca", "tls12"])
def test_tls_handshake(certificates, mode) -> None:
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_3
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.load_cert_chain(certificates / "brain.crt", certificates / "brain.key")
    server_context.load_verify_locations(certificates / "ca.crt")
    settings = Settings(
        _env_file=None,
        tls_ca_file=str(certificates / "ca.crt"),
        tls_cert_file=str(certificates / "twin.crt"),
        tls_key_file=str(certificates / "twin.key"),
    )
    client = client_context(settings)
    if mode == "no_certificate":
        client = ssl.create_default_context(cafile=str(certificates / "ca.crt"))
    elif mode == "untrusted_ca":
        client = ssl.create_default_context()
    elif mode == "tls12":
        client.minimum_version = ssl.TLSVersion.TLSv1_2
        client.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)

        def serve() -> bool:
            connection, _ = listener.accept()
            connection.settimeout(5)
            try:
                with server_context.wrap_socket(connection, server_side=True) as secure:
                    secure.sendall(b"ok")
                    return secure.version() == "TLSv1.3"
            except (ssl.SSLError, ConnectionResetError):
                connection.close()
                return False

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(serve)
            try:
                with (
                    socket.create_connection(listener.getsockname(), timeout=5) as connection,
                    client.wrap_socket(connection, server_hostname="localhost") as secure,
                ):
                    received = secure.recv(2)
                    if mode == "valid":
                        assert received == b"ok"
                        assert secure.version() == "TLSv1.3"
                    else:
                        assert received == b""
            except (ssl.SSLError, ConnectionResetError):
                assert mode != "valid"
            assert future.result(timeout=5) == (mode == "valid")
