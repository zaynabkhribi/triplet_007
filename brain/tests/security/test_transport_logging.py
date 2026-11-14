import json
import logging
import sys

from app.core.logging import JsonFormatter, configure_logging


def test_orion_credentials_redacted_from_message_and_exception():
    url = "https://orion.invalid/entity?elementid=demo&type=DemoActuator&k1=synthetic-one&k2=synthetic-two"
    try:
        raise RuntimeError(url)
    except RuntimeError:
        record = logging.LogRecord(
            "transport", logging.ERROR, __file__, 1, "%s", (url,), sys.exc_info()
        )
    encoded = JsonFormatter().format(record)
    assert "synthetic-one" not in encoded and "synthetic-two" not in encoded
    payload = json.loads(encoded)
    assert "elementid=demo" in payload["message"]
    assert "k1=<redacted>&k2=<redacted>" in payload["exception"]


def test_debug_application_level_does_not_enable_transport_secrets():
    configure_logging("DEBUG")
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
    assert not logging.getLogger("httpcore").isEnabledFor(logging.DEBUG)
