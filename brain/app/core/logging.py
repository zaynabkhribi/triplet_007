import json
import logging
import re
from datetime import UTC, datetime
from typing import Any


def redact_transport_secrets(text: str) -> str:
    return re.sub(r"(?i)([?&](?:k1|k2)=)[^&\s\"']*", r"\1<redacted>", text)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_transport_secrets(record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = redact_transport_secrets(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=level.upper(), handlers=[handler], force=True)
    # HTTPX INFO includes full URLs, and HTTP transport DEBUG may include
    # headers. Device credentials belong on the wire, never in service logs.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
