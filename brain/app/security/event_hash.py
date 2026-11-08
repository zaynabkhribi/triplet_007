import hashlib
import json

from pydantic import BaseModel


def event_hash(event: BaseModel) -> str:
    canonical = json.dumps(
        event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256(canonical.encode()).hexdigest()
