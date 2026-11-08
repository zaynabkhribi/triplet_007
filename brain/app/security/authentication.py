import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def authenticate_service(
    request: Request,
    provided_key: Annotated[str | None, Depends(api_key_header)] = None,
) -> str:
    for role in ("twin", "guardian", "brain"):
        configured = getattr(request.app.state.settings, f"{role}_api_key")
        if (
            configured
            and provided_key
            and secrets.compare_digest(
                provided_key.encode(), configured.get_secret_value().encode()
            )
        ):
            return role
    raise HTTPException(401, "invalid service credentials")
