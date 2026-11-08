from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException

from app.security.authentication import authenticate_service


def require_role(*allowed_roles: str) -> Callable:
    async def authorize(role: Annotated[str, Depends(authenticate_service)]) -> str:
        if role not in allowed_roles:
            raise HTTPException(403, "insufficient role")
        return role

    return authorize
