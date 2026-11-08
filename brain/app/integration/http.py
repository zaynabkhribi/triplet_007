import ssl

import httpx
from fastapi import HTTPException, Request
from pydantic import BaseModel

from app.core.config import Settings


def client_context(settings: Settings) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=settings.tls_ca_file or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if settings.tls_cert_file:
        context.load_cert_chain(settings.tls_cert_file, settings.tls_key_file)
    return context


async def post_to_brain(
    request: Request, role: str, path: str, event: BaseModel | list[BaseModel]
) -> dict | list[dict]:
    settings = request.app.state.settings
    key = getattr(settings, f"{role}_api_key")
    if settings.brain_base_url is None or key is None:
        raise HTTPException(503, "Brain URL and service credential must be configured")
    transport = getattr(request.app.state, "transport", None)
    async with httpx.AsyncClient(
        verify=client_context(settings),
        transport=transport,
        timeout=5,
        trust_env=False,
    ) as client:
        try:
            response = await client.post(
                str(settings.brain_base_url).rstrip("/") + path,
                headers={"X-API-Key": key.get_secret_value()},
                json=(
                    [item.model_dump(mode="json") for item in event]
                    if isinstance(event, list)
                    else event.model_dump(mode="json")
                ),
            )
        except httpx.HTTPError as exc:
            print(
                f"[Guardian -> Brain] {path}: {type(exc).__name__}",
                flush=True,
            )
            raise HTTPException(502, "Brain unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(response.status_code, "Brain rejected event")
    return response.json()
