import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import Settings
from app.schemas.actuator import ActuatorCommand


class OrionError(Exception):
    def __init__(self, code: str, retryable: bool, uncertain: bool = False) -> None:
        super().__init__(code)
        self.code, self.retryable, self.uncertain = code, retryable, uncertain


@dataclass(frozen=True)
class Delivery:
    accepted: bool
    transport_status: int


class OrionAdapter:
    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings, self.transport = settings, transport

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.settings.orion_bearer_token:
            headers["Authorization"] = (
                f"Bearer {self.settings.orion_bearer_token.get_secret_value()}"
            )
        elif self.settings.orion_api_key:
            headers[self.settings.orion_api_key_header] = (
                self.settings.orion_api_key.get_secret_value()
            )
        if self.settings.orion_fiware_service:
            headers["Fiware-Service"] = self.settings.orion_fiware_service
        if self.settings.orion_fiware_service_path:
            headers["Fiware-ServicePath"] = self.settings.orion_fiware_service_path
        return headers

    def payload(self, command: ActuatorCommand) -> dict[str, Any]:
        return {
            self.settings.orion_command_attribute: {
                "type": "StructuredValue",
                "value": command.model_dump(mode="json"),
                "metadata": {"commandId": {"type": "Text", "value": str(command.command_id)}},
            }
        }

    def _verify(self) -> ssl.SSLContext | bool:
        if self.settings.orion_base_url and self.settings.orion_base_url.scheme == "http":
            return False
        context = ssl.create_default_context(cafile=self.settings.orion_tls_ca_file or None)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if self.settings.orion_tls_cert_file:
            context.load_cert_chain(
                self.settings.orion_tls_cert_file,
                self.settings.orion_tls_key_file,
            )
        return context

    async def deliver(self, command: ActuatorCommand) -> Delivery:
        entity = quote(self.settings.orion_entity_prefix + command.actuator_id, safe="")
        url = f"{str(self.settings.orion_base_url).rstrip('/')}/v2/entities/{entity}/attrs"
        try:
            async with httpx.AsyncClient(
                verify=self._verify(),
                transport=self.transport,
                timeout=self.settings.command_timeout_seconds,
                trust_env=False,
            ) as client:
                response = await client.patch(
                    url, headers=self.headers(), json=self.payload(command)
                )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise OrionError("orion_delivery_uncertain", True, True) from exc
        if response.status_code == 204:
            return Delivery(True, 204)
        if response.status_code in {408, 429, 500, 502, 503, 504}:
            raise OrionError("orion_temporarily_unavailable", True)
        if response.status_code not in {400, 401, 403, 404, 409, 422}:
            raise OrionError("orion_invalid_response", False)
        raise OrionError(f"orion_rejected_{response.status_code}", False)

    async def state(self, actuator_id: str) -> dict[str, Any] | None:
        entity = quote(self.settings.orion_entity_prefix + actuator_id, safe="")
        attribute = quote(self.settings.orion_state_attribute, safe="")
        base = str(self.settings.orion_base_url).rstrip("/")
        url = f"{base}/v2/entities/{entity}/attrs/{attribute}"
        try:
            async with httpx.AsyncClient(
                verify=self._verify(),
                transport=self.transport,
                timeout=self.settings.command_timeout_seconds,
                trust_env=False,
            ) as client:
                response = await client.get(url, headers=self.headers())
        except httpx.HTTPError as exc:
            raise OrionError("orion_state_unavailable", True) from exc
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise OrionError("orion_state_invalid_response", response.status_code >= 500)
        value = response.json()
        if not isinstance(value, dict) or not isinstance(value.get("value"), dict):
            raise OrionError("orion_state_invalid_payload", False)
        return value["value"]
