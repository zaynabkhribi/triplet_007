import ssl
from dataclasses import dataclass
from pathlib import Path
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


class OrionActuatorCredentials:
    """Per-actuator K1/K2 credentials for the hosted Orion Broker Filter.

    Task 7.3G: the platform authenticates WRITES with per-device query
    parameters (`?elementid=<id>&type=<type>&k1=<K1>&k2=<K2>`); a PATCH
    without them is rejected 401. Values live in a git-ignored JSON file
    (same schema as the Twin's secrets.json); they are read at delivery
    time, never logged, never returned in API responses, and only attached
    to the exact device being commanded.
    """

    def __init__(self, path: str | None) -> None:
        self.path = Path(path) if path else None
        self._keys: dict[str, dict[str, str]] | None = None

    def _load(self) -> dict[str, dict[str, str]]:
        if self._keys is not None:
            return self._keys
        self._keys = {}
        if self.path and self.path.exists():
            import json

            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._keys = {}
            else:
                if isinstance(raw, dict):
                    self._keys = {
                        str(dev): {"k1": str(v.get("k1", "")), "k2": str(v.get("k2", ""))}
                        for dev, v in raw.items()
                        if isinstance(v, dict) and v.get("k1") and v.get("k2")
                    }
        return self._keys

    def for_device(self, device_id: str) -> dict[str, str] | None:
        """Return k1/k2 for one device, or None (unauthenticated attempt)."""
        return self._load().get(device_id) or None


class OrionAdapter:
    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings, self.transport = settings, transport
        self.credentials = OrionActuatorCredentials(
            settings.orion_actuator_secrets_file
        )

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
        """Match the REAL Twin actuator contract (INTERFACE-DETAILS.md §5).

        A command is a plain NGSI attribute write: the action name IS the
        attribute name (alarmState, phase, taskStatus, ...), the parameters
        are the attribute values. The previous StructuredValue wrapper with
        a commandId metadata blob is not part of the real contract and the
        Twin would IGNORE the unknown attribute (model.py poll_commands).
        """
        attrs: dict[str, Any] = {}
        for name, value in command.parameters.items():
            if isinstance(value, bool):
                attrs[name] = {"type": "string", "value": "true" if value else "false"}
            elif isinstance(value, (int, float)):
                attrs[name] = {"type": "float", "value": float(value)}
            else:
                attrs[name] = {"type": "string", "value": str(value)}
        return attrs

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
        params: dict[str, str] = {
            # Twin INTERFACE-DETAILS.md §3: every write MUST carry the entity
            # routing params elementid/type alongside the device keys.
            "elementid": self.settings.orion_entity_prefix + command.actuator_id,
            "type": self.entity_type_for(command.actuator_id),
        }
        # Task 7.3G: the hosted Broker Filter authenticates WRITES with the
        # commanded device's own k1/k2 (Twin INTERFACE-DETAILS.md §3). Attach
        # ONLY that device's credentials from the git-ignored secrets file;
        # a missing entry means an unauthenticated attempt that the broker
        # will reject 401 (fail closed, reported honestly).
        device_keys = self.credentials.for_device(command.actuator_id)
        if device_keys:
            params.update(k1=device_keys["k1"], k2=device_keys["k2"])
        try:
            async with httpx.AsyncClient(
                verify=self._verify(),
                transport=self.transport,
                timeout=self.settings.command_timeout_seconds,
                trust_env=False,
            ) as client:
                response = await client.patch(
                    url, headers=self.headers(), json=self.payload(command),
                    params=params,
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

    async def read_entity(self, actuator_id: str) -> dict[str, Any] | None:
        """Read-only entity fetch for command acknowledgement (Task 7.3G).

        The worker requires a publication timestamp AFTER delivery and exact
        target values. An immediate echo of our PATCH is not execution proof.
        Reads are unauthenticated per contract (no k1/k2 needed).
        """
        base = str(self.settings.orion_base_url).rstrip("/")
        identifier = self.settings.orion_entity_prefix + actuator_id
        url = f"{base}/v2/entities/{quote(identifier, safe='')}"
        try:
            async with httpx.AsyncClient(
                verify=self._verify(),
                transport=self.transport,
                timeout=self.settings.command_timeout_seconds,
                trust_env=False,
            ) as client:
                response = await client.get(
                    url,
                    params={
                        "elementid": identifier,
                        "type": self.entity_type_for(actuator_id),
                    },
                )
        except httpx.HTTPError as exc:
            raise OrionError("orion_state_unavailable", True) from exc
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise OrionError("orion_state_invalid_response", response.status_code >= 500)
        try:
            entity = response.json()
        except ValueError as exc:
            raise OrionError("orion_state_invalid_payload", False) from exc
        if (
            not isinstance(entity, dict)
            or entity.get("id") != identifier
            or entity.get("type") != self.entity_type_for(actuator_id)
        ):
            raise OrionError("orion_state_invalid_payload", False)
        return {
            k: (v.get("value") if isinstance(v, dict) and "value" in v else v)
            for k, v in entity.items()
            if k not in ("id", "type")
        }

    def entity_type_for(self, actuator_id: str) -> str:
        """NGSI type per the real platform registry (Twin config devices)."""
        return {
            "us-a-light-01": "TrafficLight",
            "us-a-light-03": "TrafficLight",
            "us-a-sign-01": "RoadSign",
            "us-b-alarm-01": "FireAlarm",
            "us-b-disp-01": "EmergencyDispatch",
            "us-c-task-01": "CleaningTask",
        }.get(actuator_id, "")
