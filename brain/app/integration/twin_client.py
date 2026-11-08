import httpx

from app.schemas.actuator import ActuatorCommand, ActuatorFeedback


class TwinClient:
    def __init__(self, base_url: str, api_key: str, client: httpx.AsyncClient) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"X-API-Key": api_key}
        self._client = client

    async def send_command(self, command: ActuatorCommand) -> ActuatorFeedback:
        response = await self._client.post(
            f"{self._base_url}/commands",
            json=command.model_dump(mode="json"),
            headers=self._headers,
        )
        response.raise_for_status()
        return ActuatorFeedback.model_validate(response.json())

    async def deliver(self, command: ActuatorCommand) -> ActuatorFeedback:
        return await self.send_command(command)
