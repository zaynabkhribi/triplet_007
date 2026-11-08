import httpx

from app.schemas.guardian import GuardianVerdict
from app.schemas.sensor import SensorReading


class GuardianClient:
    def __init__(self, base_url: str, api_key: str, client: httpx.AsyncClient) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"X-API-Key": api_key}
        self._client = client

    async def evaluate(self, reading: SensorReading) -> GuardianVerdict:
        response = await self._client.post(
            f"{self._base_url}/evaluate",
            headers=self._headers,
            json=reading.model_dump(mode="json"),
        )
        response.raise_for_status()
        return GuardianVerdict.model_validate(response.json())
