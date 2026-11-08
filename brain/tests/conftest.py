import secrets

import pytest

from app.core.config import Settings


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'events.db'}",
        brain_api_key=secrets.token_urlsafe(48),
        twin_api_key=secrets.token_urlsafe(48),
        guardian_api_key=secrets.token_urlsafe(48),
        brain_base_url="http://brain",
    )
