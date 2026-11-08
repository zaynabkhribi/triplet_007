from app.core.config import Settings


def test_configuration_defaults() -> None:
    settings = Settings(_env_file=None)
    assert settings.environment == "development"
    assert settings.database_url.startswith("sqlite:")


def test_configuration_reads_environment(monkeypatch: object) -> None:
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")  # type: ignore[attr-defined]
    assert Settings(_env_file=None).log_level == "DEBUG"
