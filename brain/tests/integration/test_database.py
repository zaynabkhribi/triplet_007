from pathlib import Path

from sqlalchemy import inspect

from app.core.config import Settings
from app.database.session import Database


def test_database_initialization(tmp_path: Path) -> None:
    database = Database(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}", _env_file=None))
    database.initialize()
    tables = inspect(database.engine).get_table_names()
    database.close()
    assert "sensor_events" in tables
    assert "audit_events" in tables
