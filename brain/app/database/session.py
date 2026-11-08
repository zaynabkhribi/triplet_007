import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import RLock

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Settings
from app.database import models  # noqa: F401
from app.database.base import Base

logger = logging.getLogger(__name__)

# Instrumentation thresholds (milliseconds) for logging slow phases.
_LOCK_WARN_MS = 500.0
_BEGIN_WARN_MS = 500.0
_BODY_WARN_MS = 1000.0
_COMMIT_WARN_MS = 500.0


class Database:
    def __init__(self, settings: Settings) -> None:
        options = {}
        if settings.database_url in {"sqlite://", "sqlite:///:memory:"}:
            options = {"poolclass": StaticPool, "connect_args": {"check_same_thread": False}}
        self.engine: Engine = create_engine(settings.database_url, **options)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)
        self._lock = RLock()

    @contextmanager
    def transaction(self, *, _source: str = "") -> Iterator[Session]:
        # Serialize short state mutations across processes; never hold this during network I/O.
        started = time.perf_counter()
        with self._lock, self.session_factory() as session:
            lock_ms = (time.perf_counter() - started) * 1000.0
            begin_started = time.perf_counter()
            try:
                if self.engine.dialect.name == "sqlite":
                    session.execute(text("BEGIN IMMEDIATE"))
                else:
                    session.execute(text("SELECT pg_advisory_xact_lock(1128416338)"))
                begin_ms = (time.perf_counter() - begin_started) * 1000.0
                if lock_ms > _LOCK_WARN_MS:
                    logger.warning(
                        "db_transaction_lock_slow lock_ms=%.1f source=%s",
                        lock_ms,
                        _source,
                    )
                if begin_ms > _BEGIN_WARN_MS:
                    logger.warning(
                        "db_transaction_begin_slow begin_ms=%.1f source=%s",
                        begin_ms,
                        _source,
                    )
                body_started = time.perf_counter()
                yield session
                body_ms = (time.perf_counter() - body_started) * 1000.0
                commit_started = time.perf_counter()
                session.commit()
                commit_ms = (time.perf_counter() - commit_started) * 1000.0
                total_ms = (time.perf_counter() - started) * 1000.0
                if (
                    body_ms > _BODY_WARN_MS
                    or commit_ms > _COMMIT_WARN_MS
                    or lock_ms > _LOCK_WARN_MS
                    or begin_ms > _BEGIN_WARN_MS
                ):
                    logger.warning(
                        "db_transaction_slow total_ms=%.1f lock_ms=%.1f "
                        "begin_ms=%.1f body_ms=%.1f commit_ms=%.1f source=%s",
                        total_ms,
                        lock_ms,
                        begin_ms,
                        body_ms,
                        commit_ms,
                        _source,
                    )
            except BaseException:
                session.rollback()
                raise

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)

        if self.engine.dialect.name == "sqlite":
            with self.engine.begin() as connection:
                connection.execute(
                    text("""
                        CREATE INDEX IF NOT EXISTS ix_audit_events_event_id_json
                        ON audit_events (
                            JSON_EXTRACT(payload, '$."event_id"')
                        )
                    """)
                )

    def close(self) -> None:
        self.engine.dispose()

    def session(self) -> Iterator[Session]:
        with self.session_factory() as session:
            yield session
