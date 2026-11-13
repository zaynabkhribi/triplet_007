"""Offline tests for Guardian SHADOW reconciliation (Task 7.3C-3A/-R).

The shadow worker observes and validates real Guardian evidence but NEVER
authorizes it: no GuardianVerdict records are minted, no real event becomes
TRUSTED, and decisions/actuators are untouched. All transports are injected;
no live calls.

Metric definitions asserted here:
* ``missing_rows`` — previously VERIFIED observation matches (by Brain event
  id) no longer returned; an operational observation, never revocation.
* ``stale_evidence`` — Guardian rows whose phenomenon_time exceeds the
  freshness window, evaluated independently of observation binding.
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.database.models import EventLifecycle, GuardianVerdictRecord, SensorEvent
from app.integration.guardian_compat import (
    GuardianCompatError,
    GuardianShadowWorker,
    GuardianVerifier,
)
from app.integration.ngsi_twin import TwinDeviceMap, poll_and_post
from app.main import create_app
from tests.integration.test_guardian_compat import guardian_frame
from tests.integration.test_ngsi_twin import (
    building_entity,
    fresh_stamp,
    transport_with,
)

GUARDIAN_TOKEN = "token-123"
ENTITY = "us-b-bldg-01"


def guardian_transport(status: int, body, rows_override=None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-Integration-Token") == GUARDIAN_TOKEN
        payload = {"verdicts": rows_override()} if rows_override else body
        return httpx.Response(status, json=payload if isinstance(payload, dict) else {})

    return httpx.MockTransport(handler)


@pytest.fixture
def shadow_mapping() -> TwinDeviceMap:
    return TwinDeviceMap.model_validate(
        {
            "version": 1,
            "sensors": [
                {
                    "entity_id": ENTITY,
                    "ngsi_type": "BuildingSensor",
                    "attribute": "smokeLevel",
                    "sensor_id": f"{ENTITY}:fire_smoke",
                    "measurement": "smoke",
                    "unit": "ppm",
                    "guardian_zone": "ZONE-B",
                    "guardian_property": "fire_smoke",
                    "guardian_unit": "ppm",
                }
            ],
        }
    )


@pytest.fixture
def shadow_settings(tmp_path) -> Settings:
    mapping_path = tmp_path / "devices.yaml"
    mapping_path.write_text(
        "version: 1\nsensors:\n"
        f"  - entity_id: {ENTITY}\n"
        "    ngsi_type: BuildingSensor\n"
        "    attribute: smokeLevel\n"
        f"    sensor_id: {ENTITY}:fire_smoke\n"
        "    measurement: smoke\n"
        "    unit: ppm\n"
        "    guardian_zone: ZONE-B\n"
        "    guardian_property: fire_smoke\n"
        "    guardian_unit: ppm\n",
        encoding="utf-8",
    )
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'events.db'}",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://brain",
        orion_base_url="http://orion",
        snap4city_ingest_enabled=True,
        snap4city_devices_file=str(mapping_path),
        worker_enabled=False,
        guardian_base_url="https://guardian",
        guardian_integration_token=GUARDIAN_TOKEN,
    )


def make_worker(shadow_settings, database, transport, shadow_mapping) -> GuardianShadowWorker:
    verifier = GuardianVerifier(
        shadow_settings, list(shadow_mapping.sensors), transport=transport
    )
    return GuardianShadowWorker(
        verifier,
        database,
        poll_seconds=0.05,
        stale_after_seconds=float(shadow_settings.event_freshness_seconds),
        transport=transport,
    )


async def ingest(shadow_settings, shadow_mapping, stamp=None):
    from app.integration.ngsi_twin import NgsiTwinPoller as Poller

    app = create_app(shadow_settings)
    async with app.router.lifespan_context(app):
        poller_obj = Poller(
            shadow_settings,
            shadow_mapping,
            transport=transport_with({ENTITY: building_entity(stamp=stamp)}),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://brain"
        ) as client:
            await poll_and_post(
                poller_obj, client, shadow_settings.twin_api_key.get_secret_value()
            )
        await app.state.processor.tick()
    return app, stamp


async def test_shadow_matches_persisted_observation(shadow_settings, shadow_mapping):
    stamp = fresh_stamp()
    app, _ = await ingest(shadow_settings, shadow_mapping, stamp)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=stamp
                )
            ],
        ),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["verified_matches"] == 1
    assert stats["trusted_granted"] == 0
    assert stats["mode"] == "shadow_reconciliation"


async def test_shadow_records_dispositions_and_does_not_grant_trust(
    shadow_settings, shadow_mapping
):
    stamp = fresh_stamp()
    app, _ = await ingest(shadow_settings, shadow_mapping, stamp)
    base = guardian_frame(property_name="fire_smoke", value=2.2, unit="ppm", stamp=stamp)
    rows = [base] + [
        {**base, "disposition": adverse}
        for adverse in ("SUSPECT", "RESTRICT", "MALICIOUS")
    ]
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(200, None, rows_override=lambda: rows),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["verified_matches"] == 4  # same digest, four dispositions
    assert stats["adverse_dispositions"] == 3
    assert stats["trusted_granted"] == 0
    with app.state.database.transaction() as session:
        assert session.scalars(select(GuardianVerdictRecord)).all() == []
        event_id = session.scalars(select(SensorEvent.id)).first()
        life = session.scalars(
            select(EventLifecycle).where(EventLifecycle.event_id == event_id)
        ).first()
        # Shadow observations must not flip trust: no verdict was ingested.
        assert life.state == "PENDING_VERDICT"


async def test_shadow_counts_mismatch_unknown_and_missing(
    shadow_settings, shadow_mapping
):
    stamp = fresh_stamp()
    app, _ = await ingest(shadow_settings, shadow_mapping, stamp)
    rows = [
        guardian_frame(property_name="fire_smoke", value=2.2, unit="ppm", stamp=stamp),
        guardian_frame(sensor_id="us-x-unknown-99", stamp=fresh_stamp()),
        guardian_frame(property_name="air_quality", stamp=stamp),
    ]
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(200, None, rows_override=lambda: rows),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["verified_matches"] == 1
    assert stats["unknown_mappings"] >= 1
    # Second cycle with no rows: the previously VERIFIED match goes missing —
    # an operational observation, NEVER treated as verified revocation.
    empty = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(200, {"verdicts": []}),
        shadow_mapping,
    )
    empty.stats.last_event_ids = worker.stats.last_event_ids
    stats2 = await empty.cycle()
    assert stats2["rows_fetched"] == 0
    assert stats2["missing_rows"] == 1
    assert stats2["trusted_granted"] == 0


async def test_shadow_flags_stale_evidence_without_binding(
    shadow_settings, shadow_mapping
):
    """Stale Guardian rows count as stale telemetry even with no Brain event.

    The NGSI Twin adapter rightly refuses to ingest stale observations, so no
    persisted event exists; staleness is evaluated from the row itself and
    the row is never accepted as evidence.
    """
    old_stamp = fresh_stamp(-10_000)  # far beyond the freshness window
    app, _ = await ingest(shadow_settings, shadow_mapping)  # current-time event only
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=old_stamp
                )
            ],
        ),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["stale_evidence"] == 1
    assert stats["verified_matches"] == 0  # nothing to bind the stale row to
    assert stats["trusted_granted"] == 0


async def test_shadow_fails_closed_per_worker(shadow_settings, shadow_mapping):
    app, _ = await ingest(shadow_settings, shadow_mapping)
    unauth = make_worker(
        shadow_settings, app.state.database, guardian_transport(401, {}), shadow_mapping
    )
    with pytest.raises(GuardianCompatError):
        await unauth.cycle()
    assert unauth.stats.transport_failures == 1  # per-worker counter
    down = make_worker(
        shadow_settings,
        app.state.database,
        httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(
                httpx.ConnectError("down", request=request)
            )
        ),
        shadow_mapping,
    )
    with pytest.raises(GuardianCompatError):
        await down.cycle()
    assert down.stats.transport_failures == 1


async def test_shadow_retries_in_loop_after_transport_failure(
    shadow_settings, shadow_mapping
):
    app, _ = await ingest(shadow_settings, shadow_mapping)
    worker = make_worker(
        shadow_settings, app.state.database, guardian_transport(401, {}), shadow_mapping
    )
    worker.start()
    for _ in range(100):
        if worker.stats.transport_failures >= 2:
            break
        await asyncio.sleep(0.05)
    assert worker.stats.transport_failures >= 2
    assert worker._task is not None and not worker._task.done()
    await worker.stop()
    assert worker._task is None


async def test_shadow_disabled_by_default(tmp_path):
    minimal = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'events.db'}",
        brain_api_key="b" * 48,
        twin_api_key="t" * 48,
        guardian_api_key="g" * 48,
        brain_base_url="http://brain",
    )
    assert minimal.guardian_shadow_reconciliation_enabled is False
    with pytest.raises(GuardianCompatError, match="disabled"):
        GuardianShadowWorker.from_settings(minimal, database=None)


async def test_shadow_requires_https_and_token(shadow_settings):
    enabled = {"guardian_shadow_reconciliation_enabled": True}
    plain = shadow_settings.model_copy(
        update={**enabled, "guardian_base_url": "http://guardian"}
    )
    with pytest.raises(GuardianCompatError, match="HTTPS"):
        GuardianShadowWorker.from_settings(plain, database=None)
    bare = shadow_settings.model_copy(
        update={**enabled, "guardian_integration_token": None}
    )
    with pytest.raises(GuardianCompatError, match="token"):
        GuardianShadowWorker.from_settings(bare, database=None)
    valid = shadow_settings.model_copy(update=enabled)
    assert GuardianShadowWorker.from_settings(valid, database=None) is not None


async def test_shadow_no_trust_no_commands(shadow_settings, shadow_mapping):
    """End-to-end offline: shadow reconciliation changes nothing authoritative."""
    stamp = fresh_stamp()
    app, _ = await ingest(shadow_settings, shadow_mapping, stamp)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=stamp
                )
            ],
        ),
        shadow_mapping,
    )
    await worker.cycle()
    assert await app.state.actuator_manager.tick() == 0
    with app.state.database.transaction() as session:
        assert session.scalars(select(GuardianVerdictRecord)).all() == []
        life = session.scalars(select(EventLifecycle)).first()
        assert life.state == "PENDING_VERDICT"
        assert life.eligible is False

# ---------------------------------------------------------------------------
# Task 7.3C-3B — hardening tests
# ---------------------------------------------------------------------------


async def test_shadow_bounded_candidate_scan_with_large_history(
    shadow_settings, shadow_mapping
):
    """Large historical table, small candidate set: bounded indexed query.

    Seeds many historical SensorEvents outside the recency window and asserts
    the worker inspects only the recent candidates — counted via
    ``candidates_inspected``, not elapsed-time guesses.
    """
    stamp = fresh_stamp()
    app, _ = await ingest(shadow_settings, shadow_mapping, stamp)
    with app.state.database.transaction() as session:
        reading = session.scalars(select(SensorEvent)).first()
        historical_payload = {
            **reading.payload,
            "event": {**reading.payload["event"], "sensor_id": f"{ENTITY}:fire_smoke"},
        }
        for i in range(300):
            session.add(
                SensorEvent(
                    id=uuid.uuid4(),
                    correlation_id=uuid.uuid4(),
                    occurred_at=datetime.now(UTC) - timedelta(days=i + 1),
                    payload=historical_payload,
                    sensor_id=f"{ENTITY}:fire_smoke",
                )
            )
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=stamp
                )
            ],
        ),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["verified_matches"] == 1
    assert stats["candidates_inspected"] == 1
    assert stats["trusted_granted"] == 0


async def test_shadow_identical_timestamps_across_sensors(shadow_settings):
    """Two mapped sensors sharing a timestamp are matched independently."""
    mapping = TwinDeviceMap.model_validate(
        {
            "version": 1,
            "sensors": [
                {
                    "entity_id": ENTITY,
                    "ngsi_type": "BuildingSensor",
                    "attribute": "smokeLevel",
                    "sensor_id": f"{ENTITY}:fire_smoke",
                    "measurement": "smoke",
                    "unit": "ppm",
                    "guardian_zone": "ZONE-B",
                    "guardian_property": "fire_smoke",
                    "guardian_unit": "ppm",
                },
                {
                    "entity_id": ENTITY,
                    "ngsi_type": "BuildingSensor",
                    "attribute": "temperature",
                    "sensor_id": f"{ENTITY}:temperature",
                    "measurement": "temperature",
                    "unit": "degC",
                    "guardian_zone": "ZONE-B",
                    "guardian_property": "temperature",
                    "guardian_unit": "C",
                },
            ],
        }
    )
    stamp = fresh_stamp()
    app, _ = await ingest(shadow_settings, mapping, stamp)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=stamp
                ),
                guardian_frame(
                    property_name="temperature", value=21.7, unit="C", stamp=stamp
                ),
            ],
        ),
        mapping,
    )
    stats = await worker.cycle()
    assert stats["verified_matches"] == 2
    assert stats["trusted_granted"] == 0


async def test_shadow_unknown_row_is_unknown_not_missing(
    shadow_settings, shadow_mapping
):
    """An unknown row never becomes a verified identity: no missing delta."""
    app, _ = await ingest(shadow_settings, shadow_mapping)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(sensor_id="us-x-unknown-99", stamp=fresh_stamp())
            ],
        ),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["unknown_mappings"] == 1
    assert stats["verified_matches"] == 0
    assert stats["missing_rows"] == 0


async def test_shadow_oversized_response_is_incomplete_not_absence(
    shadow_settings, shadow_mapping
):
    app, _ = await ingest(shadow_settings, shadow_mapping)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                # exceeds guardian_shadow_max_rows=500 default
                guardian_frame(stamp=fresh_stamp()) for _ in range(501)
            ],
        ),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["incomplete_cycles"] == 1
    assert stats["rows_fetched"] == 0
    assert stats["missing_rows"] == 0
    assert stats["trusted_granted"] == 0

# ---------------------------------------------------------------------------
# Task 7.3C-3C — candidate-query correctness tests
# ---------------------------------------------------------------------------


async def test_shadow_candidate_overflow_marks_cycle_incomplete(
    shadow_settings, shadow_mapping
):
    """More qualifying candidates than the cap: cycle must be incomplete.

    LIMIT+1 probe; unexamined candidates must never produce definitive
    missing/mismatched classifications. TWO distinct qualifying SensorEvents
    are persisted through the real ingestion API (distinct deterministic IDs,
    different timestamps, both inside the candidate window) and proven to
    exist in the database before the cycle runs.
    """
    old_stamp = fresh_stamp(-60)  # within the 300 s window of the newest row
    new_stamp = fresh_stamp()
    app, _ = await ingest(shadow_settings, shadow_mapping, old_stamp)
    # Second ingestion against the same app database: a distinct timestamp
    # yields a distinct deterministic event identity, so both persist.
    async with app.router.lifespan_context(app):
        from app.integration.ngsi_twin import NgsiTwinPoller

        poller_obj = NgsiTwinPoller(
            shadow_settings,
            shadow_mapping,
            transport=transport_with({ENTITY: building_entity(stamp=new_stamp)}),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://brain"
        ) as client:
            await poll_and_post(
                poller_obj, client, shadow_settings.twin_api_key.get_secret_value()
            )
    # Prove two distinct qualifying persisted records actually exist.
    with app.state.database.transaction() as session:
        persisted = session.scalars(
            select(SensorEvent).where(SensorEvent.sensor_id == f"{ENTITY}:fire_smoke")
        ).all()
        assert len(persisted) == 2
        assert len({str(row.id) for row in persisted}) == 2
        assert len({row.occurred_at.isoformat() for row in persisted}) == 2
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=old_stamp
                ),
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=new_stamp
                ),
            ],
        ),
        shadow_mapping,
    )
    worker.max_candidates = 1  # two qualify, one allowed -> overflow
    stats = await worker.cycle()
    assert stats["incomplete_cycles"] == 1
    assert stats["trusted_granted"] == 0
    assert stats["verified_matches"] == 0  # deferred, never misclassified
    assert stats["missing_rows"] == 0
    with app.state.database.transaction() as session:
        assert session.scalars(select(GuardianVerdictRecord)).all() == []


async def test_shadow_exact_cap_is_complete_not_incomplete(
    shadow_settings, shadow_mapping
):
    """Candidate count EQUAL to the cap: complete cycle, normal verification."""
    stamp = fresh_stamp()
    app, _ = await ingest(shadow_settings, shadow_mapping, stamp)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=stamp
                )
            ],
        ),
        shadow_mapping,
    )
    worker.max_candidates = 1  # exactly one qualifying candidate
    stats = await worker.cycle()
    assert stats["incomplete_cycles"] == 0
    assert stats["verified_matches"] == 1
    assert stats["candidates_inspected"] == 1
    assert stats["trusted_granted"] == 0


async def test_shadow_future_dated_row_cannot_exclude_valid_row(
    shadow_settings, shadow_mapping
):
    """A future-dated row must not push the window and drop a valid row."""
    stamp = fresh_stamp()
    future_stamp = fresh_stamp(600)
    app, _ = await ingest(shadow_settings, shadow_mapping, stamp)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=stamp
                ),
                guardian_frame(
                    property_name="fire_smoke", value=5.0, unit="ppm",
                    stamp=future_stamp,
                ),
            ],
        ),
        shadow_mapping,
    )
    stats = await worker.cycle()
    # The valid row still verified despite the future-dated companion row.
    assert stats["verified_matches"] == 1
    assert stats["trusted_granted"] == 0


async def test_shadow_old_row_alongside_recent_row(shadow_settings, shadow_mapping):
    """Old-but-valid evidence beside a recent row: stale counted, recent verified."""
    recent = fresh_stamp()
    old = fresh_stamp(-3600)  # beyond the 300 s freshness window
    app, _ = await ingest(shadow_settings, shadow_mapping, recent)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=recent
                ),
                guardian_frame(
                    property_name="fire_smoke", value=2.2, unit="ppm", stamp=old
                ),
            ],
        ),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["verified_matches"] == 1
    assert stats["stale_evidence"] == 1
    assert stats["trusted_granted"] == 0


async def test_shadow_malformed_timestamp_classified_as_mismatch(
    shadow_settings, shadow_mapping
):
    app, _ = await ingest(shadow_settings, shadow_mapping)
    worker = make_worker(
        shadow_settings,
        app.state.database,
        guardian_transport(
            200,
            None,
            rows_override=lambda: [
                guardian_frame(stamp="not-a-timestamp")
            ],
        ),
        shadow_mapping,
    )
    stats = await worker.cycle()
    assert stats["rejected_or_mismatched"] == 1
    assert stats["trusted_granted"] == 0
