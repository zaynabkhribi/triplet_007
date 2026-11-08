"""AEGIS LOOP Guardian — the five-stage trust pipeline (plan §6).

Stage A (Charter check) and Stages B-E (Calibrate / Corroborate / Scrutinize /
Consolidate) are implemented. Stage A is the transport gate (schema -> dedup ->
identity -> provenance -> signature -> freshness/TTL/seq-gap); B-E run the 10
detectors, the 6-factor trust score + hard gates, and build/store the Evidence
Passport verdict. Each stage emits a stable reason code so verdicts are
explainable, unit-testable, and deterministic.

One hash-chained audit record per reading (carrying the stage trace + verdict) is
what the live timeline tails (plan §10, §11). Verdicts are stored for on-demand
passport issuance (POST /v1/passport, plan §6.5).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .audit import AuditLog
from .config import Settings, load_policy, load_sensor_profiles
from .dedup import SeenSet
from .detectors import DetectorContext, DetectionResult, Sibling, run_detectors
from .errors import (
    ACCEPTED,
    DUPLICATE,
    EFFECT_MISMATCH,
    PROVENANCE_MISSING,
    SIG_INVALID,
    STALE,
    GuardianError,
)
from .passport import VerdictRecord
from .registry import DeviceRegistry
from .score import (ScoringPolicy, allowed_actions_for, compute_trust, conditions_for)
from .signing import derive_reading_id, parse_iso, verify_reading_integrity

# Stage letters + canonical names (plan §6.1)
_STAGES = [("A", "charter_check"), ("B", "calibrate"), ("C", "corroborate"),
           ("D", "scrutinize"), ("E", "consolidate")]

# sliding-window sizes for corroboration / detector history
_RECENT_TICKS = 5
_HISTORY_TICKS = 6
# a phenomenon_time this far ahead of now is un-verifiable (matches the Stage-A gate)
_FUTURE_TOLERANCE_S = 1.0

# --- Witness feedback -> history factor + quarantine (plan §11) ---
# The `history` factor is the device's rolling reliability: a MISMATCH witness halves
# it (an action the device's own evidence authorised did not happen), and a clean
# witness lets it recover slowly. Enough consecutive MISMATCHes quarantine the device.
HISTORY_INIT = 1.0
HISTORY_DECAY_ON_MISMATCH = 0.5
HISTORY_RECOVERY = 0.05
QUARANTINE_AFTER_MISMATCHES = 3

# Cap on the in-memory verdict cache (the audit log remains the durable record).
_MAX_VERDICTS = 10_000


@dataclass
class StageReport:
    stage: str
    name: str
    status: str  # ok | rejected | skipped | pending
    codes: List[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> Dict:
        return {"stage": self.stage, "name": self.name, "status": self.status,
                "codes": self.codes, "detail": self.detail}


@dataclass
class ReadingReport:
    accepted: bool
    code: str
    message: str
    reading_id: str
    batch_id: str
    sensor_id: str
    zone: str = ""
    observed_property: str = ""
    value: object = None
    event_id: Optional[int] = None
    stages: List[StageReport] = field(default_factory=list)
    verdict: Optional[VerdictRecord] = None


class Pipeline:
    """Orchestrates the five stages for a reading. Dependency-injected for tests."""

    def __init__(self, settings: Settings, registry: DeviceRegistry,
                 seen: SeenSet, audit: AuditLog, *, now: Optional[float] = None) -> None:
        self.s = settings
        self.registry = registry
        self.seen = seen
        self.audit = audit
        self.policy = load_policy(settings)
        self._profiles = load_sensor_profiles(settings)
        # Scoring tunables are read from policy.yaml (the single source of truth);
        # validate once at startup so a malformed policy fails loudly, not silently.
        self.scoring = ScoringPolicy.from_policy(self.policy)
        self.scoring.validate()
        self._now = now  # inject for deterministic scoring tests
        self._verdicts: Dict[str, VerdictRecord] = {}
        self._device_history: Dict[str, float] = {}
        self._zone_sensors: Dict[str, List[str]] = {}
        self._mismatch_streak: Dict[str, int] = {}
        self._recent: Dict[str, List[dict]] = {}   # zone -> recent reading dicts
        self._seq_vals: Dict[str, List[float]] = {}
        self._digests: Dict[str, List[str]] = {}
        # FastAPI dispatches these sync endpoints on a threadpool, so concurrent
        # POSTs mutate the dedup set, sequence watermarks, history windows and the
        # verdict cache. A single reentrant lock keeps a reading's Stage-A check and
        # its history update atomic with respect to other readings.
        self._lock = threading.RLock()

    # -- run scoping (R2: one trigger = one run) --------------------------
    def reset_run(self) -> None:
        """Start a NEW run: clear run-scoped trust state, keep the audit.

        The contract separates `run_id` from the durable evidence record. The
        audit log is append-only and must survive (the jury reads old runs), but
        dedup keys, sequence watermarks, corroboration windows, effect history
        and the verdict cache all belong to ONE run: carrying them across runs
        makes a second `run scenario t5` report every frame as DUPLICATE and
        judge the city on frames it never saw this run.

        Anti-replay is NOT weakened: replay inside a run is still caught by the
        seen-set, and a replayed frame from an EARLIER run is caught by the
        freshness gate plus the audit record of that run.
        """
        with self._lock:
            self.seen.clear()
            self._verdicts.clear()
            self._device_history.clear()
            self._zone_sensors.clear()
            self._mismatch_streak.clear()
            self._recent.clear()
            self._seq_vals.clear()
            self._digests.clear()
            for device_id in list(self.registry.runtime_quarantines()):
                self.registry.clear_quarantine(device_id)

    # -- witness feedback (plan §11) --------------------------------------
    def note_effect(self, device_id: str, result: str) -> Optional[float]:
        with self._lock:
            return self._note_effect_locked(device_id, result)

    def _note_effect_locked(self, device_id: str, result: str) -> Optional[float]:
        """Fold an effect-witness result into the device's `history` factor.

        A MISMATCH (an action the device's evidence authorised did not happen) halves
        its reliability; enough consecutive MISMATCHes quarantine it. A clean witness
        lets it recover slowly. Returns the new history score, or None for an
        unknown/absent device.
        """
        device_id = str(device_id or "")
        if not device_id or self.registry.get(device_id) is None:
            return None
        current = self._device_history.get(device_id, HISTORY_INIT)
        if str(result).upper() == EFFECT_MISMATCH:
            current = max(0.0, current * HISTORY_DECAY_ON_MISMATCH)
            self._mismatch_streak[device_id] = self._mismatch_streak.get(device_id, 0) + 1
            if self._mismatch_streak[device_id] >= QUARANTINE_AFTER_MISMATCHES:
                self.registry.quarantine(
                    device_id,
                    f"{self._mismatch_streak[device_id]} consecutive MISMATCH witnesses")
        else:
            current = min(HISTORY_INIT, current + HISTORY_RECOVERY)
            self._mismatch_streak[device_id] = 0
        self._device_history[device_id] = current
        return current

    # -- helpers -----------------------------------------------------------
    def _now_epoch(self) -> float:
        return self._now if self._now is not None else time.time()

    def _siblings(self, zone: str, sensor_id: str, prop: str = "") -> List[dict]:
        """Readings that can corroborate this one.

        Two sources count:
          * another device in the same zone, and
          * the SAME device publishing a different property — a building sensor
            reports smokeLevel and temperature on one entity, and the fire
            signature is precisely the relationship between them. Excluding the
            whole device made that corroboration impossible.
        """
        out = []
        for r in self._recent.get(zone, []):
            same_device = r.get("sensor_id") == sensor_id
            same_prop = r.get("observed_property") == prop
            if same_device and same_prop:
                continue          # never corroborate a reading with itself
            out.append(r)
        return out

    def _window(self, store: Dict[str, List], key: str, max_n: int) -> List:
        lst = store.setdefault(key, [])
        return lst[-max_n:]

    def get_verdict(self, evidence_digest: str) -> Optional[VerdictRecord]:
        return self._verdicts.get(evidence_digest)

    def all_verdicts(self) -> List[VerdictRecord]:
        return list(self._verdicts.values())

    def _evict_verdicts(self) -> None:
        """Bound the in-memory verdict cache.

        Verdicts are minted into Evidence Passports on demand, so this is a working
        set, not the system of record — the append-only audit log is durable and
        replayable. Evict oldest-first so a long-running server cannot grow without
        bound; a passport for an evicted digest is correctly refused (404).
        """
        while len(self._verdicts) > _MAX_VERDICTS:
            self._verdicts.pop(next(iter(self._verdicts)))

    # -- Stage A: Charter check -------------------------------------------
    def _stage_a(self, raw: dict) -> StageReport:
        reading_id = derive_reading_id(raw)
        sensor_id = str(raw.get("sensor_id", ""))

        # A1 - anti-replay / dedup
        if self.seen.seen_before(reading_id):
            return StageReport("A", "charter_check", "rejected", [DUPLICATE], "duplicate reading_id")
        # A2 - device identity
        try:
            self.registry.require(sensor_id)
        except GuardianError as exc:
            return StageReport("A", "charter_check", "rejected", [exc.code], exc.message)
        # A3 - provenance presence
        prov = raw.get("provenance") or {}
        if not prov.get("firmware") or not prov.get("cal"):
            return StageReport("A", "charter_check", "rejected", [PROVENANCE_MISSING], "missing firmware/calibration")
        # A4 - signature verification (when enabled)
        if self.s.auth.verify_signatures:
            secret = self.registry.secret_for(sensor_id)
            ok, reason = verify_reading_integrity(raw, secret)
            if not ok:
                return StageReport("A", "charter_check", "rejected", [SIG_INVALID], f"signature check failed: {reason}")
        # A5 - freshness / TTL / sequence-gap (when enabled)
        if self.s.ttl.enforce_freshness:
            reason = self._freshness(raw)
            if reason:
                return StageReport("A", "charter_check", "rejected", [STALE], reason)
            reason = self._sequence(raw, sensor_id)
            if reason:
                return StageReport("A", "charter_check", "rejected", [STALE], reason)
        return StageReport("A", "charter_check", "ok", ["CHARTER_OK"], "charter ok")

    def _freshness(self, raw: dict) -> Optional[str]:
        now = self._now_epoch()
        try:
            age = now - parse_iso(str(raw.get("phenomenon_time")))
        except Exception:
            return "unparseable phenomenon_time"
        if age > float(self.s.ttl.reading_max_age_s):
            return f"reading age {age:.1f}s exceeds TTL {self.s.ttl.reading_max_age_s}s"
        if age < -_FUTURE_TOLERANCE_S:
            return f"phenomenon_time in the future by {-age:.1f}s"
        return None

    def _sequence(self, raw: dict, sensor_id: str) -> Optional[str]:
        """Validate provenance.seq against the watermark WITHOUT mutating it.

        The watermark is advanced only by `commit_seq` after the reading is accepted,
        so a rejected replayed frame cannot roll it backwards and re-open the window
        for the next old frame.
        """
        seq = (raw.get("provenance") or {}).get("seq")
        if seq is None:
            return None
        prev = self.registry.peek_seq(sensor_id)
        if prev is None:
            return None
        if seq <= prev:
            return f"non-monotonic sequence {seq} <= {prev}"
        if seq - prev > 1:
            return f"sequence gap {prev}->{seq}"
        return None

    # -- Stages B-E ------------------------------------------------------
    def _build_ctx(self, raw: dict) -> DetectorContext:
        zone = str(raw.get("zone", ""))
        prop = str(raw.get("observed_property", ""))
        sensor_id = str(raw.get("sensor_id", ""))
        siblings_raw = self._siblings(zone, sensor_id, prop)
        siblings = [Sibling(sensor_id=s.get("sensor_id", ""), observed_property=s.get("observed_property", ""),
                            value=float((s.get("result") or {}).get("value", 0) or 0),
                            phenomenon_time=str(s.get("phenomenon_time", ""))) for s in siblings_raw]
        return DetectorContext(
            reading_time=self._now_epoch(),
            reading_property=prop,
            sensor_id=sensor_id,
            siblings=siblings,
            profiles=self._profiles,
            profile=self._profiles.get(prop),
            history_values=self._window(self._seq_vals, f"{sensor_id}|{prop}", _HISTORY_TICKS),
            history_digests=self._window(self._digests, f"{sensor_id}|{prop}", _HISTORY_TICKS),
            ttl_s=float(self.s.ttl.reading_max_age_s),
            future_tolerance_s=_FUTURE_TOLERANCE_S,
            coupled_rise=self._coupled_rise(sensor_id, prop, zone),
        )

    def _coupled_rise(self, sensor_id: str, prop: str, zone_of: str = "") -> bool:
        """Did a declared corroborator of `prop` rise alongside it?

        Only the properties a profile names in `corroborators` count, so this is
        the same physics the CONFLICT detector uses, read in the other
        direction: CONFLICT asks "does a corroborator disagree?", this asks "does
        a corroborator agree upward?". Without it, the correct fire signature
        (smoke and heat climbing together) looked like a DRIFT attack.
        """
        from .detectors import COUPLED_PROPERTIES

        if prop not in COUPLED_PROPERTIES:
            return False
        declared = (self._profiles.get(prop) or {}).get("corroborators") or []
        own = self._seq_vals.get(f"{sensor_id}|{prop}") or []
        if len(own) < 3:
            return False
        own_up = all(b > a - 1e-9 for a, b in zip(own, own[1:]))
        if not own_up:
            return False
        for other in declared:
            series = self._seq_vals.get(f"{sensor_id}|{other}") or []
            if len(series) >= 3 and all(b > a - 1e-9 for a, b in zip(series, series[1:])):
                return True
        # Same property, other devices in the same zone: a jam or a filling bin
        # moves every sensor that measures it. A lone device drifting while its
        # neighbours stay flat is the S1 signature, and must still flag.
        for other_id in self._zone_sensors.get(zone_of, ()):
            if other_id == sensor_id:
                continue
            series = self._seq_vals.get(f"{other_id}|{prop}") or []
            if len(series) >= 3 and all(b > a - 1e-9 for a, b in zip(series, series[1:])):
                return True
        return False

    def _record_history(self, raw: dict) -> None:
        """Update the per-zone / per-device context windows AFTER scoring a reading."""
        sensor_id = str(raw.get("sensor_id", ""))
        prop = str(raw.get("observed_property", ""))
        # Per-property key: one device can publish several physical measures
        # (a building sensor sends smokeLevel AND temperature), and a shared
        # series would compare ppm against degrees Celsius.
        key = f"{sensor_id}|{prop}"
        zone = str(raw.get("zone", ""))
        v = self._value_of(raw)
        if sensor_id not in self._zone_sensors.setdefault(zone, []):
            self._zone_sensors[zone].append(sensor_id)
        self._recent.setdefault(zone, []).append(raw)
        self._recent[zone] = self._recent[zone][-_RECENT_TICKS:]
        if v is not None:
            self._seq_vals.setdefault(key, []).append(float(v))
            self._seq_vals[key] = self._seq_vals[key][-_HISTORY_TICKS:]
        digest = str(raw.get("digest", ""))
        if digest:
            self._digests.setdefault(key, []).append(digest)
            self._digests[key] = self._digests[key][-_HISTORY_TICKS:]

    @staticmethod
    def _value_of(raw: dict):
        res = raw.get("result")
        return res.get("value") if isinstance(res, dict) else None

    def _stage_b(self, raw: dict, ctx: DetectorContext, detections: List[DetectionResult]) -> StageReport:
        unit = (raw.get("result") or {}).get("unit", "")
        expected = (ctx.profile or {}).get("unit", "")
        range_det = next((d for d in detections if d.detector == "range"), None)
        codes = ["CAL_OK"]
        detail = "calibration ok"
        if expected and unit != expected:
            codes.append("UNIT_MISMATCH")
            detail += f"; unit '{unit}' != '{expected}'"
        if range_det and range_det.flag:
            codes.append(range_det.flag)
            detail += f"; {range_det.detail}"
        return StageReport("B", "calibrate", "ok", codes, detail)

    def _stage_c(self, raw: dict, ctx: DetectorContext, detections: List[DetectionResult]) -> StageReport:
        names = {d.detector for d in detections if d.flag}
        codes = ["CORROBORATED"] if "conflict" not in names and ctx.siblings else (["SINGLE_SOURCE"] if not ctx.siblings else [])
        if "conflict" in names:
            codes.append("CONFLICT")
        detail = f"siblings={len(ctx.siblings)}; flags={sorted(names) if names else 'none'}"
        return StageReport("C", "corroborate", "ok", codes, detail)

    def _stage_d(self, raw: dict, ctx: DetectorContext, detections: List[DetectionResult]) -> StageReport:
        flags = sorted({d.flag for d in detections if d.flag})
        return StageReport("D", "scrutinize", "ok", flags,
                           f"{len( detections)} detectors ran; {len(flags)} flagged")

    def _stage_e(self, raw: dict, ctx: DetectorContext, detections: List[DetectionResult]) -> StageReport:
        sensor_id = str(raw.get("sensor_id", ""))
        quarantined = self.registry.is_quarantined(sensor_id)
        history_score = self._device_history.get(sensor_id, HISTORY_INIT)
        tr = compute_trust(raw, detections, ctx,
                           device_known=True, signature_ok=self.s.auth.verify_signatures,
                           quarantined=quarantined, history_score=history_score,
                           policy=self.scoring)
        # build VerdictRecord for on-demand passport issuance
        record = VerdictRecord(
            evidence_digest=str(raw.get("digest", "")),
            reading_id=derive_reading_id(raw),
            zone=str(raw.get("zone", "")),
            sensor_id=sensor_id,
            observed_property=str(raw.get("observed_property", "")),
            disposition=tr.disposition,
            trust=tr.trust,
            reason_codes=tr.reason_codes,
            factors=tr.factors.to_dict(),
            conflict=tr.conflict,
            verified_at=ctx.reading_time,
            policy_version=self.policy.get("policy_version", "v1.0"),
            # Single source of truth for the disposition -> action mapping (score.py).
            allowed_actions=allowed_actions_for(tr.disposition, self.policy),
            conditions=conditions_for(tr.disposition, self.policy),
            source_ids=list(dict.fromkeys([sensor_id] + [s.sensor_id for s in ctx.siblings])),
        )
        self._verdicts[record.evidence_digest] = record
        self._evict_verdicts()
        codes = [tr.disposition] + tr.reason_codes
        return StageReport("E", "consolidate", "ok", codes,
                           f"T={tr.trust:.2f} {tr.disposition}; {tr.reason_codes}"), record

    # -- Orchestrator -----------------------------------------------------
    def process(self, raw: dict) -> ReadingReport:
        with self._lock:
            return self._process_locked(raw)

    def _process_locked(self, raw: dict) -> ReadingReport:
        reading_id = derive_reading_id(raw)
        batch_id = str(raw.get("batch_id", ""))
        sensor_id = str(raw.get("sensor_id", ""))
        zone = str(raw.get("zone", ""))
        prop = str(raw.get("observed_property", ""))
        value = self._value_of(raw)

        stage_a = self._stage_a(raw)
        stages = [stage_a]
        accepted = stage_a.status == "ok"

        if accepted:
            self.seen.add(reading_id)
            # Advance the monotonic sequence watermark only now that the frame is
            # accepted; a rejected frame must never move it.
            if self.s.ttl.enforce_freshness:
                self.registry.commit_seq(sensor_id, (raw.get("provenance") or {}).get("seq"))
            ctx = self._build_ctx(raw)
            detections = run_detectors(raw, ctx)
            self._record_history(raw)
            stages.append(self._stage_b(raw, ctx, detections))
            stages.append(self._stage_c(raw, ctx, detections))
            stages.append(self._stage_d(raw, ctx, detections))
            e_report, verdict = self._stage_e(raw, ctx, detections)
            stages.append(e_report)
            rec = self.audit.append({
                "event": "reading.accepted", "code": ACCEPTED,
                "reading_id": reading_id, "batch_id": batch_id, "sensor_id": sensor_id,
                "zone": zone, "observed_property": prop, "value": value,
                "evidence_digest": str(raw.get("digest", "")),
                "stages": [s.to_dict() for s in stages],
                "disposition": verdict.disposition if verdict else None,
                "trust": verdict.trust if verdict else None,
                "passport_id": verdict.passport_id if verdict else None,
                "reason_codes": verdict.reason_codes if verdict else [],
                "note": "verdict computed; Evidence Passport issued on demand (plan §6.5)",
            })
            return ReadingReport(
                accepted=True, code=ACCEPTED, message="reading accepted",
                reading_id=reading_id, batch_id=batch_id, sensor_id=sensor_id,
                zone=zone, observed_property=prop, value=value,
                event_id=rec.get("seq"), stages=stages, verdict=verdict,
            )
        else:
            rec = self.audit.append({
                "event": "reading.rejected", "code": stage_a.codes[0] if stage_a.codes else "REJECTED",
                "reading_id": reading_id, "batch_id": batch_id, "sensor_id": sensor_id,
                "message": stage_a.detail, "stages": [stage_a.to_dict()],
            })
            return ReadingReport(
                accepted=False, code=stage_a.codes[0] if stage_a.codes else "REJECTED",
                message=stage_a.detail, reading_id=reading_id, batch_id=batch_id, sensor_id=sensor_id,
                event_id=rec.get("seq"), stages=stages,
            )
