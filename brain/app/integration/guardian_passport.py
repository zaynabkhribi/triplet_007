"""Guardian-native short-lived trust eligibility (Task 7.3G-6).

Adapts City Brain to the REAL Guardian's native authorization artifact: the
HMAC-signed Evidence Passport (guardian/src/guardian/passport.py), issued on
demand by ``POST /v1/passport`` for one specific ``evidence_digest``.

What this module does and does NOT claim:

* A passport IS cryptographically bound to one observation: its
  ``evidence_digest`` is sha256 over Guardian's canonical reading body, which
  Brain reconstructs FROM THE PERSISTED OBSERVATION and rejects on mismatch.
* A passport is NOT a durable GuardianVerdict: it has NO revision counter,
  NO revocation semantics, and a Guardian-side TTL of ~6 seconds. It is
  therefore represented here as SHORT-LIVED, NON-PERSISTENT eligibility --
  re-derived fresh before every externally visible action -- never written to
  the guardian_verdicts table, never attributed revision/revocation Guardian
  did not attest.

Security conditions (all mandatory, fail closed):

1. Explicit verification key (``guardian_passport_hmac_key``). The Guardian
   development default (``dev-guardian-service-key``) is REFUSED for
   authorization: it is public knowledge in this repository, so accepting it
   would let anyone forge Guardian-signed trust.
2. Signature check replicates Guardian exactly: HMAC-SHA256 over canonical
   JSON (sorted keys, compact separators, ensure_ascii=False) of the passport
   body minus ``signature``, value formatted ``hmac-sha256:<hex>``.
3. ``issued_at`` + ``ttl_s`` validity on the half-open interval
   [issued, issued+ttl) -- IDENTICAL arithmetic to Guardian's is_expired, so
   Brain never extends Guardian's TTL.
4. ``disposition`` must be exactly Guardian's TRUSTED literal.
5. Digest must equal the recomputed digest of the persisted observation.
6. The observation itself must still be freshness-valid.
7. Guardian device quarantine is not directly observable per-request, so
   quarantine checks remain OWNED by the existing Brain quarantine gates --
   this module NEVER overrides them.

Disabled by default: authorization requires BOTH
``guardian_passport_enabled=true`` AND the dev-environment restriction below.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.integration.guardian_compat import (
    GuardianCompatError,
    evidence_body,
    evidence_digest,
    require_guardian_url,
)

logger = logging.getLogger(__name__)

#: The only disposition this adapter may accept, spelled EXACTLY as Guardian's
#: score.py emits it (Stage E: ``codes = [tr.disposition] + ...``).
GUARDIAN_TRUSTED_DISPOSITION = "TRUSTED"

#: Guardian's development fallback key literal (config.py: key_env_var ->
#: passport._service_key). Authorization is REFUSED when the configured
#: verification key equals this value: it is not a secret.
_DEV_DEFAULT_KEY = "dev-guardian-service-key"


class PassportError(GuardianCompatError):
    """Fail-closed error for passport authorization attempts."""


@dataclass(frozen=True)
class PassportEligibility:
    """The result of one successful, momentary passport authorization.

    Deliberately carries NO revision and NO revocation state: Guardian does
    not attest either. ``valid_until`` is Brain's OWN enforced mirror of the
    passport TTL -- it authorizes NOTHING by itself; every consumer must
    revalidate (call ``authorize`` again) at its decision point.
    """

    evidence_digest: str
    disposition: str
    trust: float
    passport_id: str
    issued_at: datetime
    expires_at: datetime
    authorized_at: datetime


def _canonical(passport_body: dict[str, Any]) -> bytes:
    """Guardian passport canonicalization (passport.py::_canonical).

    Sorted keys, compact separators, ensure_ascii=False, minus ``signature``.
    MUST stay byte-identical to Guardian's implementation.
    """
    body = {k: v for k, v in passport_body.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sign(passport_body: dict[str, Any], key: bytes) -> str:
    return "hmac-sha256:" + hmac.new(
        key, _canonical(passport_body), hashlib.sha256
    ).hexdigest()


def verify_passport_signature(passport: dict[str, Any], key: bytes) -> bool:
    """Byte-exact mirror of Guardian's sign_passport comparison."""
    provided = str(passport.get("signature", ""))
    return hmac.compare_digest(_sign(passport, key), provided)


def parse_issued_at(raw: Any) -> datetime:
    """Parse Guardian's iso_from_epoch output (always UTC Z-suffixed)."""
    text = str(raw or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    stamp = datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        raise PassportError("passport issued_at has no timezone")
    return stamp.astimezone(UTC)


class GuardianPassportAuthorizer:
    """Derives SHORT-LIVED observation eligibility from signed passports.

    Disabled by default and only constructible for supervised development or
    test environments (see ``from_settings``).
    """

    def __init__(
        self,
        settings: Any,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Any = None,
    ) -> None:
        self.settings = settings
        self.transport = transport
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- configuration gates -------------------------------------------------

    @staticmethod
    def require_key_material(settings: Any) -> bytes:
        """Return the verification key or refuse to authorize.

        The known development default is rejected: possession of a PUBLIC
        constant is not Guardian authenticity. Both sides must be configured
        with a real shared secret (Brain: guardian_passport_hmac_key;
        Guardian: GUARDIAN_HMAC_KEY / auth.key_env_var).
        """
        key = getattr(settings, "guardian_passport_hmac_key", None)
        if key is None:
            raise PassportError(
                "guardian_passport_hmac_key is not configured; passport "
                "authorization requires explicitly provisioned key material"
            )
        value = key.get_secret_value() if hasattr(key, "get_secret_value") else str(key)
        if not value.strip() or value.strip() == _DEV_DEFAULT_KEY:
            raise PassportError(
                "guardian_passport_hmac_key must be a provisioned secret; the "
                "Guardian development default is refused for authorization"
            )
        return value.encode("utf-8")

    @staticmethod
    def require_environment(settings: Any) -> None:
        """Passports authorize ONLY in supervised dev/test environments."""
        environment = str(getattr(settings, "environment", "development")).lower()
        if environment not in {"development", "test"}:
            raise PassportError(
                "guardian passport authorization is restricted to supervised "
                f"development/test environments (found: {environment})"
            )
        if not getattr(settings, "guardian_passport_enabled", False):
            raise PassportError(
                "guardian_passport_enabled is not set; adapter stays disabled"
            )

    def _require_transport_policy(self) -> str:
        """HTTPS, or loopback HTTP under the explicit dev-only opt-in."""
        return require_guardian_url(self.settings)

    # -- authorization -------------------------------------------------------

    async def authorize(
        self,
        reading: Any,
        entry: Any,
        now: datetime | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> PassportEligibility:
        """Attempt momentary authorization for ONE persisted observation.

        ``reading`` is the persisted Brain SensorReading; ``entry`` its
        SensorMapping (Guardian vocabulary). Returns eligibility ONLY when
        every gate passes; every failure raises PassportError (fail closed).
        """
        self.require_environment(self.settings)
        key = self.require_key_material(self.settings)
        now = now or self._clock()
        if (
            reading.sensor_id != entry.sensor_id
            or reading.sensor_type != entry.measurement
            or reading.unit != entry.unit
            or reading.attributes.get("entity_id") != entry.entity_id
            or reading.attributes.get("attribute") != entry.attribute
        ):
            raise PassportError("observation does not match its Guardian channel mapping")

        # 1. Observation binding: recompute the digest from the PERSISTED
        #    observation -- never from attacker-controllable audit rows.
        entity_timestamp = str(reading.attributes.get("entity_timestamp", "") or "")
        if not entity_timestamp:
            raise PassportError("observation carries no entity timestamp")
        zone = str(reading.attributes.get("zone_id", "") or "")
        if not zone:
            raise PassportError("observation carries no zone")
        body = evidence_body(
            entry.entity_id,
            entry.guardian_zone or "",
            entry.guardian_property or "",
            entity_timestamp,
            float(reading.value),
            entry.guardian_unit or "",
        )
        digest = evidence_digest(body)
        # Observation freshness (Brain's own policy, independent of Guardian).
        occurred_at = reading.occurred_at
        if occurred_at.tzinfo is None:
            raise PassportError("observation timestamp has no timezone")
        age = (now - occurred_at).total_seconds()
        max_age = float(
            getattr(self.settings, "event_freshness_seconds", 300)
        )
        if age < 0 or age > max_age:
            raise PassportError(
                f"observation outside freshness window (age={age:.1f}s)"
            )

        # A cached verdict can be re-signed indefinitely. Bound the ORIGINAL
        # digest-bound observation time, never just the new issuance time.
        # This is a conservative evidence-age bound, not an attested assessment
        # timestamp or proof of current Guardian quarantine/revocation state.
        source_time = parse_issued_at(entity_timestamp)
        evidence_limit = float(
            getattr(self.settings, "guardian_passport_max_evidence_age_seconds", 30)
        )
        evidence_expiry = min(
            source_time + timedelta(seconds=evidence_limit),
            occurred_at + timedelta(seconds=max_age),
        )
        if source_time > now or now >= evidence_expiry:
            raise PassportError("original evidence outside freshness window")

        passport = await self._fetch_passport(digest, client)
        # Receipt time matters: the server issues the passport AFTER the
        # request starts, and network delay must consume its lifetime.
        now = max(now, self._clock())
        if now >= evidence_expiry:
            raise PassportError("original evidence expired during passport request")

        # 2. Guardian authenticity.
        if not verify_passport_signature(passport, key):
            raise PassportError("passport signature verification FAILED")

        # 3. Binding: the passport must certify THIS digest.
        if str(passport.get("evidence_digest", "")) != digest:
            raise PassportError("passport certifies a different evidence digest")

        # 4. Disposition: TRUSTED only.
        disposition = str(passport.get("disposition", ""))
        if disposition != GUARDIAN_TRUSTED_DISPOSITION:
            raise PassportError(
                f"passport disposition is {disposition!r}; refusing"
            )

        # 5. Expiry: Guardian's exact arithmetic, no TTL extension.
        issued_at = parse_issued_at(passport.get("issued_at"))
        ttl = float(passport.get("ttl_s", 0))
        if not math.isfinite(ttl) or not 0 < ttl <= 60:
            raise PassportError("passport ttl_s is not positive")
        expires_at = issued_at + timedelta(seconds=ttl)
        if not (issued_at <= now < expires_at):
            raise PassportError(
                f"passport outside validity window "
                f"(issued={issued_at.isoformat()}, ttl={ttl}s, now={now.isoformat()})"
            )

        return PassportEligibility(
            evidence_digest=digest,
            disposition=disposition,
            trust=float(passport.get("trust", 0.0)),
            passport_id=str(passport.get("passport_id", "")),
            issued_at=issued_at,
            expires_at=min(expires_at, evidence_expiry),
            authorized_at=now,
        )

    async def _fetch_passport(
        self,
        digest: str,
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        base = self._require_transport_policy()
        token = getattr(self.settings, "guardian_integration_token", None)
        headers = (
            {"X-Integration-Token": token.get_secret_value()}
            if token and hasattr(token, "get_secret_value")
            else {}
        )
        owned = client is None
        if owned:
            client = httpx.AsyncClient(
                transport=self.transport, trust_env=False, timeout=5.0
            )
        try:
            response = await client.post(
                f"{base}/v1/passport",
                headers=headers,
                json={"evidence_digest": digest},
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise PassportError("guardian unavailable for passport request") from exc
        finally:
            if owned:
                await client.aclose()
        if response.status_code == 404:
            # Guardian holds no current verdict for this digest: cache miss,
            # eviction, restart or the reading was REJECTED. All fail closed.
            raise PassportError(
                "guardian holds no verdict for this evidence (404)"
            )
        if response.status_code != 200:
            raise PassportError(
                f"guardian passport request returned HTTP {response.status_code}"
            )
        try:
            passport = response.json()
        except ValueError as exc:
            raise PassportError("guardian passport response is not JSON") from exc
        if not isinstance(passport, dict) or not passport.get("signature"):
            raise PassportError("guardian passport response is malformed")
        return passport
