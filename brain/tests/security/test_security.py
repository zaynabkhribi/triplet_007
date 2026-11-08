from uuid import uuid4

import pytest

from app.core.exceptions import TrustRejectedError
from app.schemas.guardian import GuardianVerdict, TrustStatus
from app.security.replay_protection import InMemoryReplayProtector
from app.security.trust_gate import GuardianTrustGate


async def test_replay_protection_rejects_duplicate() -> None:
    protector = InMemoryReplayProtector()
    event_id = uuid4()
    assert await protector.accept(event_id)
    assert not await protector.accept(event_id)


def test_trust_gate_rejects_untrusted_verdict() -> None:
    from datetime import UTC, datetime

    verdict = GuardianVerdict(
        verdict_id=uuid4(),
        event_id=uuid4(),
        event_hash="0" * 64,
        correlation_id=uuid4(),
        issued_at=datetime.now(UTC),
        status=TrustStatus.REJECTED,
        reason_code="test_rejection",
        guardian_id="guardian-test",
    )
    with pytest.raises(TrustRejectedError):
        GuardianTrustGate().enforce(verdict)
