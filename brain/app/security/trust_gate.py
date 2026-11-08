from app.core.exceptions import TrustRejectedError
from app.schemas.guardian import GuardianVerdict, TrustStatus


class GuardianTrustGate:
    def enforce(self, verdict: GuardianVerdict) -> None:
        if verdict.status is not TrustStatus.TRUSTED:
            raise TrustRejectedError(f"guardian verdict: {verdict.status}")
