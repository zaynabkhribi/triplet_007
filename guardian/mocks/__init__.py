"""R1 mocks — the Twin and Brain stand-ins that let the Guardian run alone.

The implementations are the tested modules under `guardian.mock`; this package
is the spec-shaped (`guardian/mocks/`) entry point for them.

Run either stand-in with no partner present and no Guardian code change:

    python -m mocks.mock_twin  --base http://127.0.0.1:8080 \
        --fixture shared/fixtures/fake_flood_t5.json --rebase
    python -m mocks.mock_brain --base http://127.0.0.1:8080 \
        --sensor port-gauge-1 --request valve.full_open --target valve-1

(`make mock` / `make mock-brain` run the same objects with PYTHONPATH set.)
They are the same code the Test Book drives, so the demo and the tests share
one path — there is no demo-only script.
"""
from guardian.mock import mock_brain, mock_twin  # noqa: F401

__all__ = ["mock_twin", "mock_brain"]
