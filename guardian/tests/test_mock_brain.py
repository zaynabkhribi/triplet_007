"""detect() pure-rule tests — the mock Brain's refusal logic (R1/R2).

The decision rule is unit-tested WITHOUT any I/O: given a passport, the
Brain must propose only what `allowed_actions` permits and refuse anything
else with a recorded reason. This is the machine-checked form of the
non-bypassable rule the jury watches live in T5.
"""


def _passport(disposition, allowed, pid="psp-042"):
    return {"passport_id": pid, "disposition": disposition,
            "trust": 0.9 if disposition == "TRUSTED" else 0.4,
            "allowed_actions": allowed}


def test_trusted_proposes_full_commit():
    from guardian.mock.mock_brain import decide
    d = decide(_passport("TRUSTED", ["full", "reversible", "precautionary"]),
               "valve.full_open")
    assert d["decision"] == "proposed" and d["action"] == "valve.full_open"


def test_suspect_refuses_full_open_with_reason():
    from guardian.mock.mock_brain import decide
    d = decide(_passport("SUSPECT", ["reversible", "precautionary"]),
               "valve.full_open")
    assert d["decision"] == "refused"
    assert "valve.full_open" in d["reason"] and "psp-042" in d["reason"]


def test_suspect_falls_back_to_precautionary():
    from guardian.mock.mock_brain import decide
    d = decide(_passport("SUSPECT", ["reversible", "precautionary"]),
               "valve.full_open", fallback="barrier.partial_close")
    assert d["decision"] == "refused" and d["fallback"] == "barrier.partial_close"


def test_malicious_allows_nothing_do_nothing_is_valid():
    from guardian.mock.mock_brain import decide
    d = decide(_passport("MALICIOUS", []), "valve.full_open",
               fallback="barrier.partial_close")
    assert d["decision"] == "refused" and d["fallback"] is None
    assert "do-nothing" in d["fallback_reason"]


def test_restrict_fallback_outside_allowed_is_ignored():
    from guardian.mock.mock_brain import decide
    d = decide(_passport("RESTRICT", ["precautionary"]), "valve.full_open",
               fallback="valve.full_open")
    assert d["fallback"] is None
