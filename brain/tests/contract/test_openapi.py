from app.main import create_app


def test_required_contracts_are_exposed() -> None:
    schema = create_app().openapi()
    paths = schema["paths"]
    assert "/readings" in paths
    assert "/verdicts" in paths
    assert "/feedback" in paths
    assert "/v1/actions/execute" in paths
    assert "/v1/actions/{command_id}/feedback" in paths
