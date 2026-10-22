from pathlib import Path

import pytest
from app.main import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def secured_api(tmp_path):
    """Actual middleware/repository/engine; no simulated success response."""
    project = Path(__file__).resolve().parents[2]
    assert tmp_path.is_relative_to(project)
    app = create_app(tmp_path / "data")
    with TestClient(app, base_url=app.state.security.origin, raise_server_exceptions=False) as client:
        yield client, app


@pytest.fixture
def secured_session(secured_api):
    client, app = secured_api
    result = client.post("/api/v1/sessions/exchange", json={"ticket": app.state.security.issue_bootstrap_ticket()})
    assert result.status_code == 200
    client.headers.update({"Origin": app.state.security.origin, "X-CSRF-Token": result.json()["csrf"]})
    return client, app
