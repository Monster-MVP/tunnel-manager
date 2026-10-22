from pathlib import Path

import pytest
from app.main import create_app
from fastapi.testclient import TestClient


class NoConnectionEngine:
    async def restore(self):
        return []

    async def close(self):
        return None


@pytest.fixture
def isolated_api(tmp_path):
    project = Path(__file__).resolve().parents[2]
    assert tmp_path.is_relative_to(project)
    app = create_app(tmp_path / "data", engine=NoConnectionEngine())
    with TestClient(app, base_url=app.state.security.origin, raise_server_exceptions=False) as client:
        yield client, app


@pytest.fixture
def authenticated_api(isolated_api):
    client, app = isolated_api
    response = client.post("/api/v1/sessions/exchange", json={"ticket": app.state.security.issue_bootstrap_ticket()})
    assert response.status_code == 200
    client.headers.update({"Origin": app.state.security.origin, "X-CSRF-Token": response.json()["csrf"]})
    return client, app


@pytest.fixture
def security_repo(tmp_path):
    from app.db.repository import Repository

    project = Path(__file__).resolve().parents[2]
    assert tmp_path.is_relative_to(project)
    repo = Repository(tmp_path / "data")
    yield repo
    repo.close()
