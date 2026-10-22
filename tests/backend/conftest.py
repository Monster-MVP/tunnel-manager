from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from app.api.routes import create_router
from app.api.security import SecurityManager, SecurityMiddleware
from app.db.repository import Repository
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient


@pytest.fixture
def data_dir():
    root = Path(__file__).resolve().parents[2] / "var" / "tmp" / "backend-tests"
    root.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=root) as temporary:
        yield Path(temporary)


@pytest.fixture
def repo(data_dir):
    repository = Repository(data_dir)
    yield repository
    repository.close()


@pytest.fixture
def api(repo):
    app = FastAPI()
    security = SecurityManager("http://127.0.0.1:18401")
    app.state.security = security
    app.add_middleware(SecurityMiddleware, security=security)
    app.include_router(create_router(repo))

    @app.exception_handler(HTTPException)
    async def errors(request, error):
        return JSONResponse(error.detail, status_code=error.status_code)

    with TestClient(app, base_url="http://127.0.0.1:18401") as client:
        yield client, security


@pytest.fixture
def authed(api):
    client, security = api
    response = client.post("/api/v1/sessions/exchange", json={"ticket": security.issue_bootstrap_ticket()})
    assert response.status_code == 200
    client.headers.update({"X-CSRF-Token": response.json()["csrf"], "Origin": security.origin})
    return client
