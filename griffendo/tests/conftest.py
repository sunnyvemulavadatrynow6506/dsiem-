from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
os.environ["LOGPLATFORM_TOKEN"] = "synthetic-test-token"
AUTH = {"Authorization": "Bearer synthetic-test-token"}


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    folder = tmp_path / "state"
    monkeypatch.setenv("GRIFFENDO_STATE_DIR", str(folder))
    monkeypatch.delenv("GRIFFENDO_CATALOG", raising=False)
    return folder


@pytest.fixture
def client(state_dir):
    from fastapi.testclient import TestClient
    from logplatform import anomalies
    from logplatform.app import app

    anomalies.load_catalog(force=True)
    with TestClient(app) as test_client:
        from logplatform.detection.engine.service import service
        service()                      # v5.1 starts the engine in the background: wait for it here
        yield test_client


@pytest.fixture(autouse=True)
def _no_detection_worker(monkeypatch):
    # Tests drive the engine synchronously (conftest.drain) so results are deterministic.
    monkeypatch.setenv("GRIFFENDO_DETECTION_WORKER", "0")


def ingest(client, events, host="SYNTHETIC-WS01", agent="synthetic-agent-0001"):
    import synthetic

    response = client.post("/api/ingest", json=synthetic.batch(events, host=host, agent=agent), headers=AUTH)
    assert response.status_code == 202, response.text
    drain()
    return response.json()


def drain():
    """Wait until the background detection engine has processed everything stored (v5)."""
    from logplatform.detection.engine.service import service
    service().drain()

