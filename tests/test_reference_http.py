"""Reference snapshots through the real app's guarded HTTP routes and background jobs, without a game or compiler."""

import json
import time

import pytest
from starlette.testclient import TestClient

from . import test_app_server

reference_app = test_app_server.app
JOB_DEADLINE_SECONDS = 5


@pytest.mark.parametrize("kind", ["rom", "fork"])
def test_reference_http_lifecycle_is_private_and_never_changes_game_progress(reference_app, tmp_path, kind):
    client, net, _ = reference_app
    slug = f"reference-http-{kind}"
    project = tmp_path / "project"
    project.mkdir()
    reference = tmp_path / "private-reference.cpp"
    content = b"int ReferenceNeedle;\n// <script>not executable</script>\n"
    reference.write_bytes(content)
    config = json.dumps({"kind": kind})
    with net.store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES(?,?,?)", (slug, str(project), config))
    before_functions = [tuple(row) for row in net.store.all("SELECT * FROM functions")]
    before_attempts = [tuple(row) for row in net.store.all("SELECT * FROM attempts")]
    before_symbols = [tuple(row) for row in net.store.all("SELECT * FROM symbols")]
    anonymous = TestClient(client.app, base_url=f"http://127.0.0.1:{test_app_server.PORT}")
    assert anonymous.get("/api/references", params={"slug": slug}).status_code == 401
    assert client.post("/api/references/add", json={"slug": slug, "path": str(reference)}).status_code == 403

    response = client.post("/api/references/add", headers={"X-Decomp": "1"},
                           json={"slug": slug, "path": str(reference)})
    assert response.status_code == 200, response.text
    added = response.json()
    assert str(reference) not in response.text
    deadline = time.monotonic() + JOB_DEADLINE_SECONDS
    while True:
        job_response = client.get("/api/job", params={"id": added["job"]})
        assert job_response.status_code == 200, job_response.text
        job = job_response.json()
        if job["state"] != "running":
            break
        assert time.monotonic() < deadline, job
        time.sleep(0.01)
    assert job["state"] == "done", job
    assert job["result"]["source"]["status"] == "ready"
    assert str(reference) not in job_response.text

    listing = client.get("/api/references", params={"slug": slug}).json()
    assert listing["sources"][0]["file_count"] == 1
    search = client.get("/api/references/search", params={"slug": slug, "q": "referenceneedle"})
    assert search.status_code == 200, search.text
    hit = search.json()["results"][0]
    assert hit["path"] == reference.name and hit["line"] == 1
    assert hit["source_id"] == added["source"]["id"]
    body = {"slug": slug, "id": added["source"]["id"]}
    disabled = client.post("/api/references/enabled", headers={"X-Decomp": "1"},
                           json=body | {"enabled": False})
    assert disabled.status_code == 200 and disabled.json()["source"]["enabled"] is False
    assert client.get("/api/references/search", params={"slug": slug, "q": "ReferenceNeedle"}).json()["results"] == []
    removed = client.post("/api/references/remove", headers={"X-Decomp": "1"}, json=body)
    assert removed.status_code == 200 and removed.json() == {"removed": True}
    assert reference.read_bytes() == content
    assert list(project.iterdir()) == []
    assert net.store.one("SELECT config FROM projects WHERE slug=?", slug)["config"] == config
    assert [tuple(row) for row in net.store.all("SELECT * FROM functions")] == before_functions
    assert [tuple(row) for row in net.store.all("SELECT * FROM attempts")] == before_attempts
    assert [tuple(row) for row in net.store.all("SELECT * FROM symbols")] == before_symbols
    net.remove_project(slug)
