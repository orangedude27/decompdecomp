"""The real app guards reference-trial endpoints before touching preparation or execution."""

from starlette.testclient import TestClient

from . import test_app_server

reference_app = test_app_server.app


def test_reference_trial_routes_use_window_and_write_guards(reference_app):
    client, net, _ = reference_app
    slug = "reference-trial-http"
    with net.store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES(?,?,?)", (slug, ".", '{"kind":"rom"}'))
    anonymous = TestClient(client.app, base_url=f"http://127.0.0.1:{test_app_server.PORT}")
    assert anonymous.get("/api/reference-trials", params={"slug": slug}).status_code == 401
    assert client.get("/api/reference-trials", params={"slug": slug}).status_code == 200
    body = {
        "slug": slug,
        "plan": "not-a-plan",
        "source": "int f(){}",
        "prelude": "",
        "accept_if_verified": True,
        "allow_progress_copy": False,
    }
    assert client.post("/api/reference-trials/run", json=body).status_code == 403
    response = client.post("/api/reference-trials/run", headers={"X-Decomp": "1"}, json=body)
    assert response.status_code == 400
    assert "consent" in response.json()["error"]
    extra = client.post("/api/reference-trials/run", headers={"X-Decomp": "1"}, json=body | {"flags": []})
    assert extra.status_code == 400 and "exactly" in extra.json()["error"]
    assert net.store.one("SELECT COUNT(*) AS n FROM reference_trials")["n"] == 0
    net.remove_project(slug)
