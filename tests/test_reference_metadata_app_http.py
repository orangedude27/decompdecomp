"""Metadata review and consent through the actual app HTTP transport, without compiling or launching a game."""

import json

import pytest
from starlette.testclient import TestClient

from decompnet.references import References

from . import test_app_server

reference_app = test_app_server.app


@pytest.mark.parametrize("kind", ["rom", "fork"])
def test_metadata_app_http_requires_explicit_mapping_review_and_model_consent(reference_app, tmp_path, kind):
    client, net, _ = reference_app
    slug, other = f"metadata-app-{kind}", f"metadata-other-{kind}"
    project = tmp_path / "project"
    project.mkdir()
    config = json.dumps({"kind": kind})
    with net.store.tx() as db:
        for name in (slug, other):
            db.execute("INSERT INTO projects(slug,root,config) VALUES(?,?,?)", (name, str(project), config))
        pid = db.execute("SELECT id FROM projects WHERE slug=?", (slug,)).fetchone()[0]
        target_id = db.execute("INSERT INTO functions(project_id,name,size,unit,vram,meta) VALUES(?,?,?,?,?,?)",
                               (pid, "old_http_name", 4, "unit.c", 0x80001000, "{}")).lastrowid
    file = tmp_path / "private-metadata.json"
    file.write_text(json.dumps({"schema": "decompdecomp.reference-metadata", "version": 1,
                                "kind": "symbols", "build": None,
                                "records": [{"id": "external", "kind": "function", "name": "ImportedHttpName",
                                             "signature": "void ImportedHttpName(void)"}]}), encoding="utf-8")
    body = {"slug": slug, "path": str(file)}
    headers = {"X-Decomp": "1"}
    anonymous = TestClient(client.app, base_url=f"http://127.0.0.1:{test_app_server.PORT}")
    assert anonymous.get("/api/reference-metadata", params={"slug": slug}).status_code == 401
    assert client.post("/api/reference-metadata/preview", json=body).status_code == 403
    preview = client.post("/api/reference-metadata/preview", headers=headers, json=body)
    assert preview.status_code == 200, preview.text
    assert preview.json()["identity_status"] == "unknown"
    assert net.store.one("SELECT COUNT(*) n FROM metadata_imports")["n"] == 0
    imported = client.post("/api/reference-metadata/import", headers=headers,
                           json=body | {"content_hash": preview.json()["content_hash"]})
    assert imported.status_code == 200, imported.text
    assert str(file) not in imported.text
    source = imported.json()["source"]
    assert source["agent_access"] is False
    refs = References(net.store)
    assert "ImportedHttpName" not in refs.agent_search(slug, "ImportedHttpName")["text"]
    consent = client.post("/api/references/agent-access", headers=headers,
                          json={"slug": slug, "id": source["id"], "agent_access": True})
    assert consent.status_code == 200, consent.text
    assert "ImportedHttpName" in refs.agent_search(slug, "ImportedHttpName")["text"]
    listing = client.get("/api/reference-metadata/records",
                         params={"slug": slug, "import_id": imported.json()["import"]["id"]})
    assert listing.status_code == 200, listing.text
    record = listing.json()["records"][0]
    assert record["status"] == "unbound"
    payload = {"slug": slug, "record_id": record["record_id"],
               "target": {"kind": "function", "id": target_id}, "proposed_name": "ReviewedHttpName"}
    cross = client.post("/api/reference-metadata/map", headers=headers, json=payload | {"slug": other})
    assert cross.status_code == 400, cross.text
    mapped = client.post("/api/reference-metadata/map", headers=headers, json=payload)
    assert mapped.status_code == 200, mapped.text
    assert mapped.json()["record"]["status"] == "pending"
    assert net.store.one("SELECT name FROM functions WHERE id=?", target_id)["name"] == "old_http_name"
    assert client.post("/api/reference-metadata/apply",
                       json={"slug": slug, "record_id": record["record_id"]}).status_code == 403
    rejected = client.post("/api/reference-metadata/reject", headers=headers,
                           json={"slug": slug, "record_id": record["record_id"]})
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["record"]["status"] == "rejected"
    assert net.store.one("SELECT name FROM functions WHERE id=?", target_id)["name"] == "old_http_name"
    assert net.store.one("SELECT config FROM projects WHERE id=?", pid)["config"] == config
    assert list(project.iterdir()) == []
    net.remove_project(slug)
    net.remove_project(other)
    assert net.store.one("SELECT COUNT(*) n FROM metadata_imports")["n"] == 0
