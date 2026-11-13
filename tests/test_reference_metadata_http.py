from __future__ import annotations

import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from starlette.responses import JSONResponse

from decompnet.app.routes.reference_metadata import register
from decompnet.store import Store


class FakeMCP:
    def __init__(self):
        self.handlers = {}

    def custom_route(self, path, methods):
        def add(fn):
            self.handlers[path, methods[0]] = fn
            return fn

        return add


class Request:
    def __init__(self, query=None, data=None, writable=True):
        self.query_params = query or {}
        self.data = data or {}
        self.headers = {"write": writable}


@pytest.fixture
def metadata_api(tmp_path):
    store = Store(tmp_path / "metadata.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('game',?,'{\"kind\":\"rom\"}')", (str(tmp_path),))
    mcp = FakeMCP()

    def guard(request, write=False):
        if write and not request.headers.get("write"):
            return JSONResponse({"error": "write guard"}, status_code=403)
        return None

    async def body(request):
        return request.data

    async def call(fn, *args):
        return fn(*args)

    def fail(error, code=400):
        return JSONResponse({"error": str(error)}, status_code=code)

    register(
        SimpleNamespace(
            mcp=mcp, net=SimpleNamespace(store=store, links={}), guard=guard, body=body, call=call, fail=fail
        )
    )
    yield mcp.handlers, tmp_path
    store.conn.close()


def invoke(handler, request):
    return asyncio.run(handler(request))


def test_metadata_routes_guard_preview_import_and_pages(metadata_api):
    handlers, root = metadata_api
    path = root / "metadata.json"
    path.write_text(
        json.dumps(
            {
                "schema": "decompdecomp.reference-metadata",
                "version": 1,
                "kind": "symbols",
                "build": None,
                "records": [{"id": "x", "kind": "function", "name": "ref_fn"}],
            }
        )
    )
    preview = invoke(
        handlers["/api/reference-metadata/preview", "POST"], Request(data={"slug": "game", "path": str(path)})
    )
    pdata = json.loads(preview.body)
    assert pdata["identity_status"] == "unknown" and pdata["record_count"] == 1
    imported = invoke(
        handlers["/api/reference-metadata/import", "POST"],
        Request(
            data={"slug": "game", "path": str(path), "content_hash": hashlib.sha256(path.read_bytes()).hexdigest()}
        ),
    )
    payload = json.loads(imported.body)
    assert payload["source"]["agent_access"] is False
    listing = invoke(handlers["/api/reference-metadata", "GET"], Request(query={"slug": "game"}))
    assert len(json.loads(listing.body)["imports"]) == 1
    page = invoke(
        handlers["/api/reference-metadata/records", "GET"],
        Request(query={"slug": "game", "import_id": str(payload["import"]["id"])}),
    )
    assert json.loads(page.body)["records"][0]["status"] == "unbound"
    blocked = invoke(handlers["/api/reference-metadata/import", "POST"], Request(data={}, writable=False))
    assert blocked.status_code == 403


def test_file_open_errors_do_not_disclose_local_path(metadata_api, monkeypatch):
    handlers, root = metadata_api
    path = root / "private-location" / "source.json"
    path.parent.mkdir()
    path.write_text(
        json.dumps(
            {"schema": "decompdecomp.reference-metadata", "version": 1, "kind": "symbols", "build": None, "records": []}
        )
    )

    def denied(_path, *_args, **_kwargs):
        raise PermissionError(13, "permission denied", str(path))

    monkeypatch.setattr("decompnet.reference_metadata.os.open", denied)
    response = invoke(
        handlers["/api/reference-metadata/preview", "POST"], Request(data={"slug": "game", "path": str(path)})
    )
    assert response.status_code == 400
    assert str(root) not in response.body.decode()


def test_nonstring_paths_and_record_ids_return_client_errors(metadata_api):
    handlers, _ = metadata_api
    bad_path = invoke(
        handlers["/api/reference-metadata/preview", "POST"],
        Request(data={"slug": "game", "path": {"path": "/tmp/nope"}}),
    )
    bad_id = invoke(
        handlers["/api/reference-metadata/apply", "POST"],
        Request(data={"slug": "game", "record_id": "999999999999999999999999"}),
    )
    wrong_type_id = invoke(
        handlers["/api/reference-metadata/apply", "POST"], Request(data={"slug": "game", "record_id": {"id": 1}})
    )
    assert bad_path.status_code == 400 and bad_id.status_code == 400 and wrong_type_id.status_code == 400


def test_malformed_schema_types_are_client_errors(metadata_api):
    handlers, root = metadata_api
    path = root / "invalid-kind.json"
    path.write_text('{"schema":"decompdecomp.reference-metadata","version":1,"kind":[],"records":[]}')
    response = invoke(
        handlers["/api/reference-metadata/preview", "POST"], Request(data={"slug": "game", "path": str(path)})
    )
    assert response.status_code == 400
    assert "metadata" in json.loads(response.body)["error"].lower()


def test_metadata_route_target_search_is_scoped_and_bounded(metadata_api):
    handlers, _ = metadata_api
    response = invoke(
        handlers["/api/reference-metadata/targets", "GET"], Request(query={"slug": "game", "q": "x" * 257})
    )
    assert response.status_code == 400
