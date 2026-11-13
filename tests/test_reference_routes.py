from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from decompnet.app.routes.references import register
from decompnet.store import Store


class FakeMCP:
    def __init__(self):
        self.handlers = {}

    def custom_route(self, path, methods):
        def register(fn):
            self.handlers[(path, methods[0])] = fn
            return fn

        return register


class FakeJobs:
    def __init__(self):
        self.jobs = {}

    def start(self, kind, fn):
        jid = f"job{len(self.jobs) + 1}"
        self.jobs[jid] = (kind, fn)
        return jid


class Request:
    def __init__(self, query=None, data=None, writable=True):
        self.query_params = query or {}
        self.headers = {"write": writable}
        self.data = data or {}


@pytest.fixture
def harness(tmp_path):
    store = Store(tmp_path / "routes.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('one',?,'{}')", (str(tmp_path),))
        db.execute("INSERT INTO projects(slug,root,config) VALUES('two',?,'{}')", (str(tmp_path),))
    mcp, jobs = FakeMCP(), FakeJobs()

    def guard(req, write=False):
        if not req.headers:
            return {"error": "guard"}
        if write and not req.headers.get("write"):
            return {"error": "write guard"}
        return None

    async def body(req):
        return req.data

    async def call(fn, *args):
        return fn(*args)

    from starlette.responses import JSONResponse

    def fail(error, code=400):
        return JSONResponse({"error": str(error)}, status_code=code)

    app = SimpleNamespace(
        mcp=mcp, net=SimpleNamespace(store=store), jobs=jobs, guard=guard, body=body, call=call, fail=fail
    )
    register(app)
    yield mcp.handlers, jobs, tmp_path
    store.conn.close()


def invoke(handler, request):
    return asyncio.run(handler(request))


def test_route_guards_shapes_jobs_and_search(harness):
    handlers, jobs, root = harness
    path = root / "route.txt"
    path.write_text("searchword")
    add = invoke(handlers[("/api/references/add", "POST")], Request(data={"slug": "one", "path": str(path)}))
    payload = json.loads(add.body)
    assert payload["job"] == "job1" and payload["source"]["name"] == "route.txt"
    kind, work = jobs.jobs["job1"]
    assert kind == "reference-index"
    assert work(SimpleNamespace(check_cancel=lambda: None))["source"]["status"] == "ready"
    search = invoke(handlers[("/api/references/search", "GET")], Request(query={"slug": "one", "q": "searchword"}))
    assert json.loads(search.body)["results"][0]["path"] == "route.txt"
    assert (
        invoke(handlers[("/api/references/refresh", "POST")], Request(data={"slug": "one", "id": 1})).body
        == b'{"job":"job2"}'
    )
    assert (
        invoke(
            handlers[("/api/references/enabled", "POST")], Request(data={"slug": "one", "id": 1, "enabled": False})
        ).status_code
        == 200
    )
    assert (
        invoke(handlers[("/api/references/remove", "POST")], Request(data={"slug": "one", "id": 1})).body
        == b'{"removed":true}'
    )
    blocked = invoke(
        handlers[("/api/references/add", "POST")], Request(data={"slug": "one", "path": str(path)}, writable=False)
    )
    assert blocked["error"] == "write guard"
    missing = invoke(handlers[("/api/references/search", "GET")], Request(query={"slug": "missing", "q": ""}))
    assert missing.status_code == 400


def test_every_route_is_guarded(harness):
    handlers, _, _ = harness
    requests = {
        ("/api/references", "GET"): Request(query={"slug": "one"}, writable=False),
        ("/api/references/search", "GET"): Request(query={"slug": "one", "q": "x"}, writable=False),
        ("/api/references/add", "POST"): Request(data={}, writable=False),
        ("/api/references/refresh", "POST"): Request(data={}, writable=False),
        ("/api/references/enabled", "POST"): Request(data={"enabled": True}, writable=False),
        ("/api/references/remove", "POST"): Request(data={}, writable=False),
    }
    for key, request in requests.items():
        request.headers = {}
        assert invoke(handlers[key], request)["error"] == "guard"


def test_route_project_id_scoping_and_invalid_inputs(harness):
    handlers, jobs, root = harness
    file = root / "owned.txt"
    file.write_text("owned")
    add = invoke(handlers[("/api/references/add", "POST")], Request(data={"slug": "one", "path": str(file)}))
    assert add.status_code == 200
    cross = invoke(handlers[("/api/references/refresh", "POST")], Request(data={"slug": "two", "id": 1}))
    assert cross.status_code == 400
    bad_enabled = invoke(
        handlers[("/api/references/enabled", "POST")], Request(data={"slug": "one", "id": 1, "enabled": "false"})
    )
    assert bad_enabled.status_code == 400
    invalid_id = invoke(handlers[("/api/references/remove", "POST")], Request(data={"slug": "one", "id": "bad"}))
    assert invalid_id.status_code == 400
    long_query = invoke(handlers[("/api/references/search", "GET")], Request(query={"slug": "one", "q": "x" * 1001}))
    assert long_query.status_code == 400
