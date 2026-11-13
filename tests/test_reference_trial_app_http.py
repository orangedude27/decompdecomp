"""Actual app transport + real signed preparation + existing core; only build/diff tools are stand-ins."""
import hashlib
import json
from contextlib import nullcontext
from types import MethodType, SimpleNamespace

import pytest
from starlette.testclient import TestClient

from decompnet.app.engine import autopilot
from decompnet.app.server import build
from decompnet.network import Network
from decompnet.scoring import DiffResult

from .test_app_server import PORT, SECRET, WINDOW
from .test_reference_trial_core import CANDIDATE, ORIGINAL_BYTES, NoMatchHooksNetwork, make_fork_core

HEADERS = {"X-Decomp": "1"}


def http_trial(tmp_path, monkeypatch, mode, *, match=False, build_ok=True):
    if mode == "fork":
        core = make_fork_core(tmp_path, match=match, build_ok=build_ok)
        net, root, unit = core["net"], core["fp"].root, core["unit"]
        (root / "expected").mkdir()
        unit.target = root / "expected/unit.o"
        unit.target.write_bytes(b"synthetic original object")
        unit.base = root / "build/unit.o"
        (root / "objdiff.json").write_text(json.dumps({"units": [{"name": "unit", "target_path": "expected/unit.o",
            "base_path": "build/unit.o", "metadata": {"source_path": unit.source}}]}))
        (root / "build.ninja").write_text("rule cc\n  command = never-run $in -o $out\n")
        slug = "fork-trial"
        fid, sid = core["function_id"], core["preparer"].payload["origin"]["source_id"]
        calls = core["build_calls"]
    else:
        root = tmp_path / "game"
        root.mkdir()
        net = NoMatchHooksNetwork(tmp_path / "app.db", tmp_path / "work")
        slug = "rom-trial"
        with net.store.tx() as db:
            pid = db.execute("INSERT INTO projects(slug,root,config,arch) VALUES(?,?,?,'mips')",
                (slug, str(root), json.dumps({"kind": "rom", "compiler": {"cmd": ["never-run"], "flags": ["-O2"]}}))).lastrowid
            fid = db.execute("INSERT INTO functions(project_id,name,status,n_insns,size,target,relocs,vram) VALUES(?,'trial_fn','open',1,4,?,'[]',4096)", (pid, b"abcd")).lastrowid
            sid = db.execute("INSERT INTO reference_sources(project_id,name,root,kind,status) VALUES(?,'Private reference','/never-open-reference-root','file','ready')", (pid,)).lastrowid
            db.execute("INSERT INTO context_versions(project_id,version,header,unit) VALUES(?,1,'typedef int T;','')", (pid,))
        calls = []
        net._compile = lambda *_args: (calls.append(_args) or SimpleNamespace(ok=build_ok, obj=object()))
        net._evaluate = lambda *_args: (object(), match, None)
        net._target_obj = lambda *_args: object()
        monkeypatch.setattr(autopilot.scoring, "diff", lambda *_args: DiffResult(0, 1, [], True))
        # Isolate disk projection/background match hooks, not admission/evaluation/normal recording.
        net.progress.judging = lambda *_args: nullcontext()
        net._record = MethodType(Network._record, net)
        core = {"net": net, "path": None, "events": []}
    digest = hashlib.sha256(CANDIDATE.encode()).hexdigest()
    with net.store.tx() as db:
        db.execute("INSERT INTO reference_files(source_id,path,text,content_hash) VALUES(?,'ref.c',?,?)", (sid, CANDIDATE, digest))
    origin = {"kind": "file", "source_id": sid, "path": "ref.c", "content_hash": digest}
    state = tmp_path / "server-state"
    state.mkdir()
    net.rangechecks.reopen = lambda *_args: None  # no startup surveys for the synthetic compiler
    mcp, _, security, _ = build(net, state, PORT, SECRET)
    client = TestClient(mcp.streamable_http_app(transport_security=security, host="127.0.0.1"),
                        base_url=f"http://127.0.0.1:{PORT}", headers=WINDOW)
    return client, net, core, {"slug": slug, "target_id": fid, "origin": origin}, calls


def prepare(client, body):
    response = client.post("/api/reference-trials/prepare", headers=HEADERS, json=body)
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["ready"] is True, value
    return value


def submit(client, body, plan, **extras):
    return client.post("/api/reference-trials/run", headers=HEADERS,
        json={"slug": body["slug"], "plan": plan["plan"], "source": plan["source"], "prelude": plan["prelude"],
              "accept_if_verified": True, "allow_progress_copy": True, **extras})


@pytest.mark.parametrize("mode", ["rom", "fork"])
@pytest.mark.parametrize("match", [False, True])
def test_actual_app_preview_consent_existing_judge_and_replay(tmp_path, monkeypatch, mode, match):
    client, net, core, body, calls = http_trial(tmp_path, monkeypatch, mode, match=match)
    slug = body["slug"]
    anon = TestClient(client.app, base_url=f"http://127.0.0.1:{PORT}")
    assert anon.get("/api/reference-trials", params={"slug": slug}).status_code == 401
    assert client.post("/api/reference-trials/prepare", json=body).status_code == 403
    before = list(net.store.conn.iterdump())
    before_files = {str(p): p.read_bytes() for p in (tmp_path / "game").rglob("*") if p.is_file()}
    targets = client.get("/api/reference-trials/targets", params={"slug": slug}).json()["targets"]
    assert targets[0]["id"] == body["target_id"]
    source = client.post("/api/reference-trials/source", headers=HEADERS, json={"slug": slug, "origin": body["origin"]})
    assert source.status_code == 200 and "trial_fn" in source.json()["text"]
    plan = prepare(client, body)
    assert not calls and not core["events"]
    assert list(net.store.conn.iterdump()) == before
    assert before_files == {str(p): p.read_bytes() for p in (tmp_path / "game").rglob("*") if p.is_file()}
    assert submit(client, body, plan, allow_progress_copy=False).status_code == 400
    assert not calls
    response = submit(client, body, plan)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["matched"] is match, result
    assert result["outcome"] == ("matched" if match else "nonmatch"), result
    assert calls
    count = len(calls)
    replay = submit(client, body, plan)
    assert replay.status_code == 200 and replay.json()["matched"] is match, replay.text
    assert len(calls) == count
    assert net.store.one("SELECT 1 FROM claims") is None
    row = net.store.one("SELECT * FROM functions WHERE id=?", body["target_id"])
    assert row["status"] == ("matched" if match else "open")
    if mode == "fork" and not match:
        assert core["path"].read_bytes() == ORIGINAL_BYTES
        assert result["percent"] == 100.0  # a literal/explicit-verdict miss is not an identity proof
    assert net.store.one("SELECT agent_access FROM reference_sources WHERE id=?", body["origin"]["source_id"])[0] == 0
    history = client.get("/api/reference-trials", params={"slug": slug}).json()["trials"]
    assert len(history) == 1
    detail = client.get("/api/reference-trials/detail", params={"slug": slug, "id": history[0]["id"]})
    assert detail.status_code == 200 and detail.json()["source"] == plan["source"]


@pytest.mark.parametrize("mode", ["rom", "fork"])
def test_actual_app_build_failure_cleans_claim_without_accepting(tmp_path, monkeypatch, mode):
    client, net, core, body, calls = http_trial(tmp_path, monkeypatch, mode, build_ok=False)
    response = submit(client, body, prepare(client, body))
    assert response.status_code == 200, response.text
    assert response.json()["matched"] is False and response.json()["outcome"] == "failed"
    assert calls and net.store.one("SELECT 1 FROM claims") is None
    assert net.store.one("SELECT status FROM functions WHERE id=?", body["target_id"])[0] == "open"
    if mode == "fork":
        assert core["path"].read_bytes() == ORIGINAL_BYTES


@pytest.mark.parametrize("mode", ["rom", "fork"])
def test_actual_app_stale_text_source_and_forbidden_extras_never_compile(tmp_path, monkeypatch, mode):
    client, net, _, body, calls = http_trial(tmp_path, monkeypatch, mode)
    plan = prepare(client, body)
    assert submit(client, body, plan, source=plan["source"] + " ").status_code == 400
    assert submit(client, body, plan, file_overrides={"anything": "old"}).status_code == 400
    assert client.post("/api/reference-trials/prepare", headers=HEADERS, json=body | {"compiler": "other"}).status_code == 400
    with net.store.tx() as db:
        db.execute("UPDATE reference_sources SET enabled=0 WHERE id=?", (body["origin"]["source_id"],))
    assert submit(client, body, plan).status_code == 400
    assert not calls and net.store.one("SELECT 1 FROM claims") is None


def test_actual_fork_core_rejects_stale_project_row_before_baseline(tmp_path, monkeypatch):
    client, net, core, body, calls = http_trial(tmp_path, monkeypatch, "fork")
    with net.store.tx() as db:
        config = json.loads(core["project"]["config"])
        config["options"] = {"compiler_revision": "new"}
        db.execute("UPDATE projects SET config=?", (json.dumps(config),))
    # get() deliberately returns the OLD project row; the plan captures fresh DB configuration.
    plan = prepare(client, body)
    response = submit(client, body, plan)
    assert response.status_code == 400 and "context differs" in response.json()["error"], response.text
    assert net.store.one("SELECT 1 FROM claims") is None
    assert not calls and not core["events"]
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert net.store.one("SELECT 1 FROM attempts") is None


def test_actual_core_rejects_stale_function_metadata_before_baseline(tmp_path, monkeypatch):
    client, net, core, body, calls = http_trial(tmp_path, monkeypatch, "fork")
    with net.store.tx() as db:
        db.execute("UPDATE functions SET meta=? WHERE id=?",
                   (json.dumps({"symbol": "new_symbol", "real": "trial_fn"}), body["target_id"]))
    response = submit(client, body, prepare(client, body))
    assert response.status_code == 400 and "context differs" in response.json()["error"], response.text
    assert not calls and not core["events"] and net.store.one("SELECT 1 FROM claims") is None


def test_actual_app_rejects_cross_project_ids_and_malformed_json(tmp_path, monkeypatch):
    client, net, _, body, calls = http_trial(tmp_path, monkeypatch, "rom")
    with net.store.tx() as db:
        pid = db.execute("INSERT INTO projects(slug,root,config) VALUES('other','.',?)", ('{"kind":"rom"}',)).lastrowid
        fid = db.execute("INSERT INTO functions(project_id,name) VALUES(?,'trial_fn')", (pid,)).lastrowid
    assert client.post("/api/reference-trials/prepare", headers=HEADERS,
                       json=body | {"target_id": fid}).status_code == 400
    assert client.post("/api/reference-trials/source", headers=HEADERS,
                       json={"slug": "other", "origin": body["origin"]}).status_code == 400
    assert client.post("/api/reference-trials/prepare", headers=HEADERS,
                       content="{",).status_code == 400
    assert not calls and net.store.one("SELECT 1 FROM claims") is None


def test_actual_rom_core_binds_the_header_it_really_compiles(tmp_path, monkeypatch):
    client, net, _, body, calls = http_trial(tmp_path, monkeypatch, "rom")
    plan = prepare(client, body)
    net._context = lambda *_: {"version": 0, "header": "stale cached header"}
    response = submit(client, body, plan)
    assert response.status_code == 200 and not response.json()["matched"], response.text
    assert not calls and net.store.one("SELECT 1 FROM attempts") is None
    assert net.store.one("SELECT 1 FROM claims") is None


def test_final_recorder_rejection_restores_bytes_and_preserves_best_work(tmp_path, monkeypatch):
    client, net, core, body, _ = http_trial(tmp_path, monkeypatch, "fork", match=True)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET best_score=1,best_source='better existing code' WHERE id=?", (body["target_id"],))
    plan = prepare(client, body)
    record = net._record
    def late_change(*args, **kwargs):
        with net.store.tx() as db:
            db.execute("UPDATE reference_sources SET enabled=0")
        return record(*args, **kwargs)
    net._record = late_change
    response = submit(client, body, plan)
    assert response.status_code == 200 and not response.json()["matched"], response.text
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert net.store.one("SELECT 1 FROM attempts") is None
    row = net.store.one("SELECT * FROM functions WHERE id=?", body["target_id"])
    assert row["status"] == "open" and row["best_source"] == "better existing code"


def test_unexpected_build_exception_restores_owned_source_under_core_locks(tmp_path, monkeypatch):
    client, net, core, body, _ = http_trial(tmp_path, monkeypatch, "fork")
    plan = prepare(client, body)
    def explode(*_args):
        raise RuntimeError("controlled build exception")
    core["engine"]._build_unit = explode
    response = submit(client, body, plan)
    assert response.status_code == 200 and not response.json()["matched"], response.text
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert net.store.one("SELECT 1 FROM attempts") is None


def test_postcommit_bookkeeping_failure_does_not_undo_or_misreport_a_match(tmp_path, monkeypatch):
    client, net, core, body, _ = http_trial(tmp_path, monkeypatch, "fork", match=True)
    plan = prepare(client, body)
    def fail_after_record(*_args, **_kwargs):
        raise RuntimeError("controlled bookkeeping failure")
    core["engine"]._remember = fail_after_record
    response = submit(client, body, plan)
    assert response.status_code == 200 and response.json()["matched"] is True, response.text
    assert core["path"].read_bytes() != ORIGINAL_BYTES
    assert net.store.one("SELECT status FROM functions WHERE id=?", body["target_id"])[0] == "matched"


def test_source_removal_after_normal_commit_reports_the_accepted_match(tmp_path, monkeypatch):
    client, net, core, body, calls = http_trial(tmp_path, monkeypatch, "fork", match=True)
    plan = prepare(client, body)
    record = net._record
    def remove_source_after_commit(*args, **kwargs):
        result = record(*args, **kwargs)
        with net.store.tx() as db:
            db.execute("DELETE FROM reference_sources WHERE id=?", (body["origin"]["source_id"],))
        return result
    net._record = remove_source_after_commit
    response = submit(client, body, plan)
    assert response.status_code == 200 and response.json()["matched"] is True, response.text
    assert response.json()["trial"] is None and response.json()["warnings"]
    assert core["path"].read_bytes() != ORIGINAL_BYTES
    count = len(calls)
    replay = submit(client, body, plan)
    assert replay.status_code == 200 and replay.json()["matched"] is True, replay.text
    assert len(calls) == count


def test_linked_original_rebuild_rejection_remains_authoritative(tmp_path, monkeypatch):
    client, net, core, body, _ = http_trial(tmp_path, monkeypatch, "fork", match=True)
    core["unit"].complete = True
    core["fp"].linkable = lambda: True
    config_path = core["fp"].root / "objdiff.json"
    config = json.loads(config_path.read_text())
    config["units"][0]["metadata"]["complete"] = True
    config_path.write_text(json.dumps(config))
    checks = []
    core["engine"]._verify = lambda *_args: (checks.append("original rebuild") or (False, "synthetic original SHA-1 mismatch"))
    response = submit(client, body, prepare(client, body))
    assert response.status_code == 200 and not response.json()["matched"], response.text
    assert checks == ["original rebuild"]
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert net.store.one("SELECT status FROM functions WHERE id=?", body["target_id"])[0] == "open"


def test_existing_neighbor_rejection_remains_authoritative(tmp_path, monkeypatch):
    client, net, core, body, _ = http_trial(tmp_path, monkeypatch, "fork", match=True)
    core["engine"]._baseline = lambda *_args: ({"neighbor": 100.0}, True)
    original_diff = core["fp"].diff
    def broken_neighbor(*args):
        result = original_diff(*args)
        result.unit_scores = {"neighbor": 0.0}
        return result
    core["fp"].diff = broken_neighbor
    result = submit(client, body, prepare(client, body))
    assert result.status_code == 200 and not result.json()["matched"], result.text
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert net.store.one("SELECT matched_source FROM functions WHERE id=?", body["target_id"])[0] is None
