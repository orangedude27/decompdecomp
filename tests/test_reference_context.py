import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from decompnet.forks.project import ForkProject
from decompnet.reference_context import ReferenceContextError, TrialContext, _safe_bytes
from decompnet.store import Store


def make_net(tmp_path, kind="rom"):
    root = tmp_path / "project"
    root.mkdir()
    net = SimpleNamespace(store=Store(tmp_path / "state.db"), rooms={}, links={})
    cfg = {"kind": kind, "compiler": {"cmd": ["never-run", "{src}", "{obj}"], "flags": ["-O2"]}}
    with net.store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,name,root,config,arch) VALUES(1,'game','Game',?,?,'mips')", (str(root), json.dumps(cfg)))
        db.execute("INSERT INTO functions(id,project_id,name,size,target,relocs,status,vram,unit) VALUES(1,1,'func',4,?,'[]','open',4096,?)", (b"abcd", "unit" if kind == "fork" else ""))
        db.execute("INSERT INTO context_versions(project_id,version,header,unit) VALUES(1,1,'typedef int T;','')")
    if kind == "fork":
        (root / "src").mkdir()
        (root / "include").mkdir()
        (root / "expected").mkdir()
        (root / "src/unit.cpp").write_bytes(b"int func(void) { return 0; }\r\n")
        (root / "include/types.h").write_text("typedef int T;\n")
        (root / "expected/unit.o").write_bytes(b"original object")
        (root / "build.ninja").write_text("rule cc\n  command = original-compiler -O2 $in -o $out\n")
        (root / "objdiff.json").write_text(json.dumps({"units": [{"name": "unit", "target_path": "expected/unit.o", "base_path": "build/unit.o", "metadata": {"source_path": "src/unit.cpp"}}]}))
    return net, root


def dump(net):
    return list(net.store.conn.iterdump())


def test_rom_capture_db_is_readonly_and_has_actual_aliases(tmp_path, monkeypatch):
    net, root = make_net(tmp_path)
    ctx = TrialContext(net)
    before = dump(net)
    monkeypatch.setattr(Path, "read_bytes", lambda *_: pytest.fail("ROM capture opened a file"))
    data = ctx.capture("game", 1)
    assert data["target"]["compiler_names"] == ["func", "func::~func"]
    assert data["context"]["flags"] == ["-O2"]
    assert data["context"]["header_version"] == 1
    assert data["unit_source"] is None
    assert ctx.capture_db("game", 1)["target_hash"] == data["target_hash"]
    assert dump(net) == before and list(root.iterdir()) == []


def test_db_only_check_never_reads_or_resolves_files(tmp_path, monkeypatch):
    net, _ = make_net(tmp_path, "fork")
    context = TrialContext(net)
    before = context.capture_db("game", 1)
    def forbidden(*_args, **_kwargs):
        pytest.fail("DB final check touched filesystem")
    for method in ("read_bytes", "read_text", "resolve", "stat", "open"):
        monkeypatch.setattr(Path, method, forbidden)
    assert context.capture_db("game", 1) == before


@pytest.mark.parametrize("column,value", [("target", b"efgh"), ("relocs", '[{"different":1}]'), ("unit", "other"), ("meta", '{"real":"changed"}'), ("vram", 8192), ("size", 8)])
def test_target_changes_invalidate_db_fingerprint(tmp_path, column, value):
    net, _ = make_net(tmp_path)
    ctx = TrialContext(net)
    before = ctx.capture_db("game", 1)
    with net.store.tx() as db:
        db.execute(f"UPDATE functions SET {column}=? WHERE id=1", (value,))
    assert ctx.capture_db("game", 1)["target_hash"] != before["target_hash"]


def test_header_fallback_and_irrelevant_ui_scores(tmp_path):
    net, _ = make_net(tmp_path)
    ctx = TrialContext(net)
    before = ctx.capture_db("game", 1)
    with net.store.tx() as db:
        db.execute("UPDATE projects SET name='Other title' WHERE id=1")
        db.execute("UPDATE functions SET best_score=8,attempts=2 WHERE id=1")
        db.execute("INSERT INTO context_versions(project_id,version,header,unit) VALUES(1,2,'unrelated','elsewhere')")
    assert ctx.capture_db("game", 1) == before
    with net.store.tx() as db:
        db.execute("INSERT INTO context_versions(project_id,version,header,unit) VALUES(1,3,'changed','')")
    assert ctx.capture_db("game", 1)["db_context_hash"] != before["db_context_hash"]


def test_symbols_and_compiler_changes_invalidate(tmp_path):
    net, _ = make_net(tmp_path)
    ctx = TrialContext(net)
    before = ctx.capture_db("game", 1)
    with net.store.tx() as db:
        db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(1,'global',42,4,'data')")
    assert ctx.capture_db("game", 1)["db_context_hash"] != before["db_context_hash"]
    before = ctx.capture_db("game", 1)
    with net.store.tx() as db:
        cfg = json.loads(db.execute("SELECT config FROM projects").fetchone()[0])
        cfg["compiler"]["flags"] = ["-O0"]
        db.execute("UPDATE projects SET config=?", (json.dumps(cfg),))
    assert ctx.capture_db("game", 1)["db_context_hash"] != before["db_context_hash"]


@pytest.mark.parametrize("attribute", ["rooms", "links"])
def test_room_hosts_and_guests_refused(tmp_path, attribute):
    net, _ = make_net(tmp_path)
    getattr(net, attribute)["game"] = object()
    with pytest.raises(ReferenceContextError, match="local project"):
        TrialContext(net).capture("game", 1)


def test_only_own_active_claim_is_allowed_and_no_claims_are_created(tmp_path):
    net, _ = make_net(tmp_path)
    ctx = TrialContext(net)
    with net.store.tx() as db:
        db.execute("INSERT INTO claims(function_id,agent_id,claimed_at,expires_at) VALUES(1,9,?,?)", (time.time(), time.time() + 60))
    with pytest.raises(ReferenceContextError, match="claimed"):
        ctx.capture("game", 1)
    assert ctx.capture("game", 1, allow_claim_agent_id=9)
    assert len(net.store.all("SELECT * FROM claims")) == 1
    with net.store.tx() as db:
        db.execute("UPDATE claims SET expires_at=0")
    assert ctx.capture("game", 1)  # readonly eligibility ignores expired claims; admission owns cleanup


@pytest.mark.parametrize("change", ["status='matched'", "gone_mark='removed'", "status='not_c'"])
def test_closed_targets_refused(tmp_path, change):
    net, _ = make_net(tmp_path)
    with net.store.tx() as db:
        db.execute("UPDATE functions SET " + change + " WHERE id=1")
    with pytest.raises(ReferenceContextError, match="open"):
        TrialContext(net).capture("game", 1)


def test_project_capture_raw_bytes_context_without_state_or_cache(tmp_path):
    net, root = make_net(tmp_path, "fork")
    ctx = TrialContext(net)
    before_db = dump(net)
    before_files = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    data = ctx.capture("game", 1)
    assert data["unit_source"] == "src/unit.cpp"  # a PATH, not source text
    assert data["unit_source_hash"]
    assert data["target_hash"] == ctx.capture_db("game", 1)["target_hash"]
    assert data["context"]["compiler"] == "Existing project build (no override)"
    assert not (root / ".decomp-wtf").exists()
    assert dump(net) == before_db
    assert before_files == {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("path", ["src/unit.cpp", "include/types.h", "build.ninja", "expected/unit.o"])
def test_same_stat_content_changes_are_detected(tmp_path, path):
    net, root = make_net(tmp_path, "fork")
    ctx = TrialContext(net)
    before = ctx.capture("game", 1)
    file = root / path
    old = file.stat()
    data = file.read_bytes()
    file.write_bytes(data.replace(b"0", b"1") if b"0" in data else bytes([data[0] ^ 1]) + data[1:])
    os.utime(file, ns=(old.st_atime_ns, old.st_mtime_ns))
    assert ctx.capture("game", 1)["context_hash"] != before["context_hash"]


def test_no_mtime_objdiff_cache_and_only_signed_source_override(tmp_path):
    net, root = make_net(tmp_path, "fork")
    fp = ForkProject(root, read_only=True)
    assert fp.unit("unit").source == "src/unit.cpp"
    cfg = root / "objdiff.json"
    old = cfg.stat()
    cfg.write_bytes(cfg.read_bytes().replace(b"unit.cpp", b"next.cpp"))
    os.utime(cfg, ns=(old.st_atime_ns, old.st_mtime_ns))
    (root / "src/next.cpp").write_text("int func(void) { return 0; }\n")
    ctx = TrialContext(net)
    assert ctx.capture("game", 1)["unit_source"] == "src/next.cpp"
    before = ctx.capture("game", 1)
    previous = (root / "src/next.cpp").read_text()
    (root / "src/next.cpp").write_text("int func(void) { return 1; }\n")
    assert ctx.capture("game", 1, file_overrides={"src/next.cpp": previous})["context_hash"] == before["context_hash"]
    with pytest.raises(ReferenceContextError, match="Only"):
        ctx.capture("game", 1, file_overrides={"include/types.h": "different"})


@pytest.mark.parametrize("kind", ["source", "header", "target", "directory"])
def test_symlinked_context_is_refused(tmp_path, kind):
    net, root = make_net(tmp_path, "fork")
    outside = tmp_path / "outside"
    outside.write_text("int func(void) {}")
    name = {"source": "src/unit.cpp", "header": "include/types.h", "target": "expected/unit.o", "directory": "linked"}[kind]
    dest = root / name
    if dest.exists():
        dest.unlink()
    dest.symlink_to(outside)
    with pytest.raises(ReferenceContextError, match="[Ss]ymlink"):
        TrialContext(net).capture("game", 1)


@pytest.mark.parametrize("limit,value", [("MAX_FILES", 1), ("MAX_BYTES", 4), ("MAX_ENTRIES", 1), ("MAX_FILE", 4)])
def test_project_context_resource_limits(tmp_path, monkeypatch, limit, value):
    net, _ = make_net(tmp_path, "fork")
    monkeypatch.setattr("decompnet.reference_context." + limit, value)
    with pytest.raises(ReferenceContextError):
        TrialContext(net).capture("game", 1)


@pytest.mark.parametrize("change", ["missing_source", "missing_object", "no_unit", "auto", "invalid_json"])
def test_unsupported_project_context_fails_closed(tmp_path, change):
    net, root = make_net(tmp_path, "fork")
    path = root / "objdiff.json"
    data = json.loads(path.read_text())
    if change == "missing_source":
        (root / "src/unit.cpp").unlink()
    elif change == "missing_object":
        (root / "expected/unit.o").unlink()
    elif change == "no_unit":
        data["units"] = []
    elif change == "auto":
        data["units"][0]["metadata"]["auto_generated"] = True
    else:
        path.write_text("{")
    if change != "invalid_json":
        path.write_text(json.dumps(data))
    with pytest.raises(ReferenceContextError):
        TrialContext(net).capture("game", 1)


@pytest.mark.parametrize("like", ["", "synthetic-profile"])
def test_own_compiler_defaults_follow_actual_connector_without_runtime_install(tmp_path, monkeypatch, like):
    net, root = make_net(tmp_path)
    own = SimpleNamespace(version="private-sdk-version", build="synthetic-build", like=like, exe=root / "cc",
                          root=root, includes=(root / "include",), runner="", args=("-c",), flags=("-O0",))
    with net.store.tx() as db:
        db.execute("UPDATE projects SET config=?", (json.dumps({"kind": "rom", "compiler": {"toolchain": own.version}}),))
    monkeypatch.setattr("decompnet.reference_context.kits.own_compiler", lambda _id: own)
    profile = SimpleNamespace(id=like, name="Synthetic profile", flags=["-O3"], cc=["cc"], cmd=None, prelude="", cplusplus=False)
    def get_profile(identifier):
        assert identifier == like and like
        return profile
    monkeypatch.setattr("decompnet.reference_context.toolchains.get", get_profile)
    monkeypatch.setattr("decompnet.reference_context.toolchains.ensure", lambda *_a, **_k: pytest.fail("preview installed a tool"))
    context = TrialContext(net).capture("game", 1)
    assert context["context"]["flags"] == (["-O3"] if like else ["-O0"])
    before = context["context_hash"]
    own.build = "different-build"
    assert TrialContext(net).capture("game", 1)["context_hash"] != before


def test_safe_read_rejects_outside_non_regular_and_bad_target_query(tmp_path):
    net, root = make_net(tmp_path)
    with pytest.raises(ReferenceContextError):
        _safe_bytes(tmp_path / "state.db", root)
    with pytest.raises(ReferenceContextError):
        _safe_bytes(root, root)
    with pytest.raises(ValueError):
        TrialContext(net).targets("game", limit=True)
    assert TrialContext(net).targets("game")["targets"][0]["eligible"]
