"""Strict trial hooks around the real ROM/fork judge seams, with controlled build and diff results."""

import hashlib
import json
import time
from types import MethodType, SimpleNamespace

import pytest

from decompnet.app.engine import RomNetwork, autopilot
from decompnet.forks.project import Unit
from decompnet.network import Network, NetworkError
from decompnet.reference_trials import ReferenceTrials
from decompnet.scoring import DiffResult

CANDIDATE = "int trial_fn(void) {\n    return 1;\n}\n"
ORIGINAL_BYTES = b"\xef\xbb\xbf/*\tbefore */\r\nint trial_fn(void) {\r\n    return 0;\r\n}\r\n"


class NoMatchHooksNetwork(RomNetwork):
    def on_match(self, proj, function_id, agent=None):
        return None


class CorePreparer:
    def __init__(self, project, source_id, function_id, unit_source, original, source=CANDIDATE):
        self.source = source
        self.payload = {
            "nonce": "core-trial",
            "project_id": project,
            "function_id": function_id,
            "origin": {"kind": "file", "source_id": source_id, "path": "ref.c"},
            "source_hash": hashlib.sha256(source.encode()).hexdigest(),
            "prelude_hash": hashlib.sha256(b"").hexdigest(),
            "reference_hash": "reference-hash",
            "context_hash": "db-context-hash",
            "target_hash": "target-hash",
            "unit_source": unit_source,
            "unit_source_hash": hashlib.sha256(original).hexdigest(),
            "ready": True,
            "expires": int(time.time()) + 600,
        }
        self.unit_contexts = []
        self.db_checks = 0
        self.reject_unit = False
        self.net = None

    def verify(
        self,
        slug,
        plan,
        source,
        prelude,
        *,
        check_current=True,
        allow_expired=False,
        allow_claim_agent_id=None,
        file_overrides=None,
        unit_context=None,
    ):
        assert not self.net.store.conn.in_transaction
        assert plan == "signed-plan" and source == self.source and prelude == ""
        if unit_context is not None:
            self.unit_contexts.append(unit_context)
            assert unit_context["unit"].source == self.payload["unit_source"]
            assert unit_context["path"].relative_to(self.project_root).as_posix() == self.payload["unit_source"]
            if self.reject_unit:
                raise NetworkError("raw unit signature changed")
        return self.payload

    def verify_db(self, slug, payload, *, allow_claim_agent_id=None, db=None):
        assert db is self.net.store.conn and db.in_transaction
        self.db_checks += 1
        fn = db.execute("SELECT project_id,status FROM functions WHERE id=?", (payload["function_id"],)).fetchone()
        claim = db.execute(
            "SELECT agent_id,expires_at FROM claims WHERE function_id=?", (payload["function_id"],)
        ).fetchone()
        if (
            fn is None
            or fn["project_id"] != payload["project_id"]
            or fn["status"] != "open"
            or claim is None
            or claim["agent_id"] != allow_claim_agent_id
            or claim["expires_at"] <= time.time()
        ):
            raise NetworkError("final trial facts changed")


def make_fork_core(tmp_path, *, match=False, build_ok=True, external_edit=False, reject_unit=False, source=CANDIDATE):
    root = tmp_path / "game"
    source_path = root / "src" / "unit.c"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(ORIGINAL_BYTES)
    net = NoMatchHooksNetwork(tmp_path / "app.db", tmp_path / "work")
    with net.store.tx() as db:
        project_id = db.execute(
            "INSERT INTO projects(slug,root,config) VALUES(?,?,?)",
            ("fork-trial", str(root), json.dumps({"kind": "fork", "platform": "n64"})),
        ).lastrowid
        source_id = db.execute(
            "INSERT INTO reference_sources(project_id,name,root,kind,status) VALUES(?,?,?,?,?)",
            (project_id, "ref", ".", "directory", "ready"),
        ).lastrowid
        function_id = db.execute(
            "INSERT INTO functions(project_id,name,status,n_insns,unit,meta) VALUES(?,?,?,?,?,?)",
            (project_id, "trial_fn", "open", 1, "unit", json.dumps({"symbol": "trial_fn"})),
        ).lastrowid
    project = net.store.one("SELECT * FROM projects WHERE id=?", project_id)
    fn = net.store.one("SELECT * FROM functions WHERE id=?", function_id)
    agent, _ = net.local_agent("reference-trial")
    unit = Unit("unit", None, None, "src/unit.c", False, None)

    class FakeForkProject:
        def __init__(self):
            self.root = root
            self.manifest = None

        def unit(self, name):
            assert name == "unit"
            return unit

        def safe_path(self, rel, write=False):
            return self.root / rel

        def linkable(self):
            return False

        def build_problem(self):
            return None

        def diff(self, _unit, _symbol):
            return SimpleNamespace(
                score=0,
                max_score=1,
                rows=[],
                matched=match,
                renamed=False,
                bytes_match=match,
                match_percent=100.0,
                literals=[],
                unit_scores={},
                render=lambda: "controlled diff",
            )

    fp = FakeForkProject()
    events = []
    engine = net.forks
    engine.get = lambda slug: (project, fp, {"kind": "fork", "platform": "n64"})
    engine._fn = lambda slug, name: fn
    engine._baseline = lambda proj, fork, u, text: (events.append(("baseline", text)) or ({}, True))
    engine._held = lambda *args: set()
    engine._apply_scores = lambda *args, **kwargs: None
    engine._keep_scores = lambda *args, **kwargs: None
    engine._remember = lambda *args, **kwargs: None
    engine._file_done = lambda *args, **kwargs: ""
    engine._unresolved_lines = lambda *args, **kwargs: []
    engine._convention_warning = lambda *args, **kwargs: []
    engine._missing_note = lambda *args, **kwargs: ""
    engine._commit_paths = lambda *args, **kwargs: None
    net.compile_key = lambda *args, **kwargs: "key"
    net.keep_diff = lambda *args, **kwargs: None
    net.stall_note = lambda *args, **kwargs: ""
    net.dependents_note = lambda *args, **kwargs: ""
    net._record = MethodType(Network._record, net)
    build_calls = []

    def build(*args):
        build_calls.append(args)
        events.append(("build", source_path.read_bytes()))
        if external_edit:
            source_path.write_bytes(b"external editor bytes\r\n")
        return build_ok, "controlled build result"

    engine._build_unit = build
    preparer = CorePreparer(project_id, source_id, function_id, "src/unit.c", ORIGINAL_BYTES, source)
    preparer.net = net
    preparer.project_root = root
    preparer.reject_unit = reject_unit
    service = ReferenceTrials(net, preparer=preparer)
    guard = service._trial_guard(
        "fork-trial", "signed-plan", source, "", function_id, agent.id, preparer.payload, {"value": False}
    )
    return {
        "net": net,
        "engine": engine,
        "project": project,
        "fn": fn,
        "agent": agent,
        "unit": unit,
        "fp": fp,
        "path": source_path,
        "events": events,
        "build_calls": build_calls,
        "preparer": preparer,
        "guard": guard,
        "function_id": function_id,
    }


def test_project_strict_guard_checks_unit_before_any_baseline_build_or_write(tmp_path):
    core = make_fork_core(tmp_path, reject_unit=True)
    with pytest.raises(NetworkError, match="raw unit signature changed"):
        core["engine"].attempt(
            core["agent"],
            "fork-trial",
            "trial_fn",
            CANDIDATE,
            keep=False,
            strict_reference=True,
            trial_guard=core["guard"],
            reference_token=core["preparer"].payload["nonce"],
        )
    assert not core["events"] and not core["build_calls"]
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert (
        core["net"].store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", core["function_id"])["n"] == 0
    )
    assert core["net"].store.one("SELECT 1 FROM claims WHERE function_id=?", core["function_id"]) is None
    assert core["preparer"].unit_contexts


@pytest.mark.parametrize("same_agent", [True, False])
def test_fork_expired_trial_cannot_record_or_delete_replacement_claim(tmp_path, same_agent):
    core = make_fork_core(tmp_path)
    net, engine, agent = core["net"], core["engine"], core["agent"]
    replacement = agent if same_agent else net.local_agent("other-model")[0]
    guard = core["guard"]

    def handoff_guard(*args):
        if len(args) == 2 and args[0] == "before_baseline":
            guard(*args)
            with net.store.tx() as db:
                db.execute("UPDATE claims SET expires_at=? WHERE function_id=?", (time.time() - 1, core["function_id"]))
            assert (
                engine._hold_for_try("fork-trial", "trial_fn", replacement, reference_token="trial-b")
                == core["function_id"]
            )
        else:
            guard(*args)

    with pytest.raises(NetworkError, match="active trial claim changed"):
        engine.attempt(
            agent,
            "fork-trial",
            "trial_fn",
            CANDIDATE,
            keep=False,
            strict_reference=True,
            trial_guard=handoff_guard,
            reference_token=core["preparer"].payload["nonce"],
        )
    claim = net.store.one("SELECT agent_id,reference_token FROM claims WHERE function_id=?", core["function_id"])
    assert claim is not None and claim["agent_id"] == replacement.id and claim["reference_token"] == "trial-b"
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert not core["build_calls"]
    assert net.store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", core["function_id"])["n"] == 0


def test_project_nonmatch_restores_exact_bom_crlf_and_tabs_after_real_core_build(tmp_path):
    core = make_fork_core(tmp_path)
    result = core["engine"].attempt(
        core["agent"],
        "fork-trial",
        "trial_fn",
        CANDIDATE,
        keep=False,
        strict_reference=True,
        trial_guard=core["guard"],
        reference_token=core["preparer"].payload["nonce"],
    )
    assert result["matched"] is False and result["score"] == 0
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert any(event[0] == "baseline" for event in core["events"])
    assert any(event[0] == "build" and event[1] != ORIGINAL_BYTES for event in core["events"])
    assert core["preparer"].unit_contexts
    assert core["preparer"].db_checks == 2  # atomic admission and final recording
    assert core["net"].store.one("SELECT status FROM functions WHERE id=?", core["function_id"])["status"] == "open"
    assert core["net"].store.one("SELECT 1 FROM claims WHERE function_id=?", core["function_id"]) is None


def test_project_build_failure_restores_exact_original_bytes(tmp_path):
    core = make_fork_core(tmp_path, build_ok=False)
    result = core["engine"].attempt(
        core["agent"],
        "fork-trial",
        "trial_fn",
        CANDIDATE,
        keep=False,
        strict_reference=True,
        trial_guard=core["guard"],
        reference_token=core["preparer"].payload["nonce"],
    )
    assert result["matched"] is False and result["score"] is None
    assert core["path"].read_bytes() == ORIGINAL_BYTES
    assert (
        core["net"].store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", core["function_id"])["n"] == 1
    )


def test_external_editor_bytes_are_not_rolled_back_over(tmp_path):
    core = make_fork_core(tmp_path, external_edit=True)
    with pytest.raises(NetworkError, match="external edits were preserved"):
        core["engine"].attempt(
            core["agent"],
            "fork-trial",
            "trial_fn",
            CANDIDATE,
            keep=False,
            strict_reference=True,
            trial_guard=core["guard"],
            reference_token=core["preparer"].payload["nonce"],
        )
    assert core["path"].read_bytes() == b"external editor bytes\r\n"
    assert (
        core["net"].store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", core["function_id"])["n"] == 0
    )


def test_fork_match_uses_explicit_diff_verdict_not_percent_only(tmp_path):
    core = make_fork_core(tmp_path, match=True)
    result = core["engine"].attempt(
        core["agent"],
        "fork-trial",
        "trial_fn",
        CANDIDATE,
        keep=False,
        strict_reference=True,
        trial_guard=core["guard"],
        reference_token=core["preparer"].payload["nonce"],
    )
    assert result["matched"] is True
    assert core["net"].store.one("SELECT status FROM functions WHERE id=?", core["function_id"])["status"] == "matched"


def test_source_assembly_is_rejected_before_baseline_or_build(tmp_path):
    source = 'int trial_fn(void) { asm("nop"); return 1; }\n'
    core = make_fork_core(tmp_path, source=source)
    with pytest.raises(NetworkError, match="inline assembly"):
        core["engine"].attempt(
            core["agent"],
            "fork-trial",
            "trial_fn",
            source,
            keep=False,
            strict_reference=True,
            trial_guard=core["guard"],
            reference_token=core["preparer"].payload["nonce"],
        )
    assert not core["events"] and not core["build_calls"]
    assert core["path"].read_bytes() == ORIGINAL_BYTES


def test_constructor_spelling_is_not_auto_renamed_in_a_strict_trial(tmp_path):
    source = "Bar::Bar() { return; }\n"
    core = make_fork_core(tmp_path, source=source)
    with core["net"].store.tx() as db:
        db.execute(
            "UPDATE functions SET meta=? WHERE id=?",
            (json.dumps({"symbol": "trial_fn", "demangled": "Foo::Foo()"}), core["function_id"]),
        )
    core["fn"] = core["net"].store.one("SELECT * FROM functions WHERE id=?", core["function_id"])
    core["engine"]._fn = lambda slug, name: core["fn"]
    with pytest.raises(NetworkError, match="send the complete definition of Foo::Foo"):
        core["engine"].attempt(
            core["agent"],
            "fork-trial",
            "trial_fn",
            source,
            keep=False,
            strict_reference=True,
            trial_guard=core["guard"],
            reference_token=core["preparer"].payload["nonce"],
        )
    assert not core["events"] and not core["build_calls"]
    assert core["path"].read_bytes() == ORIGINAL_BYTES


def test_prelude_assembly_is_rejected_before_baseline_or_build(tmp_path):
    core = make_fork_core(tmp_path)
    with pytest.raises(NetworkError, match="inline assembly"):
        core["engine"].attempt(
            core["agent"],
            "fork-trial",
            "trial_fn",
            CANDIDATE,
            keep=False,
            prelude='void helper(void) { asm("nop"); }',
            strict_reference=True,
            trial_guard=core["guard"],
            reference_token=core["preparer"].payload["nonce"],
        )
    assert not core["events"] and not core["build_calls"]
    assert core["path"].read_bytes() == ORIGINAL_BYTES


def test_rom_trial_owns_and_releases_atomic_claim_and_runs_final_guard(monkeypatch, tmp_path):
    net = NoMatchHooksNetwork(tmp_path / "rom.db", tmp_path / "work")
    with net.store.tx() as db:
        project_id = db.execute(
            "INSERT INTO projects(slug,root,config) VALUES(?,?,?)", ("rom-trial", str(tmp_path), '{"kind":"rom"}')
        ).lastrowid
        function_id = db.execute(
            "INSERT INTO functions(project_id,name,status,n_insns) VALUES(?,?,?,?)", (project_id, "f", "open", 1)
        ).lastrowid
    project = net.store.one("SELECT * FROM projects WHERE id=?", project_id)
    fn = net.store.one("SELECT * FROM functions WHERE id=?", function_id)
    agent, _ = net.local_agent("reference-trial")
    net._context = lambda *_args: {"version": 0, "header": ""}
    net._compile = lambda *_args: SimpleNamespace(ok=True, obj=object())
    net._evaluate = lambda *_args: (object(), None, None)
    net._target_obj = lambda *_args: object()
    monkeypatch.setattr(autopilot.scoring, "diff", lambda *_args: DiffResult(0, 1, [], False))
    net._record = MethodType(Network._record, net)
    phases = []

    def guard(*args):
        if args and hasattr(args[0], "execute"):
            db, facts = args
            phases.append("record")
            claim = db.execute("SELECT agent_id,expires_at FROM claims WHERE function_id=?", (function_id,)).fetchone()
            assert claim is not None and claim["agent_id"] == agent.id and claim["expires_at"] > time.time()
            assert facts["function_id"] == function_id
        else:
            phases.append(args[0])

    result = net._try_quietly(agent, project, fn, "int f(void) { return 0; }", trial_guard=guard)
    assert result["matched"] is False and result["score"] == 0
    assert phases == ["admitted", "before_compile", "after_build", "record"]
    assert net.store.one("SELECT 1 FROM claims WHERE function_id=?", function_id) is None
    assert net.store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", function_id)["n"] == 1


def test_rom_claim_conflict_compile_error_and_final_guard_failure_clean_up(monkeypatch, tmp_path):
    net = NoMatchHooksNetwork(tmp_path / "rom.db", tmp_path / "work")
    with net.store.tx() as db:
        project_id = db.execute(
            "INSERT INTO projects(slug,root,config) VALUES(?,?,?)", ("rom-trial", str(tmp_path), '{"kind":"rom"}')
        ).lastrowid
        fn_ids = [
            db.execute(
                "INSERT INTO functions(project_id,name,status,n_insns) VALUES(?,?,?,?)",
                (project_id, f"f{i}", "open", 1),
            ).lastrowid
            for i in range(3)
        ]
    project = net.store.one("SELECT * FROM projects WHERE id=?", project_id)
    agent, _ = net.local_agent("reference-trial")
    compile_calls = []
    net._context = lambda *_args: {"version": 0, "header": ""}

    def compile_stub(*_args):
        compile_calls.append(1)
        return SimpleNamespace(ok=len(compile_calls) > 1, obj=object() if len(compile_calls) > 1 else None)

    net._compile = compile_stub
    net._evaluate = lambda *_args: (object(), None, None)
    net._target_obj = lambda *_args: object()
    monkeypatch.setattr(autopilot.scoring, "diff", lambda *_args: DiffResult(0, 1, [], False))
    net._record = MethodType(Network._record, net)
    first = net.store.one("SELECT * FROM functions WHERE id=?", fn_ids[0])
    with net.store.tx() as db:
        db.execute(
            "INSERT INTO claims(function_id,agent_id,claimed_at,expires_at) VALUES(?,?,?,?)",
            (fn_ids[0], agent.id + 1, time.time(), time.time() + 300),
        )
    with pytest.raises(NetworkError, match="claimed"):
        net._try_quietly(agent, project, first, "candidate")
    assert compile_calls == []
    assert net.store.one("SELECT agent_id FROM claims WHERE function_id=?", fn_ids[0])["agent_id"] == agent.id + 1

    second = net.store.one("SELECT * FROM functions WHERE id=?", fn_ids[1])
    failed = net._try_quietly(agent, project, second, "candidate")
    assert failed == {"matched": False, "score": None}
    assert net.store.one("SELECT 1 FROM claims WHERE function_id=?", fn_ids[1]) is None

    third = net.store.one("SELECT * FROM functions WHERE id=?", fn_ids[2])

    def reject_record(*args):
        if args and hasattr(args[0], "execute"):
            raise NetworkError("final guard rejected")

    with pytest.raises(NetworkError, match="final guard rejected"):
        net._try_quietly(agent, project, third, "candidate", trial_guard=reject_record)
    assert net.store.one("SELECT 1 FROM claims WHERE function_id=?", fn_ids[2]) is None
    assert net.store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", fn_ids[2])["n"] == 0


@pytest.mark.parametrize("same_agent", [True, False])
def test_rom_expired_trial_cannot_record_or_delete_replacement_claim(monkeypatch, tmp_path, same_agent):
    net = NoMatchHooksNetwork(tmp_path / "rom.db", tmp_path / "work")
    with net.store.tx() as db:
        project_id = db.execute(
            "INSERT INTO projects(slug,root,config) VALUES(?,?,?)", ("rom-trial", str(tmp_path), '{"kind":"rom"}')
        ).lastrowid
        function_id = db.execute(
            "INSERT INTO functions(project_id,name,status,n_insns) VALUES(?,?,?,?)", (project_id, "f", "open", 1)
        ).lastrowid
    project = net.store.one("SELECT * FROM projects WHERE id=?", project_id)
    fn = net.store.one("SELECT * FROM functions WHERE id=?", function_id)
    agent, _ = net.local_agent("reference-trial")
    replacement = agent if same_agent else net.local_agent("other-model")[0]
    net._context = lambda *_args: {"version": 0, "header": ""}
    net._evaluate = lambda *_args: (object(), None, None)
    net._target_obj = lambda *_args: object()
    monkeypatch.setattr(autopilot.scoring, "diff", lambda *_args: DiffResult(0, 1, [], False))
    net._record = MethodType(Network._record, net)

    def compile_stub(*_args):
        with net.store.tx() as db:
            db.execute("UPDATE claims SET expires_at=? WHERE function_id=?", (time.time() - 1, function_id))
            net._expire_claims(db)
            db.execute(
                "INSERT INTO claims(function_id,agent_id,claimed_at,expires_at,reference_token) VALUES(?,?,?,?,?)",
                (function_id, replacement.id, time.time(), time.time() + 300, "trial-b"),
            )
        return SimpleNamespace(ok=True, obj=object())

    net._compile = compile_stub

    def guard(*args):
        if args and hasattr(args[0], "execute"):
            db, facts = args
            claim = db.execute(
                "SELECT agent_id,reference_token FROM claims WHERE function_id=?", (function_id,)
            ).fetchone()
            if facts.get("phase") == "claim":
                assert claim["agent_id"] == agent.id and claim["reference_token"] == "trial-a"
            elif claim is None or claim["reference_token"] != "trial-a":
                raise NetworkError("reference claim token changed")

    with pytest.raises(NetworkError, match="reference claim token changed"):
        net._try_quietly(agent, project, fn, "candidate", trial_guard=guard, reference_token="trial-a")
    claim = net.store.one("SELECT agent_id,reference_token FROM claims WHERE function_id=?", function_id)
    assert claim is not None and claim["agent_id"] == replacement.id and claim["reference_token"] == "trial-b"
    assert net.store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", function_id)["n"] == 0
