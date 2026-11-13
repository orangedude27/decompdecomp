"""Private reference-trial history and execution through the existing recorder seam."""

import json
import threading
import time
from types import SimpleNamespace
from typing import Any, cast

import pytest

from decompnet.app.engine import RomNetwork
from decompnet.app.forkengine import ForkEngine
from decompnet.network import Network, NetworkError
from decompnet.reference_trials import ReferenceTrials
from decompnet.store import Store


def test_concurrent_first_previews_share_one_preparer_and_signing_key(monkeypatch):
    import importlib

    service = ReferenceTrials(object())
    entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
    created, returned, errors = [], [], []
    original_import = importlib.import_module
    def constructor(_net):
        assert service._preparer_lock.locked()
        value = object()
        created.append(value)
        entered.set()
        assert release.wait(5)
        return value
    monkeypatch.setattr(importlib, "import_module", lambda name: SimpleNamespace(CandidatePreparer=constructor)
                        if name == "decompnet.reference_candidates" else original_import(name))
    def load(second=False):
        try:
            if second:
                second_started.set()
            returned.append(service.preparer)
        except Exception as exc:
            errors.append(exc)
    first = threading.Thread(target=load)
    second = threading.Thread(target=load, args=(True,))
    first.start()
    assert entered.wait(5)
    second.start()
    assert second_started.wait(5)
    release.set()
    first.join(5)
    second.join(5)
    assert not first.is_alive() and not second.is_alive() and not errors
    assert len(created) == 1 and returned == [created[0], created[0]]


class Net:
    def __init__(self, store):
        self.store = store


def required_one(store, sql, *args):
    row = store.one(sql, *args)
    assert row is not None
    return row


def make_store(path):
    store = Store(path)
    with store.tx() as db:
        project = db.execute(
            "INSERT INTO projects(slug,root,config) VALUES(?,?,?)", ("trial-test", ".", json.dumps({"kind": "rom"}))
        ).lastrowid
        source = db.execute(
            "INSERT INTO reference_sources(project_id,name,root,kind,status) VALUES(?,?,?,?,?)",
            (project, "ref", ".", "directory", "ready"),
        ).lastrowid
        function = db.execute(
            "INSERT INTO functions(project_id,name,status) VALUES(?,?,?)", (project, "func_1", "open")
        ).lastrowid
    return store, project, source, function


class NoMatchHooksNetwork(RomNetwork):
    def on_match(self, proj, function_id, agent=None):
        return None


class FakePreparer:
    def __init__(self, project_id, source_id, function_id):
        self.payload = {
            "nonce": "trial-nonce",
            "project_id": project_id,
            "function_id": function_id,
            "origin": {"kind": "file", "source_id": source_id, "path": "ref.c"},
            "source_hash": "source-hash",
            "prelude_hash": "prelude-hash",
            "reference_hash": "reference-hash",
            "context_hash": "context-hash",
            "unit_source": None,
            "ready": True,
            "expires": int(time.time()) + 600,
        }
        self.verify_calls = []
        self.db_checks = []
        self.reject_current: str | None = None
        self.ready = True
        self.expired = False
        self.expected_source = "int func_1(void) { return 1; }"
        self.expected_prelude = ""
        self.net: Any = None

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
        self.verify_calls.append(
            {
                "check_current": check_current,
                "allow_expired": allow_expired,
                "allow_claim_agent_id": allow_claim_agent_id,
                "file_overrides": file_overrides,
                "unit_context": unit_context,
            }
        )
        if plan != "signed-plan" or source != self.expected_source or prelude != self.expected_prelude:
            raise NetworkError("plan or code hash mismatch")
        if check_current and self.reject_current:
            raise NetworkError(self.reject_current)
        if check_current and not allow_expired and (self.expired or self.payload["expires"] < time.time()):
            raise NetworkError("plan expired")
        return self.payload | {"ready": self.ready}

    def verify_db(self, slug, payload, *, allow_claim_agent_id=None, db=None):
        assert db is not None
        assert db is self.net.store.conn
        assert db.in_transaction
        self.db_checks.append((slug, allow_claim_agent_id, db, db.in_transaction))
        project = db.execute("SELECT id FROM projects WHERE id=? AND slug=?", (payload["project_id"], slug)).fetchone()
        function = db.execute(
            "SELECT project_id,status FROM functions WHERE id=?", (payload["function_id"],)
        ).fetchone()
        source = db.execute(
            "SELECT project_id,enabled,stale,status FROM reference_sources WHERE id=?",
            (payload["origin"]["source_id"],),
        ).fetchone()
        if project is None or function is None or source is None:
            raise NetworkError("target or source removed")
        if function["project_id"] != payload["project_id"] or function["status"] != "open":
            raise NetworkError("target changed")
        if not (
            source["project_id"] == payload["project_id"]
            and source["enabled"]
            and not source["stale"]
            and source["status"] in ("ready", "partial")
        ):
            raise NetworkError("source changed")

    def prepare(self, slug, **options):
        return {"ready": self.ready, "plan": "signed-plan"}


def make_execution(tmp_path, verdict=(False, 7, 91.0), core_action=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    net = NoMatchHooksNetwork(tmp_path / "execution.db", tmp_path)
    with net.store.tx() as db:
        project_id = db.execute(
            "INSERT INTO projects(slug,root,config) VALUES(?,?,?)", ("execution", str(tmp_path), '{"kind":"rom"}')
        ).lastrowid
        source_id = db.execute(
            "INSERT INTO reference_sources(project_id,name,root,kind,status) VALUES(?,?,?,?,?)",
            (project_id, "ref", ".", "directory", "ready"),
        ).lastrowid
        function_id = db.execute(
            "INSERT INTO functions(project_id,name,status,n_insns) VALUES(?,?,?,?)", (project_id, "func_1", "open", 1)
        ).lastrowid
    preparer = FakePreparer(project_id, source_id, function_id)
    preparer.net = net
    executions = []
    entered = threading.Event()
    release = threading.Event()

    def judge(agent, proj, fn, source, *, trial_guard, reference_token=None):
        assert reference_token == preparer.payload["nonce"]
        executions.append(source)
        now = time.time()
        with net.store.tx() as db:
            if db.execute("SELECT 1 FROM claims WHERE function_id=?", (fn["id"],)).fetchone():
                raise NetworkError("target is claimed")
            db.execute(
                "INSERT INTO claims(function_id,agent_id,claimed_at,expires_at,reference_token) VALUES(?,?,?,?,?)",
                (fn["id"], agent.id, now, now + 300, reference_token),
            )
            if reference_token is not None:
                trial_guard(db, {"phase": "claim", "fn": fn, "project": proj, "reference_token": reference_token})
        try:
            trial_guard("admitted", {"fn": fn, "project": proj})
            entered.set()
            if core_action == "wait":
                release.wait(timeout=5)
            if core_action == "compile-error":
                return {"matched": False, "score": None, "percent": None, "text": "compile failed"}
            if core_action == "mutate-claim":
                with net.store.tx() as db:
                    db.execute("DELETE FROM claims WHERE function_id=?", (fn["id"],))
            if core_action in ("replace-claim-same-agent", "replace-claim-other-agent"):
                owner_id = agent.id
                if core_action == "replace-claim-other-agent":
                    owner_id = net.local_agent("other-model")[0].id
                with net.store.tx() as db:
                    db.execute("UPDATE claims SET expires_at=? WHERE function_id=?", (time.time() - 1, fn["id"]))
                    net._expire_claims(db)
                    db.execute(
                        "INSERT INTO claims(function_id,agent_id,claimed_at,expires_at,reference_token) "
                        "VALUES(?,?,?,?,?)",
                        (fn["id"], owner_id, time.time(), time.time() + 300, "trial-b"),
                    )
            if core_action == "mutate-target":
                with net.store.tx() as db:
                    db.execute("UPDATE functions SET status='matched' WHERE id=?", (fn["id"],))
            if core_action == "mutate-source":
                with net.store.tx() as db:
                    db.execute(
                        "UPDATE reference_sources SET stale=1 WHERE id=?", (preparer.payload["origin"]["source_id"],)
                    )
            if core_action == "expire-claim":
                with net.store.tx() as db:
                    db.execute("UPDATE claims SET expires_at=? WHERE function_id=?", (time.time() - 1, fn["id"]))
            matched, score, percent = verdict
            if core_action == "other-agent-match":
                other, _ = net.local_agent("other-model")
                cast(Any, Network._record)(net, fn, other, 0, source, 0, matched=True)
                raise RuntimeError("post-commit hook failed")
            cast(Any, Network._record)(net, fn, agent, score, source, 0, matched=matched, trial_guard=trial_guard)
            if core_action == "committed-error":
                raise RuntimeError("error after normal commit")
            if core_action == "remove-source":
                with net.store.tx() as db:
                    db.execute("DELETE FROM reference_sources WHERE id=?", (preparer.payload["origin"]["source_id"],))
            return {"matched": matched, "score": score, "percent": percent, "text": "judge result"}
        finally:
            with net.store.tx() as db:
                db.execute(
                    "DELETE FROM claims WHERE function_id=? AND agent_id=? AND reference_token IS ?",
                    (fn["id"], agent.id, reference_token),
                )

    setattr(net, "try_quietly", judge)
    service = ReferenceTrials(net, preparer=preparer)
    return net, service, preparer, executions, entered, release


def run_trial(service, prep, *, accept=True, allow=True):
    return service.execute("execution", "signed-plan", prep.expected_source, prep.expected_prelude, accept, allow)


def test_private_history_is_project_scoped_and_source_cascades(tmp_path):
    store, project, source, function = make_store(tmp_path / "history.db")
    with store.tx() as db:
        trial_id = db.execute(
            "INSERT INTO reference_trials(project_id,source_id,function_id,nonce,submitted_source,"
            "submitted_prelude,source_hash,prelude_hash,provenance,context_hash,status,created_at,result) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                project,
                source,
                function,
                "nonce",
                "int f(){}",
                "",
                "hash",
                "hash",
                '{"record_id":4}',
                "context",
                "nonmatch",
                1.0,
                '{"score":3}',
            ),
        ).lastrowid
    service = ReferenceTrials(Net(store), preparer=object())
    assert len(service.history("trial-test", 1)["trials"]) == 1
    detail = service.detail("trial-test", trial_id)
    assert detail["source"] == "int f(){}"
    assert detail["provenance"] == {"record_id": 4}
    assert detail["outcome"]["score"] == 3
    with pytest.raises(NetworkError, match="not found"):
        service.detail("other-project", trial_id)
    with store.tx() as db:
        db.execute("DELETE FROM reference_sources WHERE id=?", (source,))
    assert store.one("SELECT COUNT(*) AS n FROM reference_trials")["n"] == 0


def test_both_explicit_consents_are_required_before_preparation(tmp_path):
    store, _, _, _ = make_store(tmp_path / "consent.db")

    class ForbiddenPreparer:
        def verify(self, *args, **kwargs):
            raise AssertionError("verification must not run without both explicit consents")

    service = ReferenceTrials(Net(store), preparer=ForbiddenPreparer())
    for accept, progress in ((False, True), (True, False), (1, True), (True, 1)):
        with pytest.raises(NetworkError, match="both explicit consent flags"):
            service.execute("trial-test", "plan", "int f(){}", "", accept, progress)
    assert store.one("SELECT COUNT(*) AS n FROM reference_trials")["n"] == 0


def test_run_revalidates_expired_unready_and_mismatched_candidate_before_effects(tmp_path):
    net, service, prep, executions, _, _ = make_execution(tmp_path)
    prep.expired = True
    with pytest.raises(NetworkError, match="expired"):
        run_trial(service, prep)
    prep.expired = False
    prep.ready = False
    with pytest.raises(NetworkError, match="not ready"):
        run_trial(service, prep)
    prep.ready = True
    prep.reject_current = "target or context changed"
    with pytest.raises(NetworkError, match="changed"):
        run_trial(service, prep)
    with pytest.raises(NetworkError, match="code hash mismatch"):
        service.execute("execution", "signed-plan", "tampered source", "", True, True)
    assert executions == []
    assert net.store.one("SELECT COUNT(*) AS n FROM reference_trials")["n"] == 0
    assert net.store.one("SELECT COUNT(*) AS n FROM agents WHERE name='reference-trial'")["n"] == 0
    assert prep.verify_calls[0]["check_current"] is False and prep.verify_calls[0]["allow_expired"] is True
    assert any(call["check_current"] and not call["allow_expired"] for call in prep.verify_calls)


def test_host_and_guest_rooms_are_denied_before_agent_or_history_creation(tmp_path):
    for room_kind in ("host", "guest"):
        net, service, prep, executions, _, _ = make_execution(tmp_path / room_kind)
        (net.rooms if room_kind == "host" else net.links)["execution"] = object()
        with pytest.raises(NetworkError, match="room hosts and guests"):
            run_trial(service, prep)
        assert executions == []
        assert net.store.one("SELECT COUNT(*) AS n FROM reference_trials")["n"] == 0
        assert net.store.one("SELECT COUNT(*) AS n FROM agents WHERE name='reference-trial'")["n"] == 0


def test_real_recorder_guard_is_db_only_and_zero_score_does_not_fake_match(tmp_path):
    net, service, prep, executions, _, _ = make_execution(tmp_path, verdict=(False, 0, 100.0))
    result = run_trial(service, prep)
    assert result["outcome"] == "nonmatch" and result["matched"] is False
    assert result["score"] == 0 and result["percent"] == 100.0
    assert len(executions) == 1 and len(prep.db_checks) == 2  # atomic admission and final recording
    assert prep.db_checks[0][3]
    assert len(net.store.all("SELECT id FROM attempts WHERE function_id=?", prep.payload["function_id"])) == 1
    assert prep.verify_calls[0]["check_current"] is False and prep.verify_calls[0]["allow_expired"] is True


def test_late_db_source_target_claim_and_expiry_changes_abort_before_attempt(tmp_path):
    for action in ("mutate-claim", "mutate-target", "mutate-source", "expire-claim"):
        net, service, prep, _, _, _ = make_execution(tmp_path / action, core_action=action)
        response = run_trial(service, prep)
        assert response["outcome"] == "stale" and response["matched"] is False
        assert (
            net.store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", prep.payload["function_id"])["n"]
            == 0
        )


@pytest.mark.parametrize("action", ["replace-claim-same-agent", "replace-claim-other-agent"])
def test_expired_trial_cannot_record_or_delete_replacement_claim(tmp_path, action):
    net, service, prep, _, _, _ = make_execution(tmp_path, core_action=action)
    response = run_trial(service, prep)
    assert response["outcome"] == "stale" and response["matched"] is False
    claim = required_one(
        net.store,
        "SELECT agent_id,reference_token FROM claims WHERE function_id=?",
        prep.payload["function_id"],
    )
    owner = required_one(net.store, "SELECT id FROM agents WHERE name='reference-trial'")["id"]
    if action == "replace-claim-other-agent":
        owner = required_one(net.store, "SELECT id FROM agents WHERE name='other-model'")["id"]
    assert claim["agent_id"] == owner and claim["reference_token"] == "trial-b"
    assert (
        required_one(net.store, "SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", prep.payload["function_id"])[
            "n"
        ]
        == 0
    )


def test_normal_match_recovery_requires_our_attempt_and_agent_identity(tmp_path):
    net, service, prep, executions, _, _ = make_execution(
        tmp_path / "committed", verdict=(True, 0, 100.0), core_action="committed-error"
    )
    recovered = run_trial(service, prep)
    assert recovered["outcome"] == "matched" and recovered["matched"] is True
    owner = required_one(net.store, "SELECT id FROM agents WHERE name='reference-trial'")["id"]
    assert (
        required_one(net.store, "SELECT matched_agent_id FROM functions WHERE id=?", prep.payload["function_id"])[
            "matched_agent_id"
        ]
        == owner
    )
    assert len(executions) == 1

    other_net, other_service, other_prep, other_exec, _, _ = make_execution(
        tmp_path / "external", core_action="other-agent-match"
    )
    external = run_trial(other_service, other_prep)
    assert external["outcome"] == "stale" and external["matched"] is False
    assert (
        required_one(other_net.store, "SELECT status FROM functions WHERE id=?", other_prep.payload["function_id"])[
            "status"
        ]
        == "matched"
    )
    assert (
        required_one(
            other_net.store,
            "SELECT COUNT(*) AS n FROM attempts WHERE agent_id=(SELECT id FROM agents WHERE name='reference-trial')",
        )["n"]
        == 0
    )
    assert len(other_exec) == 1


def test_core_compile_failure_and_source_removal_return_truthful_results(tmp_path):
    net, service, prep, _, _, _ = make_execution(tmp_path / "failed", core_action="compile-error")
    result = run_trial(service, prep)
    assert result["outcome"] == "failed" and result["score"] is None
    assert (
        net.store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", prep.payload["function_id"])["n"] == 0
    )

    net, service, prep, executions, _, _ = make_execution(
        tmp_path / "removed", verdict=(True, 0, 100.0), core_action="remove-source"
    )
    result = run_trial(service, prep)
    assert result["outcome"] == "matched" and result["matched"] is True
    assert result["trial"] is None and result["warnings"]
    assert run_trial(service, prep) == result
    assert len(executions) == 1


def test_persisted_replay_uses_history_even_after_plan_expiry(tmp_path):
    net, service, prep, executions, _, _ = make_execution(tmp_path)
    first = run_trial(service, prep)
    prep.payload["expires"] = int(time.time()) - 1
    restarted_service = ReferenceTrials(net, preparer=prep)
    replay = run_trial(restarted_service, prep)
    assert replay["outcome"] == first["outcome"]
    assert replay["trial"]["id"] == first["trial"]["id"]
    assert len(executions) == 1


def test_same_nonce_is_refused_while_running_and_never_compiles_twice(tmp_path):
    net, service, prep, executions, entered, release = make_execution(tmp_path, core_action="wait")
    first_response = []
    thread = threading.Thread(target=lambda: first_response.append(run_trial(service, prep)))
    thread.start()
    assert entered.wait(timeout=5)
    with pytest.raises(NetworkError, match="already running"):
        run_trial(service, prep)
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive() and len(first_response) == 1 and len(executions) == 1
    assert first_response[0]["outcome"] == "nonmatch"
    assert (
        net.store.one("SELECT COUNT(*) AS n FROM attempts WHERE function_id=?", prep.payload["function_id"])["n"] == 1
    )


def test_preview_does_not_create_trial_agent_and_history_capacity_is_clear(tmp_path):
    net, service, prep, executions, _, _ = make_execution(tmp_path)
    assert service.prepare("execution")["plan"] == "signed-plan"
    assert executions == []
    assert net.store.one("SELECT COUNT(*) AS n FROM agents WHERE name='reference-trial'")["n"] == 0
    assert net.store.one("SELECT COUNT(*) AS n FROM reference_trials")["n"] == 0
    project_id = prep.payload["project_id"]
    source_id = prep.payload["origin"]["source_id"]
    function_id = prep.payload["function_id"]
    with net.store.tx() as db:
        for index in range(200):
            db.execute(
                "INSERT INTO reference_trials(project_id,source_id,function_id,nonce,submitted_source,"
                "submitted_prelude,source_hash,prelude_hash,provenance,context_hash,status,created_at,result) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    project_id,
                    source_id,
                    function_id,
                    f"old-{index}",
                    "x",
                    "",
                    "h",
                    "h",
                    "{}",
                    "c",
                    "nonmatch",
                    float(index),
                    "{}",
                ),
            )
    with pytest.raises(NetworkError, match="200-record limit; no trial was run"):
        run_trial(service, prep)
    assert executions == []
    assert net.store.one("SELECT COUNT(*) AS n FROM reference_trials")["n"] == 200
    assert net.store.one("SELECT COUNT(*) AS n FROM agents WHERE name='reference-trial'")["n"] == 0


def test_result_json_stays_bounded_and_malformed_history_is_safe():
    packed = ReferenceTrials._result_json(
        {"matched": False, "score": None, "percent": None, "text": "x" * 20000, "warnings": ["w" * 1000] * 20}
    )
    assert len(packed.encode("utf-8")) < 16000
    assert len(json.loads(packed)["text"]) == 4000
    assert ReferenceTrials._read_result("not JSON") == {}


def test_project_guard_binds_canonical_unit_and_preserves_raw_before_hash(tmp_path):
    net, service, prep, _, _, _ = make_execution(tmp_path)
    unit_source = "src/unit.c"
    path = tmp_path / unit_source
    path.parent.mkdir()
    before = "int old(void);\n"
    after = "int new(void);\n"
    path.write_bytes(before.encode("utf-8"))
    prep.payload["unit_source"] = unit_source
    prep.payload["unit_source_hash"] = __import__("hashlib").sha256(before.encode()).hexdigest()
    with net.store.tx() as db:
        db.execute(
            "INSERT INTO claims(function_id,agent_id,claimed_at,expires_at,reference_token) VALUES(?,?,?,?,?)",
            (prep.payload["function_id"], 7, time.time(), time.time() + 300, prep.payload["nonce"]),
        )
    guard = service._trial_guard(
        "execution",
        "signed-plan",
        prep.expected_source,
        prep.expected_prelude,
        prep.payload["function_id"],
        7,
        prep.payload,
        {"value": False},
    )
    facts = {"path": path, "unit": SimpleNamespace(source=unit_source), "before": before, "after": after}
    guard("before_write", facts)
    assert prep.verify_calls[-1]["unit_context"] is facts
    assert prep.verify_calls[-1]["file_overrides"] == {unit_source: before}
    path.write_bytes(after.encode("utf-8"))
    guard("after_build", facts)
    path.write_text("external edit", encoding="utf-8")
    with pytest.raises(NetworkError, match="external edits were preserved"):
        guard("before_record", facts)


def test_fork_trial_refuses_when_exclusive_hold_failed():
    engine = object.__new__(ForkEngine)
    engine._hold_for_try = lambda *args, **kwargs: None
    engine._attempt = lambda *args, **kwargs: pytest.fail("must not enter the judge without the hold")
    with pytest.raises(NetworkError, match="open, unclaimed"):
        engine.attempt(SimpleNamespace(id=9), "local", "f", "int f(){}", keep=False, strict_reference=True)
