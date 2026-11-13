"""Owner-only explicit trials using the existing preparation and judge seams."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from contextlib import contextmanager
from typing import Any

from .network import NetworkError


@contextmanager
def _trial_source_cleanup(net, fn, agent, state):
    """Restore unaccepted owned bytes before the core releases its tree/unit locks.

    Final DB preconditions and unexpected build/diff errors can fail after the
    temporary write. Conversely, bookkeeping may fail AFTER a normal match was
    committed: that accepted code must not be undone.
    """
    try:
        yield
    finally:
        if state.get("applied") and not state.get("accepted"):
            current = net.store.one("SELECT status,matched_agent_id,matched_source FROM functions WHERE id=?", fn["id"])
            accepted = bool(current and current["status"] == "matched" and current["matched_agent_id"] == agent.id
                            and current["matched_source"] == state.get("code"))
            if not accepted:
                if state.get("undo") is not None:
                    state["undo"]()
                elif state["path"].read_bytes() == state["after"].encode():
                    state["path"].write_bytes(state["before"].encode())


class ReferenceTrials:
    """Coordinate reference plans and keep their private, bounded outcome history."""

    def __init__(self, net, preparer=None):
        self.net = net
        self._preparer = preparer
        self._preparer_lock = threading.Lock()
        self._nonce_lock = threading.Lock()
        self._running: set[tuple[str, str]] = set()
        self._completed: dict[tuple[str, str], tuple[int, dict]] = {}

    @property
    def preparer(self):
        if self._preparer is None:
            # Concurrent first previews must share one signing key. Keep this lock
            # separate from nonce bookkeeping and the store's writer transaction.
            with self._preparer_lock:
                if self._preparer is None:
                    from importlib import import_module

                    self._preparer = import_module("decompnet.reference_candidates").CandidatePreparer(self.net)
        return self._preparer

    def targets(self, slug: str, query: str = "", limit: int = 20):
        return self.preparer.targets(slug, query, limit)

    def files(self, slug: str, source_id: int, query: str = "", offset: int = 0, limit: int = 30):
        return self.preparer.files(slug, source_id, query, offset, limit)

    def source(self, slug: str, origin: dict, start: int = 1, count: int = 160):
        return self.preparer.read_origin(slug, origin, start, count)

    def prepare(self, slug: str, **options):
        return self.preparer.prepare(slug, **options)

    def history(self, slug: str, limit: int = 20) -> dict:
        project = self._project(slug)
        limit = self._bounded_int(limit, "limit", 1, 200)
        rows = self.net.store.all(
            "SELECT id,function_id,source_id,status,created_at,result FROM reference_trials "
            "WHERE project_id=? ORDER BY id DESC LIMIT ?",
            project["id"],
            limit,
        )
        return {"trials": [self._summary(row) for row in rows]}

    def detail(self, slug: str, trial_id: int) -> dict:
        project = self._project(slug)
        trial_id = self._bounded_int(trial_id, "id", 1, 2**63 - 1)
        row = self.net.store.one("SELECT * FROM reference_trials WHERE project_id=? AND id=?", project["id"], trial_id)
        if row is None:
            raise NetworkError("reference trial not found")
        result = self._read_result(row["result"])
        return self._summary(row) | {
            "source": row["submitted_source"],
            "prelude": row["submitted_prelude"],
            "provenance": json.loads(row["provenance"]),
            "outcome": result,
        }

    def execute(
        self, slug: str, plan: str, source: str, prelude: str, accept_if_verified: bool, allow_progress_copy: bool
    ) -> dict:
        if accept_if_verified is not True or allow_progress_copy is not True:
            raise NetworkError("both explicit consent flags must be true")
        if not all(isinstance(value, str) for value in (plan, source, prelude)):
            raise NetworkError("plan, source and prelude must be text")
        source_size = len(source.encode("utf-8"))
        prelude_size = len(prelude.encode("utf-8"))
        if source_size > 48 * 1024 or prelude_size > 16 * 1024 or source_size + prelude_size > 65536:
            raise NetworkError("trial source and prelude exceed their 48 KiB / 16 KiB limits")
        project = self._project(slug)
        payload = self.preparer.verify(slug, plan, source, prelude, check_current=False, allow_expired=True)
        nonce = payload.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            raise NetworkError("prepared plan has no valid nonce")
        key = (slug, nonce)
        with self._nonce_lock:
            self._prune_completed()
            if key in self._running:
                raise NetworkError("this reference trial is already running")
            if key in self._completed:
                expires, completed = self._completed[key]
                if expires >= time.time():
                    return completed
                del self._completed[key]
            old = self.net.store.one(
                "SELECT * FROM reference_trials WHERE project_id=? AND nonce=?", project["id"], nonce
            )
            if old:
                if old["status"] == "running":
                    raise NetworkError("this reference trial was interrupted; prepare a new plan")
                result = self._read_result(old["result"])
                return {"trial": self._summary(old), "outcome": old["status"], **result}
            self._running.add(key)
        trial_id = None
        agent = None
        trial_agent_id = 0
        attempts_before_id = 0
        admitted = {"value": False}
        try:
            payload = self.preparer.verify(slug, plan, source, prelude, check_current=True)
            if payload.get("ready") is not True:
                raise NetworkError("candidate is not ready; prepare it again")
            origin = payload.get("origin")
            sid = origin.get("source_id") if isinstance(origin, dict) else None
            if sid is None and isinstance(origin, dict) and origin.get("kind") == "metadata":
                rec = self.net.store.one(
                    "SELECT i.source_id FROM metadata_records r JOIN metadata_imports i "
                    "ON i.id=r.import_id WHERE r.record_id=?",
                    origin.get("record_id"),
                )
                sid = rec["source_id"] if rec else None
            fn = self.net.store.one(
                "SELECT * FROM functions WHERE id=? AND project_id=?", payload.get("function_id"), project["id"]
            )
            if fn is None or fn["status"] != "open":
                raise NetworkError("target is no longer open; prepare again")
            src = self.net.store.one(
                "SELECT id FROM reference_sources WHERE id=? AND project_id=? AND enabled=1 "
                "AND stale=0 AND status IN ('ready','partial')",
                sid,
                project["id"],
            )
            if src is None:
                raise NetworkError("reference source is no longer enabled and current; prepare again")
            if slug in self.net.links or slug in getattr(self.net, "rooms", {}):
                raise NetworkError("reference trials are unavailable for room hosts and guests")
            claim = self.net.store.one(
                "SELECT 1 FROM claims WHERE function_id=? AND expires_at>?", fn["id"], time.time()
            )
            if claim is not None:
                raise NetworkError("target is claimed; reference trial was not started")
            with self.net.store.tx() as db:
                count = db.execute(
                    "SELECT COUNT(*) AS n FROM reference_trials WHERE project_id=?", (project["id"],)
                ).fetchone()["n"]
                if count >= 200:
                    raise NetworkError(
                        "private reference-trial history has reached its 200-record limit; no trial was run"
                    )
                agent, _ = self.net.local_agent("reference-trial")
                trial_agent_id = agent.id
                db.execute(
                    "INSERT INTO reference_trials(project_id,source_id,function_id,nonce,submitted_source,"
                    "submitted_prelude,source_hash,prelude_hash,provenance,context_hash,status,created_at,result) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        project["id"],
                        sid,
                        fn["id"],
                        nonce,
                        source,
                        prelude,
                        hashlib.sha256(source.encode()).hexdigest(),
                        hashlib.sha256(prelude.encode()).hexdigest(),
                        json.dumps(
                            {"origin": payload.get("origin"), "reference_hash": payload.get("reference_hash")},
                            separators=(",", ":"),
                        ),
                        str(payload.get("context_hash") or ""),
                        "running",
                        time.time(),
                        "{}",
                    ),
                )
                trial_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            baseline = self.net.store.one(
                "SELECT COALESCE(MAX(id),0) AS id FROM attempts WHERE function_id=?", fn["id"]
            )
            attempts_before_id = baseline["id"]
            guard = self._trial_guard(slug, plan, source, prelude, fn["id"], agent.id, payload, admitted)
            if self.net.is_rom(project):
                outcome = self.net.try_quietly(
                    agent, project, fn, prelude + "\n" + source, trial_guard=guard, reference_token=nonce
                )
            else:
                outcome = self.net.forks.attempt(
                    agent,
                    slug,
                    fn["name"],
                    source,
                    keep=False,
                    prelude=prelude,
                    strict_reference=True,
                    trial_guard=guard,
                    reference_token=nonce,
                )
            matched = outcome.get("matched") is True
            result = {
                "matched": matched,
                "score": outcome.get("score"),
                "percent": outcome.get("percent"),
                "text": str(outcome.get("text") or ""),
                "warnings": [],
            }
            status = "matched" if matched else "failed" if outcome.get("score") is None else "nonmatch"
            with self.net.store.tx() as db:
                db.execute(
                    "UPDATE reference_trials SET status=?,result=? WHERE id=? AND project_id=?",
                    (status, self._result_json(result), trial_id, project["id"]),
                )
            history = self._history_detail(trial_id)
            if history is None:
                result["warnings"].append("Reference source or private trial history was removed after judging.")
            response = {"trial": history, "outcome": status, **result}
            self._remember_completed(key, payload, response)
            return response
        except Exception as exc:
            if trial_id is not None and not admitted["value"]:
                with self.net.store.tx() as db:
                    db.execute("DELETE FROM reference_trials WHERE id=? AND status='running'", (trial_id,))
                raise
            if trial_id is not None:
                current = self.net.store.one(
                    "SELECT status,matched_source,matched_agent_id,best_score FROM functions WHERE id=?",
                    payload.get("function_id"),
                )
                attempts = self.net.store.all(
                    "SELECT id,score,source,compiled FROM attempts WHERE function_id=? AND agent_id=? AND id>? "
                    "ORDER BY id",
                    payload.get("function_id"),
                    trial_agent_id,
                    attempts_before_id,
                )
                own_match = next(
                    (
                        row
                        for row in attempts
                        if row["score"] == 0
                        and row["compiled"]
                        and current
                        and current["status"] == "matched"
                        and current["matched_agent_id"] == trial_agent_id
                        and current["matched_source"] == row["source"]
                    ),
                    None,
                )
                committed_match = own_match is not None
                own_attempt = attempts[-1] if attempts else None
                recorded = own_attempt is not None
                stale = isinstance(exc, NetworkError) or (current and current["status"] == "matched")
                status = (
                    "matched"
                    if committed_match
                    else "failed"
                    if own_attempt and not own_attempt["compiled"]
                    else "nonmatch"
                    if recorded
                    else "stale"
                    if stale
                    else "error"
                )
                result = {
                    "matched": committed_match,
                    "score": 0 if committed_match else (own_attempt["score"] if own_attempt else None),
                    "percent": None,
                    "text": str(exc)[:4000],
                    "warnings": ["The trial history may have been removed meanwhile."],
                }
                with self.net.store.tx() as db:
                    db.execute(
                        "UPDATE reference_trials SET status=?,result=? WHERE id=? AND status='running'",
                        (status, self._result_json(result), trial_id),
                    )
                history = self._history_detail(trial_id)
                if history is None:
                    result["warnings"].append("Reference source or private trial history was removed after judging.")
                response = {"trial": history, "outcome": status, **result}
                self._remember_completed(key, payload, response)
                return response
            raise
        finally:
            with self._nonce_lock:
                self._running.discard(key)

    def _trial_guard(self, slug, plan, source, prelude, function_id, agent_id, payload, admitted):
        raw_before_hash: dict[str, str | None] = {"value": None}

        def check_claim(db):
            fn = db.execute("SELECT status,project_id FROM functions WHERE id=?", (function_id,)).fetchone()
            claim = db.execute(
                "SELECT agent_id,expires_at,reference_token FROM claims WHERE function_id=?", (function_id,)
            ).fetchone()
            if (
                fn is None
                or fn["status"] != "open"
                or fn["project_id"] != payload["project_id"]
                or claim is None
                or claim["agent_id"] != agent_id
                or claim["reference_token"] != payload["nonce"]
                or claim["expires_at"] <= time.time()
            ):
                raise NetworkError("target or active trial claim changed; candidate was not recorded")

        def guard(*args):
            if args and hasattr(args[0], "execute"):
                db, _facts = args
                check_claim(db)
                self.preparer.verify_db(slug, payload, allow_claim_agent_id=agent_id, db=db)
                return
            phase, facts = args
            claim = self.net.store.one(
                "SELECT agent_id,expires_at,reference_token FROM claims WHERE function_id=?", function_id
            )
            if (
                claim is None
                or claim["agent_id"] != agent_id
                or claim["reference_token"] != payload["nonce"]
                or claim["expires_at"] <= time.time()
            ):
                raise NetworkError("target or active trial claim changed; candidate was not recorded")
            overrides = None
            if phase in ("before_write", "after_build", "before_record") and facts.get("path") is not None:
                unit_source = facts["unit"].source
                if unit_source != payload.get("unit_source"):
                    raise NetworkError("target unit source changed; candidate was not recorded")
                before = facts["before"]
                overrides = {payload["unit_source"]: before} if payload.get("unit_source") else None
                try:
                    current_bytes = facts["path"].read_bytes()
                    current = current_bytes.decode("utf-8")
                except (OSError, UnicodeDecodeError) as e:
                    raise NetworkError("target source disappeared or is no longer UTF-8") from e
                expected_text = (
                    facts["before"]
                    if phase == "before_write"
                    else (facts["after"] if phase == "after_build" else (facts["before"], facts["after"]))
                )
                if current not in (expected_text if isinstance(expected_text, tuple) else (expected_text,)):
                    raise NetworkError("target source changed during trial; external edits were preserved")
                if phase == "before_write":
                    raw_before_hash["value"] = hashlib.sha256(current_bytes).hexdigest()
                    if raw_before_hash["value"] != payload.get("unit_source_hash"):
                        raise NetworkError("target source bytes changed since preparation")
                elif raw_before_hash["value"] != payload.get("unit_source_hash"):
                    raise NetworkError("target source before-image is not the signed source")
            if phase == "before_compile" and payload.get("unit_source") is None and facts.get("context") is None:
                raise NetworkError("Actual compiler header context is missing; trial was not compiled.")
            unit_context = facts if isinstance(facts, dict) else None
            self.preparer.verify(
                slug,
                plan,
                source,
                prelude,
                check_current=True,
                allow_claim_agent_id=agent_id,
                file_overrides=overrides,
                unit_context=unit_context,
                allow_expired=True,
            )
            if phase in ("admitted", "before_write"):
                admitted["value"] = True

        return guard

    def _prune_completed(self) -> None:
        now = time.time()
        self._completed = {key: value for key, value in self._completed.items() if value[0] >= now}

    def _remember_completed(self, key, payload, response) -> None:
        with self._nonce_lock:
            self._completed[key] = (payload.get("expires", 0), response)

    @staticmethod
    def _read_result(value: str) -> dict:
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return {}
        if not isinstance(parsed, dict):
            return {}
        return {
            "matched": parsed.get("matched") is True,
            "score": parsed.get("score") if isinstance(parsed.get("score"), (int, float)) else None,
            "percent": parsed.get("percent") if isinstance(parsed.get("percent"), (int, float)) else None,
            "text": str(parsed.get("text") or "")[:4000],
            "warnings": [str(item)[:500] for item in parsed.get("warnings", [])[:8]]
            if isinstance(parsed.get("warnings", []), list)
            else [],
        }

    @staticmethod
    def _result_json(result: dict) -> str:
        bounded = {
            "matched": bool(result.get("matched")),
            "score": result.get("score"),
            "percent": result.get("percent"),
            "text": str(result.get("text") or "")[:4000],
            "warnings": [str(item)[:500] for item in result.get("warnings", [])[:8]],
        }
        return json.dumps(bounded, separators=(",", ":"))

    def _history_detail(self, trial_id):
        row = self.net.store.one("SELECT * FROM reference_trials WHERE id=?", trial_id)
        return self._summary(row) if row else None

    def _project(self, slug: str):
        row = self.net.store.one("SELECT * FROM projects WHERE slug=?", slug)
        if row is None:
            raise NetworkError("project not found")
        return row

    @staticmethod
    def _bounded_int(value: Any, name: str, low: int, high: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise NetworkError(f"{name} must be an integer from {low} to {high}")
        return value

    @staticmethod
    def _summary(row) -> dict:
        try:
            result = json.loads(row["result"])
        except (TypeError, json.JSONDecodeError):
            result = {}
        return {
            "id": row["id"],
            "function_id": row["function_id"],
            "source_id": row["source_id"],
            "status": row["status"],
            "created_at": row["created_at"],
            "outcome": result if isinstance(result, dict) else {},
        }
