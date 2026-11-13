"""Read-only, raw-byte fingerprints of the existing judge's target and build inputs.

This is not a build-system interpreter or a second compiler. Project trials use the
project's own bound build rules, never flags or scripts supplied by a reference.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path

from . import kits, toolchains
from .forks.project import BUILD_FILES, BUILD_SUFFIXES, SOURCE_SUFFIXES, ForkError, ForkProject
from .project import compiler_for

MAX_FILES = 4000
MAX_ENTRIES = 20000
MAX_BYTES = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
SKIP = {".git", ".decomp-wtf", ".venv", "venv", "node_modules", "__pycache__", ".pi"}


class ReferenceContextError(ValueError):
    """The actual target's context cannot be safely prepared."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _safe_bytes(path: Path, root: Path) -> bytes:
    """Bounded regular-file read; reject symlinks (including parent directories)."""
    root = root.resolve(strict=True)
    path = Path(os.path.abspath(path))
    if not path.is_relative_to(root):
        raise ReferenceContextError("Context file is outside the project.")
    try:
        part = root
        for name in path.relative_to(root).parts:
            part /= name
            if part.is_symlink():
                raise ReferenceContextError("Symlinked context files are not supported.")
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise ReferenceContextError("Context input is not a bounded regular file.")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ReferenceContextError("Context input changed while reading; prepare again.")
            data = stream.read(MAX_FILE + 1)
            after = os.fstat(stream.fileno())
        if len(data) > MAX_FILE or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ReferenceContextError("Context input changed or exceeded its limit; prepare again.")
        return data
    except OSError as exc:
        raise ReferenceContextError(f"Cannot read required context input {path.name}.") from exc


def _aliases(row):
    # Reuse the exact, pure alias selection used by _attempt, not its mutating get().
    from .app.forkengine import ForkEngine
    try:
        meta = json.loads(row["meta"] or "{}")
        if not isinstance(meta, dict):
            raise ValueError
        return ForkEngine._names(meta, row)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReferenceContextError("Target compiler aliases cannot be established.") from exc


def _unit_fingerprint(unit, root):
    """Compare the core's actual (possibly cached) unit with the fresh signed unit."""
    root = Path(root).resolve(strict=True)
    def relative(path):
        if path is None:
            return None
        resolved = (root / path).resolve(strict=False)
        if not resolved.is_relative_to(root):
            raise ReferenceContextError("Actual judge unit points outside the project.")
        return resolved.relative_to(root).as_posix()
    return _digest(_canonical({"name": unit.name, "source": relative(unit.source), "target": relative(unit.target),
                               "base": relative(unit.base), "scratch": unit.scratch, "options": unit.options,
                               "mappings": unit.mappings, "complete": unit.complete, "auto": unit.auto}))


BUILD_KEYS = ("kind", "platform", "version", "compiler", "compiler_ranges", "rom", "build", "profile", "options")


def _project_fingerprint(proj, cfg=None):
    if cfg is None:
        try:
            cfg = json.loads(proj["config"])
        except (ValueError, TypeError) as exc:
            raise ReferenceContextError("Actual compiler project configuration is invalid.") from exc
    return _digest(_canonical({"id": proj["id"], "root": proj["root"], "arch": proj["arch"],
                               "big_endian": proj["big_endian"],
                               "config": {k: cfg[k] for k in BUILD_KEYS if k in cfg}}))


def _target_fingerprint(row, proj):
    target = {k: row[k] for k in ("id", "project_id", "name", "unit", "size", "vram", "meta", "relocs")}
    if len(row["target"] or b"") > MAX_FILE:
        raise ReferenceContextError("Target object data exceeds its byte limit.")
    target["bytes"] = bytes(row["target"] or b"").hex()
    target["arch"], target["big_endian"] = proj["arch"], proj["big_endian"]
    return _digest(_canonical(target))


class TrialContext:
    def __init__(self, net):
        self.net = net

    def _project(self, slug):
        if not isinstance(slug, str) or not slug or len(slug) > 256:
            raise ValueError("Choose a valid project.")
        row = self.net.store.one("SELECT * FROM projects WHERE slug=?", slug)
        if row is None:
            raise ReferenceContextError("Project no longer exists.")
        if slug in getattr(self.net, "rooms", {}) or slug in getattr(self.net, "links", {}):
            raise ReferenceContextError("Reference trials require a local project, not a shared room.")
        return row

    def _target(self, project_id, target_id, agent_id=None):
        if type(target_id) is not int or target_id < 1:
            raise ValueError("Choose a valid function target.")
        row = self.net.store.one("SELECT * FROM functions WHERE id=? AND project_id=?", target_id, project_id)
        if row is None:
            raise ReferenceContextError("Target no longer belongs to this project.")
        if row["status"] != "open" or row["matched_source"] or row["gone_mark"] is not None:
            raise ReferenceContextError("Target must be open and not already matched or removed.")
        claim = self.net.store.one("SELECT * FROM claims WHERE function_id=?", target_id)
        if claim and (claim["expires_at"] is None or claim["expires_at"] > time.time()) and claim["agent_id"] != agent_id:
            raise ReferenceContextError("Target is claimed by another operation.")
        return row

    def _db_facts(self, slug, target_id, agent_id=None):
        proj = self._project(slug)
        row = self._target(proj["id"], target_id, agent_id)
        try:
            cfg = json.loads(proj["config"])
        except (ValueError, TypeError) as exc:
            raise ReferenceContextError("Project configuration is invalid.") from exc
        if not isinstance(cfg, dict) or cfg.get("kind") not in {"rom", "fork"}:
            raise ReferenceContextError("This project type does not support explicit reference trials.")
        target_hash = _target_fingerprint(row, proj)
        header = self.net.store.one(
            "SELECT version,header,unit FROM context_versions WHERE project_id=? AND unit IN (?, '') "
            "ORDER BY unit=? DESC, version DESC LIMIT 1", proj["id"], row["unit"] or "", row["unit"] or ""
        )
        symbol_size = self.net.store.one(
            "SELECT COUNT(*) AS n,COALESCE(SUM(LENGTH(CAST(name AS BLOB))),0) AS bytes FROM symbols WHERE project_id=?",
            proj["id"]
        )
        if symbol_size["n"] > 100000 or symbol_size["bytes"] > MAX_BYTES:
            raise ReferenceContextError("Symbol context exceeds its row/byte limit.")
        symbols = self.net.store.all(
            "SELECT name,address,size,kind FROM symbols WHERE project_id=? ORDER BY name,address", proj["id"]
        )
        relevant = {k: cfg[k] for k in BUILD_KEYS if k in cfg}
        frame = {"root": proj["root"], "config": relevant, "header": dict(header) if header else None,
                 "symbols": [dict(s) for s in symbols]}
        encoded = _canonical(frame)
        if len(encoded) > MAX_BYTES:
            raise ReferenceContextError("Database compiler context exceeds its byte limit.")
        return proj, row, cfg, frame, {"target_hash": target_hash, "db_context_hash": _digest(encoded),
                                       "project_hash": _project_fingerprint(proj, cfg)}

    def capture_db(self, slug, target_id, allow_claim_agent_id=None):
        """Small final-transaction check: no filesystem, sync, tools or writes."""
        return self._db_facts(slug, target_id, allow_claim_agent_id)[-1]

    def targets(self, slug, query="", limit=20):
        """Offer bounded function choices; expensive build-context eligibility is checked at preparation."""
        if not isinstance(query, str) or len(query) > 256 or type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Use a bounded target query and limit (1–50).")
        proj = self._project(slug)
        rows = self.net.store.all(
            "SELECT * FROM functions WHERE project_id=? AND gone_mark IS NULL AND name LIKE ? "
            "ORDER BY name,id LIMIT ?", proj["id"], f"%{query}%", limit + 1
        )
        results = []
        for row in rows[:limit]:
            reason = None
            try:
                self._target(proj["id"], row["id"])
                if json.loads(proj["config"]).get("kind") == "fork" and not row["unit"]:
                    raise ReferenceContextError("Target has no assigned source unit.")
            except ReferenceContextError as exc:
                reason = str(exc)
            results.append({"id": row["id"], "name": row["name"], "unit": row["unit"], "address": row["vram"],
                            "compiler_names": _aliases(row), "eligible": reason is None, "reason": reason})
        return {"targets": results, "truncated": len(rows) > limit}

    def capture(self, slug, target_id, allow_claim_agent_id=None, file_overrides=None):
        """Fingerprint real existing inputs without warming progress, building, or creating coverage."""
        proj, row, cfg, frame, facts = self._db_facts(slug, target_id, allow_claim_agent_id)
        unit_source = unit_source_hash = unit_signature = None
        if cfg["kind"] == "rom":
            if file_overrides:
                raise ReferenceContextError("ROM trials have no source-file override.")
            if frame["header"] is None:
                raise ReferenceContextError("Target has no existing compiler header/context; initialize it first.")
            compiler = compiler_for(cfg, row["vram"])
            if not isinstance(compiler, dict):
                raise ReferenceContextError("Target compiler is not configured.")
            selected = dict(compiler)
            profile = None
            if selected.get("toolchain"):
                # Same generic connector/like-profile selection as compiler_config,
                # without calling it (it can prepare/install compiler runtimes).
                own = kits.own_compiler(selected["toolchain"])
                if own and not own.like:
                    if own.runner == "wine":
                        raise ReferenceContextError("This SDK compiler requires project mode; its ROM runner is unsupported.")
                    selected.setdefault("flags", list(own.flags))
                    profile = {}
                else:
                    try:
                        tc = toolchains.get(own.like if own else selected["toolchain"])
                    except toolchains.ToolchainError as exc:
                        raise ReferenceContextError("Target compiler profile is unavailable.") from exc
                    profile = {k: getattr(tc, k) for k in ("id", "name", "flags", "cc", "cmd", "prelude", "cplusplus")}
                    selected.setdefault("flags", tc.flags)
                if own:
                    profile["own"] = {"version": own.version, "build": own.build, "like": own.like,
                                      "exe": str(own.exe), "root": str(own.root), "runner": own.runner,
                                      "args": list(own.args), "flags": list(own.flags),
                                      "includes": [str(p) for p in own.includes]}
            elif not isinstance(selected.get("cmd"), list) or not selected["cmd"]:
                raise ReferenceContextError("Target compiler command/profile is missing.")
            context = {"mode": "rom", "unit": row["unit"], "compiler": selected.get("toolchain", "project command"),
                       "flags": selected.get("flags", []), "command": selected, "profile": profile,
                       "header_version": frame["header"]["version"],
                       "header_hash": _digest((frame["header"]["header"] or "").encode())}
        else:
            context, unit_source, unit_source_hash, unit_signature = self._project_context(proj, row, cfg, file_overrides)
        context["db_context_hash"] = facts["db_context_hash"]
        target = {"id": row["id"], "name": row["name"], "unit": row["unit"], "address": row["vram"],
                  "compiler_names": _aliases(row), "eligible": True, "reason": None}
        return {"target": target, "context": context, "context_hash": _digest(_canonical(context)), **facts,
                "unit_source": unit_source, "unit_source_hash": unit_source_hash, "unit_signature": unit_signature}

    def _project_context(self, proj, row, cfg, file_overrides):
        try:
            root = Path(proj["root"]).resolve(strict=True)
        except OSError as exc:
            raise ReferenceContextError("Project working tree is missing.") from exc
        fp = ForkProject(root, cfg.get("platform", ""), read_only=True)
        raw = _safe_bytes(root / "objdiff.json", root)
        try:
            data = json.loads(raw)
            units = [u for u in fp._units_of(data) if u.name == row["unit"]]
        except (ValueError, TypeError, KeyError) as exc:
            raise ReferenceContextError("Project unit configuration cannot be read.") from exc
        if len(units) != 1 or not units[0].source or units[0].auto:
            raise ReferenceContextError("Target needs one existing, assigned, non-generated source unit.")
        unit = units[0]
        # Validate the original spelling first: safe_path resolves links.
        source_bytes = _safe_bytes(root / unit.source, root)
        try:
            source_path = fp.safe_path(unit.source, write=True)
        except ForkError as exc:
            raise ReferenceContextError("Target source is not an editable project source file.") from exc
        try:
            source_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ReferenceContextError("Target source must be UTF-8.") from exc
        unit_source = source_path.relative_to(root).as_posix()
        if file_overrides is not None and (not isinstance(file_overrides, dict) or set(file_overrides) - {unit_source}):
            raise ReferenceContextError("Only the admitted target source may have a server-side override.")
        if file_overrides and unit_source in file_overrides:
            value = file_overrides[unit_source]
            if not isinstance(value, str) or len(value.encode()) > MAX_FILE:
                raise ReferenceContextError("Invalid admitted source override.")
            source_bytes = value.encode()
        if unit.target is None or unit.base is None:
            raise ReferenceContextError("Original/candidate object mapping is unavailable; finish project setup first.")
        original = _safe_bytes(unit.target, root)
        original_path = unit.target.resolve(strict=True)
        if original_path == source_path:
            raise ReferenceContextError("Editable source must not also be the original target object.")
        files = {"objdiff.json": _digest(raw), unit_source: _digest(source_bytes),
                 original_path.relative_to(root).as_posix(): _digest(original)}
        total = len(raw) + len(source_bytes) + len(original)
        entries = 0
        todo = [root]
        while todo:
            directory = todo.pop()
            try:
                with os.scandir(directory) as children:
                    for child in children:
                        entries += 1
                        if entries > MAX_ENTRIES:
                            raise ReferenceContextError("Project context exceeds its entry limit.")
                        if child.name in SKIP:
                            continue
                        path = Path(child.path)
                        if child.is_symlink():
                            # A linked directory can hide arbitrary header/build dependencies.
                            raise ReferenceContextError("Symlinked project context is unsupported.")
                        if child.is_dir(follow_symlinks=False):
                            todo.append(path)
                            continue
                        rel = path.relative_to(root).as_posix()
                        relevant = path.suffix in (SOURCE_SUFFIXES | BUILD_SUFFIXES | {".s", ".S", ".asm"})
                        if rel in files or not (relevant or path.name in BUILD_FILES):
                            continue
                        # Also bind implementation fragments: projects can #include .c/.cpp files.
                        content = _safe_bytes(path, root)
                        files[rel] = _digest(content)
                        total += len(content)
                        if len(files) > MAX_FILES or total > MAX_BYTES:
                            raise ReferenceContextError("Project compiler context exceeds its file/byte limit.")
            except OSError as exc:
                raise ReferenceContextError("Project compiler context cannot be enumerated.") from exc
        if total > MAX_BYTES:
            raise ReferenceContextError("Project compiler context exceeds its byte limit.")
        rules = [p for p in files if p.endswith((".ninja", ".mk")) or Path(p).name in BUILD_FILES
                 or p == ".decomp.wtf.json"]
        if not rules:
            raise ReferenceContextError("Existing project build rules are missing; finish setup first.")
        context = {"mode": "project", "unit": unit.name, "tree_identity_hash": _digest(str(root).encode()),
                   "compiler": "Existing project build (no override)",
                   "flags": "Defined by the bound project build rules, not inferred from the reference.",
                   "unit_options": unit.options, "profile": cfg.get("profile"),
                   "original_object_hash": _digest(original), "context_files": sorted(files.items()),
                   "build_rules": sorted(rules)}
        signature = _unit_fingerprint(unit, root)
        context["unit_signature"] = signature
        return context, unit_source, _digest(source_bytes), signature
