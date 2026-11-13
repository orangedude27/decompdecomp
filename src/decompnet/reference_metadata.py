"""Strict import, review and guarded application of user-owned symbol metadata.

Metadata stays in private tables; reference_files receives only a deterministic text projection for retrieval.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import time
from pathlib import Path

from . import consoles
from .network import Agent, NetworkError
from .references import MAX_SOURCES, References

SCHEMA = "decompdecomp.reference-metadata"
MAX_IMPORT_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 2000
MAX_PROJECTION_BYTES = 32 * 1024 * 1024
MAX_PROJECTION_FILE_BYTES = 512 * 1024
MAX_ADDRESS = 0xFFFFFFFFFFFFFFFF
MAX_SQLITE_ID = 0x7FFFFFFFFFFFFFFF
MAX_RESPONSE_BYTES = 256 * 1024
C_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
ROOT_KEYS = {"schema", "version", "kind", "build", "records"}
RECORD_KEYS = {"id", "kind", "name", "address", "unit", "signature", "comment", "pseudocode"}
TEXT_LIMITS = {"id": 128, "name": 256, "unit": 512, "signature": 1024, "comment": 4096, "pseudocode": 16384}


class _DuplicateKey(ValueError):
    pass


def _bounded_id(value, label, *, query=False):
    if query and isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,18}", value):
        value = int(value)
    if type(value) is not int or value < 1 or value > MAX_SQLITE_ID:
        raise ValueError(f"{label} must be a positive bounded integer.")
    return value


def _bounded_page_number(value, label, *, query=False):
    if query and isinstance(value, str) and re.fullmatch(r"[0-9]{1,18}", value):
        value = int(value)
    if type(value) is not int or value < 0 or value > MAX_SQLITE_ID:
        raise ValueError(f"{label} must be a nonnegative bounded integer.")
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def parse_metadata(raw: bytes) -> tuple[dict, list[dict]]:
    """Validate the complete v1 interchange before it can create any project state."""
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("Metadata files must be 2 MiB or smaller.")
    try:
        text = raw.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON number.")),
        )
    except _DuplicateKey:
        raise ValueError("Metadata JSON contains a duplicate key.") from None
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise ValueError("Choose valid, bounded UTF-8 metadata JSON.") from None
    if not isinstance(document, dict) or set(document) - ROOT_KEYS or not ROOT_KEYS - {"build"} <= set(document):
        raise ValueError("Metadata must be a versioned object with no unknown root fields.")
    if document.get("schema") != SCHEMA or type(document.get("version")) is not int or document["version"] != 1:
        raise ValueError("Unsupported metadata schema or version.")
    if not isinstance(document.get("kind"), str) or document["kind"] not in {"symbols", "ghidra"}:
        raise ValueError("Metadata kind must be symbols or ghidra.")
    build = document.get("build")
    if build is not None:
        if (
            not isinstance(build, dict)
            or set(build) != {"kind", "value"}
            or not isinstance(build.get("kind"), str)
            or build["kind"] not in {"rom_sha1", "program_sha1", "game_sha1"}
            or not isinstance(build.get("value"), str)
            or not HEX40.fullmatch(build["value"])
        ):
            raise ValueError("Build identity must contain a supported kind and a 40-digit SHA-1.")
        build = {"kind": build["kind"], "value": build["value"].lower()}
    records = document.get("records")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError(f"Metadata must contain at most {MAX_RECORDS} records.")
    seen = set()
    normalized = []
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) - RECORD_KEYS or not {"id", "kind", "name"} <= set(record):
            raise ValueError("Each metadata record needs id, kind and name and no unknown fields.")
        if not isinstance(record["kind"], str) or record["kind"] not in {"function", "data"}:
            raise ValueError("Record kind must be function or data.")
        item = {}
        for key, limit in TEXT_LIMITS.items():
            value = record.get(key, "")
            if not isinstance(value, str) or len(value) > limit:
                raise ValueError(f"Record {key} must be text of at most {limit} characters.")
            item[key] = value
        if not item["id"] or not item["name"]:
            raise ValueError("Record id and name cannot be empty.")
        if item["id"] in seen:
            raise ValueError("Metadata record ids must be unique.")
        seen.add(item["id"])
        address = record.get("address")
        if address is not None:
            if not isinstance(address, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]+", address):
                raise ValueError("Record addresses must be hexadecimal strings or null.")
            digits = address[2:].lstrip("0")
            if len(digits) > 16:
                raise ValueError("Record address is too large.")
            address = int(digits or "0", 16)
            if address > MAX_ADDRESS:
                raise ValueError("Record address is too large.")
        item.update(kind=record["kind"], address=address)
        rendered = _render(item)
        if len(rendered.encode("utf-8")) > MAX_PROJECTION_FILE_BYTES:
            raise ValueError("A normalized metadata record is too large.")
        total += len(rendered.encode("utf-8"))
        if total > MAX_PROJECTION_BYTES:
            raise ValueError("Normalized metadata exceeds 32 MiB.")
        normalized.append(item)
    return {"kind": document["kind"], "build": build}, normalized


def _canonical_address(address):
    return None if address is None else f"0x{address:016X}"


def _record_hash(record):
    payload = {key: record[key] for key in ("id", "kind", "name", "unit", "signature", "comment", "pseudocode")}
    address = record["address"]
    if isinstance(address, str):
        address = int(address, 16)
    payload["address"] = _canonical_address(address)
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _render(record: dict) -> str:
    address = "" if record["address"] is None else f"0x{record['address']:X}"
    return (
        f"Name: {record['name']}\nKind: {record['kind']}\nAddress: {address}\n"
        f"Signature: {record['signature']}\nComment: {record['comment']}\n"
        f"Pseudocode: {record['pseudocode']}\n"
    )


class ReferenceMetadata:
    """Owner-only metadata workflow; no operation here reads or executes imported game files."""

    def __init__(self, store, net=None):
        self.store, self.net = store, net
        self._lock = threading.RLock()
        self._active: set[tuple[int, str]] = set()
        with self.store.tx() as db:
            db.execute(
                "UPDATE metadata_records SET status='error',error='A previous metadata application was interrupted; verify the target before retrying.' "
                "WHERE status='applying'"
            )

    @staticmethod
    def _renames_in_report(config):
        return consoles.of(ReferenceMetadata._config(config)).renames_in_report

    def _target_matches(self, project_id, row):
        return self._target_renamed(project_id, row)

    def _target_renamed(self, project_id, row, *, check_size=True):
        project = self.store.one("SELECT config FROM projects WHERE id=?", project_id)
        if project is None:
            return False
        renames_in_report = self._renames_in_report(project["config"])
        if row["target_kind"] == "function":
            current = self.store.one(
                "SELECT name,unit,vram AS address,size,meta FROM functions WHERE id=? AND project_id=?",
                int(row["target_id"]),
                project_id,
            )
            if current is None or current["unit"] != row["target_unit"] or current["address"] != row["target_address"]:
                return False
            if check_size and current["size"] != row["target_size"]:
                return False
            try:
                meta = json.loads(current["meta"] or "{}")
            except (TypeError, json.JSONDecodeError):
                return False
            if not isinstance(meta, dict):
                return False
            original = meta.get("symbol") or meta.get("real") or ""
            if renames_in_report:
                if current["name"] != row["proposed_name"]:
                    return False
                return original in {row["target_original"], row["proposed_name"]}
            return (
                current["name"] == row["target_name"]
                and meta.get("symbol") == row["target_original"]
                and meta.get("real") == row["proposed_name"]
            )
        try:
            target_rowid = int(row["target_original"])
        except (TypeError, ValueError):
            return False
        current = self.store.one(
            "SELECT name,address,size,kind FROM symbols WHERE rowid=? AND project_id=?", target_rowid, project_id
        )
        if (
            current is None
            or current["name"] != row["proposed_name"]
            or current["address"] != row["target_address"]
            or current["kind"] != row["kind"]
            or check_size
            and current["size"] != row["target_size"]
        ):
            return False
        return True

    def _mark_applied(self, record_id, warning=None):
        with self.store.tx() as db:
            record = db.execute("SELECT * FROM metadata_records WHERE record_id=?", (record_id,)).fetchone()
            if record is None:
                return None
            db.execute("UPDATE metadata_records SET status='applied',error=? WHERE record_id=?", (warning, record_id))
            return self._record(db.execute("SELECT * FROM metadata_records WHERE record_id=?", (record_id,)).fetchone())

    def _project(self, slug):
        project = self.store.one("SELECT id,config FROM projects WHERE slug=?", slug)
        if project is None:
            raise NetworkError("That project no longer exists.")
        return project

    @staticmethod
    def _json_size(value):
        return len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))

    @staticmethod
    def _bounded_page(base, key, values):
        kept = []
        for value in values:
            candidate = base | {key: kept + [value]}
            if ReferenceMetadata._json_size(candidate) > MAX_RESPONSE_BYTES:
                break
            kept.append(value)
        return kept

    @staticmethod
    def _read(path):
        if not isinstance(path, str):
            raise ValueError("Choose a local metadata JSON file path.")
        rawpath = path.strip()
        if not rawpath or "://" in rawpath:
            raise ValueError("Choose a local metadata JSON file.")
        path = Path(rawpath).expanduser()
        if not path.is_absolute() or path == Path(path.anchor):
            raise ValueError("Choose an absolute local metadata file.")
        try:
            References._check_path(path)
            before = path.lstat()
        except (OSError, ValueError):
            raise ValueError("The selected metadata file cannot be read safely.") from None
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Choose a regular metadata file.")
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except (OSError, ValueError):
            raise ValueError("The selected metadata file cannot be read safely.") from None
        try:
            try:
                opened = os.fstat(fd)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or not stat.S_ISREG(opened.st_mode):
                    raise ValueError("The metadata file changed while it was opened.")
                data = bytearray()
                while len(data) <= MAX_IMPORT_BYTES:
                    block = os.read(fd, min(65536, MAX_IMPORT_BYTES + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
                after = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
                    raise ValueError("The metadata file changed while it was read.")
            except (OSError, ValueError):
                raise ValueError("The selected metadata file could not be read safely.") from None
        finally:
            try:
                os.close(fd)
            except OSError:
                raise ValueError("The selected metadata file could not be closed safely.") from None
        raw = bytes(data)
        meta, records = parse_metadata(raw)
        return raw, meta, records

    @staticmethod
    def _config(config):
        try:
            value = json.loads(config)
        except (TypeError, json.JSONDecodeError):
            raise NetworkError("Project metadata is unavailable; reopen the project and try again.") from None
        if not isinstance(value, dict):
            raise NetworkError("Project metadata is unavailable; reopen the project and try again.")
        return value

    @classmethod
    def _builds_from_config(cls, config):
        cfg = cls._config(config)
        rom = cfg.get("rom")
        rom = rom if isinstance(rom, dict) else {}
        result = []
        for kind, value in (
            ("rom_sha1", rom.get("sha1")),
            ("program_sha1", cfg.get("program_sha1")),
            ("game_sha1", cfg.get("game_sha1")),
        ):
            if isinstance(value, str) and HEX40.fullmatch(value):
                result.append({"kind": kind, "value": value.lower()})
        return result

    @classmethod
    def _project_snapshot(cls, config):
        cfg = cls._config(config)
        return json.dumps(
            {
                "builds": cls._builds_from_config(config),
                "platform": cfg.get("platform"),
                "version": cfg.get("version"),
                "kind": cfg.get("kind"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def _identity(self, config, build):
        if build is None:
            return "unknown"
        if (
            not isinstance(build, dict)
            or not isinstance(build.get("kind"), str)
            or build["kind"] not in {"rom_sha1", "program_sha1", "game_sha1"}
            or not isinstance(build.get("value"), str)
            or not HEX40.fullmatch(build["value"])
        ):
            raise NetworkError("The imported build identity is invalid; review this metadata source again.")
        cfg = self._config(config)
        rom = cfg.get("rom")
        rom = rom if isinstance(rom, dict) else {}
        choices = {
            "rom_sha1": rom.get("sha1"),
            "program_sha1": cfg.get("program_sha1"),
            "game_sha1": cfg.get("game_sha1"),
        }
        value = choices.get(build["kind"])
        return (
            "match"
            if isinstance(value, str) and HEX40.fullmatch(value) and value.lower() == build["value"]
            else "mismatch"
        )

    def preview(self, slug, path):
        project = self._project(slug)
        raw, meta, records = self._read(path)
        identity = self._identity(project["config"], meta["build"])
        base = {
            "content_hash": hashlib.sha256(raw).hexdigest(),
            "kind": meta["kind"],
            "build": meta["build"],
            "identity_status": identity,
            "record_count": len(records),
            "records": [],
            "truncated": False,
            "warnings": []
            if identity == "match"
            else ["Build identity is unknown or differs; every mapping needs owner review."],
        }
        summaries = [self._summary(r) for r in records[:50]]
        base["records"] = self._bounded_page(base, "records", summaries)
        base["truncated"] = len(base["records"]) < len(records)
        return base

    @staticmethod
    def _clip(value, limit):
        return value[:limit], len(value) > limit

    @classmethod
    def _summary(cls, record):
        result = {key: record[key] for key in ("id", "kind", "name", "unit")}
        result["address"] = _canonical_address(record["address"])
        truncated = []
        for key, limit in (("signature", 512), ("comment", 512)):
            result[key], cut = cls._clip(record[key], limit)
            if cut:
                truncated.append(key)
        result["truncated_fields"] = truncated
        return result

    @staticmethod
    def _source(row):
        return {
            "id": row["id"],
            "name": row["name"],
            "kind": row["kind"],
            "enabled": bool(row["enabled"]),
            "status": row["status"],
            "file_count": row["file_count"],
            "byte_count": row["byte_count"],
            "indexed_at": row["indexed_at"],
            "warnings": [],
            "error": row["error"],
            "stale": bool(row["stale"]),
            "agent_access": False,
        }

    def import_file(self, slug, path, content_hash):
        project = self._project(slug)
        raw, meta, records = self._read(path)
        digest = hashlib.sha256(raw).hexdigest()
        if not isinstance(content_hash, str) or digest != content_hash:
            raise NetworkError("The metadata file changed after preview. Preview it again before importing.")
        identity = self._identity(project["config"], meta["build"])
        name = Path(path).name
        rendered = [(_render(row), hashlib.sha256(_render(row).encode()).hexdigest()) for row in records]
        with self.store.tx() as db:
            if (
                db.execute("SELECT COUNT(*) FROM reference_sources WHERE project_id=?", (project["id"],)).fetchone()[0]
                >= MAX_SOURCES
            ):
                raise NetworkError(f"A project can have at most {MAX_SOURCES} reference sources.")
            cur = db.execute(
                "INSERT INTO reference_sources(project_id,name,root,kind,status,file_count,byte_count,agent_access) "
                "VALUES(?,?,?,'metadata','ready',?,?,0)",
                (project["id"], name, "", len(records), sum(len(x[0].encode()) for x in rendered)),
            )
            sid = cur.lastrowid
            cur = db.execute(
                "INSERT INTO metadata_imports(source_id,kind,build,identity_status,record_count,content_hash,imported_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (sid, meta["kind"], json.dumps(meta["build"]), identity, len(records), digest, time.time()),
            )
            iid = cur.lastrowid
            db.executemany(
                "INSERT INTO reference_files(source_id,path,text,content_hash) VALUES(?,?,?,?)",
                [(sid, f"entries/{i:06}.txt", text, hashed) for i, (text, hashed) in enumerate(rendered, 1)],
            )
            db.executemany(
                "INSERT INTO metadata_records(import_id,external_id,kind,name,address,unit,signature,comment,pseudocode,record_hash) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        iid,
                        row["id"],
                        row["kind"],
                        row["name"],
                        _canonical_address(row["address"]),
                        row["unit"],
                        row["signature"],
                        row["comment"],
                        row["pseudocode"],
                        _record_hash(row),
                    )
                    for row in records
                ],
            )
            source = db.execute("SELECT * FROM reference_sources WHERE id=?", (sid,)).fetchone()
            imp = db.execute("SELECT * FROM metadata_imports WHERE id=?", (iid,)).fetchone()
        return {"source": self._source(source), "import": self._import(imp) | {"name": name}}

    @staticmethod
    def _import(row):
        return {
            "id": row["id"],
            "source_id": row["source_id"],
            "name": row["kind"],
            "kind": row["kind"],
            "build": json.loads(row["build"] or "null"),
            "identity_status": row["identity_status"],
            "record_count": row["record_count"],
            "content_hash": row["content_hash"],
        }

    def listing(self, slug):
        project = self._project(slug)
        rows = self.store.all(
            "SELECT i.*,s.name FROM metadata_imports i JOIN reference_sources s ON s.id=i.source_id "
            "WHERE s.project_id=? ORDER BY i.id DESC LIMIT 20",
            project["id"],
        )
        imports = []
        for row in rows:
            identity = self._identity(project["config"], json.loads(row["build"] or "null"))
            warnings = (
                []
                if identity == "match"
                else ["Current project build differs or is unknown; review mappings manually."]
            )
            imports.append(self._import(row) | {"name": row["name"], "identity_status": identity, "warnings": warnings})
        return {"builds": self.builds(slug), "imports": imports}

    def builds(self, slug):
        project = self._project(slug)
        return self._builds_from_config(project["config"])

    def records(self, slug, import_id, offset=0, limit=50, query_ids=False):
        project = self._project(slug)
        import_id = _bounded_id(import_id, "Import id", query=query_ids)
        offset = _bounded_page_number(offset, "Offset", query=query_ids)
        limit = _bounded_page_number(limit, "Limit", query=query_ids)
        limit = min(50, max(1, limit))
        imp = self.store.one(
            "SELECT i.id FROM metadata_imports i JOIN reference_sources s ON s.id=i.source_id "
            "WHERE i.id=? AND s.project_id=?",
            import_id,
            project["id"],
        )
        if imp is None:
            raise NetworkError("That metadata import no longer exists.")
        count_row = self.store.one("SELECT COUNT(*) n FROM metadata_records WHERE import_id=?", imp["id"])
        total = count_row["n"] if count_row is not None else 0
        rows = self.store.all(
            "SELECT * FROM metadata_records WHERE import_id=? ORDER BY record_id LIMIT ? OFFSET ?",
            imp["id"],
            limit,
            offset,
        )
        base = {"records": [], "offset": offset, "total": total, "truncated": False}
        candidates = [self._record(row) for row in rows]
        base["records"] = self._bounded_page(base, "records", candidates)
        base["truncated"] = offset + len(base["records"]) < total
        return base

    @classmethod
    def _record(cls, row):
        result = {
            "record_id": row["record_id"],
            "id": row["external_id"],
            "kind": row["kind"],
            "name": row["name"],
            "address": row["address"],
            "unit": row["unit"],
            "status": row["status"],
            "proposed_name": row["proposed_name"],
            "error": row["error"],
            "target": (
                {
                    "kind": row["target_kind"],
                    "id": row["target_id"],
                    "name": row["target_name"],
                    "unit": row["target_unit"],
                    "address": row["target_address"],
                }
                if row["target_kind"]
                else None
            ),
        }
        truncated = []
        for key, limit in (("signature", 512), ("comment", 512), ("pseudocode", 512)):
            result[key], cut = cls._clip(row[key], limit)
            if cut:
                truncated.append(key)
        result["text_truncated"] = bool(truncated)
        result["truncated_fields"] = truncated
        return result

    def targets(self, slug, query="", limit=20, query_values=False):
        project = self._project(slug)
        if not isinstance(query, str):
            raise ValueError("Target search must be text.")
        if len(query) > 256:
            raise ValueError("Target search is limited to 256 characters.")
        limit = min(50, max(1, _bounded_page_number(limit, "Limit", query=query_values)))
        literal = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{literal}%"
        rows = self.store.all(
            "SELECT id,name,unit,vram,size,meta FROM functions WHERE project_id=? AND "
            "(name LIKE ? ESCAPE '\\' OR CASE WHEN json_valid(meta) THEN "
            "json_extract(meta,'$.real') LIKE ? ESCAPE '\\' END) ORDER BY name LIMIT ?",
            project["id"],
            like,
            like,
            limit + 1,
        )
        targets = []
        renames_in_report = self._renames_in_report(project["config"])
        for row in rows:
            try:
                meta = json.loads(row["meta"] or "{}")
            except (TypeError, json.JSONDecodeError):
                meta = {}
            real = meta.get("real") if isinstance(meta, dict) and isinstance(meta.get("real"), str) else None
            shown_real = self._clip(real, 256)[0] if real else None
            report_name = self._clip(row["name"], 256)[0]
            show_real = not renames_in_report and bool(shown_real)
            label = (
                f"{shown_real} (report: {report_name})"
                if show_real and shown_real != report_name
                else shown_real or report_name
            )
            targets.append(
                {
                    "target": {"kind": "function", "id": row["id"]},
                    "name": label,
                    "report_name": report_name if show_real and shown_real != report_name else None,
                    "unit": row["unit"],
                    "address": row["vram"],
                    "kind": "function",
                }
            )
        config = self._config(project["config"])
        if config.get("kind") == "rom" and len(targets) <= limit:
            symbols = self.store.all(
                "SELECT name,address,size,kind FROM symbols WHERE project_id=? AND name LIKE ? ESCAPE '\\' "
                "ORDER BY name LIMIT ?",
                project["id"],
                like,
                limit + 1 - len(targets),
            )
            targets.extend(
                {
                    "target": {"kind": "symbol", "name": row["name"]},
                    "name": row["name"],
                    "unit": "",
                    "address": row["address"],
                    "kind": row["kind"],
                }
                for row in symbols
            )
        return {"targets": targets[:limit], "truncated": len(targets) > limit}

    def map_record(self, slug, record_id, target, proposed_name=None):
        record_id = _bounded_id(record_id, "Record id")
        project = self._project(slug)
        key = (project["id"], str(record_id))
        with self._lock:
            if key in self._active:
                raise NetworkError("This metadata proposal is already being reviewed.")
            self._active.add(key)
        try:
            return self._map_record(slug, record_id, target, proposed_name)
        finally:
            with self._lock:
                self._active.discard(key)

    def _map_record(self, slug, record_id, target, proposed_name=None):
        project = self._project(slug)
        if not isinstance(target, dict):
            raise ValueError("Choose a project target.")
        row = self.store.one(
            "SELECT r.*,i.id iid,i.identity_status,i.build,s.enabled,s.project_id FROM metadata_records r "
            "JOIN metadata_imports i ON i.id=r.import_id JOIN reference_sources s ON s.id=i.source_id "
            "WHERE r.record_id=? AND s.project_id=?",
            int(record_id),
            project["id"],
        )
        if row is None:
            raise NetworkError("That metadata record no longer exists.")
        if row["status"] == "applied":
            raise NetworkError("An applied record cannot be remapped.")
        target_kind = target.get("kind")
        if target_kind == "function" and row["kind"] == "function":
            raw_target_id = target.get("id")
            if type(raw_target_id) is not int or raw_target_id <= 0:
                raise ValueError("Choose a listed project function.")
            target_id = str(raw_target_id)
            fn = self.store.one(
                "SELECT id,name,unit,vram,size,meta FROM functions WHERE id=? AND project_id=?",
                raw_target_id,
                project["id"],
            )
            if fn is None:
                raise NetworkError("That target no longer exists in this project.")
            if (
                fn["vram"] is not None
                and self.store.one(
                    "SELECT COUNT(*) n FROM functions WHERE project_id=? AND vram=?", project["id"], fn["vram"]
                )["n"]
                > 1
            ):
                raise NetworkError("That function address has overlay targets; choose an unambiguous target.")
            target_name, unit, address, size = fn["name"], fn["unit"], fn["vram"], fn["size"]
            try:
                meta = json.loads(fn["meta"] or "{}")
            except (TypeError, json.JSONDecodeError):
                raise NetworkError("The target symbol metadata is invalid; choose another target.") from None
            if not isinstance(meta, dict) or any(
                key in meta and meta[key] is not None and not isinstance(meta[key], str) for key in ("symbol", "real")
            ):
                raise NetworkError("The target symbol metadata is invalid; choose another target.")
            renames_in_report = self._renames_in_report(project["config"])
            original = meta.get("symbol") or (target_name if not renames_in_report else meta.get("real")) or ""
            old_name = (meta.get("real") or target_name) if not renames_in_report else target_name
        elif target_kind == "symbol" and row["kind"] == "data" and json.loads(project["config"]).get("kind") == "rom":
            target_id = target.get("name")
            if not isinstance(target_id, str):
                raise ValueError("Choose a listed project symbol.")
            fn = self.store.one(
                "SELECT rowid AS selected_rowid,name,address,size,kind FROM symbols WHERE project_id=? AND name=?",
                project["id"],
                target_id,
            )
            if fn is None:
                raise NetworkError("That ROM symbol no longer exists in this project.")
            if fn["kind"] != "data":
                raise NetworkError("Choose a verified ROM data symbol.")
            target_name = old_name = fn["name"]
            unit, address, size, original = "", fn["address"], fn["size"], str(fn["selected_rowid"])
        else:
            raise NetworkError("Choose a supported function, or a ROM symbol for a data record.")
        new_name = proposed_name if proposed_name is not None else row["name"]
        if not isinstance(new_name, str) or not C_IDENTIFIER.fullmatch(new_name):
            raise ValueError("The proposed name must be a simple C identifier.")
        if new_name == old_name:
            raise ValueError("Choose a new name different from the target's current name.")
        identity = self._identity(project["config"], json.loads(row["build"] or "null"))
        with self.store.tx() as db:
            collision = db.execute(
                "SELECT 1 FROM metadata_records r JOIN metadata_imports i ON i.id=r.import_id "
                "JOIN reference_sources s ON s.id=i.source_id WHERE s.project_id=? "
                "AND r.status IN ('pending','applying') AND r.proposed_name=? AND r.target_id<>?",
                (project["id"], new_name, target_id),
            ).fetchone()
            existing = db.execute(
                "SELECT id FROM functions WHERE project_id=? AND id<>? AND (name=? OR "
                "CASE WHEN json_valid(meta) THEN json_extract(meta,'$.real') END=?) LIMIT 1",
                (project["id"], int(target_id) if target_kind == "function" else -1, new_name, new_name),
            ).fetchone()
            symbol_collision = db.execute(
                "SELECT 1 FROM symbols WHERE project_id=? AND name=? AND name<>?", (project["id"], new_name, target_id)
            ).fetchone()
            if collision or existing or symbol_collision:
                raise NetworkError("That proposed name conflicts with another target.")
            db.execute(
                "UPDATE metadata_records SET status='pending',target_kind=?,target_id=?,target_name=?,"
                "target_unit=?,target_address=?,target_size=?,target_original=?,target_build=?,target_build_kind=?,target_import_build=?,old_name=?,proposed_name=?,error=NULL "
                "WHERE record_id=?",
                (
                    target_kind,
                    target_id,
                    target_name,
                    unit,
                    address,
                    size,
                    original,
                    self._project_snapshot(project["config"]),
                    identity,
                    row["build"],
                    old_name,
                    new_name,
                    row["record_id"],
                ),
            )
            fresh = db.execute("SELECT * FROM metadata_records WHERE record_id=?", (row["record_id"],)).fetchone()
        return self._record(fresh)

    def reject(self, slug, record_id):
        record_id = _bounded_id(record_id, "Record id")
        project = self._project(slug)
        key = (project["id"], str(record_id))
        with self._lock:
            if key in self._active:
                raise NetworkError("This metadata proposal is already being reviewed.")
            self._active.add(key)
        try:
            return self._reject(slug, record_id)
        finally:
            with self._lock:
                self._active.discard(key)

    def _reject(self, slug, record_id):
        project = self._project(slug)
        with self.store.tx() as db:
            row = db.execute(
                "SELECT r.* FROM metadata_records r JOIN metadata_imports i ON i.id=r.import_id "
                "JOIN reference_sources s ON s.id=i.source_id WHERE r.record_id=? AND s.project_id=?",
                (int(record_id), project["id"]),
            ).fetchone()
            if row is None:
                raise NetworkError("That metadata record no longer exists.")
            if row["status"] == "applied":
                raise NetworkError("An applied record cannot be rejected.")
            db.execute(
                "UPDATE metadata_records SET status='rejected',error=NULL WHERE record_id=?", (row["record_id"],)
            )
            return self._record(
                db.execute("SELECT * FROM metadata_records WHERE record_id=?", (row["record_id"],)).fetchone()
            )

    def apply(self, slug, record_id):
        if self.net is None:
            raise NetworkError("Guarded rename is unavailable.")
        record_id = _bounded_id(record_id, "Record id")
        project = self._project(slug)
        key = (project["id"], str(record_id))
        with self._lock:
            if key in self._active:
                raise NetworkError("This metadata proposal is already being reviewed.")
            self._active.add(key)
        row = None
        attempt_started = False
        try:
            row = self.store.one(
                "SELECT r.*,s.enabled,s.id source_id,i.build,i.content_hash FROM metadata_records r JOIN metadata_imports i "
                "ON i.id=r.import_id JOIN reference_sources s ON s.id=i.source_id WHERE r.record_id=? AND s.project_id=?",
                int(record_id),
                project["id"],
            )
            if row is None:
                raise NetworkError("That metadata record no longer exists in this project.")
            if not row["enabled"]:
                raise NetworkError("Enable the metadata source before applying its proposal.")
            if row["status"] != "pending" or not row["target_id"]:
                raise NetworkError("Map this record before applying it.")
            if not isinstance(row["proposed_name"], str) or not C_IDENTIFIER.fullmatch(row["proposed_name"]):
                raise NetworkError("The proposed name is not a C identifier.")
            attempt_started = True

            def precondition(db):
                fresh = db.execute(
                    "SELECT r.*,s.enabled,s.id source_id,i.build,i.content_hash FROM metadata_records r JOIN metadata_imports i "
                    "ON i.id=r.import_id JOIN reference_sources s ON s.id=i.source_id WHERE r.record_id=?",
                    (int(record_id),),
                ).fetchone()
                current_project = db.execute("SELECT config FROM projects WHERE id=?", (project["id"],)).fetchone()
                if row["target_kind"] == "function":
                    current = db.execute(
                        "SELECT name,unit,vram AS address,size,meta FROM functions WHERE id=? AND project_id=?",
                        (int(row["target_id"]), project["id"]),
                    ).fetchone()
                else:
                    current = db.execute(
                        "SELECT name,'' AS unit,address,size,kind FROM symbols WHERE rowid=? AND project_id=?",
                        (int(row["target_original"]), project["id"]),
                    ).fetchone()
                if (
                    fresh is None
                    or fresh["status"] not in {"pending", "applying"}
                    or not fresh["enabled"]
                    or current is None
                    or current_project is None
                ):
                    raise NetworkError("This proposal or target changed; review and map it again.")
                record_data = {
                    "id": fresh["external_id"],
                    "kind": fresh["kind"],
                    "name": fresh["name"],
                    "address": fresh["address"],
                    "unit": fresh["unit"],
                    "signature": fresh["signature"],
                    "comment": fresh["comment"],
                    "pseudocode": fresh["pseudocode"],
                }
                try:
                    current_record_hash = _record_hash(record_data)
                except (TypeError, ValueError):
                    raise NetworkError("This metadata record is invalid; import it again before applying.") from None
                if (
                    current_record_hash != fresh["record_hash"]
                    or fresh["content_hash"] != row["content_hash"]
                    or fresh["proposed_name"] != row["proposed_name"]
                    or fresh["target_kind"] != row["target_kind"]
                    or fresh["target_id"] != row["target_id"]
                    or fresh["target_name"] != row["target_name"]
                    or fresh["old_name"] != row["old_name"]
                    or fresh["target_unit"] != row["target_unit"]
                    or fresh["target_address"] != row["target_address"]
                    or fresh["target_size"] != row["target_size"]
                    or fresh["target_original"] != row["target_original"]
                    or fresh["build"] != row["target_import_build"]
                ):
                    raise NetworkError("This metadata record or mapping changed; review and map it again.")
                if (
                    current["name"],
                    current["unit"],
                    current["address"],
                    current["size"],
                    self._project_snapshot(current_project["config"]),
                ) != (
                    row["target_name"],
                    row["target_unit"],
                    row["target_address"],
                    row["target_size"],
                    row["target_build"],
                ):
                    raise NetworkError("The target or project build changed; map this record again.")
                if row["target_kind"] == "symbol" and current["kind"] != fresh["kind"]:
                    raise NetworkError("The ROM symbol kind changed; map this record again.")
                if row["target_kind"] == "function":
                    try:
                        current_meta = json.loads(current["meta"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        raise NetworkError("The target symbol metadata changed; map this record again.") from None
                    if not isinstance(current_meta, dict):
                        raise NetworkError("The target symbol metadata changed; map this record again.")
                    if self._renames_in_report(current_project["config"]):
                        current_original = current_meta.get("symbol") or current_meta.get("real") or ""
                        if current_original != row["target_original"]:
                            raise NetworkError("The target's original symbol changed; map this record again.")
                    else:
                        current_original = current_meta.get("symbol") or row["target_name"]
                        current_real = current_meta.get("real") or row["target_name"]
                        if current_original != row["target_original"] or current_real != row["old_name"]:
                            raise NetworkError("The target's original or real name changed; map it again.")
                if (
                    self._identity(current_project["config"], json.loads(fresh["build"] or "null"))
                    != fresh["target_build_kind"]
                ):
                    raise NetworkError("The metadata build identity changed; map this record again.")

            with self.store.tx() as db:
                precondition(db)
                db.execute("UPDATE metadata_records SET status='applying' WHERE record_id=?", (record_id,))
            agent = Agent(0, "decompdecomp", None)
            try:
                result = self.net.rename_symbol(
                    agent, slug, row["old_name"], row["proposed_name"], "", precondition=precondition
                )
            except Exception as error:
                if not self._target_renamed(project["id"], row, check_size=False):
                    raise error
                result = "Guarded rename committed; completion message unavailable."
            if not self._target_renamed(project["id"], row, check_size=False):
                raise NetworkError(
                    "The rename guard returned without changing the selected target; no rename was confirmed."
                )
            layout_warning = (
                None
                if self._target_matches(project["id"], row)
                else ("The rename committed, but target layout changed during final verification.")
            )
            try:
                record = self._mark_applied(record_id, layout_warning)
            except Exception:
                record = None
            if record is None:
                raise NetworkError(
                    f"Rename to {row['proposed_name']} was committed, but metadata state could not be "
                    "recorded; do not apply it again."
                )
            return {"record": record, "result": result}
        except Exception as error:
            committed = row is not None and self._target_renamed(project["id"], row, check_size=False)
            if committed and row is not None:
                try:
                    warning = (
                        None
                        if self._target_matches(project["id"], row)
                        else ("The rename committed, but target layout changed during final verification.")
                    )
                    record = self._mark_applied(record_id, warning)
                except Exception:
                    record = None
                if record is None:
                    raise NetworkError(
                        f"Rename to {row['proposed_name']} was committed, but metadata state could not "
                        "be saved; do not apply it again."
                    ) from None
                return {"record": record, "result": "Guarded rename committed; recovery confirmed the target."}
            if attempt_started:
                with self.store.tx() as db:
                    db.execute(
                        "UPDATE metadata_records SET status='error',error=? WHERE record_id=? "
                        "AND status IN ('pending','applying') AND EXISTS (SELECT 1 FROM metadata_imports i "
                        "JOIN reference_sources s ON s.id=i.source_id WHERE i.id=metadata_records.import_id "
                        "AND s.project_id=?)",
                        (
                            "The rename was not confirmed. Review and map this proposal before retrying.",
                            record_id,
                            project["id"],
                        ),
                    )
            if isinstance(error, NetworkError):
                raise
            raise NetworkError("The guarded rename did not complete; review and map the proposal again.") from None
        finally:
            with self._lock:
                self._active.discard(key)
