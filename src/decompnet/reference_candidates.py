"""Owner-only, snapshot-only candidate preparation. No builds, claims or writes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from pathlib import Path

from .network import NetworkError
from .reference_context import (
    ReferenceContextError,
    TrialContext,
    _canonical,
    _digest,
    _project_fingerprint,
    _target_fingerprint,
    _unit_fingerprint,
)
from .reference_metadata import _object, _record_hash

TOKEN_TTL = 600
MAX_TOKEN = 32 * 1024
MAX_SOURCE = 48 * 1024
MAX_PRELUDE = 16 * 1024
MAX_RESPONSE = 256 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NAME = re.compile(r"^(?:~?[A-Za-z_]\w*::)*~?[A-Za-z_]\w*$", re.ASCII)
HEX = re.compile(r"^[0-9a-f]{64}$")
RAW_STRING = re.compile(r'(?:u8|u|U|L)?R"([^\s()\\]{0,16})\(')
QUOTED = re.compile(r"(?:u8|u|U|L)?[\"']")
KEYS = {"version", "nonce", "project_id", "function_id", "origin", "reference_hash", "source_hash", "prelude_hash",
        "context_hash", "db_context_hash", "project_hash", "target_hash", "unit_source", "unit_source_hash", "unit_signature", "ready", "issued", "expires"}


def _text(value, maximum, label):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be UTF-8 text.")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError(f"{label} must be UTF-8 text.") from None
    if size > maximum or "\0" in value:
        raise ValueError(f"{label} exceeds its {maximum}-byte limit or contains NUL.")
    return value


def _lex(source):
    """Blank literals/comments without changing offsets; yield real identifier tokens.

    Raw C++ strings are handled separately so quotes inside them cannot expose
    identifiers or braces to the conservative extractor.
    """
    clean = list(source)
    identifiers = []
    i = 0
    while i < len(source):
        start = i
        if source.startswith("//", i):
            while True:
                end = source.find("\n", i)
                if end < 0:
                    i = len(source)
                    break
                line = source[i:end].removesuffix("\r")
                i = end + 1
                if not line.endswith("\\"):
                    break
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                raise ValueError("Unterminated C comment; select a complete definition.")
            i = end + 2
        elif (raw := RAW_STRING.match(source, i)) is not None:
            close = ")" + raw.group(1) + '"'
            end = source.find(close, raw.end())
            if end < 0:
                raise ValueError("Unterminated raw string literal.")
            i = end + len(close)
        elif (quoted := QUOTED.match(source, i)) is not None:
            quote = source[quoted.end() - 1]
            i = quoted.end()
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError("Unterminated C string/character literal.")
        elif (source[i].isascii() and source[i].isdigit()) or (source[i] == "." and i + 1 < len(source) and source[i + 1].isdigit()):
            # A preprocessing number is one token, including hex/exponent/suffix letters.
            # Never turn 0xCAFE into an identifier replacement for xCAFE.
            i += 1
            while i < len(source):
                char = source[i]
                if (char.isascii() and char.isalnum()) or char in "_.'":
                    i += 1
                elif char in "+-" and source[i - 1] in "eEpP":
                    i += 1
                else:
                    break
            continue
        elif source.startswith("\\\n", i) or source.startswith("\\\r\n", i):
            end = i + (3 if source.startswith("\\\r\n", i) else 2)
            if i and end < len(source) and (source[i - 1].isalnum() or source[i - 1] == "_") and (source[end].isalnum() or source[end] == "_"):
                raise ValueError("Line-spliced identifiers require manual simplification before mapping.")
            i = end
            continue
        elif source[i].isascii() and (source[i].isalpha() or source[i] == "_"):
            i += 1
            while i < len(source) and source[i].isascii() and (source[i].isalnum() or source[i] == "_"):
                i += 1
            identifiers.append((start, i))
            continue
        else:
            i += 1
            continue
        # A C++ user-defined literal suffix belongs to the literal, not an identifier token.
        if source[start:start + 2] not in {"//", "/*"} and i < len(source) and source[i] == "_":
            while i < len(source) and source[i].isascii() and (source[i].isalnum() or source[i] == "_"):
                i += 1
        for j in range(start, min(i, len(clean))):
            if clean[j] != "\n":
                clean[j] = " "
    return "".join(clean), identifiers


def _replace_identifiers(source, mappings):
    replacements = {m["old"]: m["new"] for m in mappings}
    _, tokens = _lex(source)
    for start, end in reversed(tokens):
        if source[start:end] in replacements:
            source = source[:start] + replacements[source[start:end]] + source[end:]
    return source


def _definitions(source):
    """Conservative file-scope definitions, not a C++ semantic parser.

    Namespace/class bodies, operators, macro-generated names, K&R parameters,
    constructor initializer lists and overloaded selections require manual
    simplification/ranges rather than guessed declaration/type reconstruction.
    """
    clean, _ = _lex(source)
    clean = re.sub(r"^[ \t]*#[^\n]*(?:\\\n[^\n]*)*", lambda m: "".join("\n" if c == "\n" else " " for c in m[0]), clean, flags=re.M)
    depths = []
    depth = 0
    for char in clean:
        depths.append(depth)
        depth += (char == "{") - (char == "}")
        if depth < 0:
            raise ValueError("Unbalanced source braces; select one complete definition.")
    if depth:
        raise ValueError("Unbalanced source braces; select one complete definition.")
    result = []
    pattern = re.compile(r"(?<![\w:~])((?:~?[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\(", re.ASCII)
    for match in pattern.finditer(clean):
        if depths[match.start()] != 0 or match[1] in {"if", "for", "while", "switch", "sizeof", "decltype", "noexcept", "__attribute__", "__declspec"}:
            continue
        parens, at = 1, match.end()
        while at < len(clean) and parens:
            parens += (clean[at] == "(") - (clean[at] == ")")
            at += 1
        if parens:
            raise ValueError("Unbalanced function parameters.")
        tail = re.compile(r"(?:\s|const\b|volatile\b|noexcept\b|override\b|final\b|&)*").match(clean, at)
        opening = tail.end()
        if opening >= len(clean) or clean[opening] != "{":
            continue
        start = match.start()
        while start and not (clean[start - 1] in ";}" and depths[start - 1] <= 1):
            start -= 1
        while start < match.start() and clean[start].isspace():
            start += 1
        prefix = clean[start:match.start()]
        if not re.fullmatch(r"[\w\s*&:<>,\[\]~]*", prefix, re.ASCII):
            continue
        nesting, end = 1, opening + 1
        while end < len(clean) and nesting:
            nesting += (clean[end] == "{") - (clean[end] == "}")
            end += 1
        if nesting:
            raise ValueError("Incomplete function body.")
        result.append((match[1], start, end))
    return result


def _choose(source, reference_name="", *, manual=False):
    definitions = _definitions(source)
    selected = [d for d in definitions if not reference_name or d[0] == reference_name
                or ("::" not in reference_name and d[0].split("::")[-1] == reference_name)]
    if len(selected) != 1:
        raise ValueError("Choose one unambiguous complete function using its name, a line range, or edited source.")
    name, start, end = selected[0]
    if manual:
        outside, _ = _lex(source[:start] + source[end:])
        if outside.strip():
            raise ValueError("Edited source must contain one definition only; put reviewed declarations in Prelude.")
    return name, source[start:end].strip()


def _forbidden_trial_source(source):
    """The existing anti-asm policy, also scanning real tokens hidden by quoted comment markers.

    Computed includes/token pasting are conservatively unsupported in submitted
    code: resolving them would require a compiler preview or guessed declarations.
    Existing project headers/build rules are not rewritten or filtered here.
    """
    from .app.forkengine import _CHEAT, _strip_comments
    clean, _ = _lex(source)
    if _CHEAT.search(_strip_comments(source)) or _CHEAT.search(clean) or "##" in clean:
        return True
    for directive in re.finditer(r"^[ \t]*#[ \t]*include\b", clean, re.M):
        end = source.find("\n", directive.end())
        tail = source[directive.end():None if end < 0 else end]
        header = re.match(r'\s*(?:/\*.*?\*/\s*)*(?:"([^"\n]+)"|<([^>\n]+)>)', tail)
        if header is None:  # no inferred macro/header expansion during source-only preview
            return True
        if (header[1] or header[2]).endswith((".s", ".S", ".asm", ".bin", ".inc.c")):
            return True
    return False


class CandidatePreparer:
    def __init__(self, net, secret=None):
        if secret is not None and (not isinstance(secret, bytes) or len(secret) < 32):
            raise ValueError("Preparation signing keys must contain at least 32 bytes.")
        self.net = net
        self.secret = secrets.token_bytes(32) if secret is None else secret
        self.context = TrialContext(net)

    def _project(self, slug):
        return self.context._project(slug)

    def targets(self, slug, query="", limit=20):
        return self._bounded(self.context.targets(slug, query, limit))

    @staticmethod
    def _check_source(row):
        if row is None or not row["enabled"] or row["stale"] or row["status"] not in {"ready", "partial"}:
            raise NetworkError("Reference is disabled, stale or not ready; refresh/enable it and prepare again.")

    @staticmethod
    def _origin(origin):
        if not isinstance(origin, dict):
            raise ValueError("Choose a reference file or metadata record.")
        if origin.get("kind") == "metadata" and set(origin) == {"kind", "record_id"}:
            if type(origin["record_id"]) is int and 0 < origin["record_id"] < 2**63:
                return
        if origin.get("kind") == "file" and set(origin) == {"kind", "source_id", "path", "content_hash"}:
            path = origin["path"]
            if (type(origin["source_id"]) is int and 0 < origin["source_id"] < 2**63
                    and isinstance(path, str) and 0 < len(path) <= 2048 and "\0" not in path
                    and isinstance(origin["content_hash"], str) and HEX.fullmatch(origin["content_hash"])):
                return
        raise ValueError("Invalid bounded reference origin.")

    def _origin_text(self, project_id, origin):
        self._origin(origin)
        if origin["kind"] == "file":
            sid = origin["source_id"]
            src = self.net.store.one("SELECT * FROM reference_sources WHERE id=? AND project_id=?", sid, project_id)
            self._check_source(src)
            if src["kind"] == "metadata":
                raise ValueError("Select the full metadata record, not its normalized retrieval projection.")
            row = self.net.store.one("SELECT text,content_hash FROM reference_files WHERE source_id=? AND path=?", sid, origin["path"])
            if row is not None:
                _text(row["text"], 512 * 1024, "Indexed reference")
            if (row is None or row["content_hash"] != origin["content_hash"]
                    or _digest(row["text"].encode()) != row["content_hash"]):
                raise NetworkError("Indexed reference changed or is corrupt; refresh and prepare again.")
            return row["text"], {"source_id": sid, "source_name": src["name"], "path": origin["path"],
                                 "content_hash": row["content_hash"], "record_id": None}
        row = self.net.store.one(
            "SELECT r.*,i.source_id FROM metadata_records r JOIN metadata_imports i ON i.id=r.import_id "
            "JOIN reference_sources s ON s.id=i.source_id WHERE r.record_id=? AND s.project_id=?",
            origin["record_id"], project_id
        )
        if row is None or row["kind"] != "function":
            raise NetworkError("Choose an existing function metadata record.")
        src = self.net.store.one("SELECT * FROM reference_sources WHERE id=? AND project_id=?", row["source_id"], project_id)
        self._check_source(src)
        record = {k: row[k] for k in ("kind", "name", "address", "unit", "signature", "comment", "pseudocode")}
        record["id"] = row["external_id"]
        try:
            record_hash = _record_hash(record)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise NetworkError("Metadata record is corrupt; refresh and prepare again.") from exc
        if record_hash != row["record_hash"]:
            raise NetworkError("Metadata record changed or is corrupt; refresh and prepare again.")
        return row["pseudocode"], {"source_id": row["source_id"], "source_name": src["name"], "record_id": row["record_id"],
                                   "content_hash": row["record_hash"], "name": row["name"]}

    def _bounded(self, result):
        if len(_canonical(result)) > MAX_RESPONSE:
            raise ValueError("Response exceeds its bound; narrow the query or candidate.")
        return result

    def files(self, slug, source_id, query="", offset=0, limit=30):
        """List private snapshot handles without opening reference files or sending text to a model."""
        if type(source_id) is not int or not 0 < source_id < 2**63:
            raise ValueError("Choose a valid source.")
        _text(query, 256, "File query")
        if type(offset) is not int or not 0 <= offset <= 1_000_000 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Choose a bounded file page.")
        project = self._project(slug)
        src = self.net.store.one("SELECT * FROM reference_sources WHERE id=? AND project_id=?", source_id, project["id"])
        self._check_source(src)
        if src["kind"] == "metadata":
            base = "FROM metadata_records r JOIN metadata_imports i ON i.id=r.import_id WHERE i.source_id=? AND r.kind='function' AND r.name LIKE ?"
            rows = self.net.store.all("SELECT r.record_id,r.name,r.record_hash,LENGTH(r.pseudocode)>0 AS has_code " + base + " ORDER BY r.record_id LIMIT ? OFFSET ?", source_id, f"%{query}%", limit, offset)
            count = self.net.store.one("SELECT COUNT(*) AS n " + base, source_id, f"%{query}%")["n"]
            files = [{"origin": {"kind": "metadata", "record_id": r["record_id"]}, "name": r["name"], "path": None,
                      "content_hash": r["record_hash"], "has_code": bool(r["has_code"])} for r in rows]
        else:
            base = "FROM reference_files WHERE source_id=? AND path LIKE ?"
            rows = self.net.store.all("SELECT path,content_hash,LENGTH(text)>0 AS has_code " + base + " ORDER BY path LIMIT ? OFFSET ?", source_id, f"%{query}%", limit, offset)
            count = self.net.store.one("SELECT COUNT(*) AS n " + base, source_id, f"%{query}%")["n"]
            files = [{"origin": {"kind": "file", "source_id": source_id, "path": r["path"], "content_hash": r["content_hash"]},
                      "name": r["path"], "path": r["path"], "content_hash": r["content_hash"], "has_code": bool(r["has_code"])} for r in rows]
        return self._bounded({"files": files, "offset": offset, "total": count, "truncated": offset + len(files) < count})

    def read_origin(self, slug, origin, start=1, count=160):
        """Show bounded indexed text; metadata uses its full pseudocode, not a retrieval projection."""
        if type(start) is not int or not 1 <= start <= 1_000_000 or type(count) is not int or not 1 <= count <= 300:
            raise ValueError("Use a bounded line range.")
        text, provenance = self._origin_text(self._project(slug)["id"], origin)
        lines = text.splitlines()
        chosen = lines[start - 1:start - 1 + count]
        selected = "\n".join(chosen)
        # Preserve part of an oversized single line rather than returning a misleading empty view.
        encoded = selected.encode()
        clipped = len(encoded) > 64 * 1024
        if clipped:
            selected = encoded[:64 * 1024].decode("utf-8", errors="ignore")
        return self._bounded({"text": selected, "start": start, "end_line": start + len(selected.splitlines()) - 1,
                              "truncated": clipped or start - 1 + len(chosen) < len(lines), "provenance": provenance})

    def prepare(self, slug, target_id, origin, reference_name="", start=None, end=None, mappings=None, source_override=None, prelude=""):
        """Extract one reviewed definition and bind it to existing target facts without building or writing."""
        _text(prelude, MAX_PRELUDE, "Prelude")
        _text(reference_name, 256, "Reference function name")
        if reference_name and not NAME.fullmatch(reference_name):
            raise ValueError("Use a plain or qualified function name; simplify unsupported operators manually.")
        if mappings is None:
            mappings = []
        if not isinstance(mappings, list) or len(mappings) > 32:
            raise ValueError("Use at most 32 explicit identifier mappings.")
        seen = set()
        for m in mappings:
            if (not isinstance(m, dict) or set(m) != {"old", "new"}
                    or any(not isinstance(m[k], str) or len(m[k]) > 256 or not IDENTIFIER.fullmatch(m[k]) for k in ("old", "new"))):
                raise ValueError("Mappings require plain C identifiers.")
            if m["old"] in seen:
                raise ValueError("Mappings must have unique source names.")
            seen.add(m["old"])
        project = self._project(slug)
        raw, provenance = self._origin_text(project["id"], origin)
        if start is not None or end is not None:
            lines = raw.splitlines()
            if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines):
                raise ValueError("Choose a complete bounded source line range.")
            raw = "\n".join(lines[start - 1:end])
        if source_override is not None:
            _text(source_override, MAX_SOURCE, "Edited source")
            raw = source_override
        _, source = _choose(raw, "" if source_override is not None else reference_name, manual=source_override is not None)
        source = _replace_identifiers(source, mappings)
        _text(source, MAX_SOURCE, "Candidate source")
        facts = self.context.capture(slug, target_id)
        definitions = _definitions(source)
        if len(definitions) != 1:
            raise ValueError("Mappings must preserve exactly one complete function definition.")
        warnings = ["Review all declarations and dependencies; no reference headers, types or build flags are imported."]
        if not any(definitions[0][0] == alias for alias in facts["target"]["compiler_names"]):
            warnings.append("Candidate does not define a verified target alias; map identifiers explicitly or edit it.")
        # Apply the SAME project anti-assembly policy, including the prelude. It is not a byte-match judge.
        if _forbidden_trial_source(source + "\n" + prelude):
            warnings.append("Assembly shortcuts, computed includes and token pasting require manual simplification in source/Prelude.")
        if "M2C_" in source + prelude:
            warnings.append("M2C placeholders/macros require manual declaration and type review.")
        ready = len(warnings) == 1 or (len(warnings) == 2 and warnings[-1].startswith("M2C"))
        now = int(time.time())
        payload = {"version": 1, "nonce": secrets.token_hex(16), "project_id": project["id"], "function_id": target_id,
                   "origin": origin, "reference_hash": provenance["content_hash"], "source_hash": _digest(source.encode()),
                   "prelude_hash": _digest(prelude.encode()), "context_hash": facts["context_hash"],
                   "db_context_hash": facts["db_context_hash"], "project_hash": facts["project_hash"],
                   "target_hash": facts["target_hash"],
                   "unit_source": facts["unit_source"], "unit_source_hash": facts["unit_source_hash"],
                   "unit_signature": facts["unit_signature"],
                   "ready": ready, "issued": now, "expires": now + TOKEN_TTL}
        context = dict(facts["context"])
        if "context_files" in context:
            context["context_file_count"] = len(context["context_files"])
            context["context_files"] = context["context_files"][:20]
        provenance.update({"start": start, "end_line": end, "manual_source": source_override is not None})
        return self._bounded({"plan": self._sign(payload), "source": source, "prelude": prelude,
                              "source_hash": payload["source_hash"], "prelude_hash": payload["prelude_hash"],
                              "ready": ready, "warnings": warnings, "target": facts["target"], "context": context,
                              "provenance": provenance})

    def _sign(self, payload):
        encoded = base64.urlsafe_b64encode(_canonical(payload)).decode().rstrip("=")
        token = encoded + "." + hmac.new(self.secret, encoded.encode(), hashlib.sha256).hexdigest()
        if len(token) > MAX_TOKEN:
            raise ValueError("Preparation plan is too large.")
        return token

    def _validate_payload(self, payload):
        if not isinstance(payload, dict) or set(payload) != KEYS:
            raise ValueError
        if type(payload["version"]) is not int or payload["version"] != 1 or type(payload["ready"]) is not bool:
            raise ValueError
        if any(type(payload[k]) is not int or not 0 < payload[k] < 2**63 for k in ("project_id", "function_id", "issued", "expires")):
            raise ValueError
        if payload["expires"] != payload["issued"] + TOKEN_TTL or payload["issued"] > time.time() + 30:
            raise ValueError
        if not isinstance(payload["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", payload["nonce"]):
            raise ValueError
        for key in ("reference_hash", "source_hash", "prelude_hash", "context_hash", "db_context_hash", "project_hash", "target_hash"):
            if not isinstance(payload[key], str) or not HEX.fullmatch(payload[key]):
                raise ValueError
        self._origin(payload["origin"])
        path = payload["unit_source"]
        if path is None:
            if payload["unit_source_hash"] is not None or payload["unit_signature"] is not None:
                raise ValueError
        elif (not isinstance(path, str) or not 0 < len(path) <= 2048 or path.startswith(("/", "\\"))
              or "\\" in path or any(p in ("", ".", "..") for p in path.split("/"))
              or not isinstance(payload["unit_source_hash"], str) or not HEX.fullmatch(payload["unit_source_hash"])
              or not isinstance(payload["unit_signature"], str) or not HEX.fullmatch(payload["unit_signature"])):
            raise ValueError

    def verify(self, slug, plan, source, prelude, *, check_current=True, allow_claim_agent_id=None, file_overrides=None, allow_expired=False, unit_context=None):
        """Check a signed plan. Crypto-only mode is for replay lookup, NEVER permission to compile.

        Admitted project checks additionally require the core's actual unit facts,
        so an mtime-cached unit cannot silently substitute a different build input.
        """
        _text(plan, MAX_TOKEN, "Preparation plan")
        _text(source, MAX_SOURCE, "Candidate source")
        _text(prelude, MAX_PRELUDE, "Prelude")
        try:
            encoded, signature = plan.split(".")
            if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded) or not HEX.fullmatch(signature):
                raise ValueError
            expected = hmac.new(self.secret, encoded.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError
            raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            if base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded:
                raise ValueError
            payload = json.loads(raw, object_pairs_hook=_object)
            self._validate_payload(payload)
            if raw != _canonical(payload):
                raise ValueError
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise NetworkError("Preparation plan is invalid; prepare again.") from None
        if not allow_expired and payload["expires"] <= time.time():
            raise NetworkError("Preparation plan expired; prepare again.")
        if payload["project_id"] != self._project(slug)["id"]:
            raise NetworkError("Preparation plan belongs to another project.")
        if payload["source_hash"] != _digest(source.encode()) or payload["prelude_hash"] != _digest(prelude.encode()):
            raise NetworkError("Candidate text changed; prepare again.")
        if file_overrides is not None:
            if not isinstance(file_overrides, dict) or set(file_overrides) - {payload["unit_source"]}:
                raise NetworkError("Only the signed target source may be overridden by an admitted trial.")
            for before in file_overrides.values():
                if not isinstance(before, str) or _digest(before.encode()) != payload["unit_source_hash"]:
                    raise NetworkError("Admitted before-text does not match the prepared source bytes.")
        if check_current:
            if payload["ready"] is not True:
                raise NetworkError("Candidate is not ready; review the warnings and prepare again.")
            if allow_claim_agent_id is not None and (not isinstance(unit_context, dict)
                    or not {"fn", "project"} <= unit_context.keys()):
                raise NetworkError("Admitted checks require actual judge unit/function/project facts before effects.")
            self.verify_db(slug, payload, allow_claim_agent_id=allow_claim_agent_id)
            try:
                current = self.context.capture(slug, payload["function_id"], allow_claim_agent_id, file_overrides)
            except ReferenceContextError as exc:
                raise NetworkError(f"Prepared target context changed: {exc}") from exc
            if unit_context is not None:
                try:
                    if "project" in unit_context:
                        actual_project = unit_context["project"]
                        if _project_fingerprint(actual_project) != payload["project_hash"]:
                            raise ValueError
                        if _target_fingerprint(unit_context["fn"], actual_project) != payload["target_hash"]:
                            raise ValueError
                    if payload["unit_source"] is not None:
                        root = self._project(slug)["root"]
                        signature = _unit_fingerprint(unit_context["unit"], root)
                        path = unit_context["path"].resolve(strict=True)
                        expected_path = (Path(root) / payload["unit_source"]).resolve(strict=True)
                        if signature != payload["unit_signature"] or path != expected_path:
                            raise ValueError
                    elif unit_context.get("context") is not None:
                        header = unit_context["context"]
                        if (header["version"] != current["context"]["header_version"]
                                or _digest(header["header"].encode()) != current["context"]["header_hash"]):
                            raise ValueError
                except (ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
                    raise NetworkError("Actual judge unit/source or compiler/function context differs from preparation.") from exc
            for key in ("context_hash", "target_hash", "db_context_hash", "project_hash", "unit_source", "unit_source_hash", "unit_signature"):
                if current[key] != payload[key]:
                    raise NetworkError("Target source or build context changed; prepare again.")
        return payload

    def verify_db(self, slug, payload, *, allow_claim_agent_id=None, db=None):
        """Pure DB recheck inside the recorder's existing Store.tx (never open a new tx)."""
        # Store.one/all automatically use the writer on the current tx thread.
        project = self._project(slug)
        if payload["project_id"] != project["id"]:
            raise NetworkError("Project changed during trial.")
        _, provenance = self._origin_text(project["id"], payload["origin"])
        if provenance["content_hash"] != payload["reference_hash"]:
            raise NetworkError("Reference snapshot changed during trial.")
        try:
            facts = self.context.capture_db(slug, payload["function_id"], allow_claim_agent_id)
        except ReferenceContextError as exc:
            raise NetworkError(f"Target context changed during trial: {exc}") from exc
        if any(facts[k] != payload[k] for k in ("target_hash", "db_context_hash", "project_hash")):
            raise NetworkError("Target/compiler/header context changed during trial.")
