import base64
import hashlib
import json
import time

import pytest

from decompnet.forks.project import ForkProject
from decompnet.network import NetworkError
from decompnet.reference_candidates import (
    MAX_PRELUDE,
    MAX_SOURCE,
    CandidatePreparer,
    _definitions,
    _replace_identifiers,
)
from decompnet.reference_metadata import _record_hash

from .test_reference_context import dump, make_net


def setup(tmp_path, kind="rom", text="int original(void) { return 7; }\n"):
    net, root = make_net(tmp_path, kind)
    digest = hashlib.sha256(text.encode()).hexdigest()
    with net.store.tx() as db:
        db.execute("INSERT INTO reference_sources(id,project_id,name,root,kind,enabled,status,agent_access) VALUES(1,1,'Private reference','/never/read/me','file',1,'ready',0)")
        db.execute("INSERT INTO reference_files(source_id,path,text,content_hash) VALUES(1,'code.cpp',?,?)", (text, digest))
    origin = {"kind": "file", "source_id": 1, "path": "code.cpp", "content_hash": digest}
    return net, root, CandidatePreparer(net, secret=b"k" * 32), origin


def preview(preparer, origin, **kwargs):
    return preparer.prepare("game", 1, origin, mappings=[{"old": "original", "new": "func"}], **kwargs)


def verify(preparer, result, **kwargs):
    return preparer.verify("game", result["plan"], result["source"], result["prelude"], **kwargs)


@pytest.mark.parametrize("kind", ["rom", "fork"])
def test_prepare_verify_have_no_db_file_claim_agent_or_subprocess_effects(tmp_path, kind, monkeypatch):
    net, root, preparer, origin = setup(tmp_path, kind)
    before_db = dump(net)
    before_files = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    def forbidden(*_args, **_kwargs):
        pytest.fail("preview invoked a mutating/compiler/agent helper")
    for name in ("_project", "sync", "compile", "local_agent", "try_quietly"):
        setattr(net, name, forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    net.forks = type("ForbiddenForks", (), {"get": forbidden, "attempt": forbidden})()
    result = preview(preparer, origin)
    assert result["ready"] and result["source"] == "int func(void) { return 7; }"
    assert verify(preparer, result)["ready"]
    assert dump(net) == before_db
    assert before_files == {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert not (root / ".decomp-wtf").exists()
    assert net.store.one("SELECT agent_access FROM reference_sources")[0] == 0


def test_explicit_mapping_preserves_comments_escaped_and_raw_literals():
    code = 'int old(void) { /* old } */ const char *s = R"xx(old " } old)xx"; return old + "old\\\"old"; } // old\n'
    changed = _replace_identifiers(code, [{"old": "old", "new": "new"}])
    assert changed.startswith("int new(void)") and "return new +" in changed
    assert 'R"xx(old " } old)xx"' in changed and "/* old } */" in changed
    assert changed.endswith("// old\n")
    assert len(_definitions(changed)) == 1


@pytest.mark.parametrize("text", ["INCLUDE_ASM(func);", "int original(void) {", "int original(int x){}\nint original(float x){}", "int a(void){}\nint b(void){}", "int original(void);", "namespace X { int original(void){} }"])
def test_ambiguous_stub_incomplete_or_unsupported_extraction_is_rejected(tmp_path, text):
    _, _, preparer, origin = setup(tmp_path, text=text)
    with pytest.raises(ValueError):
        preview(preparer, origin)


def test_named_and_explicit_range_selection_and_manual_override(tmp_path):
    text = "int helper(void){return 0;}\nint original(void){return 1;}\n"
    _, _, preparer, origin = setup(tmp_path, text=text)
    assert preview(preparer, origin, reference_name="original")["source"] == "int func(void){return 1;}"
    assert preview(preparer, origin, start=2, end=2)["ready"]
    assert preview(preparer, origin, source_override="int original(void){return 2;}")["ready"]
    with pytest.raises(ValueError, match="one definition"):
        preview(preparer, origin, source_override="typedef int T; int original(void){}")
    with pytest.raises(ValueError):
        preview(preparer, origin, source_override="int original(void){} int extra(void){}")


def test_no_implicit_alias_or_constructor_rename(tmp_path):
    net, _, preparer, origin = setup(tmp_path)
    assert not preparer.prepare("game", 1, origin)["ready"]
    result = preview(preparer, origin, source_override="Other::Other() {}")
    assert not result["ready"]
    assert net.store.one("SELECT name FROM functions WHERE id=1")[0] == "func"


@pytest.mark.parametrize("part", ["source", "prelude"])
def test_assembly_is_not_ready_in_either_input(tmp_path, part):
    _, _, preparer, origin = setup(tmp_path)
    kwargs = {"source_override": 'int original(void) { asm("nop"); }'} if part == "source" else {"prelude": 'asm("nop");'}
    result = preview(preparer, origin, **kwargs)
    assert not result["ready"] and any("Assembly" in w for w in result["warnings"])


@pytest.mark.parametrize("field,value", [("prelude", "x" * (MAX_PRELUDE + 1)), ("source_override", "x" * (MAX_SOURCE + 1)), ("reference_name", []), ("start", True)])
def test_bad_or_oversized_inputs_fail_without_claims(tmp_path, field, value):
    net, _, preparer, origin = setup(tmp_path)
    with pytest.raises(ValueError):
        preview(preparer, origin, **{field: value})
    assert not net.store.all("SELECT * FROM claims")


def test_mapping_never_rewrites_numbers_literal_prefixes_suffixes_or_spliced_comments():
    code = 'int old(){ int xCAFE=1; double e3=2; float f=3; return 0xCAFE + xCAFE + 1e3 + e3 + 1.0f + f; }\n'
    maps = [{"old": a, "new": b} for a, b in [("old", "func"), ("xCAFE", "value"), ("e3", "expvalue"), ("f", "floatvalue")]]
    result = _replace_identifiers(code, maps)
    assert '0xCAFE + value + 1e3 + expvalue + 1.0f + floatvalue' in result
    literal = 'L"old" u8"old" u\'x\' "old"_suffix L u8 _suffix old'
    maps = [{"old": name, "new": "changed"} for name in ("L", "u8", "_suffix", "old")]
    assert _replace_identifiers(literal, maps) == 'L"old" u8"old" u\'x\' "old"_suffix changed changed changed changed'
    comment = '// old \\\nold\nold'
    assert _replace_identifiers(comment, [{"old": "old", "new": "new"}]) == '// old \\\nold\nnew'
    with pytest.raises(ValueError, match="spliced identifiers"):
        _replace_identifiers('old\\\nname', [{"old": "old", "new": "new"}])


@pytest.mark.parametrize("prelude", [
    'const char *url="http://host"; __asm("nop");',
    '#include "asm//original.inc.c"',
    '#define HEADER "original.h"\n#include HEADER',
    '#define JOIN(a,b) a ## b',
])
def test_assembly_or_unresolved_preprocessor_cannot_hide_behind_literals(tmp_path, prelude):
    _, _, preparer, origin = setup(tmp_path)
    result = preview(preparer, origin, prelude=prelude)
    assert not result["ready"]
    with pytest.raises(NetworkError, match="not ready"):
        verify(preparer, result)


def test_bad_mappings_rejected_before_project_access():
    preparer = CandidatePreparer(None)
    with pytest.raises(ValueError, match="identifiers"):
        preparer.prepare("x", 1, {}, mappings=[{"old": "bad-name", "new": "fine"}])


@pytest.mark.parametrize("change", ["source", "prelude", "signature", "project"])
def test_signed_plan_cannot_be_rebound(tmp_path, change):
    net, _, preparer, origin = setup(tmp_path)
    result = preview(preparer, origin)
    if change == "source":
        result["source"] += " "
    elif change == "prelude":
        result["prelude"] += " "
    elif change == "signature":
        result["plan"] = result["plan"][:-1] + ("1" if result["plan"][-1] != "1" else "2")
    else:
        with net.store.tx() as db:
            db.execute("INSERT INTO projects(id,slug,root,config) VALUES(2,'other','.',?)", ('{"kind":"rom"}',))
        with pytest.raises(NetworkError, match="another project"):
            preparer.verify("other", result["plan"], result["source"], result["prelude"])
        return
    with pytest.raises(NetworkError):
        verify(preparer, result)


@pytest.mark.parametrize("field,value", [("version", True), ("ready", 1), ("function_id", True), ("source_hash", 0), ("nonce", []), ("extra", 1), ("unit_source", "../escape"), ("expires", 1)])
def test_even_signed_malformed_payloads_fail_strict_schema(tmp_path, field, value):
    _, _, preparer, origin = setup(tmp_path)
    result = preview(preparer, origin)
    payload = verify(preparer, result, check_current=False)
    payload[field] = value
    result["plan"] = preparer._sign(payload)
    with pytest.raises(NetworkError, match="invalid"):
        verify(preparer, result, check_current=False)


def test_expiry_replay_checks_and_new_admission_rules(tmp_path, monkeypatch):
    _, _, preparer, origin = setup(tmp_path)
    result = preview(preparer, origin)
    payload = verify(preparer, result)
    monkeypatch.setattr(time, "time", lambda: payload["expires"] + 1)
    with pytest.raises(NetworkError, match="expired"):
        verify(preparer, result)
    assert verify(preparer, result, check_current=False, allow_expired=True)["nonce"] == payload["nonce"]
    assert verify(preparer, result, allow_expired=True)["nonce"] == payload["nonce"]


@pytest.mark.parametrize("change", ["enabled=0", "stale=1", "status='indexing'"])
def test_reference_revocation_invalidates_preview_and_db_guard(tmp_path, change):
    net, _, preparer, origin = setup(tmp_path)
    result = preview(preparer, origin)
    payload = verify(preparer, result)
    with net.store.tx() as db:
        db.execute("UPDATE reference_sources SET " + change)
        with pytest.raises(NetworkError):
            preparer.verify_db("game", payload, db=db)
    with pytest.raises(NetworkError):
        verify(preparer, result)


def test_context_change_and_corrupt_snapshot_fail_closed(tmp_path):
    net, _, preparer, origin = setup(tmp_path)
    result = preview(preparer, origin)
    with net.store.tx() as db:
        db.execute("UPDATE context_versions SET header='different'")
    with pytest.raises(NetworkError, match="context changed"):
        verify(preparer, result)
    result = preview(preparer, origin)
    with net.store.tx() as db:
        db.execute("UPDATE reference_files SET text='changed without hash'")
    with pytest.raises(NetworkError, match="corrupt"):
        verify(preparer, result)


def test_private_file_listing_pagination_and_clipped_long_line(tmp_path):
    _, _, preparer, origin = setup(tmp_path, text="x" * 70000)
    page = preparer.files("game", 1)
    assert page["total"] == 1 and page["files"][0]["origin"] == origin
    result = preparer.read_origin("game", origin)
    assert result["truncated"] and len(result["text"].encode()) == 65536
    assert preparer.files("game", 1, offset=1)["files"] == []
    with pytest.raises(ValueError):
        preparer.files("game", True)


def test_metadata_reads_full_immutable_pseudocode_not_normalized_projection(tmp_path):
    net, _, preparer, _ = setup(tmp_path)
    pseudocode = "int original(void){\n" + "/* full pseudocode */\n" * 180 + "return 1;\n}"
    record = {"id": "external", "kind": "function", "name": "original", "address": None, "unit": "", "signature": "int original(void)", "comment": "", "pseudocode": pseudocode}
    with net.store.tx() as db:
        db.execute("UPDATE reference_sources SET kind='metadata'")
        db.execute("INSERT INTO metadata_imports(id,source_id,kind,identity_status,record_count,content_hash,imported_at) VALUES(1,1,'ghidra','unknown',1,'hash',0)")
        db.execute("INSERT INTO metadata_records(record_id,import_id,external_id,kind,name,unit,signature,comment,pseudocode,record_hash) VALUES(1,1,'external','function','original','',?,'',?,?)", (record["signature"], pseudocode, _record_hash(record)))
    origin = {"kind": "metadata", "record_id": 1}
    assert preparer.files("game", 1)["total"] == 1
    result = preview(preparer, origin)
    assert result["ready"] and result["source"].count("full pseudocode") == 180
    assert verify(preparer, result)
    with net.store.tx() as db:
        db.execute("UPDATE metadata_records SET pseudocode='tampered'")
    with pytest.raises(NetworkError, match="corrupt"):
        verify(preparer, result)


def test_project_file_override_and_final_db_check_do_not_scan_files(tmp_path, monkeypatch):
    net, root, preparer, origin = setup(tmp_path, "fork")
    result = preview(preparer, origin)
    payload = verify(preparer, result)
    before = (root / "src/unit.cpp").read_bytes().decode()
    (root / "src/unit.cpp").write_text("int func(void){return 7;}")
    with pytest.raises(NetworkError, match="context changed"):
        verify(preparer, result)
    assert verify(preparer, result, file_overrides={"src/unit.cpp": before})
    monkeypatch.setattr(preparer.context, "capture", lambda *_a, **_k: pytest.fail("full scan in final recorder"))
    with net.store.tx() as db:
        preparer.verify_db("game", payload, db=db)
        db.execute("UPDATE context_versions SET header='new header'")
        with pytest.raises(NetworkError, match="context changed"):
            preparer.verify_db("game", payload, db=db)


@pytest.mark.parametrize("field", ["source", "target", "base", "scratch", "options", "mappings", "complete"])
def test_actual_cached_judge_unit_must_equal_fresh_prepared_unit(tmp_path, field):
    net, root, preparer, origin = setup(tmp_path, "fork")
    fp = ForkProject(root, read_only=True)
    stale_unit = fp.unit("unit")
    config = root / "objdiff.json"
    data = json.loads(config.read_text())
    unit = data["units"][0]
    if field == "source":
        unit["metadata"]["source_path"] = "src/next.cpp"
        (root / "src/next.cpp").write_bytes((root / "src/unit.cpp").read_bytes())
    elif field == "target":
        unit["target_path"] = "expected/next.o"
        (root / "expected/next.o").write_bytes((root / "expected/unit.o").read_bytes())
    elif field == "base":
        unit["base_path"] = "build/different.o"
    elif field == "scratch":
        unit["scratch"] = {"compiler": "different"}
    elif field == "options":
        unit["options"] = {"diff_obj": "changed"}
    elif field == "mappings":
        unit["symbol_mappings"] = {"func": "different"}
    else:
        unit["metadata"]["complete"] = True
    config.write_text(json.dumps(data))
    result = preview(preparer, origin)  # Fresh raw parsing, unlike stale_unit.
    assert verify(preparer, result)
    with pytest.raises(NetworkError, match="Actual judge unit/source"):
        verify(preparer, result, unit_context={"unit": stale_unit, "path": root / "src/unit.cpp"})


def test_invalid_context_and_metadata_are_caught_not_unchecked_json_calls(tmp_path):
    net, _, preparer, origin = setup(tmp_path)
    with net.store.tx() as db:
        db.execute("UPDATE projects SET config='{'")
    with pytest.raises(ValueError, match="configuration is invalid"):
        preview(preparer, origin)
    with net.store.tx() as db:
        db.execute("UPDATE projects SET config=?", ('{"kind":"rom","compiler":{"cmd":["never-run"]}}',))
        db.execute("UPDATE functions SET meta='{'")
    with pytest.raises(ValueError, match="aliases"):
        preview(preparer, origin)


def test_signed_not_ready_plan_is_never_current_admission_permission(tmp_path):
    _, _, preparer, origin = setup(tmp_path)
    result = preparer.prepare("game", 1, origin)  # No explicit target-name mapping.
    assert not result["ready"]
    assert verify(preparer, result, check_current=False)["ready"] is False  # Replay identity only.
    with pytest.raises(NetworkError, match="not ready"):
        verify(preparer, result)


def test_admitted_project_checks_require_actual_core_unit_facts(tmp_path):
    _, _, preparer, origin = setup(tmp_path, "fork")
    result = preview(preparer, origin)
    with pytest.raises(NetworkError, match="actual judge unit"):
        verify(preparer, result, allow_claim_agent_id=9)


def test_private_override_must_match_signed_original_bytes(tmp_path):
    _, _, preparer, origin = setup(tmp_path, "fork")
    result = preview(preparer, origin)
    with pytest.raises(NetworkError, match="before-text"):
        verify(preparer, result, file_overrides={"src/unit.cpp": "different"})
    with pytest.raises(NetworkError, match="signed target"):
        verify(preparer, result, file_overrides={"include/types.h": "different"})


def test_read_only_constructor_and_token_bounds(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    ForkProject(root, read_only=True)
    assert not (root / ".decomp-wtf").exists()
    preparer = CandidatePreparer(None, secret=b"k" * 32)
    token = preparer._sign({"test": 1})
    assert json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "==")) == {"test": 1}
    with pytest.raises(ValueError, match="too large"):
        preparer._sign({"data": "x" * 32768})
