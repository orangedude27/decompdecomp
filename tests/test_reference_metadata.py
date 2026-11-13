from __future__ import annotations

import hashlib
import json
import re
from types import SimpleNamespace

import pytest

from decompnet.app.engine import RomNetwork
from decompnet.app.forkengine import ForkEngine
from decompnet.network import Agent, NetworkError
from decompnet.reference_metadata import ReferenceMetadata, parse_metadata
from decompnet.references import References
from decompnet.store import Store

SCHEMA = "decompdecomp.reference-metadata"


def document(**updates):
    value = {
        "schema": SCHEMA,
        "version": 1,
        "kind": "symbols",
        "build": None,
        "records": [
            {
                "id": "f-1",
                "kind": "function",
                "name": "external_fn",
                "address": "0x1000",
                "unit": "src/a.c",
                "signature": "int external_fn(void)",
                "comment": "note",
                "pseudocode": "",
            }
        ],
    }
    value.update(updates)
    return value


def encoded(value):
    return json.dumps(value).encode()


def _metadata_fixture(tmp_path, config, records, *, functions=(), symbols=()):
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = Store(tmp_path / "metadata-fixture.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('game',?,?)", (str(tmp_path), json.dumps(config)))
        for function_id, name, unit, address, size, meta in functions:
            db.execute(
                "INSERT INTO functions(id,project_id,name,unit,vram,size,meta) VALUES(?,1,?,?,?,?,?)",
                (function_id, name, unit, address, size, json.dumps(meta)),
            )
        for name, address, size, kind in symbols:
            db.execute(
                "INSERT INTO symbols(project_id,name,address,size,kind) VALUES(1,?,?,?,?)",
                (name, address, size, kind),
            )
    path = tmp_path / "metadata.json"
    path.write_bytes(encoded(document(records=records)))
    service = ReferenceMetadata(store)
    imported = service.import_file("game", str(path), hashlib.sha256(path.read_bytes()).hexdigest())
    listed = service.records("game", imported["import"]["id"])["records"]
    return store, service, imported, listed


def test_parse_metadata_and_optional_fields():
    meta, records = parse_metadata(encoded(document(records=[{"id": "d", "kind": "data", "name": "external"}])))
    assert meta == {"kind": "symbols", "build": None}
    assert records[0]["address"] is None and records[0]["unit"] == ""


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema":"decompdecomp.reference-metadata","schema":"duplicate","version":1,"kind":"symbols","records":[]}',
        encoded(document(version=True)),
        encoded(document(kind=[])),
        encoded(document(extra=True)),
        encoded(document(build={"kind": [], "value": "0" * 40})),
        encoded(document(records=[{"id": "x", "kind": [], "name": "n"}])),
        encoded(document(build={"kind": "rom_sha1", "value": "0" * 39})),
        encoded(document(records=[{"id": "x", "kind": "function", "name": "n", "address": -1}])),
        encoded(document(records=[{"id": "x", "kind": "function", "name": "n", "address": True}])),
        encoded(document(records=[{"id": "x", "kind": "function", "name": "n", "address": "0x" + "f" * 17}])),
        encoded(
            document(records=[{"id": "x", "kind": "function", "name": "n"}, {"id": "x", "kind": "data", "name": "m"}])
        ),
        *[
            encoded(document(records=[{"id": "x", "kind": "function", "name": "n", key: "x" * (limit + 1)}]))
            for key, limit in (
                ("id", 128),
                ("name", 256),
                ("unit", 512),
                ("signature", 1024),
                ("comment", 4096),
                ("pseudocode", 16384),
            )
        ],
        b"{} trailing",
        b"\xff",
        b'{"schema":"decompdecomp.reference-metadata","version":1,"kind":"symbols","records":[],"build":'
        + b"[" * 5000
        + b"0"
        + b"]" * 5000
        + b"}",
        b'{"schema":"decompdecomp.reference-metadata","version":' + b"9" * 5000 + b',"kind":"symbols","records":[]}',
    ],
)
def test_rejects_malformed_or_ambiguous_metadata(raw):
    with pytest.raises(ValueError):
        parse_metadata(raw)


def test_rejects_record_and_file_bounds():
    with pytest.raises(ValueError, match="comment"):
        parse_metadata(encoded(document(records=[{"id": "x", "kind": "function", "name": "n", "comment": "x" * 4097}])))
    with pytest.raises(ValueError, match="2 MiB"):
        parse_metadata(b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="at most 2000"):
        parse_metadata(
            encoded(document(records=[{"id": str(i), "kind": "function", "name": "n"} for i in range(2001)]))
        )


def test_preview_import_privacy_hash_guard_and_projection(tmp_path):
    store = Store(tmp_path / "metadata.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES(?,?,?)", ("game", str(tmp_path), '{"kind":"rom"}'))
    service = ReferenceMetadata(store)
    assert service.builds("game") == [] and service.targets("game")["targets"] == []
    with pytest.raises(NetworkError, match="no longer exists"):
        service.targets("missing")
    file = tmp_path / "symbols.json"
    file.write_bytes(encoded(document()))
    preview = service.preview("game", str(file))
    assert preview["identity_status"] == "unknown" and preview["record_count"] == 1
    assert store.one("SELECT 1 FROM reference_sources") is None
    file.write_text(encoded(document(records=[])).decode())
    with pytest.raises(NetworkError, match="changed after preview"):
        service.import_file("game", str(file), preview["content_hash"])
    file.write_bytes(encoded(document()))
    imported = service.import_file("game", str(file), hashlib.sha256(file.read_bytes()).hexdigest())
    source, imp = imported["source"], imported["import"]
    assert source["kind"] == "metadata" and source["agent_access"] is False and source["enabled"]
    assert source["id"] == imp["source_id"] and imp["name"] == "symbols.json"
    root_row = store.one("SELECT root FROM reference_sources WHERE id=?", source["id"])
    projection = store.one("SELECT path FROM reference_files WHERE source_id=?", source["id"])
    assert root_row is not None and root_row["root"] == ""
    assert projection is not None and projection["path"] == "entries/000001.txt"
    assert service.records("game", imp["id"])["records"][0]["status"] == "unbound"
    reopened_store = Store(tmp_path / "metadata.sqlite")
    reopened = ReferenceMetadata(reopened_store)
    assert reopened.records("game", imp["id"])["total"] == 1
    References(store).remove("game", source["id"])
    assert store.one("SELECT 1 FROM metadata_imports WHERE id=?", imp["id"]) is None
    assert store.one("SELECT 1 FROM metadata_records WHERE import_id=?", imp["id"]) is None
    assert store.one("SELECT 1 FROM reference_files WHERE source_id=?", source["id"]) is None
    store.conn.close()
    reopened_store.conn.close()


def test_local_file_read_rejects_symlink_and_nonregular_paths(tmp_path):
    file = tmp_path / "metadata.json"
    file.write_text(encoded(document()).decode())
    link = tmp_path / "linked.json"
    link.symlink_to(file)
    with pytest.raises(ValueError, match="read safely"):
        ReferenceMetadata._read(str(link))
    with pytest.raises(ValueError, match="regular"):
        ReferenceMetadata._read(str(tmp_path))


@pytest.mark.parametrize("mode", ["rom", "project"])
def test_explicit_apply_guard_and_stale_recheck(tmp_path, mode):
    store = Store(tmp_path / f"{mode}.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('game',?,'{}')", (str(tmp_path),))
        db.execute("INSERT INTO functions(id,project_id,name,size,unit,vram) VALUES(1,1,'original',4,'unit.c',4096)")
    file = tmp_path / "metadata.json"
    file.write_bytes(
        encoded(
            document(
                records=[
                    {"id": "f1", "kind": "function", "name": "external_fn"},
                    {"id": "f2", "kind": "function", "name": "external_fn2"},
                    {"id": "f3", "kind": "function", "name": "external_fn3"},
                    {"id": "f4", "kind": "function", "name": "external_fn4"},
                    {"id": "f5", "kind": "function", "name": "external_fn5"},
                    {"id": "f6", "kind": "function", "name": "external_fn6"},
                    {"id": "f7", "kind": "function", "name": "external_fn7"},
                ]
            )
        )
    )
    service = ReferenceMetadata(store)
    imported = service.import_file("game", str(file), hashlib.sha256(file.read_bytes()).hexdigest())
    records = service.records("game", imported["import"]["id"])["records"]
    service.map_record("game", records[0]["record_id"], {"kind": "function", "id": 1}, "approved_name")
    original = store.one("SELECT name FROM functions WHERE id=1")
    assert original is not None and original["name"] == "original"

    class FakeNet:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            assert slug == "game" and (old, new) == ("original", "approved_name")
            with store.tx() as db:
                precondition(db)
                db.execute("UPDATE functions SET name=? WHERE id=1", (new,))
            return "✅ guarded rename"

    service.net = FakeNet()
    applied = service.apply("game", records[0]["record_id"])
    assert applied["record"]["status"] == "applied"
    updated = store.one("SELECT name FROM functions WHERE id=1")
    assert updated is not None and updated["name"] == "approved_name"

    stale = service.map_record("game", records[1]["record_id"], {"kind": "function", "id": 1}, "second_name")
    assert stale["status"] == "pending"
    with store.tx() as db:
        db.execute("UPDATE functions SET size=8 WHERE id=1")
    with pytest.raises(NetworkError, match="target or project build changed"):
        service.apply("game", records[1]["record_id"])
    assert service.records("game", imported["import"]["id"])["records"][1]["status"] == "error"

    race = service.map_record("game", records[2]["record_id"], {"kind": "function", "id": 1}, "race_name")
    assert race["status"] == "pending"

    class RacingNet:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                db.execute("UPDATE functions SET size=99 WHERE id=1")
                precondition(db)
            raise AssertionError("stale proposal must stop before rename")

    service.net = RacingNet()
    with pytest.raises(NetworkError, match="target or project build changed"):
        service.apply("game", records[2]["record_id"])
    current = store.one("SELECT name,size FROM functions WHERE id=1")
    assert current is not None and tuple(current) == ("approved_name", 8)
    assert service.records("game", imported["import"]["id"])["records"][2]["status"] == "error"

    service.map_record("game", records[3]["record_id"], {"kind": "function", "id": 1}, "ghost_name")

    class NoopNet:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            return "✅ misleading success"

    service.net = NoopNet()
    with pytest.raises(NetworkError, match="without changing"):
        service.apply("game", records[3]["record_id"])
    assert service.records("game", imported["import"]["id"])["records"][3]["status"] == "error"
    current_name = store.one("SELECT name FROM functions WHERE id=1")
    assert current_name is not None and current_name["name"] == "approved_name"

    service.map_record("game", records[4]["record_id"], {"kind": "function", "id": 1}, "commit_then_disable")

    class DisableAfterCommit:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                precondition(db)
                db.execute("UPDATE functions SET name=? WHERE id=1", (new,))
            References(store).enabled("game", imported["source"]["id"], False)
            return "guard declined after the project rename"

    service.net = DisableAfterCommit()
    result = service.apply("game", records[4]["record_id"])
    assert result["record"]["status"] == "applied"
    current_name = store.one("SELECT name FROM functions WHERE id=1")
    assert current_name is not None and current_name["name"] == "commit_then_disable"

    References(store).enabled("game", imported["source"]["id"], True)
    service.map_record("game", records[6]["record_id"], {"kind": "function", "id": 1}, "integrity_guard")

    class CorruptRecordNet:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                db.execute(
                    "UPDATE metadata_records SET proposed_name='db_tampered' WHERE record_id=?",
                    (records[6]["record_id"],),
                )
                precondition(db)
            raise AssertionError("tampered proposal must fail before rename")

    service.net = CorruptRecordNet()
    with pytest.raises(NetworkError, match="record or mapping changed"):
        service.apply("game", records[6]["record_id"])
    assert store.one("SELECT name FROM functions WHERE id=1")["name"] == "commit_then_disable"
    assert service.records("game", imported["import"]["id"])["records"][6]["status"] == "error"

    References(store).enabled("game", imported["source"]["id"], True)
    service.map_record("game", records[5]["record_id"], {"kind": "function", "id": 1}, "removed_source_commit")

    class RemoveAfterCommit:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                precondition(db)
                db.execute("UPDATE functions SET name=? WHERE id=1", (new,))
            References(store).remove("game", imported["source"]["id"])
            return "done"

    service.net = RemoveAfterCommit()
    with pytest.raises(NetworkError, match="committed.*do not apply it again"):
        service.apply("game", records[5]["record_id"])
    current_name = store.one("SELECT name FROM functions WHERE id=1")
    assert current_name is not None and current_name["name"] == "removed_source_commit"
    store.conn.close()


@pytest.mark.parametrize("existing_real", [None, "FriendlyOld"])
def test_pc_report_preserving_rename_verifies_real_name_and_keeps_report_identity(tmp_path, existing_real):
    report_name = "func_00401000"
    meta = {"symbol": report_name}
    if existing_real:
        meta["real"] = existing_real
    store, service, imported, records = _metadata_fixture(
        tmp_path,
        {"kind": "project", "platform": "pc", "version": "v1"},
        [{"id": "f", "kind": "function", "name": "external_name"}],
        functions=(
            (1, report_name, "src/a.c", 0x401000, 16, meta),
            (2, "func_00402000", "src/b.c", 0x402000, 16, {"symbol": "func_00402000", "real": "occupied_real"}),
        ),
    )
    record = records[0]
    listed = service.targets("game", existing_real or report_name)["targets"]
    first = next(target for target in listed if target["target"]["id"] == 1)
    if existing_real:
        assert first["name"] == f"{existing_real} (report: {report_name})"
        assert first["report_name"] == report_name
    else:
        assert first["name"] == report_name and first["report_name"] is None
    mapped = service.map_record("game", record["record_id"], {"kind": "function", "id": 1}, "new_real")
    assert mapped["target"]["name"] == report_name
    snapshot = store.one(
        "SELECT old_name,target_name,target_original FROM metadata_records WHERE record_id=?", record["record_id"]
    )
    assert snapshot is not None
    assert tuple(snapshot) == (existing_real or report_name, report_name, report_name)
    with pytest.raises(NetworkError, match="conflicts"):
        service.map_record("game", record["record_id"], {"kind": "function", "id": 1}, "occupied_real")

    class PcRename:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            assert (old, new) == (existing_real or report_name, "new_real")
            with store.tx() as db:
                precondition(db)
                current = db.execute("SELECT meta FROM functions WHERE id=1").fetchone()
                current_meta = json.loads(current["meta"])
                current_meta["real"] = new
                db.execute("UPDATE functions SET meta=? WHERE id=1", (json.dumps(current_meta),))
            if existing_real:
                raise NetworkError("commit message failed after sync")
            return "✅ rename completed"

    service.net = PcRename()
    result = service.apply("game", record["record_id"])
    assert result["record"]["status"] == "applied"
    current = store.one("SELECT name,meta FROM functions WHERE id=1")
    assert current is not None and current["name"] == report_name
    current_meta = json.loads(current["meta"])
    assert current_meta["symbol"] == report_name and current_meta["real"] == "new_real"
    store.conn.close()


def test_pc_fake_success_and_different_function_identity_are_not_confirmed(tmp_path):
    report_name = "func_00401000"
    store, service, _imported, records = _metadata_fixture(
        tmp_path,
        {"kind": "project", "platform": "pc"},
        [{"id": "f", "kind": "function", "name": "external_name"}],
        functions=((1, report_name, "src/a.c", 0x401000, 16, {"symbol": report_name}),),
    )
    service.map_record("game", records[0]["record_id"], {"kind": "function", "id": 1}, "new_real")

    class Noop:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            return "✅ fake success"

    service.net = Noop()
    with pytest.raises(NetworkError, match="without changing"):
        service.apply("game", records[0]["record_id"])
    assert service.records("game", _imported["import"]["id"])["records"][0]["status"] == "error"
    store.conn.close()

    store, service, _imported, records = _metadata_fixture(
        tmp_path / "replacement",
        {"kind": "project", "platform": "pc"},
        [{"id": "f", "kind": "function", "name": "external_name"}],
        functions=((1, report_name, "src/a.c", 0x401000, 16, {"symbol": report_name}),),
    )
    service.map_record("game", records[0]["record_id"], {"kind": "function", "id": 1}, "new_real")

    class Replacement:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                precondition(db)
                db.execute("DELETE FROM functions WHERE id=1")
                db.execute(
                    "INSERT INTO functions(id,project_id,name,unit,vram,size,meta) VALUES(2,1,?,?,?,?,?)",
                    (report_name, "src/a.c", 0x401000, 16, json.dumps({"symbol": report_name, "real": new})),
                )
            return "✅ replacement, not the selected function"

    service.net = Replacement()
    with pytest.raises(NetworkError, match="without changing"):
        service.apply("game", records[0]["record_id"])
    assert service.records("game", _imported["import"]["id"])["records"][0]["status"] == "error"
    store.conn.close()


def test_pc_target_size_change_is_rejected_before_rename(tmp_path):
    report_name = "func_00401000"
    store, service, imported, records = _metadata_fixture(
        tmp_path,
        {"kind": "project", "platform": "pc"},
        [{"id": "f", "kind": "function", "name": "external_name"}],
        functions=((1, report_name, "src/a.c", 0x401000, 16, {"symbol": report_name, "real": "old_real"}),),
    )
    service.map_record("game", records[0]["record_id"], {"kind": "function", "id": 1}, "new_real")
    with store.tx() as db:
        db.execute("UPDATE functions SET size=20 WHERE id=1")

    class UnexpectedRename:
        links = {}

        def rename_symbol(self, *args, **kwargs):
            raise AssertionError("stale target must fail before the rename seam")

    service.net = UnexpectedRename()
    with pytest.raises(NetworkError, match="target or project build changed"):
        service.apply("game", records[0]["record_id"])
    current = store.one("SELECT name,meta FROM functions WHERE id=1")
    assert current is not None and current["name"] == report_name and json.loads(current["meta"])["real"] == "old_real"
    assert service.records("game", imported["import"]["id"])["records"][0]["status"] == "error"
    store.conn.close()


def test_rom_data_postcheck_uses_selected_symbol_identity_and_size(tmp_path):
    store, service, imported, records = _metadata_fixture(
        tmp_path,
        {"kind": "rom", "platform": "n64"},
        [{"id": "d", "kind": "data", "name": "external_data", "address": "0x1000"}],
        symbols=(("D_original", 0x1000, 8, "data"),),
    )
    service.map_record("game", records[0]["record_id"], {"kind": "symbol", "name": "D_original"}, "D_renamed")
    row = store.one("SELECT * FROM metadata_records WHERE record_id=?", records[0]["record_id"])
    selected = store.one("SELECT rowid FROM symbols WHERE name='D_original'")
    assert row is not None and selected is not None
    assert row["target_original"] == str(selected["rowid"])

    class RomRename:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                precondition(db)
                db.execute("UPDATE symbols SET name=? WHERE rowid=?", (new, int(row["target_original"])))
            return "✅ renamed selected ROM symbol"

    service.net = RomRename()
    applied = service.apply("game", records[0]["record_id"])
    assert applied["record"]["status"] == "applied"
    assert store.one("SELECT rowid FROM symbols WHERE name='D_renamed'")["rowid"] == selected["rowid"]
    store.conn.close()


def test_rom_data_replacement_and_size_conflict_do_not_confirm_rename(tmp_path):
    store, service, imported, records = _metadata_fixture(
        tmp_path,
        {"kind": "rom", "platform": "n64"},
        [{"id": "d", "kind": "data", "name": "external_data", "address": "0x1000"}],
        symbols=(("D_original", 0x1000, 8, "data"),),
    )
    service.map_record("game", records[0]["record_id"], {"kind": "symbol", "name": "D_original"}, "D_renamed")
    row = store.one("SELECT * FROM metadata_records WHERE record_id=?", records[0]["record_id"])
    assert row is not None

    class Replacement:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                precondition(db)
                db.execute("DELETE FROM symbols WHERE rowid=?", (int(row["target_original"]),))
                db.execute(
                    "INSERT INTO symbols(rowid,project_id,name,address,size,kind) VALUES(?,1,?,?,?,?)",
                    (int(row["target_original"]) + 100, new, 0x1000, 8, "data"),
                )
            return "✅ different symbol"

    service.net = Replacement()
    with pytest.raises(NetworkError, match="without changing"):
        service.apply("game", records[0]["record_id"])
    assert service.records("game", imported["import"]["id"])["records"][0]["status"] == "error"
    store.conn.close()

    store, service, imported, records = _metadata_fixture(
        tmp_path / "size-conflict",
        {"kind": "rom", "platform": "n64"},
        [{"id": "d", "kind": "data", "name": "external_data", "address": "0x1000"}],
        symbols=(("D_original", 0x1000, 8, "data"),),
    )
    service.map_record("game", records[0]["record_id"], {"kind": "symbol", "name": "D_original"}, "D_renamed")
    with store.tx() as db:
        db.execute("UPDATE symbols SET size=12 WHERE name='D_original'")

    class UnexpectedRename:
        links = {}

        def rename_symbol(self, *args, **kwargs):
            raise AssertionError("stale symbol size must fail before the rename seam")

    service.net = UnexpectedRename()
    with pytest.raises(NetworkError, match="target or project build changed"):
        service.apply("game", records[0]["record_id"])
    current = store.one("SELECT name,size FROM symbols WHERE name='D_original'")
    assert current is not None and tuple(current) == ("D_original", 12)
    assert service.records("game", imported["import"]["id"])["records"][0]["status"] == "error"
    store.conn.close()


def test_rom_postrename_size_change_is_committed_with_layout_warning(tmp_path):
    store, service, _imported, records = _metadata_fixture(
        tmp_path,
        {"kind": "rom", "platform": "n64"},
        [{"id": "d", "kind": "data", "name": "external_data", "address": "0x1000"}],
        symbols=(("D_original", 0x1000, 8, "data"),),
    )
    service.map_record("game", records[0]["record_id"], {"kind": "symbol", "name": "D_original"}, "D_renamed")
    mapped = store.one("SELECT * FROM metadata_records WHERE record_id=?", records[0]["record_id"])

    class RenameAndGrow:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                precondition(db)
                db.execute("UPDATE symbols SET name=?,size=12 WHERE rowid=?", (new, int(mapped["target_original"])))
            return "✅ renamed"

    service.net = RenameAndGrow()
    applied = service.apply("game", records[0]["record_id"])
    assert applied["record"]["status"] == "applied"
    assert "layout changed" in applied["record"]["error"]
    assert service._target_renamed(1, mapped) is False
    assert service._target_renamed(1, mapped, check_size=False) is True
    store.conn.close()


def test_listing_recomputes_build_identity_and_unrelated_config_does_not_stale_proposal(tmp_path):
    store = Store(tmp_path / "build-snapshot.sqlite")
    first_build = "a" * 40
    with store.tx() as db:
        db.execute(
            "INSERT INTO projects(slug,root,config) VALUES('game',?,?)",
            (
                str(tmp_path),
                json.dumps(
                    {
                        "kind": "project",
                        "platform": "pc",
                        "version": "v1",
                        "program_sha1": first_build,
                        "claim_order": "old",
                    }
                ),
            ),
        )
        db.execute("INSERT INTO functions(id,project_id,name,size,unit,vram) VALUES(1,1,'original',4,'unit.c',4096)")
    file = tmp_path / "build.json"
    file.write_bytes(encoded(document(build={"kind": "program_sha1", "value": first_build})))
    service = ReferenceMetadata(store)
    imported = service.import_file("game", str(file), hashlib.sha256(file.read_bytes()).hexdigest())
    assert service.listing("game")["imports"][0]["identity_status"] == "match"
    changed = json.dumps(
        {"kind": "project", "platform": "pc", "version": "v1", "program_sha1": "b" * 40, "claim_order": "old"}
    )
    with store.tx() as db:
        db.execute("UPDATE projects SET config=? WHERE slug='game'", (changed,))
    listing = service.listing("game")["imports"][0]
    assert listing["identity_status"] == "mismatch" and listing["warnings"]
    record = service.records("game", imported["import"]["id"])["records"][0]
    service.map_record("game", record["record_id"], {"kind": "function", "id": 1}, "approved_name")
    unrelated = json.dumps(
        {
            "kind": "project",
            "platform": "pc",
            "version": "v1",
            "program_sha1": "b" * 40,
            "claim_order": "new",
            "title": "changed",
        }
    )
    with store.tx() as db:
        db.execute("UPDATE projects SET config=? WHERE slug='game'", (unrelated,))

    class FakeNet:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                precondition(db)
                current = db.execute("SELECT name,meta FROM functions WHERE id=1").fetchone()
                meta = json.loads(current["meta"] or "{}")
                meta.setdefault("symbol", current["name"])
                meta["real"] = new
                db.execute("UPDATE functions SET meta=? WHERE id=1", (json.dumps(meta),))
            return "✅ verified"

    service.net = FakeNet()
    assert service.apply("game", record["record_id"])["record"]["status"] == "applied"
    store.conn.close()


def test_interrupted_application_recovers_fail_closed(tmp_path):
    store = Store(tmp_path / "recovery.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('game',?,'{}')", (str(tmp_path),))
        db.execute(
            "INSERT INTO reference_sources(project_id,name,root,kind,status) VALUES(1,'meta','', 'metadata','ready')"
        )
        db.execute(
            "INSERT INTO metadata_imports(source_id,kind,build,identity_status,record_count,content_hash,imported_at) "
            "VALUES(1,'symbols','null','unknown',1,'hash',0)"
        )
        db.execute(
            "INSERT INTO metadata_records(import_id,external_id,kind,name,unit,signature,comment,pseudocode,record_hash,status) "
            "VALUES(1,'external','function','fn','','','','','hash','applying')"
        )
    service = ReferenceMetadata(store)
    record = service.records("game", 1)["records"][0]
    assert record["status"] == "error" and "interrupted" in record["error"]
    store.conn.close()


def test_rom_rename_rechecks_stale_layout_inside_final_transaction(tmp_path):
    net = RomNetwork(tmp_path / "rom.sqlite", tmp_path)
    net.progress.sync = lambda *_args, **_kwargs: None
    with net.store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('rom',?,'{\"kind\":\"rom\"}')", (str(tmp_path),))
        db.execute(
            "INSERT INTO functions(id,project_id,name,size,n_insns,unit,vram,status) "
            "VALUES(1,1,'old_name',4,1,'unit.c',4096,'open')"
        )
        db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(1,'old_name',4096,4,'func')")
        db.execute("INSERT INTO context_versions(project_id,version,header,unit) VALUES(1,1,'','')")
    calls = []

    def stale_during_regression(*_args, **_kwargs):
        with net.store.tx() as db:
            db.execute("UPDATE functions SET size=8 WHERE id=1")
        return []

    net.regression_test = stale_during_regression

    def precondition(db):
        calls.append(db.in_transaction)
        current = db.execute("SELECT size FROM functions WHERE id=1").fetchone()
        if current["size"] != 4:
            raise NetworkError("target changed before final rename transaction")

    with pytest.raises(NetworkError, match="target changed"):
        net.rename_symbol(Agent(1, "owner", None), "rom", "old_name", "new_name", precondition=precondition)
    assert calls == [True]
    assert net.store.one("SELECT name FROM symbols WHERE project_id=1")["name"] == "old_name"
    assert net.store.one("SELECT name,size FROM functions WHERE id=1")["name"] == "old_name"
    net.store.conn.close()


def test_fork_rename_late_precondition_restores_project_source(tmp_path, monkeypatch):
    store = Store(tmp_path / "fork-seam.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(id,slug,root,config) VALUES(1,'fork',?,'{}')", (str(tmp_path),))
        db.execute(
            "INSERT INTO functions(id,project_id,name,size,unit,vram,status) "
            "VALUES(1,1,'old_name',4,'src/main.c',4096,'open')"
        )
    source = tmp_path / "src" / "main.c"
    source.parent.mkdir()
    original_source = "void old_name(void);\n"
    source.write_text(original_source)
    fp = SimpleNamespace(root=tmp_path, manifest={}, setup_commands=lambda _version: [])

    def report():
        with store.tx() as db:
            db.execute("UPDATE functions SET size=8 WHERE id=1")
        return {"units": [{"functions": [{"name": "new_name", "fuzzy_match_percent": 100}]}]}

    fp.report = report
    project = {"id": 1, "root": str(tmp_path)}
    console = SimpleNamespace(
        features=set(), renames_in_report=True, rename_pattern=lambda old: rf"\b{re.escape(old)}\b"
    )

    def console_rename(_fp, _version, old, new):
        before = source.read_text()
        source.write_text(re.sub(rf"\b{re.escape(old)}\b", new, before))
        return {source: before}

    console.rename_symbol = console_rename
    monkeypatch.setattr("decompnet.app.forkengine.consoles.get", lambda _platform: console)
    net = SimpleNamespace(store=store, links={}, _event=lambda *_args: None)
    engine = ForkEngine(net)
    engine.get = lambda _slug: (project, fp, {"platform": "stub", "version": "v1"})
    engine._meta = lambda _row: {}
    engine._commit_paths = lambda *_args: None
    calls = []

    def precondition(db):
        calls.append(True)
        size = db.execute("SELECT size FROM functions WHERE id=1").fetchone()["size"]
        if size != 4:
            raise NetworkError("The target changed during project rename.")

    with pytest.raises(NetworkError, match="target changed"):
        engine.rename_symbol(None, "fork", "old_name", "new_name", precondition=precondition)
    assert len(calls) == 2
    assert source.read_text() == original_source
    current = store.one("SELECT name,size FROM functions WHERE id=1")
    assert current is not None and tuple(current) == ("old_name", 8)
    store.conn.close()


def test_verified_rom_symbol_mapping_is_explicit_and_guarded(tmp_path):
    store = Store(tmp_path / "rom-symbol.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('rom',?,'{\"kind\":\"rom\"}')", (str(tmp_path),))
        db.execute("INSERT INTO symbols(project_id,name,address,size,kind) VALUES(1,'D_1000',4096,4,'data')")
    file = tmp_path / "data.json"
    file.write_bytes(
        encoded(document(records=[{"id": "d-1", "kind": "data", "name": "external_data", "address": "0x1000"}]))
    )
    service = ReferenceMetadata(store)
    imported = service.import_file("rom", str(file), hashlib.sha256(file.read_bytes()).hexdigest())
    target = service.targets("rom")["targets"][0]
    assert target["target"] == {"kind": "symbol", "name": "D_1000"}
    record = service.records("rom", imported["import"]["id"])["records"][0]
    service.map_record("rom", record["record_id"], target["target"], "g_external")
    unchanged = store.one("SELECT name FROM symbols WHERE project_id=1")
    assert unchanged is not None and unchanged["name"] == "D_1000"

    class FakeRom:
        links = {}

        def rename_symbol(self, agent, slug, old, new, message, *, precondition):
            with store.tx() as db:
                precondition(db)
                db.execute("UPDATE symbols SET name=? WHERE project_id=1 AND name=?", (new, old))
            return "✅ guarded ROM rename"

    service.net = FakeRom()
    applied = service.apply("rom", record["record_id"])
    assert applied["record"]["status"] == "applied"
    renamed = store.one("SELECT name FROM symbols WHERE project_id=1")
    assert renamed is not None and renamed["name"] == "g_external"
    store.conn.close()


def test_unsigned_64bit_address_round_trips_as_text(tmp_path):
    store = Store(tmp_path / "address.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('game',?,'{}')", (str(tmp_path),))
    file = tmp_path / "max-address.json"
    file.write_bytes(
        encoded(document(records=[{"id": "max", "kind": "data", "name": "wide", "address": "0xFFFFFFFFFFFFFFFF"}]))
    )
    service = ReferenceMetadata(store)
    preview = service.preview("game", str(file))
    imported = service.import_file("game", str(file), hashlib.sha256(file.read_bytes()).hexdigest())
    row = store.one("SELECT address FROM metadata_records WHERE import_id=?", imported["import"]["id"])
    assert row is not None and row["address"] == "0xFFFFFFFFFFFFFFFF"
    record = service.records("game", imported["import"]["id"])["records"][0]
    projection = store.one("SELECT text FROM reference_files WHERE source_id=?", imported["source"]["id"])
    assert record["address"] == "0xFFFFFFFFFFFFFFFF"
    assert projection is not None and "0xFFFFFFFFFFFFFFFF" in projection["text"]
    assert preview["records"][0]["address"] == "0xFFFFFFFFFFFFFFFF"
    store.conn.close()


def test_preview_and_record_pages_respect_json_response_budget(tmp_path):
    store = Store(tmp_path / "response-limit.sqlite")
    with store.tx() as db:
        db.execute("INSERT INTO projects(slug,root,config) VALUES('game',?,'{}')", (str(tmp_path),))
    service = ReferenceMetadata(store)
    records = [
        {
            "id": f"unicode-{i}",
            "kind": "function",
            "name": "n" + "🧭" * 100,
            "signature": "s" * 1024,
            "comment": "🧭" * 4096,
            "pseudocode": "🧭" * 4096,
        }
        for i in range(50)
    ]
    file = tmp_path / "unicode.json"
    file.write_text(json.dumps(document(records=records), ensure_ascii=False), encoding="utf-8")
    preview = service.preview("game", str(file))
    assert len(json.dumps(preview, ensure_ascii=True, separators=(",", ":")).encode()) <= 256 * 1024
    assert preview["truncated"] and any(item["truncated_fields"] for item in preview["records"])
    imported = service.import_file("game", str(file), hashlib.sha256(file.read_bytes()).hexdigest())
    page = service.records("game", imported["import"]["id"], limit=50)
    serialized = json.dumps(page, ensure_ascii=True, separators=(",", ":")).encode()
    assert len(serialized) <= 256 * 1024
    assert page["truncated"] and len(page["records"]) < 50
    assert all("comment" in item["truncated_fields"] and item["text_truncated"] for item in page["records"])
    store.conn.close()


def test_rom_and_fork_rename_dispatch_preserves_optional_precondition():
    from decompnet.app.engine.editing import EditMixin

    calls = []
    hook = lambda db: None
    agent = object()

    class FakeEngine:
        def fork_slug(self, slug):
            return None

        def _project(self, slug):
            return {"id": 1, "kind": "rom"}

        def is_rom(self, project):
            return True

        def _link(self, slug):
            return None

        def rename_symbols(self, agent, slug, pairs, message, *, precondition=None):
            calls.append(("rom", precondition))
            return "✅ guarded"

    assert EditMixin.rename_symbol(FakeEngine(), agent, "rom", "old", "new", precondition=hook) == "✅ guarded"
    assert calls == [("rom", hook)]

    class FakeForks:
        def rename_symbol(self, agent, slug, old, new, message, *, precondition=None):
            calls.append(("fork", precondition))
            return "✅ guarded fork"

    class ForkEngineDispatch:
        forks = FakeForks()

        def fork_slug(self, slug):
            return "fork-project"

    assert (
        EditMixin.rename_symbol(ForkEngineDispatch(), agent, "fork-project", "old", "new", precondition=hook)
        == "✅ guarded fork"
    )
    assert calls[-1] == ("fork", hook)
