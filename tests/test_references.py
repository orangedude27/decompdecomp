from __future__ import annotations

import hashlib
import os
import threading

import pytest

from decompnet.network import NetworkError
from decompnet.references import References
from decompnet.store import Store


@pytest.fixture
def refs(tmp_path):
    store = Store(tmp_path / "data.sqlite")
    with store.tx() as db:
        for slug, kind in (("rom", "rom"), ("project", "project"), ("other", "rom")):
            db.execute(
                "INSERT INTO projects(slug,root,config) VALUES(?,?,?)", (slug, str(tmp_path), '{"kind":"' + kind + '"}')
            )
    yield store, References(store), tmp_path
    store.conn.close()


def test_index_snapshot_hash_search_enabled_remove_and_cascade(refs):
    store, service, root = refs
    folder = root / "sources"
    folder.mkdir()
    (folder / "main.cpp").write_text("first\nStraße needle\nlast\n")
    (folder / ".git").mkdir()
    (folder / ".git" / "hidden.cpp").write_text("needle")
    source = service.add("rom", str(folder))
    assert "root" not in source and str(folder) not in str(source)
    indexed = service.refresh("rom", source["id"])
    assert indexed["status"] == "ready" and indexed["file_count"] == 1
    row = store.one("SELECT content_hash FROM reference_files WHERE source_id=?", source["id"])
    assert row["content_hash"] == hashlib.sha256((folder / "main.cpp").read_bytes()).hexdigest()
    hit = service.search("rom", "STRASSE")["results"][0]
    assert hit["line"] == 2 and hit["end_line"] == 2 and hit["path"] == "main.cpp"
    assert service.search("rom", "")["results"] == []
    service.enabled("rom", source["id"], False)
    assert service.search("rom", "needle")["results"] == []
    service.enabled("rom", source["id"], True)
    service.remove("rom", source["id"])
    assert (folder / "main.cpp").exists()
    assert store.one("SELECT 1 FROM reference_files WHERE source_id=?", source["id"]) is None


@pytest.mark.parametrize("slug", ["rom", "project"])
def test_filesystem_root_is_rejected_without_disclosing_its_path(refs, slug):
    store, service, root = refs
    with pytest.raises(ValueError, match="not an entire filesystem root") as error:
        service.add(slug, root.anchor)
    assert str(error.value) == "Choose a reference folder, not an entire filesystem root."
    assert store.one("SELECT COUNT(*) n FROM reference_sources")["n"] == 0


@pytest.mark.parametrize("text,query,expected", [("alpha NEEDLE", "needle", 1), ("ß" * 1000, "absent", 0)])
def test_search_avoids_per_character_offset_maps_when_not_needed(refs, monkeypatch, text, query, expected):
    store, service, root = refs
    file = root / "efficient.txt"
    file.write_text(text, encoding="utf-8")
    source = service.add("rom", str(file))
    service.refresh("rom", source["id"])
    original_all = store.all

    class TextWithoutOffsetMap(str):
        def __iter__(self):
            raise AssertionError("ASCII and nonmatching files do not need per-character offset maps")

    def rows_with_checked_text(sql, *args):
        rows = original_all(sql, *args)
        if "JOIN reference_files" in sql:
            return [dict(row) | {"text": TextWithoutOffsetMap(row["text"])} for row in rows]
        return rows

    monkeypatch.setattr(store, "all", rows_with_checked_text)
    assert len(service.search("rom", query)["results"]) == expected


def test_project_scoping_modes_and_config_untouched(refs):
    store, service, root = refs
    (root / "ref.txt").write_text("unique")
    source = service.add("rom", str(root / "ref.txt"))
    service.refresh("rom", source["id"])
    assert service.search("project", "unique")["results"] == []
    with pytest.raises(NetworkError):
        service.source("other", source["id"])
    assert store.one("SELECT config FROM projects WHERE slug='rom'")["config"] == '{"kind":"rom"}'
    assert store.one("SELECT config FROM projects WHERE slug='project'")["config"] == '{"kind":"project"}'


def test_failure_preserves_but_excludes_last_good_snapshot_and_sanitizes(refs, monkeypatch):
    store, service, root = refs
    folder = root / "private-root"
    folder.mkdir()
    (folder / "a.txt").write_text("needle")
    source = service.add("rom", str(folder))
    service.refresh("rom", source["id"])
    monkeypatch.setattr(service, "_scan", lambda *_: (_ for _ in ()).throw(OSError(str(folder))))
    with pytest.raises(RuntimeError):
        service.refresh("rom", source["id"])
    assert store.one("SELECT COUNT(*) n FROM reference_files WHERE source_id=?", source["id"])["n"] == 1
    assert service.search("rom", "needle")["results"] == []
    info = service.sources("rom")[0]
    assert info["status"] == "error" and info["stale"] and str(folder) not in (info["error"] or "")


def test_cancel_preserves_snapshot_and_releases_refresh_guard(refs):
    store, service, root = refs
    folder = root / "cancel"
    folder.mkdir()
    (folder / "a.txt").write_text("needle")
    source = service.add("rom", str(folder))
    service.refresh("rom", source["id"])

    def cancel():
        raise RuntimeError("operation was cancelled")

    with pytest.raises(RuntimeError):
        service.refresh("rom", source["id"], cancel)
    assert service.sources("rom")[0]["status"] == "cancelled"
    assert store.one("SELECT COUNT(*) n FROM reference_files WHERE source_id=?", source["id"])["n"] == 1
    assert service.refresh("rom", source["id"])["status"] == "ready"


def test_stale_hits_during_refresh_duplicate_rejection_and_remove_race(refs, monkeypatch):
    _, service, root = refs
    folder = root / "slow"
    folder.mkdir()
    (folder / "a.txt").write_text("needle")
    source = service.add("rom", str(folder))
    service.refresh("rom", source["id"])
    entered, release = threading.Event(), threading.Event()
    original = service._scan

    def slow(*args):
        entered.set()
        release.wait(5)
        return original(*args)

    monkeypatch.setattr(service, "_scan", slow)
    thread = threading.Thread(target=lambda: service.refresh("rom", source["id"]))
    thread.start()
    assert entered.wait(2)
    assert service.search("rom", "needle")["results"][0]["stale"] is True
    with pytest.raises(NetworkError):
        service.refresh("rom", source["id"])
    service.remove("rom", source["id"])
    release.set()
    thread.join(5)
    assert not thread.is_alive() and service.sources("rom") == []


def test_limits_binary_symlink_and_result_bounds(refs, monkeypatch):
    store, service, root = refs
    folder = root / "bounded"
    folder.mkdir()
    (folder / "text.txt").write_text("needle " * 60)
    (folder / "bad.c").write_bytes(b"\x00needle")
    (folder / "unsupported.py").write_text("needle")
    source = service.add("rom", str(folder))
    monkeypatch.setattr("decompnet.references.MAX_RESULTS", 7)
    service.refresh("rom", source["id"])
    result = service.search("rom", "needle")
    assert len(result["results"]) == 7 and result["truncated"]
    assert all(len(hit["excerpt"]) <= 600 for hit in result["results"])
    with pytest.raises(ValueError):
        service.search("rom", "q" * 1001)
    assert store.one("SELECT COUNT(*) n FROM reference_files WHERE source_id=?", source["id"])["n"] == 1
    alias = root / "alias"
    alias.symlink_to(folder, target_is_directory=True)
    with pytest.raises(ValueError):
        service.add("rom", str(alias / "text.txt"))


def test_scan_limits_file_bytes_source_bytes_files_entries_and_sources(refs, monkeypatch):
    _, service, root = refs
    folder = root / "limits"
    folder.mkdir()
    (folder / "a.txt").write_text("1234")
    (folder / "b.txt").write_text("5678")
    source = service.add("rom", str(folder))
    monkeypatch.setattr("decompnet.references.MAX_FILE_BYTES", 3)
    assert service.refresh("rom", source["id"])["status"] == "partial"
    assert service.sources("rom")[0]["file_count"] == 0
    monkeypatch.setattr("decompnet.references.MAX_FILE_BYTES", 10)
    monkeypatch.setattr("decompnet.references.MAX_SOURCE_BYTES", 5)
    assert service.refresh("rom", source["id"])["status"] == "partial"
    assert service.sources("rom")[0]["byte_count"] == 4
    monkeypatch.setattr("decompnet.references.MAX_SOURCE_BYTES", 100)
    monkeypatch.setattr("decompnet.references.MAX_SOURCE_FILES", 1)
    assert service.refresh("rom", source["id"])["status"] == "partial"
    assert service.sources("rom")[0]["file_count"] == 1
    monkeypatch.setattr("decompnet.references.MAX_SOURCE_FILES", 20)
    monkeypatch.setattr("decompnet.references.MAX_VISITED_ENTRIES", 1)
    assert service.refresh("rom", source["id"])["status"] == "partial"
    monkeypatch.setattr("decompnet.references.MAX_SOURCES", 1)
    with pytest.raises(ValueError):
        service.add("rom", str(folder))


def test_fifo_and_symlink_children_are_never_read(refs):
    _, service, root = refs
    folder = root / "special"
    folder.mkdir()
    (folder / "target.txt").write_text("safe")
    (folder / "link.txt").symlink_to(folder / "target.txt")
    if hasattr(os, "mkfifo"):
        os.mkfifo(folder / "pipe.txt")
    source = service.add("rom", str(folder))
    result = service.refresh("rom", source["id"])
    assert result["status"] == "partial" and result["file_count"] == 1
    assert service.search("rom", "safe")["results"][0]["path"] == "target.txt"


def test_atomic_publish_failure_and_missing_root_keep_snapshot(refs):
    store, service, root = refs
    file = root / "stable.txt"
    file.write_text("kept")
    source = service.add("rom", str(file))
    service.refresh("rom", source["id"])
    with store.tx() as db:
        db.execute(
            "CREATE TRIGGER reject_reference_update BEFORE INSERT ON reference_files BEGIN SELECT RAISE(FAIL,'database failed'); END"
        )
    file.write_text("replacement")
    with pytest.raises(RuntimeError):
        service.refresh("rom", source["id"])
    assert store.one("SELECT text FROM reference_files WHERE source_id=?", source["id"])["text"] == "kept"
    with store.tx() as db:
        db.execute("DROP TRIGGER reject_reference_update")
    file.unlink()
    with pytest.raises(RuntimeError):
        service.refresh("rom", source["id"])
    assert store.one("SELECT text FROM reference_files WHERE source_id=?", source["id"])["text"] == "kept"


def test_crashed_indexing_recovers_and_schema_cascades(refs):
    store, service, root = refs
    file = root / "stable.txt"
    file.write_text("kept")
    source = service.add("rom", str(file))
    service.refresh("rom", source["id"])
    path = root / "data.sqlite"
    store.conn.execute("UPDATE reference_sources SET status='indexing',stale=1 WHERE id=?", (source["id"],))
    store.conn.close()
    reopened = Store(path)
    recovered = reopened.one("SELECT status,stale,error FROM reference_sources WHERE id=?", source["id"])
    assert recovered is not None and recovered["status"] == "error" and recovered["stale"] == 1
    with reopened.tx() as db:
        db.execute("DELETE FROM projects WHERE slug='rom'")
    remaining = reopened.one("SELECT COUNT(*) n FROM reference_sources")
    assert remaining is not None and remaining["n"] == 0
    reopened.conn.close()


def test_metadata_reference_refresh_is_rejected(refs):
    store, service, root = refs
    pid = service.project("rom")
    with store.tx() as db:
        cursor = db.execute(
            "INSERT INTO reference_sources(project_id,name,root,kind,status) VALUES(?,?,?,?,?)",
            (pid, "metadata", "", "metadata", "ready"),
        )
    with pytest.raises(NetworkError, match="importing the JSON"):
        service.refresh("rom", cursor.lastrowid)


def test_agent_access_is_private_by_default_and_can_be_revoked(refs):
    _, service, root = refs
    file = root / "private.txt"
    file.write_text("first\nneedle café\nlast\n", encoding="utf-8")
    source = service.add("rom", str(file))
    assert source["agent_access"] is False
    service.refresh("rom", source["id"])
    private_search = service.agent_search("rom", "needle")
    assert private_search["truncated"] is False and "No matching text." in private_search["text"]
    assert "UNTRUSTED REFERENCE DATA" in private_search["text"]
    source = service.agent_access("rom", source["id"], True)
    assert source["agent_access"] is True
    result = service.agent_search("rom", "needle")
    assert "LINES: 2-2" in result["text"] and "UNTRUSTED REFERENCE DATA" in result["text"]
    handle = result["text"].split("FILE_ID: ", 1)[1].split("\n", 1)[0]
    read = service.agent_read("rom", handle)
    assert "SOURCE: private.txt" in read and "SHA256:" in read and "first\nneedle café\nlast" in read
    service.enabled("rom", source["id"], False)
    assert service.agent_search("rom", "needle")["truncated"] is False
    with pytest.raises(NetworkError):
        service.agent_read("rom", handle)
    service.enabled("rom", source["id"], True)
    service.agent_access("rom", source["id"], False)
    with pytest.raises(NetworkError):
        service.agent_read("rom", handle)
    with pytest.raises(ValueError):
        service.agent_access("rom", source["id"], 1)


def test_agent_reference_handles_are_hash_bound_and_project_scoped(refs):
    import base64
    import json

    store, service, root = refs
    file = root / "same.txt"
    file.write_text("needle")
    source = service.add("rom", str(file))
    service.refresh("rom", source["id"])
    service.agent_access("rom", source["id"], True)
    handle = service.agent_search("rom", "needle")["text"].split("FILE_ID: ", 1)[1].split("\n", 1)[0]
    with pytest.raises(NetworkError):
        service.agent_read("project", handle)
    forged = base64.urlsafe_b64encode(json.dumps([source["id"], "same.txt", "0" * 64]).encode()).decode().rstrip("=")
    with pytest.raises(NetworkError):
        service.agent_read("rom", forged)
    with pytest.raises(NetworkError):
        service.agent_read("rom", "%%%")
    file.write_text("changed on disk")
    assert "needle" in service.agent_read("rom", handle)
    with store.tx() as db:
        db.execute("UPDATE reference_sources SET stale=1 WHERE id=?", (source["id"],))
    with pytest.raises(NetworkError):
        service.agent_read("rom", handle)


def test_agent_reference_budgets_and_validation(refs):
    _, service, root = refs
    file = root / "long.txt"
    file.write_text("x" * 20000 + "needle\n" + "z" * 20000)
    source = service.add("rom", str(file))
    service.refresh("rom", source["id"])
    service.agent_access("rom", source["id"], True)
    result = service.agent_search("rom", "needle")
    assert len(result["text"]) <= 16000
    handle = result["text"].split("FILE_ID: ", 1)[1].split("\n", 1)[0]
    assert len(service.agent_read("rom", handle, count=200)) <= 16000
    for start, count in ((0, 1), (1, True), (1, 201)):
        with pytest.raises(ValueError):
            service.agent_read("rom", handle, start, count)


def test_agent_search_casefold_maps_both_match_endpoints_and_multiline_source(refs):
    _, service, root = refs
    path = root / "unicode.txt"
    path.write_text("before\nStraße\nafter\n", encoding="utf-8")
    source = service.add("rom", str(path))
    service.refresh("rom", source["id"])
    service.agent_access("rom", source["id"], True)
    result = service.agent_search("rom", "STRASSE")
    assert "LINES: 2-2" in result["text"]
    assert "Straße" in result["text"]
    assert "before\nafter" not in result["text"]
    assert len(result["text"]) <= 16000


def test_agent_search_budget_marker_and_omitted_hit_are_inside_budget(refs):
    _, service, root = refs
    path = root / "needle.txt"
    path.write_text("needle")
    source = service.add("rom", str(path))
    service.refresh("rom", source["id"])
    service.agent_access("rom", source["id"], True)
    second = root / "second.txt"
    second.write_text("needle again")
    second_source = service.add("rom", str(second))
    service.refresh("rom", second_source["id"])
    service.agent_access("rom", second_source["id"], True)
    result = service.agent_search("rom", "needle", limit=1)
    assert len(result["text"]) <= 16000
    assert result["truncated"] is True and "[Truncated; narrow the query.]" in result["text"]
    assert "FILE_ID:" in result["text"] and "UNTRUSTED REFERENCE DATA" in result["text"]


def test_agent_read_bounds_line_range_and_rejects_deep_or_invalid_handles(refs):
    import base64

    _, service, root = refs
    path = root / "many.txt"
    path.write_text("line\n" * 250, encoding="utf-8")
    source = service.add("rom", str(path))
    service.refresh("rom", source["id"])
    service.agent_access("rom", source["id"], True)
    result = service.agent_search("rom", "line")
    handle = result["text"].split("FILE_ID: ", 1)[1].split("\n", 1)[0]
    page = service.agent_read("rom", handle, count=200)
    assert len(page) <= 16000 and "LINES: 1-200" in page and "Truncated" in page
    nested = base64.urlsafe_b64encode(("[" * 1100 + "0" + "]" * 1100).encode()).decode().rstrip("=")
    with pytest.raises(NetworkError, match="invalid"):
        service.agent_read("rom", nested)
    invalid_shape = base64.urlsafe_b64encode(b'{"source":1}').decode().rstrip("=")
    with pytest.raises(NetworkError, match="invalid"):
        service.agent_read("rom", invalid_shape)


def test_agent_search_reports_matched_but_omitted_when_provenance_cannot_fit(refs):
    store, service, root = refs
    path = root / "huge-provenance.txt"
    path.write_text("needle")
    source = service.add("rom", str(path))
    service.refresh("rom", source["id"])
    service.agent_access("rom", source["id"], True)
    with store.tx() as db:
        db.execute("UPDATE reference_sources SET name=? WHERE id=?", ("n" * 8000, source["id"]))
        db.execute("UPDATE reference_files SET path=? WHERE source_id=?", ("p" * 8000, source["id"]))
    result = service.agent_search("rom", "needle")
    assert result["truncated"] is True
    assert len(result["text"]) <= 16000
    assert "Matches omitted due to the output budget" in result["text"]


def test_agent_search_fetches_only_bounded_ordered_pages(refs, monkeypatch):
    store, service, root = refs
    for index in range(18):
        path = root / f"source-{index:02}.txt"
        path.write_text("needle")
        source = service.add("rom", str(path))
        service.refresh("rom", source["id"])
        service.agent_access("rom", source["id"], True)
    original_all = store.all
    pages = []

    def checked_pages(sql, *args):
        if "s.agent_access=1" in sql:
            assert "LIMIT 16" in sql
            page = original_all(sql, *args)
            assert len(page) <= 16
            pages.append(page)
            return page
        return original_all(sql, *args)

    monkeypatch.setattr(store, "all", checked_pages)
    result = service.agent_search("rom", "needle", limit=20)
    assert len(pages) >= 2
    assert "FILE_ID:" in result["text"] and len(result["text"]) <= 16000
