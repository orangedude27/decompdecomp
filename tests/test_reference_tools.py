from __future__ import annotations

import pytest

from decompnet.app import tools
from decompnet.network import NetworkError


class StoreStub:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def all(self, sql, *args):
        self.calls.append((sql, args))
        if len(args) == 4:
            return self.rows[:16]
        return []

    def one(self, sql, *args):
        if "FROM projects" in sql:
            return {"id": 1}
        if "JOIN reference_files" in sql:
            for row in self.rows:
                if row["id"] == args[0] and row["path"] == args[-1]:
                    return row
        return None


def test_reference_tools_are_read_only_offered_in_both_modes_and_api_schemas():
    from decompnet.agents.api import api_tool_schemas

    for fork in (False, True):
        names = tools.tool_names(fork)
        assert "search_references" in names and "read_reference" in names
        assert {item["function"]["name"] for item in api_tool_schemas(fork)} >= {"search_references", "read_reference"}
    assert {"search_references", "read_reference"} <= getattr(tools, "READ_ONLY")
    assert callable(tools.HANDLERS["search_references"])
    assert callable(tools.HANDLERS["read_reference"])


def test_agent_reference_handlers_return_untrusted_plain_text_and_validate_arguments(monkeypatch):
    class Service:
        def __init__(self, _store):
            pass

        def agent_search(self, slug, query, limit):
            if type(limit) is not int:
                raise ValueError("limit must be integer")
            return {"text": "UNTRUSTED reference\n[Truncated; narrow the query.]", "truncated": True}

        def agent_read(self, *args):
            return "UNTRUSTED snapshot"

    monkeypatch.setattr(tools, "References", Service)
    net = type("Net", (), {"store": object(), "fork_slug": lambda self, slug: None})()
    text = tools.HANDLERS["search_references"](net, None, "rom", query="x")
    assert isinstance(text, str) and "UNTRUSTED" in text and "Truncated" in text
    assert text == "UNTRUSTED reference\n[Truncated; narrow the query.]"
    with pytest.raises(NetworkError, match="integer"):
        tools.HANDLERS["search_references"](net, None, "rom", query="x", limit="many")


def test_mcp_exposes_reference_search_and_read_definitions():
    from typing import cast

    import anyio

    mcp = tools.build_mcp(cast(tools.RomNetwork, None), lambda _ctx: (cast(tools.Agent, None), "rom"))
    names = {tool.name for tool in anyio.run(mcp.list_tools)}
    assert {"search_references", "read_reference"} <= names
