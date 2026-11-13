"""Project-scoped registration and search of private reference snapshots."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ...network import NetworkError
from ...references import References
from . import App


def register(app: App) -> None:
    service = References(app.net.store)  # one coordinator for all route-triggered jobs in this app
    mcp, jobs, guard, body, call, fail = app.mcp, app.jobs, app.guard, app.body, app.call, app.fail

    @mcp.custom_route("/api/references", methods=["GET"])
    async def list_sources(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            return JSONResponse({"sources": await call(service.sources, request.query_params.get("slug", ""))})
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/references/add", methods=["POST"])
    async def add(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        try:
            source = await call(service.add, str(data.get("slug") or ""), data.get("path"))
            job = jobs.start(
                "reference-index",
                lambda log: {
                    "source": service.refresh(str(data.get("slug") or ""), source["id"], getattr(log, "check_cancel"))
                },
            )
            return JSONResponse({"source": source, "job": job})
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/references/refresh", methods=["POST"])
    async def refresh(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        try:
            slug = str(data.get("slug") or "")
            sid = data.get("id")
            await call(service.source, slug, sid)
            jid = jobs.start("reference-index", lambda log: {"source": service.refresh(slug, sid, log.check_cancel)})
            return JSONResponse({"job": jid})
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/references/enabled", methods=["POST"])
    async def enabled(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        if not isinstance(data.get("enabled"), bool):
            return fail(ValueError("enabled must be a boolean."))
        try:
            return JSONResponse(
                {"source": await call(service.enabled, str(data.get("slug") or ""), data.get("id"), data["enabled"])}
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/references/agent-access", methods=["POST"])
    async def agent_access(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        if not isinstance(data.get("agent_access"), bool):
            return fail(ValueError("agent_access must be a boolean."))
        try:
            return JSONResponse(
                {
                    "source": await call(
                        service.agent_access, str(data.get("slug") or ""), data.get("id"), data["agent_access"]
                    )
                }
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/references/remove", methods=["POST"])
    async def remove(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        try:
            await call(service.remove, str(data.get("slug") or ""), data.get("id"))
            return JSONResponse({"removed": True})
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/references/search", methods=["GET"])
    async def search(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            return JSONResponse(
                await call(service.search, request.query_params.get("slug", ""), request.query_params.get("q", ""))
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)
