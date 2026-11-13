"""Owner-only API for explicit, judged reference trials."""

from __future__ import annotations

from functools import partial

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ...network import NetworkError
from ...reference_trials import ReferenceTrials
from . import App


def register(app: App) -> None:
    service = ReferenceTrials(app.net)
    mcp, guard, body, call, fail = app.mcp, app.guard, app.body, app.call, app.fail

    @mcp.custom_route("/api/reference-trials/targets", methods=["GET"])
    async def targets(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            limit = _query_int(request, "limit", 20)
            return JSONResponse(
                await call(
                    service.targets, request.query_params.get("slug", ""), request.query_params.get("q", ""), limit
                )
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/reference-trials/files", methods=["GET"])
    async def files(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            return JSONResponse(
                await call(
                    service.files,
                    request.query_params.get("slug", ""),
                    _query_int(request, "source_id", 0),
                    request.query_params.get("q", ""),
                    _query_int(request, "offset", 0),
                    _query_int(request, "limit", 30),
                )
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/reference-trials/source", methods=["POST"])
    async def source(request: Request) -> Response:
        def read(data):
            _keys(data, {"slug", "origin"}, {"slug", "origin", "start", "count"})
            return call(service.source, _slug(data), data["origin"], data.get("start", 1), data.get("count", 160))
        return await _post(request, read)

    @mcp.custom_route("/api/reference-trials/prepare", methods=["POST"])
    async def prepare(request: Request) -> Response:
        def preview(data):
            _keys(data, {"slug", "target_id", "origin"}, {"slug", "target_id", "origin", "reference_name",
                  "start", "end", "mappings", "source_override", "prelude"})
            # App.call deliberately accepts positional arguments only. Bind the
            # reviewed options before handing blocking preparation to its thread.
            return call(partial(service.prepare, _slug(data), **{k: v for k, v in data.items() if k != "slug"}))
        return await _post(request, preview)

    @mcp.custom_route("/api/reference-trials/run", methods=["POST"])
    async def run(request: Request) -> Response:
        def execute(data):
            expected = {"slug", "plan", "source", "prelude", "accept_if_verified", "allow_progress_copy"}
            if set(data) != expected:
                raise ValueError("run requires exactly slug, plan, source, prelude and both consent flags")
            return call(
                service.execute,
                _slug(data),
                data["plan"],
                data["source"],
                data["prelude"],
                data["accept_if_verified"],
                data["allow_progress_copy"],
            )

        return await _post(request, execute)

    @mcp.custom_route("/api/reference-trials", methods=["GET"])
    async def history(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            return JSONResponse(
                await call(service.history, request.query_params.get("slug", ""), _query_int(request, "limit", 20))
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    @mcp.custom_route("/api/reference-trials/detail", methods=["GET"])
    async def detail(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            return JSONResponse(
                await call(service.detail, request.query_params.get("slug", ""), _query_int(request, "id", 0))
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as e:
            return fail(e)

    async def _post(request: Request, operation) -> Response:
        if bad := guard(request, write=True):
            return bad
        try:
            data = await body(request)
            if not isinstance(data, dict):
                raise ValueError("request body must be an object")
            return JSONResponse(await operation(data))
        except (NetworkError, ValueError, OSError, RuntimeError, TypeError) as e:
            return fail(e)


def _keys(data, required, allowed):
    if not required <= data.keys() or set(data) - allowed:
        raise ValueError("Request has missing or unsupported fields; use the documented reference-trial inputs.")


def _slug(data: dict) -> str:
    value = data.get("slug")
    if not isinstance(value, str) or not value:
        raise ValueError("slug is required")
    return value


def _query_int(request: Request, name: str, default: int) -> int:
    value = request.query_params.get(name)
    try:
        parsed = default if value is None else int(value)
    except ValueError as e:
        raise ValueError(f"{name} must be an integer") from e
    if parsed < 0:
        raise ValueError(f"{name} must not be negative")
    return parsed
