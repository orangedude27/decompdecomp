"""Owner-only routes for previewing, importing and reviewing metadata proposals."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ...network import NetworkError
from ...reference_metadata import ReferenceMetadata
from . import App


def register(app: App) -> None:
    service = ReferenceMetadata(app.net.store, app.net)
    mcp, guard, body, call, fail = app.mcp, app.guard, app.body, app.call, app.fail

    @mcp.custom_route("/api/reference-metadata", methods=["GET"])
    async def listing(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            return JSONResponse(await call(service.listing, request.query_params.get("slug", "")))
        except (NetworkError, ValueError, OSError, RuntimeError) as error:
            return fail(error)

    @mcp.custom_route("/api/reference-metadata/preview", methods=["POST"])
    async def preview(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        try:
            return JSONResponse(await call(service.preview, str(data.get("slug") or ""), data.get("path")))
        except (NetworkError, ValueError, OSError, RuntimeError) as error:
            return fail(error)

    @mcp.custom_route("/api/reference-metadata/import", methods=["POST"])
    async def import_metadata(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        try:
            return JSONResponse(
                await call(service.import_file, str(data.get("slug") or ""), data.get("path"), data.get("content_hash"))
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as error:
            return fail(error)

    @mcp.custom_route("/api/reference-metadata/records", methods=["GET"])
    async def records(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            return JSONResponse(
                await call(
                    service.records,
                    request.query_params.get("slug", ""),
                    request.query_params.get("import_id", 0),
                    request.query_params.get("offset", 0),
                    request.query_params.get("limit", 50),
                    True,
                )
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as error:
            return fail(error)

    @mcp.custom_route("/api/reference-metadata/targets", methods=["GET"])
    async def targets(request: Request) -> Response:
        if bad := guard(request):
            return bad
        try:
            return JSONResponse(
                await call(
                    service.targets,
                    request.query_params.get("slug", ""),
                    request.query_params.get("q", ""),
                    request.query_params.get("limit", 20),
                    True,
                )
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as error:
            return fail(error)

    @mcp.custom_route("/api/reference-metadata/map", methods=["POST"])
    async def map_record(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        try:
            return JSONResponse(
                {
                    "record": await call(
                        service.map_record,
                        str(data.get("slug") or ""),
                        data.get("record_id"),
                        data.get("target"),
                        data.get("proposed_name"),
                    )
                }
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as error:
            return fail(error)

    @mcp.custom_route("/api/reference-metadata/reject", methods=["POST"])
    async def reject(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        try:
            return JSONResponse(
                {"record": await call(service.reject, str(data.get("slug") or ""), data.get("record_id"))}
            )
        except (NetworkError, ValueError, OSError, RuntimeError) as error:
            return fail(error)

    @mcp.custom_route("/api/reference-metadata/apply", methods=["POST"])
    async def apply(request: Request) -> Response:
        if bad := guard(request, write=True):
            return bad
        data = await body(request)
        try:
            return JSONResponse(await call(service.apply, str(data.get("slug") or ""), data.get("record_id")))
        except (NetworkError, ValueError, OSError, RuntimeError) as error:
            return fail(error)
