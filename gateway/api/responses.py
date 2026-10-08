"""Dedicated Responses routes; the chat contract remains independent."""

from fastapi import FastAPI, Request

from gateway.api.agent import handle_request
from gateway.protocols.responses import parse_responses_request


def register_responses(app: FastAPI) -> None:
    @app.post("/v1/responses")
    async def responses(request: Request):
        return await handle_request(request, "responses", parse_responses_request)

    @app.post("/v1/responses/compact")
    async def compact(request: Request):
        return await handle_request(request, "responses", parse_responses_request, unsupported=True)
