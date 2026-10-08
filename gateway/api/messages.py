"""Native Messages routes with explicit version and cache semantics."""

from fastapi import FastAPI, Request

from gateway.api.agent import handle_request
from gateway.protocols.messages import parse_messages_request


def register_messages(app: FastAPI) -> None:
    @app.post("/v1/messages")
    async def messages(request: Request):
        return await handle_request(request, "messages", parse_messages_request)

    @app.post("/v1/messages/count_tokens")
    async def count_tokens(request: Request):
        return await handle_request(request, "messages", parse_messages_request, count_tokens=True)
