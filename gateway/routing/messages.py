"""Native Anthropic Messages transport with fixed provider authentication."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import aclosing
from typing import Any

from gateway.protocols.messages import SUPPORTED_MESSAGES_BETAS
from gateway.routing.base import ProviderError
from gateway.routing.responses import MockAgentProvider, ResponsesProvider

__all__ = ["MessagesProvider", "MockAgentProvider"]


class MessagesProvider(ResponsesProvider):
    """Use native Messages endpoints, including inspected token-count requests.

    The gateway owns the upstream credential and API version. Only explicitly
    supported, validated beta controls are forwarded on the current request.
    """

    endpoint = "messages"

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self._api_key:
            headers["x-api-key"] = self._api_key
        return headers

    @staticmethod
    def _beta_headers(betas: tuple[str, ...]) -> dict[str, str]:
        if (
            not isinstance(betas, tuple)
            or len(betas) > len(SUPPORTED_MESSAGES_BETAS)
            or any(
                not isinstance(beta, str) or beta not in SUPPORTED_MESSAGES_BETAS for beta in betas
            )
            or len(set(betas)) != len(betas)
        ):
            raise ProviderError("unsupported native Messages beta controls", 400)
        return {"anthropic-beta": ",".join(betas)} if betas else {}

    async def complete(
        self, payload: dict[str, Any], *, betas: tuple[str, ...] = ()
    ) -> dict[str, Any]:
        return await self._complete_at(
            self.endpoint, payload, request_headers=self._beta_headers(betas)
        )

    async def stream(
        self, payload: dict[str, Any], *, betas: tuple[str, ...] = ()
    ) -> AsyncIterator[bytes]:
        async with aclosing(
            self._stream_at(self.endpoint, payload, request_headers=self._beta_headers(betas))
        ) as chunks:
            async for chunk in chunks:
                yield chunk

    async def count_tokens(
        self, payload: dict[str, Any], *, betas: tuple[str, ...] = ()
    ) -> dict[str, Any]:
        # The request contract permits only native token-count fields. Preserve
        # its transformed body and avoid inventing a stream field here.
        return await self._complete_at(
            f"{self.endpoint}/count_tokens",
            payload,
            stream=None,
            request_headers=self._beta_headers(betas),
        )
