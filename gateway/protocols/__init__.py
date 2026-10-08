"""Native protocol contracts whose complete accepted content is inspectable."""

from gateway.protocols.base import ContentLocation, ValidatedRequest, loads_json, replace_location
from gateway.protocols.messages import parse_messages_request
from gateway.protocols.responses import parse_responses_request

__all__ = [
    "ContentLocation",
    "ValidatedRequest",
    "loads_json",
    "parse_messages_request",
    "parse_responses_request",
    "replace_location",
]
