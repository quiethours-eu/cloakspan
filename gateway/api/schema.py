"""Strict request models for the supported chat-completions subset.

Every accepted field is understood and inspectable. Recognized fields that
cannot be inspected get ``uninspectable_field``; unknown fields get
``unknown_field``. Outbound payloads are rebuilt from these models so rejected
content cannot survive validation by accident.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

#: Fields we recognise and deliberately refuse, mapped to the reason. Listed
#: explicitly so the error tells an integrator *why*, and so adding support for
#: one is a visible change here rather than a silent relaxation of `extra`.
UNINSPECTABLE_FIELDS: dict[str, str] = {
    "stop": "Stop sequences are sent to the provider and can contain customer "
    "content. This version only inspects message content.",
    "user": "End-user identifiers can contain personal data and this version does "
    "not inspect that field.",
    "tools": "Tool definitions carry customer content in their descriptions and "
    "schemas, and this version does not inspect them.",
    "functions": "Legacy function definitions carry customer content and are not inspected.",
    "tool_choice": "Rejected with the tool definitions it controls.",
    "function_call": "Rejected with the function definitions it controls.",
    "response_format": "Structured-output schemas carry field names and "
    "descriptions, which are customer content.",
    "logit_bias": "Correct handling requires the upstream tokenizer, which the "
    "gateway does not have.",
    "metadata": "Not inspected, and not forwarded blind.",
    "store": "Asks the provider to retain the request. That is a retention "
    "decision the gateway must not relay silently.",
    "stream_options": "Meaningless without streaming; accepting it would imply "
    "streaming is supported.",
    "prediction": "Predicted output carries customer content and is not inspected.",
    "audio": "Non-text output is not inspected.",
    "modalities": "Non-text output is not inspected.",
}

#: Message-level fields refused for the same reason.
UNINSPECTABLE_MESSAGE_FIELDS: dict[str, str] = {
    "name": "A participant name is free text and carries PERSON data, which this "
    "version does not inspect on that field.",
    "tool_calls": "Tool-call arguments are customer content and are not inspected.",
    "tool_call_id": "Rejected with the tool calls it refers to.",
    "function_call": "Legacy tool call; rejected for the same reason.",
    "refusal": "Provider-generated field with no meaning on a request.",
    "audio": "Non-text content is not inspected.",
}

ACCEPTED_ROLES = ("system", "user", "assistant", "tool")

#: A million empty messages is a cheap denial of service. The character limit
#: (`SAG_MAX_INPUT_CHARS`) does not bound this on its own.
MAX_MESSAGES = 512


class RequestRejected(Exception):
    """The request violates the contract. Carries the status and code to return.

    ``detail`` never contains message content: it names fields and roles, which
    are structure, not data (SI-11).
    """

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


class ChatMessage(BaseModel):
    """One message. Text content only, and only the four inspected roles."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant", "tool"]
    content: str


class ChatCompletionRequest(BaseModel):
    """The accepted subset of ``POST /v1/chat/completions``.

    Every field here is either inspected or structurally incapable of carrying
    customer content — sampling parameters, counts, and flags. If a field could
    carry text, it is inspected or it is not on this model.
    """

    model_config = ConfigDict(extra="forbid")

    model: str
    messages: list[ChatMessage] = Field(min_length=1, max_length=MAX_MESSAGES)

    # Numeric and boolean sampling controls cannot carry customer content.
    temperature: float | None = None
    top_p: float | None = None
    n: int | None = None
    max_tokens: int | None = None
    max_completion_tokens: int | None = None
    presence_penalty: float | None = None
    frequency_penalty: float | None = None
    seed: int | None = None
    logprobs: bool | None = None
    top_logprobs: int | None = None
    service_tier: Literal["auto", "default", "flex", "scale", "priority"] | None = None
    parallel_tool_calls: bool | None = None
    stream: bool | None = None

    def to_payload(self) -> dict[str, Any]:
        """The outbound payload, rebuilt from validated fields only.

        ``stream`` is dropped: it is rejected before we get here, and carrying a
        field we refuse would be incoherent.
        """
        payload = self.model_dump(exclude_none=True)
        payload.pop("stream", None)
        return payload


#: The type this model gives each top-level field other than ``messages``.
_REQUEST_FIELD_TYPES: dict[str, TypeAdapter[Any]] = {
    name: TypeAdapter(field.annotation)
    for name, field in ChatCompletionRequest.model_fields.items()
    if name != "messages"
}


def accepts_request_fields(payload: dict[str, Any]) -> bool:
    """Whether every top-level field but ``messages`` is one this model accepts.

    For code that calls ``SecurityPipeline`` directly, without
    :func:`parse_chat_completion_request` in front of it. The pipeline inspects
    none of these fields and forwards them as given, which is safe only while
    each is a field named here and holds the type given to it: a model name, a
    number, a flag, or a named service tier. Anything else could carry text
    that no detector saw (SI-01).
    """
    for name, value in payload.items():
        if name == "messages":
            continue
        field_type = _REQUEST_FIELD_TYPES.get(name)
        if field_type is None:
            return False
        try:
            field_type.validate_python(value)
        except ValidationError:
            return False
    return True


def _describe_pydantic_error(error: ValidationError) -> RequestRejected:
    """Turn the first validation failure into our documented code.

    Only the first is reported. A client fixing one field at a time is the
    normal case, and enumerating every problem in a body we refused to inspect
    means walking a structure we have already decided not to trust.
    """
    first = error.errors()[0]
    location = ".".join(str(part) for part in first["loc"])
    kind = first["type"]

    if kind == "extra_forbidden":
        field = str(first["loc"][-1])
        if len(first["loc"]) >= 3 and first["loc"][0] == "messages":
            if field in UNINSPECTABLE_MESSAGE_FIELDS:
                return RequestRejected(
                    422,
                    "uninspectable_field",
                    f"Message field '{field}' is not supported. "
                    f"{UNINSPECTABLE_MESSAGE_FIELDS[field]}",
                )
        return RequestRejected(
            422,
            "unknown_field",
            f"Unrecognised field '{location}'. This gateway rejects fields it "
            "does not understand rather than forwarding them uninspected.",
        )

    if location.startswith("messages") and location.endswith("role"):
        return RequestRejected(
            422,
            "unsupported_role",
            f"Message role must be one of {list(ACCEPTED_ROLES)}. Other roles are "
            "refused because this version does not inspect them, and forwarding "
            "an uninspected message would defeat the gateway.",
        )

    if location.startswith("messages") and location.endswith("content"):
        return RequestRejected(
            422,
            "inspection_failed",
            "Message content must be a string. Multimodal and structured content "
            "cannot be inspected by this version, and it is refused rather than "
            "forwarded unscanned.",
        )

    if location.startswith("messages.") and kind == "model_type":
        return RequestRejected(
            422,
            "invalid_message",
            "Every message must be a JSON object with a supported role and text content.",
        )

    if location == "messages":
        return RequestRejected(
            422,
            "invalid_message",
            f"'messages' must be a non-empty list of at most {MAX_MESSAGES} objects.",
        )

    return RequestRejected(
        422, "invalid_request", f"Invalid value for '{location}': {first['msg']}."
    )


def parse_chat_completion_request(body: Any) -> ChatCompletionRequest:
    """Validate a request body, or raise :class:`RequestRejected`.

    Checks run in a deliberate order, because the *first* failure is what the
    client is told about and the most actionable message should win:

    1. shape -- a non-object body is a 400, not a field problem;
    2. ``stream`` -- its own status and code, and the most common mistake;
    3. recognised-but-refused fields, which get an explanatory reason;
    4. everything else, via the model.
    """
    if not isinstance(body, dict):
        raise RequestRejected(400, "invalid_request", "Request body must be a JSON object.")

    if body.get("stream"):
        raise RequestRejected(
            400,
            "streaming_unsupported",
            "Streaming is not supported in this version. This gateway uses "
            "buffered output inspection so that responses are scanned before any "
            "content is released. Retry with stream=false.",
        )

    for field, reason in UNINSPECTABLE_FIELDS.items():
        if field in body:
            raise RequestRejected(
                422, "uninspectable_field", f"Field '{field}' is not supported. {reason}"
            )

    # Message-level refusals before model validation, so a recognised-but-refused
    # field reports its reason rather than the generic unknown-field message.
    messages = body.get("messages")
    if isinstance(messages, list):
        for message in messages:
            if not isinstance(message, dict):
                continue
            for field, reason in UNINSPECTABLE_MESSAGE_FIELDS.items():
                if field in message:
                    raise RequestRejected(
                        422,
                        "uninspectable_field",
                        f"Message field '{field}' is not supported. {reason}",
                    )
            role = message.get("role")
            if isinstance(role, str) and role not in ACCEPTED_ROLES:
                raise RequestRejected(
                    422,
                    "unsupported_role",
                    f"Message role '{role}' is not supported. Accepted roles are "
                    f"{list(ACCEPTED_ROLES)}; others are refused because this "
                    "version does not inspect them.",
                )

    try:
        return ChatCompletionRequest.model_validate(body)
    except ValidationError as exc:
        raise _describe_pydantic_error(exc) from exc
