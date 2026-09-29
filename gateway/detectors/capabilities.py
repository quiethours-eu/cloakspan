"""Configured detector inventory shared by diagnostics and future UIs."""

from __future__ import annotations

from gateway.detectors.deterministic import default_detectors

_BUILTIN_ENTITIES = {
    "secrets": [
        "PRIVATE_KEY",
        "AWS_ACCESS_KEY",
        "JWT",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
    ],
    "email": ["EMAIL_ADDRESS"],
    "baltic_personal_codes": [
        "LV_PERSONAL_CODE",
        "LT_PERSONAL_CODE",
        "EE_PERSONAL_CODE",
        "BALTIC_PERSONAL_CODE",
    ],
    "phone_number": ["PHONE_NUMBER"],
    "iban": ["IBAN"],
    "payment_card": ["PAYMENT_CARD"],
    "ip_address": ["IP_ADDRESS"],
}


def builtin_capabilities() -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "name": detector.name,
            "kind": "builtin",
            "entities": _BUILTIN_ENTITIES.get(detector.name, []),
        }
        for detector in default_detectors()
    )
