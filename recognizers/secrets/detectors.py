"""Secret and credential detectors.

Secrets are the one entity class where the correct default action is **block**,
not transform. Pseudonymising an AWS key still tells the provider a key was
present, and a pseudonymised secret that gets restored into a response is a
credential leak with extra steps. See the default policy in
deployment/policies/default.yaml.

These are deterministic, high-precision patterns. We deliberately do not attempt
entropy-based "generic secret" detection in v1: it is a false-positive factory
on real prompts (base64 payloads, hashes, UUIDs) and a security control that
cries wolf gets turned off by the customer.
"""

from __future__ import annotations

import re

from gateway.domain import Confidence, Span

# AWS access key IDs have a fixed, documented prefix set and length.
# AKIA = long-term user key, ASIA = temporary STS key. Both matter.
_AWS_ACCESS_KEY = re.compile(r"\b((?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[0-9A-Z]{16})\b")

# PEM private keys of any flavour. The header is unambiguous.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----"
    r".*?"
    r"-----END\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY-----",
    re.DOTALL,
)

# JWTs: three base64url segments, first decoding to a JSON header.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

# Provider API keys with distinctive prefixes.
_OPENAI_KEY = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")
_ANTHROPIC_KEY = re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")
_GITHUB_TOKEN = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")

_SIMPLE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_AWS_ACCESS_KEY, "AWS_ACCESS_KEY"),
    (_JWT, "JWT"),
    (_ANTHROPIC_KEY, "ANTHROPIC_API_KEY"),
    (_OPENAI_KEY, "OPENAI_API_KEY"),
    (_GITHUB_TOKEN, "GITHUB_TOKEN"),
    (_SLACK_TOKEN, "SLACK_TOKEN"),
)


class SecretDetector:
    """Detects credentials and private keys."""

    name = "secrets"
    uses_folded_view = True

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []

        for match in _PRIVATE_KEY.finditer(text):
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type="PRIVATE_KEY",
                    text=match.group(0),
                    score=Confidence.CERTAIN.value,
                    detector=self.name,
                )
            )

        for pattern, entity_type in _SIMPLE_PATTERNS:
            for match in pattern.finditer(text):
                spans.append(
                    Span(
                        start=match.start(),
                        end=match.end(),
                        entity_type=entity_type,
                        text=match.group(0),
                        score=Confidence.CERTAIN.value,
                        detector=self.name,
                    )
                )

        return spans
