"""Shared fixtures.

Keys are fixed constants so tests are deterministic: the same value must mint
the same token on every run, and a test that only passes sometimes is worse than
no test at all in a security suite.
"""

from __future__ import annotations

import pytest

from gateway.audit.events import MemorySink
from gateway.auth.keys import ApiKey, ApiKeyStore, hash_key
from gateway.detectors.deterministic import default_detectors
from gateway.domain import RequestContext
from gateway.inspection.pipeline import SecurityPipeline
from gateway.policy.engine import PolicyEngine
from gateway.restoration.engine import RestorationEngine
from gateway.routing.base import MockProvider
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenMinter
from gateway.vault.store import KeyRing, SurrogateVault

VAULT_KEY = b"\x01" * 32
TOKEN_KEY = b"\x02" * 32
OTHER_TOKEN_KEY = b"\x03" * 32
VAULT_KEY_V2 = b"\x04" * 32

TEST_API_KEY = "sgw_live_test_key_for_tenant_a"
TEST_API_KEY_B = "sgw_live_test_key_for_tenant_b"


@pytest.fixture
def key_ring() -> KeyRing:
    return KeyRing(keys={1: VAULT_KEY}, active_version=1)


@pytest.fixture
def vault(key_ring) -> SurrogateVault:
    return SurrogateVault(key_ring=key_ring)


@pytest.fixture
def minter() -> TokenMinter:
    return TokenMinter(secret_key=TOKEN_KEY)


@pytest.fixture
def ctx() -> RequestContext:
    return RequestContext(
        tenant_id="tenant-a",
        conversation_id="conv-1",
        request_id="req-1",
        api_key_id="key-1",
        application="test-app",
    )


@pytest.fixture
def other_tenant_ctx() -> RequestContext:
    return RequestContext(
        tenant_id="tenant-b",
        conversation_id="conv-1",
        request_id="req-2",
        api_key_id="key-2",
        application="test-app",
    )


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine.from_dict(
        {
            "version": "test-v1",
            "default_destination": "mock",
            "rules": [
                {
                    # Must stay in sync with deployment/policies/default.yaml.
                    # test_policy_matches_shipped_default() enforces this --
                    # a test policy that is more permissive than the shipped
                    # one hides real gaps.
                    "name": "block-secrets",
                    "priority": 100,
                    "match": {
                        "entities": [
                            "AWS_ACCESS_KEY",
                            "PRIVATE_KEY",
                            "JWT",
                            "OPENAI_API_KEY",
                            "ANTHROPIC_API_KEY",
                            "GITHUB_TOKEN",
                            "SLACK_TOKEN",
                        ]
                    },
                    "action": {"type": "block"},
                },
                {
                    "name": "baltic-local",
                    "priority": 90,
                    "match": {
                        "entities": [
                            "LV_PERSONAL_CODE",
                            "LT_PERSONAL_CODE",
                            "EE_PERSONAL_CODE",
                            "BALTIC_PERSONAL_CODE",
                        ]
                    },
                    "action": {"type": "route_local", "destination": "local"},
                },
                {
                    "name": "pseudonymise",
                    "priority": 50,
                    "match": {
                        "entities": ["EMAIL_ADDRESS", "IBAN", "CUSTOMER_TERM", "PAYMENT_CARD"]
                    },
                    "action": {"type": "transform", "destination": "mock"},
                },
                {
                    "name": "default-allow",
                    "priority": 10,
                    "action": {"type": "allow", "destination": "mock"},
                },
            ],
        }
    )


@pytest.fixture
def mock_provider() -> MockProvider:
    return MockProvider()


@pytest.fixture
def local_provider() -> MockProvider:
    provider = MockProvider()
    provider.name = "local"
    return provider


@pytest.fixture
def audit_sink() -> MemorySink:
    return MemorySink()


@pytest.fixture
def pipeline(policy, vault, minter, mock_provider, local_provider, audit_sink) -> SecurityPipeline:
    return SecurityPipeline(
        detectors=default_detectors(),
        policy=policy,
        transformer=TransformationEngine(minter, vault),
        restorer=RestorationEngine(vault),
        providers={"mock": mock_provider, "local": local_provider},
        audit_sink=audit_sink,
    )


@pytest.fixture
def key_store() -> ApiKeyStore:
    return ApiKeyStore(
        [
            ApiKey(
                key_id="key-a",
                key_hash=hash_key(TEST_API_KEY),
                tenant_id="tenant-a",
                application="test-app",
            ),
            ApiKey(
                key_id="key-b",
                key_hash=hash_key(TEST_API_KEY_B),
                tenant_id="tenant-b",
                application="test-app",
            ),
        ]
    )


# ---------------------------------------------------------------------------
# Known-valid Baltic personal codes, generated from the published check-digit
# algorithms. Kept here so every test uses the same verified corpus.
# ---------------------------------------------------------------------------


def _lv_with_valid_checksum(first_ten: str) -> str:
    weights = (1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    total = sum(int(first_ten[i]) * weights[i] for i in range(10))
    check = (1101 - total) % 11 % 10
    return f"{first_ten[:6]}-{first_ten[6:]}{check}"


def _baltic_with_valid_checksum(first_ten: str) -> str:
    w1 = (1, 2, 3, 4, 5, 6, 7, 8, 9, 1)
    w2 = (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)
    remainder = sum(int(first_ten[i]) * w1[i] for i in range(10)) % 11
    if remainder == 10:
        remainder = sum(int(first_ten[i]) * w2[i] for i in range(10)) % 11
        if remainder == 10:
            remainder = 0
    return first_ten + str(remainder)


VALID_LV_CODE = _lv_with_valid_checksum("1203851234")
VALID_LT_CODE = _baltic_with_valid_checksum("3850312123")
VALID_EE_CODE = _baltic_with_valid_checksum("3850312123")
