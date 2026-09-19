"""Configuration and application assembly.

Every secret comes from the environment. Nothing sensitive has a usable default:
if the vault key or token key is missing we generate an ephemeral one **and log
a loud warning**, because a silent weak default in a security product is worse
than a crash. In production (``SAG_ENVIRONMENT=production``) an ephemeral key is
a startup failure instead -- a warning nobody reads is not a control.

Operator-supplied values are **root secrets**, not keys: each working key is
derived with HKDF under a distinct info string, so setting both variables to the
same value still yields two unrelated keys. See gateway/crypto.py.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from gateway.audit.events import AuditSink, JsonLogSink
from gateway.auth.keys import KEY_PREFIX, ApiKey, ApiKeyStore, hash_key
from gateway.crypto import (
    MIN_ROOT_SECRET_BYTES,
    TOKEN_KEY_INFO,
    VAULT_KEY_INFO,
    derive_key,
)
from gateway.detectors.deterministic import default_detectors
from gateway.detectors.ner import build_ner_detector
from gateway.inspection.pipeline import SecurityPipeline
from gateway.policy.engine import PolicyEngine
from gateway.restoration.engine import RestorationEngine
from gateway.routing.base import MockProvider, OpenAICompatibleProvider, ProviderAdapter
from gateway.routing.egress import policy_for
from gateway.transformations.engine import TransformationEngine
from gateway.transformations.tokens import TokenMinter
from gateway.vault.store import KeyRing, SurrogateVault
from recognizers.custom.customer_rules import CustomRegexDetector, DictionaryDetector

logger = logging.getLogger("gateway.config")


def _default_policy_path() -> Path:
    """Locate the policy in an installed wheel or a source checkout."""
    package_dir = Path(__file__).resolve().parent
    installed_policy = package_dir / "_data" / "default-policy.yaml"
    source_policy = package_dir.parent / "deployment" / "policies" / "default.yaml"

    if installed_policy.is_file():
        return installed_policy
    if source_policy.is_file():
        return source_policy

    # Keep the eventual startup error anchored to the missing package resource,
    # rather than to a deployment directory that does not belong in a wheel.
    return installed_policy


DEFAULT_POLICY_PATH = _default_policy_path()

#: SAG_VAULT_KEY_V<n> supplies the root secret for vault key version <n>.
_VERSIONED_VAULT_KEY = re.compile(r"^SAG_VAULT_KEY_V(\d{1,5})$")


class ConfigurationError(Exception):
    """Raised for a configuration the gateway must not start with."""


def _is_production() -> bool:
    return os.environ.get("SAG_ENVIRONMENT", "").lower() in ("prod", "production")


def _decode_secret(name: str, raw: str) -> bytes:
    """Accept hex or raw UTF-8, and refuse anything too short to be a secret."""
    try:
        secret = bytes.fromhex(raw)
    except ValueError:
        secret = raw.encode("utf-8")
    if len(secret) < MIN_ROOT_SECRET_BYTES:
        raise ConfigurationError(
            f"{name} must be at least {MIN_ROOT_SECRET_BYTES} bytes "
            f"({MIN_ROOT_SECRET_BYTES * 2} hex characters); got {len(secret)}. "
            "Truncating or padding a short secret would hide the problem."
        )
    return secret


def _root_secret_from_env(name: str) -> bytes:
    raw = os.environ.get(name)
    if raw:
        return _decode_secret(name, raw)

    if _is_production():
        raise ConfigurationError(
            f"{name} is not set and SAG_ENVIRONMENT is production. Refusing to "
            "start with an ephemeral key."
        )
    logger.warning(
        "%s is not set. Generating an ephemeral key. Surrogate mappings will "
        "NOT survive a restart and MUST NOT be used in production.",
        name,
    )
    return secrets.token_bytes(MIN_ROOT_SECRET_BYTES)


def build_key_ring() -> KeyRing:
    """Assemble the vault key ring from the environment.

    Two forms, and they compose:

    * ``SAG_VAULT_KEY`` -- the unversioned form, taken as version 1.
    * ``SAG_VAULT_KEY_V<n>`` -- explicit versions, for rotation.

    ``SAG_VAULT_ACTIVE_KEY_VERSION`` selects which version new records are
    written under; it defaults to the highest configured version. Rotation is
    therefore: add ``SAG_VAULT_KEY_V2``, restart, and let the old records expire
    on their TTL. No re-encryption pass -- see
    docs/adr/0012-vault-record-envelope-and-key-rotation.md.
    """
    roots: dict[int, bytes] = {}

    for name, raw in os.environ.items():
        match = _VERSIONED_VAULT_KEY.match(name)
        if match and raw:
            roots[int(match.group(1))] = _decode_secret(name, raw)

    unversioned = os.environ.get("SAG_VAULT_KEY")
    if unversioned:
        if 1 in roots:
            raise ConfigurationError(
                "SAG_VAULT_KEY and SAG_VAULT_KEY_V1 are both set and would both "
                "be version 1. Use one form or the other."
            )
        roots[1] = _decode_secret("SAG_VAULT_KEY", unversioned)

    if not roots:
        roots[1] = _root_secret_from_env("SAG_VAULT_KEY")

    keys = {version: derive_key(root, VAULT_KEY_INFO) for version, root in roots.items()}

    declared = os.environ.get("SAG_VAULT_ACTIVE_KEY_VERSION")
    if declared:
        try:
            active = int(declared)
        except ValueError as exc:
            raise ConfigurationError(
                f"SAG_VAULT_ACTIVE_KEY_VERSION must be an integer; got {declared!r}"
            ) from exc
        if active not in keys:
            raise ConfigurationError(
                f"SAG_VAULT_ACTIVE_KEY_VERSION={active} but no key is configured for "
                f"that version; configured versions: {sorted(keys)}"
            )
    else:
        active = max(keys)

    if len(keys) > 1:
        logger.info("vault key ring: versions %s, writing under v%d", sorted(keys), active)
    return KeyRing(keys=keys, active_version=active)


@dataclass(slots=True)
class Settings:
    bind_host: str = "0.0.0.0"  # noqa: S104 - container listens on all interfaces by design
    port: int = 8080
    policy_path: Path = DEFAULT_POLICY_PATH
    vault_ttl_seconds: int = 3600
    #: Inspection size cap, lowered from 256_000 once the cost was measured
    #: rather than assumed:
    #:
    #:     input     CPU per request     requests/s/process
    #:      4 KB              7.4 ms                   ~52
    #:     16 KB               30 ms                   ~24
    #:     64 KB              123 ms                    ~8
    #:    256 KB              558 ms                    ~2
    #:
    #: Detection is CPU-bound and pure Python, so that cost is per process and
    #: does not parallelise inside one. At the old default a single tenant could
    #: reduce an instance to roughly two requests per second using nothing but
    #: the documented limit -- no malformed input, no attack, just large prompts.
    #:
    #: 65_536 characters is about 16k tokens, or 25 pages: it covers the
    #: business documents this product is for, at 123 ms instead of 558 ms.
    #:
    #: A **default, not a maximum.** Raising it is a supported choice for a
    #: customer who summarises long contracts; the figures are published so that
    #: choice carries its capacity cost openly, rather than being discovered
    #: under load.
    max_input_chars: int = 65_536
    #: HTTP request bodies are bounded separately from inspected characters.
    #: The byte limit is enforced while the ASGI stream is consumed, before
    #: JSON parsing can duplicate a large body in memory.
    max_request_bytes: int = 1_048_576
    request_timeout_seconds: float = 120.0
    log_level: str = "INFO"

    external_base_url: str = ""
    external_api_key: str = ""
    external_model: str = ""

    local_base_url: str = ""
    local_model: str = ""

    # Opt-in only. See OpenAICompatibleProvider for why the default is False.
    trust_env_proxy: bool = False

    #: Hosts the gateway may send to. Empty means "any globally routable host",
    #: which is the permissive default; setting it is how an operator pins
    #: egress to their approved providers.
    egress_allowlist: tuple[str, ...] = ()

    #: Permit private, loopback, and link-local destinations for **every**
    #: destination, not just `local`. This removes the SSRF control and is
    #: logged loudly when set.
    egress_allow_private: bool = False

    #: Refuse requests containing a word that mixes scripts. Off by default:
    #: confusable folding already protects the identifiers that matter, and a
    #: false positive here blocks legitimate multilingual traffic in the exact
    #: market this product is for. See ADR-0015.
    block_mixed_script: bool = False

    #: Directory holding a checksum-verified NER model. Empty means NER is off,
    #: and PERSON/ORG/LOCATION/ADDRESS are not detected. No model ships with the
    #: repository; see gateway/detectors/ner.py.
    ner_model_path: str = ""

    dictionary_terms: tuple[str, ...] = ()
    custom_patterns: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_env(cls) -> Settings:
        policy = os.environ.get("SAG_POLICY_PATH")
        terms = os.environ.get("SAG_DICTIONARY_TERMS", "")
        patterns_raw = os.environ.get("SAG_CUSTOM_PATTERNS", "")

        patterns: list[tuple[str, str]] = []
        for item in filter(None, (p.strip() for p in patterns_raw.split(";"))):
            entity, _, pattern = item.partition("=")
            if entity and pattern:
                patterns.append((entity.strip(), pattern.strip()))

        return cls(
            bind_host=os.environ.get("SAG_BIND_HOST", "0.0.0.0"),  # noqa: S104
            port=int(os.environ.get("SAG_PORT", "8080")),
            policy_path=Path(policy) if policy else DEFAULT_POLICY_PATH,
            vault_ttl_seconds=int(os.environ.get("SAG_VAULT_TTL_SECONDS", "3600")),
            max_input_chars=int(os.environ.get("SAG_MAX_INPUT_CHARS", "65536")),
            max_request_bytes=int(os.environ.get("SAG_MAX_REQUEST_BYTES", "1048576")),
            request_timeout_seconds=float(os.environ.get("SAG_REQUEST_TIMEOUT_SECONDS", "120")),
            log_level=os.environ.get("SAG_LOG_LEVEL", "INFO"),
            external_base_url=os.environ.get("SAG_EXTERNAL_BASE_URL", ""),
            external_api_key=os.environ.get("SAG_EXTERNAL_API_KEY", ""),
            external_model=os.environ.get("SAG_EXTERNAL_MODEL", ""),
            local_base_url=os.environ.get("SAG_LOCAL_BASE_URL", ""),
            local_model=os.environ.get("SAG_LOCAL_MODEL", ""),
            trust_env_proxy=os.environ.get("SAG_TRUST_ENV_PROXY", "").lower()
            in ("1", "true", "yes"),
            ner_model_path=os.environ.get("SAG_NER_MODEL_PATH", ""),
            block_mixed_script=os.environ.get("SAG_BLOCK_MIXED_SCRIPT", "").lower()
            in ("1", "true", "yes"),
            egress_allowlist=tuple(
                h.strip()
                for h in os.environ.get("SAG_EGRESS_ALLOWLIST", "").split(",")
                if h.strip()
            ),
            egress_allow_private=os.environ.get("SAG_EGRESS_ALLOW_PRIVATE", "").lower()
            in ("1", "true", "yes"),
            dictionary_terms=tuple(t.strip() for t in terms.split(",") if t.strip()),
            custom_patterns=tuple(patterns),
        )


def build_detectors(settings: Settings) -> list[object]:
    detectors = list(default_detectors())

    # NER is enabled by pointing at a verified local model directory. When the
    # path is set but unusable this raises rather than degrading quietly:
    # carrying on without it means the operator believes PERSON is being caught
    # while it silently is not, which is worse than a startup failure.
    ner = build_ner_detector(settings.ner_model_path or None)
    if ner is not None:
        detectors.append(ner)

    if settings.dictionary_terms:
        detectors.append(DictionaryDetector(list(settings.dictionary_terms)))
    for entity_type, pattern in settings.custom_patterns:
        detectors.append(CustomRegexDetector(pattern, entity_type))
    return detectors


def build_providers(
    settings: Settings,
    *,
    required_destinations: frozenset[str] = frozenset(),
) -> dict[str, ProviderAdapter]:
    """Assemble the destination map that policy rules refer to by name.

    'mock' is always present: it is what makes `make demo` and the whole test
    suite work with no credentials and no network.
    """
    providers: dict[str, ProviderAdapter] = {"mock": MockProvider()}
    configured_destinations = {"mock"}

    allowed_hosts = frozenset(h.lower() for h in settings.egress_allowlist)
    allow_private = settings.egress_allow_private or None

    if settings.external_base_url:
        providers["external"] = OpenAICompatibleProvider(
            base_url=settings.external_base_url,
            api_key=settings.external_api_key or None,
            model_override=settings.external_model or None,
            timeout_seconds=settings.request_timeout_seconds,
            name="external",
            trust_env=settings.trust_env_proxy,
            egress=policy_for(
                "external",
                allowed_hosts=allowed_hosts,
                allow_private_override=allow_private,
            ),
        )
        configured_destinations.add("external")
    else:
        providers["external"] = providers["mock"]
        logger.warning("SAG_EXTERNAL_BASE_URL is not set; 'external' resolves to the mock provider")

    if settings.local_base_url:
        providers["local"] = OpenAICompatibleProvider(
            base_url=settings.local_base_url,
            model_override=settings.local_model or None,
            timeout_seconds=settings.request_timeout_seconds,
            name="local",
            trust_env=settings.trust_env_proxy,
            # `local` permits private addresses by default: routing to a model
            # on loopback is the entire point of the route_local action.
            egress=policy_for("local", allowed_hosts=allowed_hosts),
        )
        configured_destinations.add("local")
    else:
        providers["local"] = providers["mock"]
        logger.warning("SAG_LOCAL_BASE_URL is not set; 'local' resolves to the mock provider")

    unknown = required_destinations - providers.keys()
    if unknown:
        raise ConfigurationError(
            f"policy refers to unknown provider destination(s): {', '.join(sorted(unknown))}"
        )

    if _is_production():
        mocked = required_destinations - configured_destinations
        if mocked:
            variables = {
                "external": "SAG_EXTERNAL_BASE_URL",
                "local": "SAG_LOCAL_BASE_URL",
                "mock": "a non-mock policy destination",
            }
            missing = ", ".join(variables.get(name, name) for name in sorted(mocked))
            raise ConfigurationError(
                "production policy can route to an unconfigured/mock provider. "
                f"Configure {missing} or change the policy."
            )

    return providers


def build_key_store() -> ApiKeyStore:
    """Load API keys from SAG_API_KEYS: 'key:tenant:application,key:tenant:app'."""
    store = ApiKeyStore()
    seen_hashes: set[str] = set()
    raw = os.environ.get("SAG_API_KEYS", "")
    for item in filter(None, (k.strip() for k in raw.split(","))):
        parts = item.split(":")
        if (
            len(parts) not in (2, 3)
            or not parts[0]
            or not parts[1]
            or (len(parts) == 3 and not parts[2])
        ):
            if _is_production():
                raise ConfigurationError(
                    "SAG_API_KEYS contains a malformed entry; expected "
                    "key:tenant[:application] with no empty or extra fields"
                )
            logger.error(
                "ignoring malformed SAG_API_KEYS entry (expected key:tenant[:application])"
            )
            continue
        plaintext, tenant = parts[0], parts[1]
        application = parts[2] if len(parts) > 2 else "default"
        if _is_production() and (
            not plaintext.startswith(KEY_PREFIX) or len(plaintext) < len(KEY_PREFIX) + 32
        ):
            raise ConfigurationError(
                f"production API keys must start with {KEY_PREFIX!r} and contain at least "
                "32 random characters after the prefix"
            )
        key_hash = hash_key(plaintext)
        if key_hash in seen_hashes:
            raise ConfigurationError(
                "SAG_API_KEYS contains the same plaintext key more than once; "
                "tenant ownership would be ambiguous"
            )
        seen_hashes.add(key_hash)
        store.add(
            ApiKey(
                key_id=f"key_{key_hash[:12]}",
                key_hash=key_hash,
                tenant_id=tenant,
                application=application,
            )
        )
    if not store:
        if _is_production():
            raise ConfigurationError(
                "SAG_API_KEYS contains no valid keys and SAG_ENVIRONMENT is production. "
                "Refusing to start an unauthenticated/unusable gateway."
            )
        logger.warning(
            "No API keys configured (SAG_API_KEYS); the gateway will reject every request"
        )
    return store


def build_pipeline(settings: Settings, audit_sink: AuditSink | None = None) -> SecurityPipeline:
    policy = PolicyEngine.from_yaml(settings.policy_path)
    vault = SurrogateVault(
        key_ring=build_key_ring(),
        ttl_seconds=settings.vault_ttl_seconds,
    )
    minter = TokenMinter(
        secret_key=derive_key(_root_secret_from_env("SAG_TOKEN_KEY"), TOKEN_KEY_INFO)
    )

    return SecurityPipeline(
        detectors=build_detectors(settings),
        policy=policy,
        transformer=TransformationEngine(minter, vault),
        restorer=RestorationEngine(vault),
        providers=build_providers(
            settings,
            required_destinations=policy.required_destinations,
        ),
        audit_sink=audit_sink or JsonLogSink(),
        max_input_chars=settings.max_input_chars,
        block_mixed_script=settings.block_mixed_script,
    )
