"""SAG_LOCAL_ROUTING ("GDPR mode"): where a request may go, and what startup refuses.

The property everything here serves: with the mode on, a request the mode keeps
local reaches no provider but `local`, whatever the policy, the filters, or the
detectors say -- and with the mode off, nothing changes at all. The leakage
evidence, through the real pipeline, is in
``evals/leakage/test_leakage_regression.py::TestLocalRoutingMode``.
"""

from __future__ import annotations

import datetime
import logging
import math
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hypothesis import given, settings
from hypothesis import strategies as st

from gateway.config import ConfigurationError, Settings, build_pipeline, build_providers
from gateway.detectors.deterministic import default_detectors
from gateway.detectors.ner import ModelManifest, NerDetector
from gateway.domain import Action, InspectionResult, PolicyDecision, RequestContext, Span
from gateway.inspection.pipeline import SecurityPipeline
from gateway.policy.engine import PolicyEngine, PolicyError, Rule
from gateway.policy.local_routing import LocalRouting, LocalRoutingViolation, apply_local_routing
from gateway.restoration.engine import RestorationEngine
from gateway.routing.base import verification_context
from gateway.routing.egress import EgressBlockedError
from gateway.transformations.engine import TransformationEngine

from .conftest import VALID_LV_CODE
from .test_ner_and_phone import StubBackend

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "deployment" / "policies" / "default.yaml"

#: An IP literal, so building a provider for it needs no DNS and opens nothing.
LOCAL_URL = "http://127.0.0.1:11434/v1"

MODES_ON = [LocalRouting.DETECTED, LocalRouting.ALL]


def user_message(text: str) -> dict:
    return {"model": "m", "messages": [{"role": "user", "content": text}]}


def inspection(*entity_types: str, score: float = 1.0) -> InspectionResult:
    return InspectionResult(
        spans=[
            Span(start=i * 10, end=i * 10 + 5, entity_type=t, text="xxxxx", score=score)
            for i, t in enumerate(entity_types)
        ]
    )


def write_internal_ca(path: Path, common_name: str) -> None:
    """A self-signed CA certificate, standing in for an operator's internal CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def catch_all_to(destination: str) -> PolicyEngine:
    """A one-rule policy whose every decision names ``destination``.

    ``default_destination`` is the same string, so an empty destination stays
    empty rather than falling back to ``external``.
    """
    return PolicyEngine.from_dict(
        {
            "version": "inline-v1",
            "default_destination": destination,
            "rules": [
                {
                    "name": "catch-all",
                    "priority": 10,
                    "action": {"type": "allow", "destination": destination},
                }
            ],
        }
    )


@pytest.fixture
def default_policy() -> PolicyEngine:
    return PolicyEngine.from_yaml(DEFAULT_POLICY)


@pytest.fixture
def stub_ner(monkeypatch) -> NerDetector:
    """An NER detector that finds nothing, standing in for a provisioned model."""
    detector = NerDetector(StubBackend([]))
    monkeypatch.setattr("gateway.config.build_ner_detector", lambda path: detector)
    return detector


class TestParsing:
    """A typo must stop startup. It must never quietly read as off."""

    @pytest.mark.parametrize("raw", [None, "", "off", " Off "])
    def test_unset_empty_and_off_mean_off(self, monkeypatch, raw):
        if raw is None:
            monkeypatch.delenv("SAG_LOCAL_ROUTING", raising=False)
        else:
            monkeypatch.setenv("SAG_LOCAL_ROUTING", raw)
        assert Settings.from_env().local_routing is LocalRouting.OFF

    @pytest.mark.parametrize(
        ("raw", "mode"),
        [
            ("detected", LocalRouting.DETECTED),
            (" Detected ", LocalRouting.DETECTED),
            ("all", LocalRouting.ALL),
            ("ALL", LocalRouting.ALL),
        ],
    )
    def test_the_modes_parse_in_any_case(self, monkeypatch, raw, mode):
        monkeypatch.setenv("SAG_LOCAL_ROUTING", raw)
        assert Settings.from_env().local_routing is mode

    @pytest.mark.parametrize("raw", ["on", "true", "1", "yes", "gdpr", "local", "strict", "detect"])
    def test_anything_else_stops_startup(self, monkeypatch, raw):
        """Each of these reads like "on" to someone. None of them may mean off."""
        monkeypatch.setenv("SAG_LOCAL_ROUTING", raw)
        with pytest.raises(
            ConfigurationError, match=r"^SAG_LOCAL_ROUTING must be one of: off, detected, all$"
        ):
            Settings.from_env()

    def test_the_default_is_off(self):
        assert Settings().local_routing is LocalRouting.OFF


class TestStartup:
    """What the gateway refuses to start with once the mode is on."""

    @pytest.mark.parametrize("environment", ["development", "production"])
    def test_detected_without_ner_refuses_to_start(self, monkeypatch, environment):
        """Without a model, names are not detected, so `detected` would pass them."""
        monkeypatch.setenv("SAG_ENVIRONMENT", environment)
        monkeypatch.setenv("SAG_VAULT_KEY", "01" * 32)
        monkeypatch.setenv("SAG_TOKEN_KEY", "02" * 32)

        with pytest.raises(ConfigurationError) as caught:
            build_pipeline(Settings(local_routing=LocalRouting.DETECTED, local_base_url=LOCAL_URL))

        assert "SAG_NER_MODEL_PATH" in str(caught.value)
        assert "SAG_LOCAL_ROUTING=all" in str(caught.value)

    def test_detected_with_ner_starts(self, stub_ner):
        pipeline = build_pipeline(
            Settings(local_routing=LocalRouting.DETECTED, local_base_url=LOCAL_URL)
        )
        assert stub_ner in pipeline._detectors
        assert pipeline._policy.version == "community-default-v1+local-routing:detected"

    @pytest.mark.parametrize("mode", MODES_ON)
    def test_the_mode_needs_a_real_local_url_even_in_development(self, monkeypatch, mode):
        """Without one, `local` would be the mock: local by name only."""
        monkeypatch.delenv("SAG_ENVIRONMENT", raising=False)
        with pytest.raises(
            ConfigurationError, match=f"SAG_LOCAL_ROUTING={mode} needs SAG_LOCAL_BASE_URL"
        ):
            build_providers(
                Settings(local_routing=mode), required_destinations=frozenset({"local"})
            )

    def test_off_still_uses_the_mock_for_local_in_development(self, monkeypatch):
        """Today's behaviour, pinned from this side too."""
        monkeypatch.delenv("SAG_ENVIRONMENT", raising=False)
        providers = build_providers(
            Settings(), required_destinations=frozenset({"external", "local"})
        )
        assert providers["local"] is providers["mock"]

    def test_all_never_builds_the_external_client(self):
        pipeline = build_pipeline(
            Settings(
                local_routing=LocalRouting.ALL,
                local_base_url=LOCAL_URL,
                external_base_url="https://1.1.1.1/v1",
                external_api_key="sk-never-used-EXAMPLE",
            )
        )
        assert "external" not in pipeline._providers
        assert pipeline._policy.required_destinations == frozenset({"local"})

    def test_all_in_production_needs_only_the_local_url(self, monkeypatch):
        monkeypatch.setenv("SAG_ENVIRONMENT", "production")
        policy = PolicyEngine.from_yaml(DEFAULT_POLICY).with_local_routing(LocalRouting.ALL)

        providers = build_providers(
            Settings(local_routing=LocalRouting.ALL, local_base_url=LOCAL_URL),
            required_destinations=policy.required_destinations,
        )

        assert set(providers) == {"mock", "local"}

    def test_the_local_provider_ignores_ambient_proxies(self):
        """An unreviewed proxy hop would put a third party back on the path."""
        settings = Settings(
            local_routing=LocalRouting.DETECTED,
            local_base_url=LOCAL_URL,
            external_base_url="https://1.1.1.1/v1",
            trust_env_proxy=True,
        )
        providers = build_providers(
            settings, required_destinations=frozenset({"external", "local"})
        )
        assert providers["local"]._trust_env is False
        assert providers["external"]._trust_env is True

    def test_off_keeps_the_proxy_setting_for_local(self):
        providers = build_providers(
            Settings(local_base_url=LOCAL_URL, trust_env_proxy=True),
            required_destinations=frozenset({"local"}),
        )
        assert providers["local"]._trust_env is True

    @pytest.mark.parametrize("mode", list(LocalRouting))
    async def test_the_proxy_ban_keeps_the_operators_ca_bundle(self, monkeypatch, tmp_path, mode):
        """Only proxies are banned. SAG_TRUST_ENV_PROXY also lets httpx read
        SSL_CERT_FILE and SSL_CERT_DIR, which is how an https model behind an
        internal CA is trusted. Dropping that along with the proxies failed
        every request to such a model with a certificate error."""
        bundle = tmp_path / "internal-ca.pem"
        write_internal_ca(bundle, "Internal test CA")
        monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)

        # Built fresh, not taken from the shared cache, which may hold a store
        # read before SSL_CERT_FILE was set.
        stores: list[ssl.SSLContext] = []

        def fresh_store(trust_env: bool) -> ssl.SSLContext:
            stores.append(verification_context.__wrapped__(trust_env))
            return stores[-1]

        monkeypatch.setattr("gateway.routing.base.verification_context", fresh_store)
        providers = build_providers(
            Settings(
                local_routing=mode, local_base_url="https://10.0.0.5/v1", trust_env_proxy=True
            ),
            required_destinations=frozenset({"local"}),
        )
        local = providers["local"]
        try:
            client = local._pooled_client()
            assert client.trust_env is (mode is LocalRouting.OFF), "proxies only with the mode off"
            assert [ca["subject"] for ca in stores[-1].get_ca_certs()] == [
                ((("commonName", "Internal test CA"),),)
            ]
        finally:
            await local.aclose()

    def test_a_public_local_address_is_refused_at_startup(self):
        with pytest.raises(EgressBlockedError, match="not loopback or a private network"):
            build_providers(
                Settings(local_routing=LocalRouting.ALL, local_base_url="https://1.1.1.1/v1"),
                required_destinations=frozenset({"local"}),
            )

    def test_a_tailscale_address_builds(self):
        providers = build_providers(
            Settings(local_routing=LocalRouting.ALL, local_base_url="http://100.64.0.10:11434/v1"),
            required_destinations=frozenset({"local"}),
        )
        assert providers["local"].egress.require_private_network is True

    def test_off_keeps_todays_local_egress(self):
        """A public `local` URL builds today. The mode off must not change that."""
        providers = build_providers(
            Settings(local_base_url="https://1.1.1.1/v1"),
            required_destinations=frozenset({"external", "local"}),
        )
        assert providers["local"].egress.require_private_network is False

    def test_the_startup_line_is_written_only_with_the_mode_on(self, caplog):
        with caplog.at_level(logging.INFO, logger="gateway.config"):
            build_pipeline(Settings())
        assert not [r for r in caplog.records if "SAG_LOCAL_ROUTING" in r.getMessage()]

    def test_the_startup_line_names_the_mode_and_hostnames_only(self, monkeypatch, caplog):
        """The operator's proof the mode is on, and still a log line (SI-11, SI-12)."""
        manifest = ModelManifest(
            name="test-ner",
            version="0.0.1",
            licence="MIT",
            sha256={"weights.bin": "0" * 64},
            languages=("lv", "en"),
        )
        monkeypatch.setattr(
            "gateway.config.build_ner_detector",
            lambda path: NerDetector(StubBackend([]), manifest=manifest),
        )
        settings = Settings(
            local_routing=LocalRouting.DETECTED,
            local_base_url="http://opuser:oppass@127.0.0.1:11434/v1/private-path",
            local_model="llama3.1:8b",
            external_base_url="https://opuser:oppass@1.1.1.1/v1/external-path",
            external_api_key="sk-startup-line-EXAMPLE",
        )

        with caplog.at_level(logging.INFO, logger="gateway.config"):
            pipeline = build_pipeline(settings)

        lines = [
            record.getMessage()
            for record in caplog.records
            if record.getMessage().startswith("SAG_LOCAL_ROUTING=")
        ]
        assert len(lines) == 1
        line = lines[0]
        assert line.startswith("SAG_LOCAL_ROUTING=detected: ")
        assert pipeline._policy.version in line
        assert "test-ner 0.0.1 (languages lv, en)" in line
        assert "local 127.0.0.1 (private network required), model llama3.1:8b" in line
        assert "external 1.1.1.1" in line
        for leaked in ("opuser", "oppass", "private-path", "external-path", "/v1", "startup-line"):
            assert leaked not in line


class TestTripwire:
    """The pipeline's own check, independent of the engine's rewrite.

    Each pipeline here is given the mode while its policy is not, which is what
    a regression in the engine would look like from the pipeline's side.
    """

    @pytest.fixture
    def tripwired(self, policy, vault, minter, audit_sink, mock_provider, local_provider):
        def build(mode: LocalRouting) -> SecurityPipeline:
            return SecurityPipeline(
                detectors=default_detectors(),
                policy=policy,
                transformer=TransformationEngine(minter, vault),
                restorer=RestorationEngine(vault),
                providers={"mock": mock_provider, "local": local_provider},
                audit_sink=audit_sink,
                local_routing=mode,
            )

        return build

    async def test_a_detected_request_cannot_reach_another_provider(
        self, tripwired, ctx, mock_provider, local_provider
    ):
        with pytest.raises(LocalRoutingViolation) as caught:
            await tripwired(LocalRouting.DETECTED).process(
                ctx, user_message("Write to alice@acme.lv")
            )

        assert mock_provider.received == []
        assert local_provider.received == []
        message = str(caught.value)
        assert "'pseudonymise'" in message
        assert "'mock'" in message
        assert "alice@acme.lv" not in message

    async def test_all_trips_with_nothing_detected(self, tripwired, ctx, mock_provider):
        with pytest.raises(LocalRoutingViolation):
            await tripwired(LocalRouting.ALL).process(ctx, user_message("Explain a mutex"))
        assert mock_provider.received == []

    async def test_detected_does_not_trip_on_a_clean_request(self, tripwired, ctx, mock_provider):
        await tripwired(LocalRouting.DETECTED).process(ctx, user_message("Explain a mutex"))
        assert len(mock_provider.received) == 1

    async def test_a_local_decision_passes(self, tripwired, ctx, mock_provider, local_provider):
        result = await tripwired(LocalRouting.DETECTED).process(
            ctx, user_message(f"Personal code {VALID_LV_CODE}")
        )
        assert result.provider == "local"
        assert mock_provider.received == []
        assert len(local_provider.received) == 1


class TestDecisionTable:
    """Every row of the routing table, at the engine, where the mode is applied."""

    @pytest.mark.parametrize(
        "found",
        [(), ("EMAIL_ADDRESS",), ("LV_PERSONAL_CODE",), ("EMPLOYEE_ID",), ("JWT", "PERSON")],
    )
    def test_off_is_the_uncomposed_engine(self, default_policy, ctx, found):
        """The default for every existing user. Not "equivalent": the same object."""
        composed = default_policy.with_local_routing(LocalRouting.OFF)
        assert composed is default_policy
        assert composed.version == "community-default-v1"
        assert composed.evaluate(ctx, inspection(*found)) == default_policy.evaluate(
            ctx, inspection(*found)
        )

    @pytest.mark.parametrize("mode", MODES_ON)
    def test_a_block_is_never_weakened(self, default_policy, ctx, mode):
        """The mode moves requests. It never releases one."""
        decision = default_policy.with_local_routing(mode).evaluate(
            ctx, inspection("EMAIL_ADDRESS", "AWS_ACCESS_KEY")
        )
        assert decision.action is Action.BLOCK
        assert decision.rule_name == "block-secrets"

    @pytest.mark.parametrize("destination", ["external", "mock", "", "Local", "external "])
    def test_any_span_moves_every_non_local_destination(self, ctx, destination):
        """An allowlist on one exact string. Near-misses are other names."""
        engine = catch_all_to(destination).with_local_routing(LocalRouting.DETECTED)
        decision = engine.evaluate(ctx, inspection("PERSON", "EMAIL_ADDRESS", "PERSON"))

        assert decision.action is Action.ROUTE_LOCAL
        assert decision.destination == "local"
        assert decision.rule_name == "local-routing:detected"
        assert decision.matched_entities == ("EMAIL_ADDRESS", "PERSON")
        assert "catch-all" in decision.reason

    def test_detected_leaves_a_clean_request_to_the_policy(self, default_policy, ctx):
        """No over-routing: nothing found, nothing moved."""
        decision = default_policy.with_local_routing(LocalRouting.DETECTED).evaluate(
            ctx, inspection()
        )
        assert decision.action is Action.ALLOW
        assert decision.destination == "external"
        assert decision.rule_name == "default-allow"

    @pytest.mark.parametrize("found", [(), ("EMAIL_ADDRESS",), ("EMPLOYEE_ID",)])
    def test_all_moves_every_decision_that_is_not_a_block(self, default_policy, ctx, found):
        decision = default_policy.with_local_routing(LocalRouting.ALL).evaluate(
            ctx, inspection(*found)
        )
        assert decision.action is Action.ROUTE_LOCAL
        assert decision.destination == "local"
        assert decision.rule_name == "local-routing:all"
        assert decision.matched_entities == found

    @pytest.mark.parametrize("mode", MODES_ON)
    def test_a_decision_already_local_keeps_its_rule(self, default_policy, ctx, mode):
        decision = default_policy.with_local_routing(mode).evaluate(
            ctx, inspection("LV_PERSONAL_CODE")
        )
        assert decision.action is Action.ROUTE_LOCAL
        assert decision.rule_name == "baltic-ids-local-only"

    @pytest.mark.parametrize("mode", MODES_ON)
    def test_an_explicit_allow_to_local_keeps_its_action(self, ctx, mode):
        """The operator chose to send original text to their own model."""
        decision = (
            catch_all_to("local")
            .with_local_routing(mode)
            .evaluate(ctx, inspection("EMAIL_ADDRESS"))
        )
        assert decision.action is Action.ALLOW
        assert decision.rule_name == "catch-all"

    @pytest.mark.parametrize("mode", MODES_ON)
    @pytest.mark.parametrize(
        "found", [(), ("EMAIL_ADDRESS",), ("LV_PERSONAL_CODE",), ("SLACK_TOKEN",)]
    )
    def test_every_decision_names_the_mode_in_its_version(self, default_policy, ctx, mode, found):
        """Blocks included: the audit must show which mode judged a request."""
        engine = default_policy.with_local_routing(mode)
        assert engine.version == f"community-default-v1+local-routing:{mode}"
        assert engine.evaluate(ctx, inspection(*found)).policy_version == engine.version

    def test_required_destinations_follow_the_mode(self, default_policy):
        """Startup checks what the mode can reach, not what the rules name."""
        external_only = catch_all_to("external")
        detected = external_only.with_local_routing(LocalRouting.DETECTED)
        everything = external_only.with_local_routing(LocalRouting.ALL)

        assert external_only.required_destinations == frozenset({"external"})
        assert detected.required_destinations == frozenset({"external", "local"})
        assert everything.required_destinations == frozenset({"local"})

        shipped = default_policy.with_local_routing(LocalRouting.ALL)
        assert shipped.required_destinations == frozenset({"local"})

    def test_the_mode_cannot_be_applied_twice(self, default_policy):
        once = default_policy.with_local_routing(LocalRouting.DETECTED)
        with pytest.raises(PolicyError, match="already applied"):
            once.with_local_routing(LocalRouting.ALL)

    def test_composing_after_the_mode_keeps_it(self, default_policy, ctx):
        """A filter composed later must not be able to drop the floor."""
        composed = default_policy.with_local_routing(LocalRouting.DETECTED).with_rules(
            [
                Rule(
                    name="filter:mail-out",
                    priority=95,
                    action=Action.TRANSFORM,
                    destination="external",
                    entities=frozenset({"EMAIL_ADDRESS"}),
                )
            ],
            version_suffix="filters:0123456789abcdef",
        )
        assert composed.local_routing is LocalRouting.DETECTED
        decision = composed.evaluate(ctx, inspection("EMAIL_ADDRESS"))
        assert decision.destination == "local"
        assert decision.rule_name == "local-routing:detected"


class TestApplyLocalRouting:
    """The pure function on its own: total, and it never invents a decision."""

    DECISION = PolicyDecision(
        action=Action.TRANSFORM,
        destination="external",
        rule_name="pseudonymise",
        policy_version="v1",
        matched_entities=("EMAIL_ADDRESS",),
    )

    def test_off_returns_the_decision_itself(self):
        found = inspection("EMAIL_ADDRESS")
        assert apply_local_routing(LocalRouting.OFF, self.DECISION, found) is self.DECISION

    def test_a_moved_decision_keeps_the_version_and_names_what_it_replaced(self):
        moved = apply_local_routing(LocalRouting.ALL, self.DECISION, inspection())
        assert moved.policy_version == "v1"
        assert moved.matched_entities == ()
        assert "'pseudonymise'" in moved.reason
        assert "'external'" in moved.reason

    def test_a_nan_score_still_counts_as_detected(self):
        """A span a rule cannot compare against is still a span."""
        found = inspection("EMAIL_ADDRESS", score=math.nan)
        moved = apply_local_routing(LocalRouting.DETECTED, self.DECISION, found)
        assert LocalRouting.DETECTED.requires_local(found)
        assert moved.destination == "local"


# ---------------------------------------------------------------------------
# The property: whatever the policy, a detected request goes nowhere but local
# ---------------------------------------------------------------------------


def _from_dict(version: str, *rules: dict, default_destination: str = "external") -> PolicyEngine:
    return PolicyEngine.from_dict(
        {"version": version, "default_destination": default_destination, "rules": list(rules)}
    )


_CATCH_ALL_EXTERNAL = {
    "name": "catch-all",
    "priority": 10,
    "action": {"type": "allow", "destination": "external"},
}


def _filter_shaped(name: str, priority: int, entity: str) -> Rule:
    return Rule(
        name=name,
        priority=priority,
        action=Action.TRANSFORM,
        destination="external",
        entities=frozenset({entity}),
    )


#: Policies that each route some detected request away from `local` without the
#: mode. Every one of them was a way round the enumerated preset this replaces.
ADVERSARIAL_POLICIES = [
    PolicyEngine.from_yaml(DEFAULT_POLICY),
    _from_dict(
        "application-scoped",
        {
            "name": "app-allow",
            "priority": 999,
            "match": {"applications": ["test-app"]},
            "action": {"type": "allow", "destination": "external"},
        },
        _CATCH_ALL_EXTERNAL,
    ),
    _from_dict(
        "route-local-without-destination",
        {
            "name": "personal-local",
            "priority": 90,
            "match": {"entities": ["EMAIL_ADDRESS", "PERSON"]},
            "action": {"type": "route_local"},
        },
        _CATCH_ALL_EXTERNAL,
    ),
    _from_dict(
        "min-score",
        {
            "name": "confident-local",
            "priority": 90,
            "match": {"entities": ["EMAIL_ADDRESS", "IP_ADDRESS"], "min_score": 0.9},
            "action": {"type": "route_local", "destination": "local"},
        },
        _CATCH_ALL_EXTERNAL,
    ),
    _from_dict(
        "name-tie",
        {
            "name": "a-allow",
            "priority": 50,
            "match": {"entities": ["PERSON"]},
            "action": {"type": "allow", "destination": "external"},
        },
        {
            "name": "b-local",
            "priority": 50,
            "match": {"entities": ["PERSON"]},
            "action": {"type": "route_local", "destination": "local"},
        },
        _CATCH_ALL_EXTERNAL,
    ),
    PolicyEngine.from_yaml(DEFAULT_POLICY).with_rules(
        [_filter_shaped("filter:mail-out", 95, "EMAIL_ADDRESS")], version_suffix="filters:95"
    ),
    # At 90, and named to sort before `baltic-ids-local-only`, so it wins the tie.
    PolicyEngine.from_yaml(DEFAULT_POLICY).with_rules(
        [_filter_shaped("a-codes-out", 90, "LV_PERSONAL_CODE")], version_suffix="filters:90"
    ),
    _from_dict(
        "typo",
        {
            # `mach` is not `match`: the loader reads a rule with no conditions,
            # which is a catch-all at priority 100.
            "name": "mail-external",
            "priority": 100,
            "mach": {"entities": ["EMAIL_ADDRESS"]},
            "action": {"type": "allow", "destination": "external"},
        },
        {
            "name": "personal-local",
            "priority": 50,
            "match": {"entities": ["EMAIL_ADDRESS"]},
            "action": {"type": "route_local", "destination": "local"},
        },
    ),
]

#: Labels the policies above name, so their rules match often enough to matter.
#: Random labels cover every type no policy names, which is the drift case.
_NAMED_LABELS = [
    "AWS_ACCESS_KEY",
    "EMAIL_ADDRESS",
    "IP_ADDRESS",
    "LV_PERSONAL_CODE",
    "PERSON",
]

entity_labels = st.one_of(
    st.sampled_from(_NAMED_LABELS),
    st.from_regex(r"[A-Z][A-Z0-9_]{0,31}", fullmatch=True),
)
scores = st.one_of(st.floats(min_value=0.0, max_value=1.0), st.just(math.nan))


@given(
    policy=st.sampled_from(ADVERSARIAL_POLICIES),
    extra_filter=st.one_of(st.none(), entity_labels),
    mode=st.sampled_from(list(LocalRouting)),
    found=st.lists(st.tuples(entity_labels, scores), max_size=4),
    application=st.sampled_from(["test-app", "other"]),
)
@settings(max_examples=300, deadline=None)
def test_no_detected_request_leaves_for_a_non_local_destination(
    policy, extra_filter, mode, found, application
):
    if extra_filter is not None:
        policy = policy.with_rules(
            [_filter_shaped("filter:drawn", 95, extra_filter)], version_suffix="filters:drawn"
        )
    ctx = RequestContext("tenant-a", "conv-1", "req-1", "key-1", application=application)
    result = InspectionResult(
        spans=[
            Span(start=i * 10, end=i * 10 + 5, entity_type=label, text="xxxxx", score=score)
            for i, (label, score) in enumerate(found)
        ]
    )

    decision = policy.with_local_routing(mode).evaluate(ctx, result)
    uncomposed = policy.evaluate(ctx, result)

    if mode is LocalRouting.OFF:
        assert decision == uncomposed
    elif mode is LocalRouting.ALL or result.spans:
        assert decision.action is Action.BLOCK or decision.destination == "local"
    else:
        assert (decision.action, decision.destination, decision.rule_name) == (
            uncomposed.action,
            uncomposed.destination,
            uncomposed.rule_name,
        )
