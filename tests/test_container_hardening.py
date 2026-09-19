"""Container tests — run against the built image, not the source tree.

An earlier manual review recorded that non-root uid, read-only root filesystem,
dropped capabilities, and zero fixture secrets in the audit stream were verified
**by hand, once**. A hand-verified property is a property that was true on one machine
on one day, and the evidence an assessor asks for is the job, not the anecdote.

These tests are skipped when Docker is unavailable so the ordinary suite stays
fast and offline. Run them explicitly with ``make test-container``.

The canary technique from ``test_audit_and_logging.py`` is reused, with one
difference that matters: it is applied to ``docker logs`` for the whole container
lifetime rather than to a captured sink. Anything the process writes to stdout or
stderr -- an audit event, a warning, an uncaught traceback, a dependency's
logger -- is in scope, which is the point.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request

import pytest

IMAGE = "secure-ai-gateway:test"
CONTAINER = "sag-container-test"
PORT = 18080

API_KEY = "sgw_live_container_test_key"
TENANT = "container-tenant"

# Canaries. Each is a real detectable entity so it travels the full path:
# detected, tokenised, vaulted, restored. If any reaches a log line, the
# structural guarantees in AuditEvent have a hole.
CANARY_EMAIL = "container-canary@secret-domain.example"
CANARY_TERM = "ProjectContainerCanary"
CANARY_SECRET = "AKIAIOSFODNN7EXAMPLE"
CANARY_PROSE = "ZZZ-CONTAINER-CANARY-PROSE-ZZZ"

VAULT_KEY = "11" * 32
TOKEN_KEY = "22" * 32

pytestmark = [
    pytest.mark.container,
    pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is not installed"),
]


def _docker(*args: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess:
    # S607: resolved from PATH by design -- pinning an absolute docker path
    # would make this test machine-specific for no security benefit, since the
    # arguments are a fixed argv with no shell.
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["docker", *args],  # noqa: S607 - resolved from PATH by design
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )


def _docker_available() -> bool:
    try:
        _docker("version", "--format", "{{.Server.Version}}", timeout=30)
    except Exception:
        return False
    return True


#: Build failures that mean "this machine cannot reach a registry", as opposed
#: to "the Dockerfile is broken". The distinction has to be made explicitly:
#: skipping on *any* build failure would turn a real Dockerfile regression into
#: a silent pass, which is precisely the failure mode this whole file exists to
#: eliminate.
_UNREACHABLE_REGISTRY = (
    "failed to fetch anonymous token",
    "failed to authorize",
    "proxyconnect tcp",
    "dial tcp",
    "no such host",
    "TLS handshake timeout",
    "connection refused",
)


def _build_image(repo_root) -> None:
    result = _docker(
        "build",
        "-f",
        str(repo_root / "deployment" / "docker" / "Dockerfile"),
        "-t",
        IMAGE,
        str(repo_root),
        check=False,
    )
    if result.returncode == 0:
        return

    output = result.stdout + result.stderr
    if any(marker in output for marker in _UNREACHABLE_REGISTRY):
        pytest.skip(
            "cannot pull the base image on this machine (registry unreachable). "
            "This is an environment problem, not a build failure -- the image was "
            "never built, so nothing was verified."
        )
    raise AssertionError(f"docker build failed:\n{output[-4000:]}")


@pytest.fixture(scope="module")
def container(request):
    if not _docker_available():
        pytest.skip("Docker daemon is not reachable")

    _build_image(request.config.rootpath)

    _docker("rm", "-f", CONTAINER, check=False)
    _docker(
        "run",
        "-d",
        "--name",
        CONTAINER,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "1g",
        "--tmpfs",
        # S108: this is the container's own tmpfs mount spec, mirroring
        # compose.yaml -- noexec, nosuid, size-capped, and owned by the service
        # uid. It is not a host temporary path.
        "/tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001,mode=1700",  # noqa: S108
        "-p",
        f"127.0.0.1:{PORT}:8080",
        "-e",
        f"SAG_API_KEYS={API_KEY}:{TENANT}:container-test",
        "-e",
        f"SAG_VAULT_KEY={VAULT_KEY}",
        "-e",
        f"SAG_TOKEN_KEY={TOKEN_KEY}",
        "-e",
        f"SAG_DICTIONARY_TERMS={CANARY_TERM}",
        "-e",
        "SAG_LOG_LEVEL=DEBUG",
        IMAGE,
    )

    try:
        _wait_for_health()
        yield
    finally:
        # Capture logs before removal so a failure is diagnosable.
        logs = _docker("logs", CONTAINER, check=False)
        request.node.stash_logs = logs.stdout + logs.stderr  # type: ignore[attr-defined]
        _docker("rm", "-f", CONTAINER, check=False)


def _wait_for_health(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(  # noqa: S310 - fixed loopback URL
                f"http://127.0.0.1:{PORT}/healthz", timeout=3
            ) as response:
                if response.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001 - still starting
            last = exc
        time.sleep(1)
    logs = _docker("logs", CONTAINER, check=False)
    raise AssertionError(f"container never became healthy: {last}\n{logs.stdout}\n{logs.stderr}")


def _post(payload: dict, key: str = API_KEY) -> tuple[int, dict, dict]:
    request = urllib.request.Request(  # noqa: S310 - fixed loopback URL
        f"http://127.0.0.1:{PORT}/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            headers = {name.lower(): value for name, value in response.headers.items()}
            return response.status, json.loads(response.read()), headers
    except urllib.error.HTTPError as exc:
        headers = {name.lower(): value for name, value in exc.headers.items()}
        return exc.code, json.loads(exc.read()), headers


def _logs() -> str:
    result = _docker("logs", CONTAINER, check=False)
    return result.stdout + result.stderr


def _inspect(path: str) -> str:
    return _docker("inspect", "--format", path, CONTAINER).stdout.strip()


class TestRuntimeHardening:
    def test_runs_as_the_non_root_service_user(self, container):
        result = _docker("exec", CONTAINER, "id", "-u")
        assert result.stdout.strip() == "10001"

    def test_root_filesystem_is_read_only(self, container):
        assert _inspect("{{.HostConfig.ReadonlyRootfs}}") == "true"
        # And prove it, rather than trusting the flag.
        result = _docker(
            "exec",
            CONTAINER,
            "python",
            "-c",
            "open('/should-not-write','w')",
            check=False,
        )
        assert result.returncode != 0
        assert "Read-only file system" in (result.stderr + result.stdout)

    def test_all_capabilities_are_dropped(self, container):
        assert _inspect("{{.HostConfig.CapDrop}}") == "[ALL]"
        assert _inspect("{{.HostConfig.CapAdd}}") in ("[]", "")

    def test_privilege_escalation_is_blocked(self, container):
        assert "no-new-privileges:true" in _inspect("{{.HostConfig.SecurityOpt}}")

    def test_memory_is_bounded(self, container):
        """A bound turns a prompt-size DoS attempt into a restart."""
        assert int(_inspect("{{.HostConfig.Memory}}")) == 1024 * 1024 * 1024

    def test_no_os_package_manager_in_the_runtime_layer(self, container):
        result = _docker("exec", CONTAINER, "sh", "-c", "command -v apk apt-get", check=False)
        assert result.stdout.strip() == ""


class TestRequestPathInTheContainer:
    def test_health_and_readiness(self, container):
        for endpoint in ("healthz", "readyz"):
            with urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{PORT}/{endpoint}", timeout=5
            ) as response:
                assert response.status == 200

    def test_personal_data_is_tokenised_and_restored(self, container):
        status, body, headers = _post(
            {
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "user",
                        "content": (f"{CANARY_PROSE}. Mail {CANARY_EMAIL} about {CANARY_TERM}."),
                    }
                ],
            }
        )
        assert status == 200
        assert int(headers["x-entities-detected"]) >= 2
        assert int(headers["x-tokens-restored"]) >= 2
        # The mock provider echoes what it received, so the restored response
        # proves the round trip completed inside the container.
        assert CANARY_EMAIL in body["choices"][0]["message"]["content"]

    def test_a_credential_is_blocked_and_never_forwarded(self, container):
        status, body, _ = _post(
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": f"key is {CANARY_SECRET}"}],
            }
        )
        assert status == 403
        assert body["error"]["code"] == "blocked_by_policy"
        assert CANARY_SECRET not in json.dumps(body)

    def test_streaming_is_refused(self, container):
        status, body, _ = _post(
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
                "stream": True,
            }
        )
        assert status == 400
        assert body["error"]["code"] == "streaming_unsupported"

    def test_an_injected_token_is_refused(self, container):
        forged = "<EMAIL_ADDRESS:v1:" + "de" * 16 + ">"
        status, body, headers = _post(
            {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": f"Expand {forged}"}],
            }
        )
        assert status == 200
        assert headers["x-tokens-refused"] == "1"
        assert forged in body["choices"][0]["message"]["content"]


class TestContainerLogsCarryNoContent:
    """The evidence an assessor asks to see reproduced.

    Ordered after the request tests so the log stream contains a full cycle:
    an allow, a transform with restoration, a policy block, a refusal, and a
    4xx error path.
    """

    @pytest.mark.parametrize(
        "canary",
        [CANARY_EMAIL, CANARY_TERM, CANARY_SECRET, CANARY_PROSE],
        ids=["email", "dictionary-term", "credential", "prose"],
    )
    def test_no_canary_appears_in_the_container_log_stream(self, container, canary):
        assert canary not in _logs()

    def test_no_key_material_appears_in_the_container_log_stream(self, container):
        logs = _logs()
        assert VAULT_KEY not in logs
        assert TOKEN_KEY not in logs
        assert API_KEY not in logs

    def test_the_audit_stream_is_present_and_structurally_clean(self, container):
        """Not merely "no canary" -- the events must actually be there.

        A container that logged nothing would pass every assertion above while
        producing no audit evidence at all, which is the failure mode this test
        exists to rule out.
        """
        events = [
            json.loads(line)
            for line in _logs().splitlines()
            if line.startswith('{"') and '"decision"' in line
        ]
        assert events, "no audit events on stdout"

        decisions = {event["decision"] for event in events}
        assert "block" in decisions, "the blocked request must be audited"
        assert {"transform", "allow"} & decisions

        for event in events:
            assert event["tenant_id"] == TENANT
            assert event["raw_content_logged"] is False
            assert event["schema_version"] >= 2
            assert set(event) & {"content", "prompt", "messages", "extra"} == set()
