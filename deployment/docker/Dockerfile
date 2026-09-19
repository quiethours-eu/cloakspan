# Multi-stage build. The runtime stage carries no build toolchain, no package
# manager cache, and no source for anything but the application itself.
#
# BASE_REF is the base image. Development builds may pass a tag; **release
# builds must pass an immutable digest** -- a tag names different bytes over
# time, so a build referencing one is not reproducible and an SBOM taken from it
# describes an artefact that no longer exists.
#
#   make image          -> tag, for development
#   make release-image  -> digest, and refuses to run without one
#
# See deployment/docker/base-image.env and scripts/pin_base_image.py.
ARG BASE_REF=python:3.12-alpine3.23

FROM ${BASE_REF} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY gateway ./gateway
COPY recognizers ./recognizers
COPY deployment/policies/default.yaml ./deployment/policies/default.yaml

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir .

# ---------------------------------------------------------------------------

# ARG is scoped per stage; redeclare so the runtime stage sees the same value.
ARG BASE_REF
FROM ${BASE_REF} AS runtime

# Patch the base image, then remove the package manager and its metadata from
# the runtime layer. Alpine's smaller package set also avoids carrying dozens
# of unfixed vulnerabilities inherited from the Debian slim image.
RUN apk upgrade --no-cache \
 && rm -rf /var/cache/apk/* /lib/apk/db/lock \
 && rm -f /sbin/apk

# Non-root, no login shell, no home directory to write into.
RUN addgroup -g 10001 -S gateway \
 && adduser -u 10001 -S -D -H -G gateway -s /sbin/nologin gateway

COPY --from=builder /opt/venv /opt/venv
COPY --chown=root:root deployment/policies /etc/secure-ai-gateway/policies

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SAG_POLICY_PATH=/etc/secure-ai-gateway/policies/default.yaml

USER 10001:10001
EXPOSE 8080

# Liveness only -- readiness is a separate endpoint and deliberately does not
# depend on any external provider (security invariant SI-15).
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
  CMD ["python", "-c", "from urllib.request import urlopen; assert urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200"]

ENTRYPOINT ["python", "-m", "uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8080", "--timeout-graceful-shutdown", "30"]
