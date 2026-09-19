# Security Policy

## Status: alpha — not production-ready

This software has **not** had an independent security review. Security invariant
#10 forbids any production claim before one. Do not place it in front of
production traffic yet.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately via GitHub private vulnerability reporting ("Report a
vulnerability" on the Security tab). If that control is unavailable, do not
open a public issue containing exploit details or sensitive data; use the
maintainer contact shown on the repository owner's GitHub profile.

Please include: affected version or commit, a description, reproduction steps,
and the impact as you see it. A proof of concept helps but is not required.

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial assessment | 10 business days |
| Fix for critical severity | 72 hours after confirmation |
| Fix for high severity | 7 days |
| Advisory published | Within 5 days of the fix |

We will credit reporters who want it, and we will not take legal action against
good-faith research that respects user privacy and avoids service disruption.

## Scope

**In scope:** the gateway request path, detection, transformation, restoration,
the surrogate vault, policy evaluation, authentication, audit generation, and
the container image.

**Especially interesting to us** — these are the claims the product rests on:

- Restoring a token that was not minted for the request (see
  `gateway/restoration/engine.py`)
- Any cross-tenant data access
- Detection evasion that gets a sensitive value past the gateway unmodified
- Raw prompt content appearing in logs, audit events, or errors
- Provider credentials appearing anywhere they should not

**Out of scope:** vulnerabilities in third-party model providers; issues
requiring a compromised host or physical access; missing hardening headers with
no demonstrated impact; volumetric denial of service; and known open risks
already documented in `docs/threat-model.md` (report them if you can demonstrate
a materially worse impact than described).

## Known limitations — deliberately public

These are documented rather than hidden. Reporting them again is not necessary,
but a working exploit demonstrating greater impact is welcome.

- Homoglyph and invisible-character evasion is only partly mitigated (NFKC does
  not fold Cyrillic↔Latin confusables) — R-04
- Tool calls and structured output are not inspected; v1 refuses non-text
  content rather than forwarding it — R-08
- Egress validation cannot prevent the final resolver/connect DNS-rebinding
  race — R-02
- The customer-regex ReDoS screen is a heuristic, not a complete analysis — R-03
- No built-in rate limiting or enforceable detector deadline yet
- Error paths do not all emit audit events, and no metrics endpoint exists
- The source SBOM path exists, but the release image SBOM, signature, scan, and
  provenance have not yet completed against a public release candidate — R-01

## Supported versions

During alpha, only the latest commit on `main` is supported. A formal
supported-version policy is a GA release gate.

## Cryptography

We use `cryptography` (AES-256-GCM) and the standard library's `hmac`/`hashlib`.
**We implement no cryptographic primitives ourselves** (invariant SI-09). Reports of
misuse of these libraries are very much in scope; reports proposing that we
replace them with custom constructions are not.
