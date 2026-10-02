# Preparing the first alpha

`v0.1.0-alpha.1` is the GitHub prerelease tag; `0.1.0a1` is the equivalent
Python package version. Release preparation does not publish a tag, release,
container, or PyPI package.

## Build and check the downloads

After `make setup`, run `make package`. This builds the wheel and source
distribution, installs each in its own temporary virtual environment outside
the checkout, and starts the installed `cloakspan playground` command. It
checks the bundled browser assets and inspects a synthetic email using the
packaged default policy, with no provider credentials.

CI repeats these checks on Linux, macOS, and Windows. After all checks on
`main` pass, it prepares a **draft prerelease** with the packages, the runtime
dependency lock, checksums, and the versioned release notes. An existing draft
is refreshed; a published release is never overwritten. The draft's target
commit identifies the checked source. Download files from the same CI run when
reviewing an unpublished draft.

## Publication gate

Before publishing the first alpha:

1. Complete the security and operational evidence in [ROADMAP.md](../../ROADMAP.md).
   In particular, record the Hetzner staging install, upgrade, rollback, and
   failure rehearsal in `docs/releases/v0.1.0-alpha.1-staging.md`, including
   the tested commit, host, commands, observed results, and date. No staging
   host or rehearsal report is available yet; the tag workflow refuses to
   publish without that report and finalized release notes.
2. Keep the base-image digest pinned and the runtime dependencies hash-verified.
   Re-run the container build, hardening tests, SBOM, and vulnerability checks
   after any base-image or dependency change.
3. Review all CI jobs for the exact release commit and the draft's assets.
4. Remove the draft-status paragraph from the release notes only after the
   missing evidence is recorded. Finalize the changelog date and merge those
   documentation changes; wait for the refreshed draft and CI checks.
5. Create and push `v0.1.0-alpha.1` at that checked commit. The tag workflow
   runs the gates again, pushes the exact tested container, signs and attests
   it, and publishes the prepared GitHub prerelease only after those steps pass.

An automated package smoke test is not an independent human installation test
or a staging rehearsal. Beta and stable milestones retain their own requirements.
