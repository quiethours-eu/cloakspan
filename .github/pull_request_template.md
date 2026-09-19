## Summary

Describe the behavior changed and why.

## Security and compatibility

- [ ] I identified whether this changes auth, policy, detection, transformation,
      restoration, vault, egress, audit, dependencies, or release workflows.
- [ ] Unknown or uninspectable content still fails closed.
- [ ] Logs, errors, audit events, metrics, and fixtures contain no real sensitive data.
- [ ] Public compatibility and limitation claims still match behavior.

## Verification

- [ ] Tests added or updated, including failure and boundary cases.
- [ ] `make test` passes.
- [ ] `make lint` passes.
- [ ] Relevant docs, risk register, and changelog are updated.
- [ ] Container/release evidence is attached when this affects the image or deployment.
