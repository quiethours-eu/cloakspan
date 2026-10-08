# Synthetic protocol fixtures and public CLI evidence

The generated v1 samples and `contract.json` are constructed gateway fixtures,
not captured client traffic. Their personal values and credentials are public
synthetic canaries; they represent no real repository, transcript, credential,
CLI version, bridge or desktop deployment. The separate public CLI aggregate
below records actual pinned binary runs using disposable synthetic data.

`sample_math.py.txt` and `test_sample_math.py.txt` are copied into a disposable
workspace by `tests/test_agent_workflows.py`. The tests execute the returned
registered read, exact edit, patch, and pytest arguments in a test-only client
harness, assert the resulting file contents and test outcome, then replay the
original restored history through the gateway. The gateway itself never runs
these operations.

`contract.json` records the generated v1 fixture scope and gates that those
fixtures do not prove. It is not the current client qualification matrix.
Explicit opaque continuation refusal is tested here; refusing an opaque request
does not establish successful inspectable compaction.

Actual pinned Codex CLI 0.161.0 and Claude Code CLI 2.1.293 runs are separate
evidence, produced by `scripts/public_client_check.py` against a deterministic
local provider and disposable synthetic repositories. The
[compatibility matrix](../../../docs/agent-compatibility.md#actual-public-cli-evidence-2026-10-08)
records those coding, history and automatic-compaction observations and their
exact test controls. These constructed fixtures remain unchanged by the actual
CLI recordings. Desktop, bridge, live-provider and production capacity
qualification remain separate.

`public-cli-qualification.json` is a sanitized aggregate from the actual pinned
CLI workflow, including successful native runs, automatic compaction/resume
assertions and exact test controls. It contains no raw requests, client session
or device IDs, or recording paths. It is separate from the generated
`contract.json` fixtures and does not qualify a live or desktop deployment.
