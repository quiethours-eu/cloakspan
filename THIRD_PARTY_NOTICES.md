# Third-Party Notices

This product includes software developed by third parties. Their licences and
required notices are reproduced below.

Full provenance for every concept, pattern, and dependency — including projects
we studied but did **not** take code from — is recorded in an internal
provenance file and licence matrix. Those are held privately rather than
published because naming projects with unreported security issues would create
an uncoordinated disclosure. They are available to auditors and reviewers on
request.

Nothing in this file depends on that record: every component below is consumed
as an installable package under its own licence, and no third-party code has
been copied into this codebase.

**No code has been copied from any third-party repository into this codebase.**
Every third-party component listed here is consumed as an installable package.
Algorithms studied during research were reimplemented independently
(clean-room); see the CLEAN_ROOM_REIMPLEMENTATION rows in the provenance file.

---

## Runtime dependencies (default install)

| Package | Licence | Purpose |
|---|---|---|
| FastAPI | MIT | HTTP framework |
| Starlette | BSD-3-Clause | ASGI toolkit (via FastAPI) |
| Pydantic | MIT | Validation |
| Uvicorn | BSD-3-Clause | ASGI server |
| httpx | BSD-3-Clause | HTTP client |
| PyYAML | MIT | Policy file parsing |
| cryptography | Apache-2.0 OR BSD-3-Clause (we elect **Apache-2.0**) | AES-256-GCM |

`cryptography` bundles statically-linked **OpenSSL** (Apache-2.0 since 3.0).

## Optional dependencies

| Extra | Package | Licence | Notes |
|---|---|---|---|
| `[ner]` | presidio-analyzer | MIT | Pulls **spaCy** (MIT). **No spaCy language model is bundled** — several are CC-BY-SA-4.0 (share-alike) and the operator supplies their own |
| `[routing]` | litellm | **MIT (core only)** | See the important notice below |
| `[postgres]` | asyncpg | Apache-2.0 | |
| `[dev]` | pytest (MIT), hypothesis (MPL-2.0), ruff (MIT) | | Development only; not distributed |

---

## ⚠️ Important notice regarding LiteLLM

The `litellm` repository is **not** uniformly licensed.

- Content under **`enterprise/`** is licensed under the proprietary **BerriAI
  Enterprise License** and is distributed as a separate PyPI package,
  `litellm-enterprise`.
- All other content is **MIT**.

This product depends **only** on the MIT-licensed `litellm` package. It does
**not** depend on, bundle, or redistribute `litellm-enterprise`, and it does not
use the LiteLLM proxy server.

This is enforced automatically by `tests/test_licence_boundary.py`, which fails
the build if `litellm-enterprise` appears in the dependency tree or is importable
in the build environment.

---

## MIT License

Applies to FastAPI, Pydantic, PyYAML, presidio-analyzer, litellm (core), spaCy,
pytest, and ruff. Copyright is held by the respective authors.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## BSD 3-Clause License

Applies to Starlette, Uvicorn, and httpx. Copyright is held by the respective
authors. Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the conditions of the BSD 3-Clause
License are met, including retention of the copyright notice and disclaimer, and
that neither the names of the copyright holders nor of their contributors may be
used to endorse or promote products derived from this software without specific
prior written permission.

## Apache License 2.0

Applies to `cryptography` (as elected) and `asyncpg`. The full text is in
[LICENSE](LICENSE), which is also this project's own licence.

## Mozilla Public License 2.0

Applies to **hypothesis**, a development-only dependency. MPL-2.0 is file-level
copyleft; because hypothesis is used unmodified as a test dependency and is not
distributed with this product, no source-disclosure obligation arises.

---

## Trademarks

This product is not affiliated with, endorsed by, or sponsored by any of the
projects or organisations named above.

In particular:

- **Presidio** is a project of the `data-privacy-stack` organisation. It was
  formerly hosted under `microsoft/presidio`, which now redirects. This product
  must **not** be described as using "Microsoft Presidio".
- **LiteLLM** and **BerriAI** are marks of Berrie AI Inc.
- **AWS**, **Amazon Bedrock**, and related marks belong to Amazon.com, Inc. or
  its affiliates. The MIT-0 licence on the AWS sample repositories grants
  copyright permission only and conveys **no trademark rights**.

## Reporting

If you believe a required notice is missing or incorrect, please report it via
the process in `SECURITY.md` or by opening an issue.
