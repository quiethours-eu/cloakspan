"""SBOM and licence inventory, generated from the resolved environment.

Run:

    python scripts/supply_chain.py sbom      --output sbom.cdx.json
    python scripts/supply_chain.py licences  --output licence-report.json
    python scripts/supply_chain.py check                  # CI gate

## Why generated here rather than by Syft

Syft is the right tool for the *container image* and the CI workflow calls it
there. This exists for the **source** SBOM, and it has one property Syft cannot
offer: it reads the interpreter that will actually run, so it reports what is
importable rather than what a manifest says should be. A dependency that got in
through a transitive pin, a local wheel, or an editable install appears here.

It also means `make sbom` works on a machine with no Internet and no extra
tooling, which matters because the people most likely to want an SBOM are the
ones who cannot install things freely.

## Licence policy

Copyleft and unknown licences are **blocking**. Not because copyleft is bad, but
because our buyers are regulated European organisations who frequently have a
written policy against AGPL, and a dependency that quietly introduces one is a
procurement problem discovered at the worst possible moment.

`REVIEW_REQUIRED` is separate from `DENIED` on purpose: weak copyleft (MPL,
LGPL) is usually fine when dynamically linked and shipped unmodified, but that
is a decision with a name attached, not a default.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from importlib.metadata import Distribution, distributions
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

#: Permissive licences, usable without further review.
ALLOWED = {
    "APACHE-2.0",
    "APACHE 2.0",
    "APACHE SOFTWARE LICENSE",
    "BSD",
    "BSD-2-CLAUSE",
    "BSD-3-CLAUSE",
    "BSD LICENSE",
    "ISC",
    "ISCL",
    "MIT",
    "MIT LICENSE",
    "MIT-CMU",
    "PSF",
    "PYTHON SOFTWARE FOUNDATION LICENSE",
    "UNLICENSE",
    "0BSD",
    "ZLIB",
    "MIT-0",
    "PSF-2.0",
    "PYTHON-2.0",
    "APACHE SOFTWARE LICENSE 2.0",
}

#: Weak copyleft and anything ambiguous: allowed only with a recorded decision.
REVIEW_REQUIRED = {
    "MPL-2.0",
    "MOZILLA PUBLIC LICENSE 2.0 (MPL 2.0)",
    "LGPL",
    "LGPL-2.1",
    "LGPL-3.0",
    "GNU LESSER GENERAL PUBLIC LICENSE V2 (LGPLV2)",
    "GNU LESSER GENERAL PUBLIC LICENSE V3 (LGPLV3)",
    "EPL-2.0",
    "CDDL-1.0",
    "CC-BY-SA-4.0",
}

#: Strong copyleft and proprietary. A dependency landing here fails the build.
DENIED = {
    "GPL",
    "GPL-2.0",
    "GPL-3.0",
    "AGPL",
    "AGPL-3.0",
    "GNU AFFERO GENERAL PUBLIC LICENSE V3 (AGPLV3)",
    "GNU GENERAL PUBLIC LICENSE V2 (GPLV2)",
    "GNU GENERAL PUBLIC LICENSE V3 (GPLV3)",
    "SSPL-1.0",
    "BUSL-1.1",
    "ELASTIC-2.0",
    "PROPRIETARY",
}

#: Distributions whose review outcome is recorded, so the gate stays green
#: without weakening the policy. Each needs a reason a lawyer would accept.
REVIEWED: dict[str, str] = {
    "certifi": "MPL-2.0. Shipped unmodified as a CA bundle; MPL obligations "
    "attach per-file to modified files, and we modify none.",
    "hypothesis": "MPL-2.0, and a development dependency only -- it is not in "
    "the runtime dependency set and is not present in the released image, so "
    "nothing it covers is distributed.",
    "boolean.py": "BSD-2-Clause reported in a non-standard field.",
    "license-expression": "Apache-2.0 reported in a non-standard field.",
}

_SPDX_SPLIT = re.compile(r"\s+(OR|AND)\s+", re.IGNORECASE)

#: Never permitted, at any version, for any reason. The LiteLLM enterprise
#: directory forbids production use without a subscription, and its presence in
#: the tree would make the Apache-2.0 Community Edition claim false.
FORBIDDEN_DISTRIBUTIONS = {"litellm-enterprise", "litellm_enterprise"}

_CLASSIFIER = re.compile(r"^License :: (?:OSI Approved :: )?(.+)$")


@dataclass(slots=True)
class Component:
    name: str
    version: str
    licences: list[str] = field(default_factory=list)
    verdict: str = "UNKNOWN"
    note: str = ""

    @property
    def purl(self) -> str:
        return f"pkg:pypi/{self.name.lower()}@{self.version}"


def _licences_of(dist: Distribution) -> list[str]:
    """Every licence string the distribution declares, from any of the fields.

    Metadata is inconsistent in practice: some projects use ``License``, some
    only classifiers, some the newer ``License-Expression``. Reading one field
    and reporting UNKNOWN for the rest would produce a report that is wrong in a
    way that looks authoritative.
    """
    metadata = dist.metadata
    found: list[str] = []

    for key in ("License-Expression", "License"):
        value = metadata.get(key)
        if value and value.strip() and "\n" not in value.strip():
            found.append(value.strip())

    for classifier in metadata.get_all("Classifier") or []:
        match = _CLASSIFIER.match(classifier)
        if match:
            found.append(match.group(1).strip())

    return sorted({item for item in found if item})


def classify_expression(expression: str) -> str:
    """Classify one licence string, honouring SPDX ``OR`` / ``AND``.

    Parsing the operators matters: ``Apache-2.0 OR BSD-3-Clause`` is a choice,
    so it is allowed if *either* side is, while ``AND`` binds us to both and is
    only allowed if *all* sides are. Matching the whole string literally would
    report `cryptography` as unrecognised, which is exactly the kind of false
    alarm that gets a policy gate switched off.
    """
    parts = [part.strip(" ()") for part in _SPDX_SPLIT.split(expression)]
    operators = {part.upper() for part in parts if part.upper() in ("OR", "AND")}
    operands = [part for part in parts if part.upper() not in ("OR", "AND") and part]

    verdicts = []
    for operand in operands:
        key = operand.upper()
        if key in DENIED:
            verdicts.append("DENIED")
        elif key in ALLOWED:
            verdicts.append("ALLOWED")
        elif key in REVIEW_REQUIRED:
            verdicts.append("REVIEW_REQUIRED")
        else:
            verdicts.append("UNKNOWN")

    if not verdicts:
        return "UNKNOWN"
    if "OR" in operators:
        # A choice: take the best option available to us.
        for preference in ("ALLOWED", "REVIEW_REQUIRED", "UNKNOWN", "DENIED"):
            if preference in verdicts:
                return preference
    # AND, or a single term: bound by the worst.
    for preference in ("DENIED", "UNKNOWN", "REVIEW_REQUIRED", "ALLOWED"):
        if preference in verdicts:
            return preference
    return "UNKNOWN"


def _verdict(name: str, licences: list[str]) -> tuple[str, str]:
    verdicts = [classify_expression(item) for item in licences]

    if "DENIED" in verdicts:
        return "DENIED", "copyleft or proprietary terms incompatible with the CE licence"
    if name.lower() in REVIEWED:
        return "REVIEWED", REVIEWED[name.lower()]
    if "ALLOWED" in verdicts:
        # Distributions often declare the same terms twice, once as a classifier
        # and once as an expression. One clearly-permissive declaration is
        # enough; requiring all of them to parse would fail on metadata style.
        return "ALLOWED", ""
    if "REVIEW_REQUIRED" in verdicts:
        return "REVIEW_REQUIRED", f"needs a recorded decision: {', '.join(licences)}"
    if not licences:
        return "UNKNOWN", "the distribution declares no licence metadata"
    return "REVIEW_REQUIRED", f"unrecognised licence: {', '.join(licences)}"


def collect() -> list[Component]:
    components: list[Component] = []
    for dist in distributions():
        name = dist.metadata["Name"]
        if not name:
            continue
        licences = _licences_of(dist)
        verdict, note = _verdict(name, licences)
        components.append(
            Component(
                name=name,
                version=dist.version or "0",
                licences=licences,
                verdict=verdict,
                note=note,
            )
        )
    return sorted(components, key=lambda c: c.name.lower())


def build_sbom(components: list[Component]) -> dict[str, Any]:
    """A CycloneDX 1.5 document.

    ``serialNumber`` is derived from the component set rather than randomly
    generated, so the same environment produces the same document. A
    randomly-serialised SBOM cannot be diffed between builds, which removes most
    of the reason to keep one.
    """
    digest = hashlib.sha256(
        "".join(f"{c.name}@{c.version};" for c in components).encode()
    ).hexdigest()

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-"
        f"8{digest[17:20]}-{digest[20:32]}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "secure-ai-gateway",
                "version": _project_version(),
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "purl": f"pkg:pypi/secure-ai-gateway@{_project_version()}",
            },
            "tools": [{"name": "scripts/supply_chain.py", "vendor": "QuietHours"}],
            "properties": [
                {"name": "python.version", "value": sys.version.split()[0]},
                {
                    "name": "note",
                    "value": "Generated from the resolved interpreter environment, "
                    "so it reports what is importable rather than what a manifest "
                    "declares.",
                },
            ],
        },
        "components": [
            {
                "type": "library",
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
                "licenses": [{"license": {"name": item}} for item in component.licences],
            }
            for component in components
        ],
    }


def _project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else "0.0.0"


def build_licence_report(components: list[Component]) -> dict[str, Any]:
    by_verdict: dict[str, list[dict[str, Any]]] = {}
    for component in components:
        by_verdict.setdefault(component.verdict, []).append(
            {
                "name": component.name,
                "version": component.version,
                "licenses": component.licences,
                "note": component.note,
            }
        )
    return {
        "project": "secure-ai-gateway",
        "version": _project_version(),
        "project_license": "Apache-2.0",
        "total": len(components),
        "summary": {verdict: len(items) for verdict, items in sorted(by_verdict.items())},
        "by_verdict": {verdict: items for verdict, items in sorted(by_verdict.items())},
    }


def check(components: list[Component]) -> list[str]:
    """Policy failures. An empty list means the gate passes."""
    problems: list[str] = []

    for component in components:
        if component.name.lower().replace("_", "-") in FORBIDDEN_DISTRIBUTIONS:
            problems.append(
                f"{component.name} is forbidden: proprietary terms that would make the "
                "Apache-2.0 Community Edition claim false"
            )
        if component.verdict == "DENIED":
            problems.append(
                f"{component.name} {component.version}: {component.note} "
                f"({', '.join(component.licences)})"
            )
        elif component.verdict in ("UNKNOWN", "REVIEW_REQUIRED"):
            problems.append(
                f"{component.name} {component.version}: {component.note}. Record a "
                f"decision in REVIEWED in {Path(__file__).name}, or remove the dependency."
            )

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=("sbom", "licences", "check"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    components = collect()

    if args.command == "sbom":
        document = build_sbom(components)
    elif args.command == "licences":
        document = build_licence_report(components)
    else:
        problems = check(components)
        if problems:
            print(f"licence policy: {len(problems)} problem(s)")
            for problem in problems:
                print(f"  {problem}")
            return 1
        print(f"licence policy: {len(components)} distributions, all cleared")
        return 0

    text = json.dumps(document, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.output} ({len(components)} components)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
