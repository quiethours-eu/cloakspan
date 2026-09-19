"""Licence boundary enforcement.

LiteLLM's repository is MIT at the core but its ``enterprise/`` directory is
under the proprietary BerriAI Enterprise License, which forbids production use
without a paid subscription and forbids redistribution outright
(internal licence matrix §2).

The MIT core imports ``litellm_enterprise`` lazily in ~20 places, guarded by
try/except. That means an accidental `pip install litellm-enterprise` anywhere
in the dependency tree would silently activate proprietary code paths in a
product we ship under Apache-2.0.

This test makes that failure loud instead of silent. It is a release gate.
"""

from __future__ import annotations

import tomllib
from importlib.util import find_spec
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# Distributions that must never appear in our dependency tree.
FORBIDDEN_DISTRIBUTIONS = ("litellm-enterprise", "litellm_enterprise")

# Import names that must not be resolvable at runtime.
FORBIDDEN_IMPORTS = ("litellm_enterprise",)


def _all_declared_dependencies() -> list[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    declared = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        declared.extend(extra)
    return declared


class TestProprietaryDependenciesAreExcluded:
    def test_no_forbidden_distribution_is_declared(self):
        declared = " ".join(_all_declared_dependencies()).lower()
        for forbidden in FORBIDDEN_DISTRIBUTIONS:
            assert forbidden not in declared, (
                f"{forbidden!r} is proprietary (BerriAI Enterprise License) and "
                "must never be a dependency of this Apache-2.0 project"
            )

    def test_forbidden_module_is_not_importable(self):
        for module in FORBIDDEN_IMPORTS:
            assert find_spec(module) is None, (
                f"{module!r} is installed in this environment. It is proprietary "
                "and its presence silently enables enterprise code paths in the "
                "MIT litellm core. Uninstall it."
            )

    def test_project_licence_is_declared_and_permissive(self):
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        assert data["project"]["license"] == "Apache-2.0"

    def test_licence_file_exists(self):
        licence = PYPROJECT.parent / "LICENSE"
        assert licence.exists()
        assert "Apache License" in licence.read_text(encoding="utf-8")[:200]


class TestRoutingIsBehindAnAdapter:
    """LiteLLM must remain swappable.

    If the security pipeline ever imports litellm directly rather than going
    through ProviderAdapter, we have lost the ability to leave -- which is the
    whole mitigation for depending on a fast-moving, split-licence project.
    """

    def test_pipeline_does_not_import_litellm_directly(self):
        pipeline_source = (PYPROJECT.parent / "gateway" / "inspection" / "pipeline.py").read_text(
            encoding="utf-8"
        )
        assert "import litellm" not in pipeline_source

    def test_core_gateway_has_no_litellm_import_outside_routing(self):
        gateway_root = PYPROJECT.parent / "gateway"
        offenders = []
        for path in gateway_root.rglob("*.py"):
            if "routing" in path.parts:
                continue
            if "import litellm" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(PYPROJECT.parent)))
        assert not offenders, f"litellm imported outside gateway/routing/: {offenders}"

    def test_default_install_does_not_require_litellm(self):
        """The Community Edition core must work with no routing extra."""
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        core = " ".join(data["project"]["dependencies"]).lower()
        assert "litellm" not in core, "litellm belongs in the [routing] extra, not core"

    def test_default_install_does_not_require_presidio(self):
        """Presidio pulls spaCy; it must stay optional so the CE image stays small."""
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        core = " ".join(data["project"]["dependencies"]).lower()
        assert "presidio" not in core
