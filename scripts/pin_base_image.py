"""Resolve the container base image to an immutable digest, and record it.

    python scripts/pin_base_image.py            # resolve and rewrite
    python scripts/pin_base_image.py --check    # verify a digest is pinned

## Why

A tag is mutable. ``python:3.12-slim-bookworm`` names a different image today
than it did last month, so a build referencing it is not reproducible and an
SBOM taken from it describes an artefact that no longer exists. For a product
whose output is evidence, that is not a minor inconvenience.

## Why this refuses to guess

If the registry is unreachable, this exits non-zero and writes nothing. It does
**not** fall back to a tag, and it does not leave a plausible-looking value
behind. A digest that was never resolved against a registry is worse than no
digest at all, because it looks verified — and the whole point of pinning is to
be able to say "this exact bytes, checked".
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / "deployment" / "docker" / "base-image.env"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def write_env(digest: str, image: str, who: str) -> None:
    text = ENV_FILE.read_text(encoding="utf-8")
    text = re.sub(r"^BASE_DIGEST=.*$", f"BASE_DIGEST={digest}", text, flags=re.MULTILINE)
    text = re.sub(
        r"^BASE_PINNED_ON=.*$",
        f"BASE_PINNED_ON={date.today().isoformat()}",
        text,
        flags=re.MULTILINE,
    )
    text = re.sub(r"^BASE_PINNED_BY=.*$", f"BASE_PINNED_BY={who}", text, flags=re.MULTILINE)
    ENV_FILE.write_text(text, encoding="utf-8")


def resolve(image: str) -> str:
    """Ask the registry for the digest of ``image``. Never invents one."""
    pull = subprocess.run(  # noqa: S603, S607 - fixed argv, no shell
        ["docker", "pull", "--quiet", image],  # noqa: S607 - resolved from PATH
        capture_output=True,
        text=True,
        timeout=600,
    )
    if pull.returncode != 0:
        raise RuntimeError(
            f"could not pull {image}:\n{(pull.stderr or pull.stdout).strip()[-800:]}"
        )

    inspect = subprocess.run(  # noqa: S603, S607
        ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=120,
    )
    if inspect.returncode != 0:
        raise RuntimeError(f"could not inspect {image}: {inspect.stderr.strip()}")

    reference = inspect.stdout.strip()
    _, _, digest = reference.partition("@")
    if not _DIGEST.match(digest):
        raise RuntimeError(f"registry returned an unusable digest: {reference!r}")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify a digest is pinned. Used by the release gate.",
    )
    parser.add_argument("--by", default="ci", help="Who pinned it, for the record.")
    args = parser.parse_args(argv)

    env = read_env()
    image = env.get("BASE_IMAGE", "")
    digest = env.get("BASE_DIGEST", "")

    if args.check:
        if not digest:
            print(
                "base image is NOT pinned. Release builds must reference an immutable "
                f"digest.\nRun `make pin-base-image`, or set BASE_DIGEST in {ENV_FILE.name}.",
                file=sys.stderr,
            )
            return 1
        if not _DIGEST.match(digest):
            print(f"BASE_DIGEST is not a sha256 digest: {digest!r}", file=sys.stderr)
            return 1
        print(f"base image pinned: {image}@{digest}")
        return 0

    try:
        resolved = resolve(image)
    except Exception as exc:
        print(f"could not pin the base image: {exc}", file=sys.stderr)
        print(
            "Nothing was written. A digest that was never resolved against a registry "
            "is worse than none, because it looks verified.",
            file=sys.stderr,
        )
        return 1

    write_env(resolved, image, args.by)
    print(f"pinned {image}@{resolved}")
    if digest and digest != resolved:
        print(
            f"NOTE: the digest changed (was {digest}). The base image moved -- re-read "
            "the vulnerability scan before releasing."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
