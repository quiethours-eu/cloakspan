"""Install release artifacts outside the checkout and exercise the real playground CLI."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@contextlib.contextmanager
def work_directory() -> Iterator[Path]:
    """A temporary directory that is removed once Windows has released its files.

    Windows ends processes asynchronously: a playground process that has just
    been stopped can still map a compiled extension from the virtual
    environment for a moment, and removing the directory then fails with
    WinError 5 although the package is fine. Retry briefly instead.
    """
    path = Path(tempfile.mkdtemp(prefix="cloakspan-package-"))
    try:
        yield path
    finally:
        for attempt in range(40):
            try:
                shutil.rmtree(path)
                break
            except PermissionError:
                if os.name != "nt" or attempt == 39:
                    raise
                time.sleep(0.25)


def stop_playground(process: subprocess.Popen[bytes]) -> None:
    """Stop the playground and every process it started.

    On Windows the installed ``cloakspan.exe`` is a launcher. The interpreter
    and the playground's inspection worker run as its descendants and outlive
    a plain terminate() of the launcher, so end the whole process tree.
    """
    if os.name == "nt":
        subprocess.run(  # noqa: S603, S607 - fixed system tool and argv, no shell
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],  # noqa: S607 - resolved from PATH
            capture_output=True,
            check=False,
            timeout=30,
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def check_artifact(artifact: Path) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SAG_") and key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
    }
    environment["PYTHONUNBUFFERED"] = "1"
    environment["PYTHONUTF8"] = "1"
    with work_directory() as work:
        venv = work / "venv"
        subprocess.run(  # noqa: S603 - fixed executable and argv, no shell
            [sys.executable, "-m", "venv", str(venv)],
            check=True,
            env=environment,
            timeout=60,
        )
        binaries = venv / ("Scripts" if os.name == "nt" else "bin")
        python = binaries / ("python.exe" if os.name == "nt" else "python")
        command = binaries / ("cloakspan.exe" if os.name == "nt" else "cloakspan")
        subprocess.run(  # noqa: S603 - install the selected local release artifact
            [str(python), "-m", "pip", "install", "--quiet", str(artifact)],
            cwd=work,
            env=environment,
            check=True,
            timeout=300,
        )
        subprocess.run(  # noqa: S603 - fixed argv, no source-tree imports
            [str(python), "-m", "pip", "check"],
            cwd=work,
            env=environment,
            check=True,
            timeout=30,
        )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        # Only loopback requests are made; a machine's outbound proxy must not
        # receive the playground's ephemeral session code or synthetic input.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        output = work / "playground.log"
        with output.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(  # noqa: S603 - installed console script, no shell
                [str(command), "playground", "--port", str(port)],
                cwd=work,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(f"{artifact.name}: playground exited before readiness")
                    access_code = next(
                        (
                            line.removeprefix("Session access code: ")
                            for line in output.read_text(encoding="utf-8").splitlines()
                            if line.startswith("Session access code: ")
                        ),
                        "",
                    )
                    if access_code:
                        request = urllib.request.Request(  # noqa: S310 - fixed loopback URL
                            f"{base}/api/status",
                            headers={"Authorization": f"Bearer {access_code}"},
                        )
                        try:
                            with opener.open(request, timeout=2) as response:
                                if json.load(response)["worker"] == "ready":
                                    break
                        except (urllib.error.URLError, TimeoutError):
                            pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError(f"{artifact.name}: playground did not become ready")

                for asset in ("/", "/style.css", "/app.js"):
                    with opener.open(f"{base}{asset}", timeout=5) as response:
                        if response.status != 200 or not response.read():
                            raise RuntimeError(f"{artifact.name}: bundled asset {asset} is missing")
                request = urllib.request.Request(  # noqa: S310 - fixed loopback URL
                    f"{base}/api/inspect",
                    data=json.dumps(
                        {
                            "text": "Please reply to alex@example.com about tomorrow's meeting.",
                            "role": "user",
                            "application": "default",
                        }
                    ).encode(),
                    headers={
                        "Authorization": f"Bearer {access_code}",
                        "Origin": base,
                        "Content-Type": "application/json",
                    },
                )
                with opener.open(request, timeout=20) as response:
                    result = json.load(response)
                projected = result["outbound_preview"]["text"]
                if (
                    result["decision"]["effective_action"] != "transform"
                    or "alex@example.com" in projected
                    or "<EMAIL_ADDRESS:v1:" not in projected
                    or result["provider_contacted"] is not False
                ):
                    raise RuntimeError(f"{artifact.name}: installed playground failed inspection")
            finally:
                stop_playground(process)
        print(f"Verified {artifact.name}: CLI, bundled assets, policy, and local email inspection.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, help="directory containing the wheel and source archive")
    args = parser.parse_args()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    name = project["name"].replace("-", "_")
    version = project["version"]
    for filename in (f"{name}-{version}-py3-none-any.whl", f"{name}-{version}.tar.gz"):
        artifact = (args.dist / filename).resolve(strict=True)
        check_artifact(artifact)


if __name__ == "__main__":
    main()
