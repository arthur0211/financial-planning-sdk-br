#!/usr/bin/env python3
"""Build a disposable tool image and execute one isolated Linux cell."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__:
    from .bounded_subprocess import (
        BoundedProcessCleanupError,
        BoundedProcessOutputLimit,
        BoundedProcessStartError,
        BoundedProcessTimeout,
        run_bounded,
    )
    from .portability_runtime_pins import PYTHON_BASE_IMAGES
else:
    from bounded_subprocess import (  # type: ignore[no-redef]
        BoundedProcessCleanupError,
        BoundedProcessOutputLimit,
        BoundedProcessStartError,
        BoundedProcessTimeout,
        run_bounded,
    )
    from portability_runtime_pins import PYTHON_BASE_IMAGES

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
HOST_OUTPUT_LIMIT = 32 * 1024 * 1024


def _run(command: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = run_bounded(
            command,
            cwd=cwd,
            timeout_seconds=timeout,
            stdout_limit=HOST_OUTPUT_LIMIT,
            stderr_limit=HOST_OUTPUT_LIMIT,
        )
    except BoundedProcessTimeout as exc:
        raise RuntimeError("host launcher command exceeded its time budget") from exc
    except BoundedProcessOutputLimit as exc:
        raise RuntimeError(f"host launcher command exceeded its {exc.stream} byte budget") from exc
    except (BoundedProcessStartError, BoundedProcessCleanupError) as exc:
        raise RuntimeError("host launcher process boundary failed") from exc
    if completed.returncode != 0:
        digest = hashlib.sha256(completed.stderr + completed.stdout).hexdigest()
        raise RuntimeError(f"host launcher command failed ({completed.returncode}; output_sha256={digest})")
    return completed


def _mount(source: Path, target: str, *, readonly: bool = True) -> str:
    value = f"type=bind,source={source.resolve(strict=True)},target={target}"
    return value + (",readonly" if readonly else "")


def _docker_owned_inventory(nonce: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    label_filter = f"label=finplanbr.portability.run={nonce}"
    containers = _run(
        ["docker", "container", "ls", "--all", "--format", "{{.Names}}", "--filter", label_filter],
        cwd=REPOSITORY_ROOT,
        timeout=30,
    ).stdout.decode("utf-8", errors="strict").splitlines()
    images = _run(
        ["docker", "image", "ls", "--no-trunc", "--quiet", "--filter", label_filter],
        cwd=REPOSITORY_ROOT,
        timeout=30,
    ).stdout.decode("ascii", errors="strict").splitlines()
    container_roster = tuple(sorted(item for item in containers if item))
    image_roster = tuple(sorted(set(item for item in images if item)))
    if len(container_roster) != len(set(container_roster)):
        raise RuntimeError("Docker owned-container inventory contains duplicates")
    if any(not item.startswith("finplanbr-portability-") for item in container_roster):
        raise RuntimeError("Docker owned-container inventory contains an unexpected name")
    if any(not item.startswith("sha256:") or len(item) != 71 for item in image_roster):
        raise RuntimeError("Docker owned-image inventory contains an invalid ID")
    return container_roster, image_roster


def _cleanup_created_docker_objects(
    *,
    nonce: str,
    container_names: tuple[str, ...],
    image_id: str | None,
    image_tag: str | None,
) -> None:
    errors: list[BaseException] = []
    owned_containers: tuple[str, ...] = ()
    owned_images: tuple[str, ...] = ()
    try:
        owned_containers, owned_images = _docker_owned_inventory(nonce)
        unexpected = set(owned_containers) - set(container_names)
        if unexpected:
            errors.append(RuntimeError("Docker cleanup found unexpected nonce-bound containers"))
        if image_id is not None and owned_images and image_id not in owned_images:
            errors.append(RuntimeError("Docker cleanup image ID differs from the nonce-bound inventory"))
    except BaseException as exc:
        errors.append(exc)
    # Known, nonce-derived targets remain safe cleanup candidates even when
    # Docker's label inventory itself is unavailable.  Inventory expands the
    # roster and verifies ownership; it is not a prerequisite for attempting
    # cleanup of identifiers created by this invocation.
    removal_containers = tuple(sorted(set(owned_containers) | set(container_names)))
    removal_images = set(owned_images)
    if image_id is not None:
        removal_images.add(image_id)
    if not removal_images and image_tag is not None:
        expected_prefix = f"finplanbr-portability-{nonce}:py"
        if not image_tag.startswith(expected_prefix) or not image_tag.removeprefix(expected_prefix).isdigit():
            errors.append(RuntimeError("Docker cleanup image tag is not nonce-bound"))
        else:
            # A successful build establishes this nonce-derived tag even when
            # both the immediate image-ID query and label inventory fail.
            removal_images.add(image_tag)
    for container_name in removal_containers:
        try:
            _run(["docker", "container", "rm", "--force", container_name], cwd=REPOSITORY_ROOT, timeout=30)
        except BaseException as exc:
            errors.append(exc)
    for owned_image in sorted(removal_images):
        try:
            _run(["docker", "image", "rm", owned_image], cwd=REPOSITORY_ROOT, timeout=60)
        except BaseException as exc:
            errors.append(exc)
    try:
        remaining_containers, remaining_images = _docker_owned_inventory(nonce)
        if remaining_containers or remaining_images:
            errors.append(RuntimeError("Docker nonce-bound objects remain after cleanup"))
    except BaseException as exc:
        errors.append(exc)
    if errors:
        raise RuntimeError(f"Docker cleanup failed for {len(errors)} owned object(s)") from errors[0]


def _write_evidence(target_argument: Path, payload: bytes) -> None:
    target = target_argument.resolve()
    try:
        target.relative_to(REPOSITORY_ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise RuntimeError("cell evidence output must remain outside the checkout")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)


def execute(python_minor: str) -> bytes:
    base_image = PYTHON_BASE_IMAGES[python_minor]
    nonce = secrets.token_hex(16)
    tag = f"finplanbr-portability-{nonce}:py{python_minor.replace('.', '')}"
    container_names = (
        f"finplanbr-portability-pre-{nonce}",
        f"finplanbr-portability-cell-{nonce}",
    )
    image_id: str | None = None
    image_build_attempted = False
    with tempfile.TemporaryDirectory(prefix="finplanbr-portability-host-") as directory:
        temporary = Path(directory).resolve(strict=True)
        try:
            temporary.relative_to(REPOSITORY_ROOT.resolve(strict=True))
        except ValueError:
            pass
        else:
            raise RuntimeError("host temporary directory must be outside the checkout")
        freeze = _run(
            [sys.executable, "-I", "-B", os.fspath(REPOSITORY_ROOT / "scripts" / "freeze_source_snapshot.py")],
            cwd=REPOSITORY_ROOT,
            timeout=60,
        ).stdout
        freeze_path = temporary / "source-freeze.json"
        freeze_path.write_bytes(freeze)
        build_context = temporary / "docker-context"
        build_context.mkdir()
        try:
            image_build_attempted = True
            _run(
                [
                    "docker",
                    "build",
                    "--build-arg",
                    f"BASE_IMAGE={base_image}",
                    "--label",
                    f"finplanbr.portability.run={nonce}",
                    "--label",
                    "finplanbr.portability.role=toolchain",
                    "--tag",
                    tag,
                    "--file",
                    os.fspath(REPOSITORY_ROOT / "scripts" / "portability-linux.Dockerfile"),
                    os.fspath(build_context),
                ],
                cwd=REPOSITORY_ROOT,
                timeout=600,
            )
            image_id = (
                _run(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", tag],
                    cwd=REPOSITORY_ROOT,
                    timeout=30,
                )
                .stdout.decode("ascii")
                .strip()
            )
            precontrol = _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    container_names[0],
                    "--label",
                    f"finplanbr.portability.run={nonce}",
                    "--label",
                    "finplanbr.portability.role=network-precontrol",
                    "--read-only",
                    "--user",
                    "65532:65532",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--mount",
                    _mount(REPOSITORY_ROOT, "/source"),
                    tag,
                    "python",
                    "/source/scripts/portability_network_control.py",
                    "--expect",
                    "reachable",
                    "--nonce",
                    nonce,
                ],
                cwd=REPOSITORY_ROOT,
                timeout=60,
            ).stdout
            precontrol_report = json.loads(precontrol)
            if precontrol_report.get("status") != "passed":
                raise RuntimeError("network precontrol did not pass")
            precontrol_path = temporary / "network-precontrol.json"
            precontrol_path.write_bytes(precontrol)
            cell = _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    container_names[1],
                    "--label",
                    f"finplanbr.portability.run={nonce}",
                    "--label",
                    "finplanbr.portability.role=offline-cell",
                    "--network",
                    "none",
                    "--read-only",
                    "--user",
                    "65532:65532",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "256",
                    "--tmpfs",
                    "/work:rw,exec,nosuid,nodev,size=1073741824,mode=0700,uid=65532,gid=65532",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=0700,uid=65532,gid=65532",
                    "--mount",
                    _mount(REPOSITORY_ROOT, "/source"),
                    "--mount",
                    _mount(freeze_path, "/control/source-freeze.json"),
                    "--mount",
                    _mount(precontrol_path, "/control/network-precontrol.json"),
                    tag,
                    "python",
                    "/source/scripts/validate_linux_portability_cell.py",
                    "--source-root",
                    "/source",
                    "--freeze-report",
                    "/control/source-freeze.json",
                    "--network-precontrol",
                    "/control/network-precontrol.json",
                    "--work-root",
                    "/work",
                    "--python-minor",
                    python_minor,
                    "--nonce",
                    nonce,
                    "--image-id",
                    image_id,
                    "--base-image-ref",
                    base_image,
                ],
                cwd=REPOSITORY_ROOT,
                timeout=900,
            )
            report = json.loads(cell.stdout)
            if report.get("status") != "passed":
                raise RuntimeError("Linux portability cell did not pass")
            return cell.stdout
        finally:
            _cleanup_created_docker_objects(
                nonce=nonce,
                container_names=container_names,
                image_id=image_id,
                image_tag=tag if image_build_attempted else None,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default="3.11", choices=("3.11", "3.12", "3.13", "3.14"))
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        payload = execute(arguments.python)
    except Exception as exc:
        failure = {
            "format": "finplanbr.installed-portability-host-launch.v1",
            "status": "failed",
            "cell": f"linux-py{arguments.python}",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "authority": "none",
            "release_authorized": False,
        }
        payload = json.dumps(failure, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if arguments.output is not None:
            _write_evidence(arguments.output, payload)
        os.write(1, payload)
        return 1
    if arguments.output is not None:
        _write_evidence(arguments.output, payload)
    os.write(1, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
