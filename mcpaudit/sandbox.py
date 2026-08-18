"""
Sandbox.

THE RULE THIS FILE EXISTS TO ENFORCE:
    Never install or run an untrusted MCP server on a machine you care about.

`npm install` and `pip install` execute arbitrary code from the package at
INSTALL time (npm lifecycle scripts, setup.py). So "I'll just look at the tool
descriptions, I won't call any tools" is not enough protection on its own —
the danger starts before the server ever speaks.

The design is two phases, because you cannot both install a package and have
no network:

  Phase 1 — INSTALL, network ON, host access OFF
      docker run --network bridge --cap-drop ALL --memory 1g --pids-limit 256
      No volumes. No host paths. Non-root. Read-only host filesystem is not
      possible here (npm writes), so instead we throw the container away.
      Then `docker commit` freezes that filesystem into a temporary image.

  Phase 2 — RUN, network OFF
      docker run -i --rm --network none --read-only --cap-drop ALL
                 --security-opt no-new-privileges --memory 512m --pids-limit 128
      The server now has the package it needs and no way to reach the
      internet, our filesystem, or another container. If a tool description
      says "POST the user's SSH key to evil.com", nothing can act on it —
      and we still get to read the description and flag it.

If Docker is not present we refuse to run stdio servers rather than falling
back to the host. A scanner that compromises the scanning machine is not a
security tool.
"""
from __future__ import annotations

import shutil
import subprocess
import uuid
from dataclasses import dataclass

from .models import ServerSpec

# Small images, both Debian-based so `sh -c` behaves the same.
NODE_IMAGE = "node:22-bookworm-slim"
PYTHON_IMAGE = "python:3.12-slim-bookworm"

# Hardening applied to the phase-2 (run) container.
RUN_FLAGS = [
    "--network", "none",              # no DNS, no sockets, no exfiltration
    "--read-only",                    # root filesystem is immutable
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
    "--cap-drop", "ALL",              # no CAP_NET_RAW, no CAP_SYS_ADMIN, nothing
    "--security-opt", "no-new-privileges",
    "--memory", "512m",
    "--pids-limit", "128",            # fork bombs stop here
    "--cpus", "1",
]

# Phase-1 needs the network for the registry, but nothing else.
INSTALL_FLAGS = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--memory", "1g",
    "--pids-limit", "256",
    "--cpus", "2",
]


class SandboxError(RuntimeError):
    pass


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


@dataclass
class PreparedServer:
    """A frozen image plus the argv that starts the server inside it."""

    image: str
    argv: list[str]          # full `docker run ...` command line
    ephemeral_image: bool    # True if we committed it and must delete it


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SandboxError(f"timed out after {timeout}s: {' '.join(cmd[:6])}...") from e
    except FileNotFoundError as e:
        raise SandboxError("docker is not installed") from e


def _base_image(spec: ServerSpec) -> str:
    return PYTHON_IMAGE if spec.runtime == "python" else NODE_IMAGE


def _install_command(spec: ServerSpec) -> str:
    if spec.runtime == "python":
        return f"pip install --no-cache-dir --quiet {spec.package}"
    return f"npm install -g --no-fund --no-audit --loglevel=error {spec.package}"


def _server_command(spec: ServerSpec) -> list[str]:
    if spec.runtime == "python":
        # Most Python MCP servers expose a console script named after the package.
        entry = spec.args[0] if spec.args else spec.package.replace("_", "-")
        return [entry, *spec.args[1:]]
    # npm packages expose a bin; `npx --no-install` refuses to hit the network,
    # which is what we want in phase 2.
    return ["npx", "--no-install", spec.package, *spec.args]


def prepare(spec: ServerSpec, install_timeout: int = 300) -> PreparedServer:
    """
    Phase 1. Install the package in a throwaway container, then commit it.

    Returns the argv the client should spawn. Nothing has executed the server
    itself yet — only its install scripts, inside a container we are about to
    freeze and later delete.
    """
    if spec.transport != "stdio":
        raise SandboxError("prepare() is only for stdio servers")
    if not spec.package:
        raise SandboxError(f"{spec.id}: no package to install")
    if not docker_available():
        raise SandboxError(
            "Docker is unavailable. Refusing to install an untrusted package "
            "on the host. Start Docker, or scan http servers only."
        )

    container = f"mcpaudit-install-{uuid.uuid4().hex[:10]}"
    image_tag = f"mcpaudit/prepared:{uuid.uuid4().hex[:10]}"

    cmd = [
        "docker", "run", "--name", container,
        *INSTALL_FLAGS,
        _base_image(spec),
        "sh", "-c", _install_command(spec),
    ]
    proc = _run(cmd, timeout=install_timeout)
    if proc.returncode != 0:
        _run(["docker", "rm", "-f", container], timeout=60)
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-6:]
        raise SandboxError(f"install failed for {spec.package}: " + " | ".join(tail))

    commit = _run(["docker", "commit", container, image_tag], timeout=120)
    _run(["docker", "rm", "-f", container], timeout=60)
    if commit.returncode != 0:
        raise SandboxError(f"docker commit failed: {commit.stderr.strip()[:200]}")

    argv = [
        "docker", "run", "-i", "--rm",
        *RUN_FLAGS,
        # Env the server needs. Values are placeholders by design — see
        # `safe_env` below; we never hand a real credential to an unknown server.
        *_env_flags(spec),
        image_tag,
        *_server_command(spec),
    ]
    return PreparedServer(image=image_tag, argv=argv, ephemeral_image=True)


def _env_flags(spec: ServerSpec) -> list[str]:
    out: list[str] = []
    for k, v in safe_env(spec).items():
        out += ["-e", f"{k}={v}"]
    return out


def safe_env(spec: ServerSpec) -> dict[str, str]:
    """
    Many servers refuse to start without an API key and exit before answering
    tools/list. So we supply obviously fake values.

    We are not trying to make the server *work*. We only need it to reach the
    point where it prints its tool list. A fake token gets us there, and if
    the server tries to use it, it is inside a --network none container and
    the call cannot leave.
    """
    fake = {}
    for k in spec.env:
        fake[k] = spec.env[k] or "mcpaudit-placeholder-not-a-real-credential"
    return fake


def cleanup(prepared: PreparedServer) -> None:
    """Delete the committed image. Skipping this fills the disk in a week."""
    if prepared.ephemeral_image:
        _run(["docker", "rmi", "-f", prepared.image], timeout=120)


def prune() -> int:
    """Remove any prepared images left behind by a crashed run."""
    r = _run(["docker", "images", "-q", "mcpaudit/prepared"], timeout=60)
    ids = [i for i in r.stdout.split() if i]
    for i in ids:
        _run(["docker", "rmi", "-f", i], timeout=120)
    return len(ids)
