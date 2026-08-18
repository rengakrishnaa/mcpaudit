"""
Orchestration.

Everything else in this package does one job. This file is the only place
that knows the ORDER those jobs happen in, and the order is the product:

    connect -> list tools -> cheap rules -> compare against history -> persist

Step 4 is the one that cannot be moved. Rug-pull detection needs the previous
fingerprints, and it needs them BEFORE we overwrite them with today's. Get
that ordering wrong and the scanner silently never reports a rug pull again —
it would compare today against today. There is a test for exactly this.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .client import HTTPClient, MCPError, StdioClient
from .detectors import rug_pull, static_rules
from .models import Finding, ScanResult, ServerSpec, Severity, Tool
from .storage import Store

SCANNER_VERSION = "0.1.0"


@dataclass
class ScanOptions:
    timeout: float = 30.0
    install_timeout: int = 300
    use_llm: bool = False
    llm_model: str = "claude-sonnet-4-5"
    allow_local: bool = False        # only for repo-local fixture servers
    repo_root: Path = field(default_factory=Path.cwd)


# --------------------------------------------------------------------------
# transport selection
# --------------------------------------------------------------------------


@contextmanager
def _connect(spec: ServerSpec, opts: ScanOptions) -> Iterator[object]:
    """
    Yield a connected client, then always tear down — including the committed
    Docker image, which otherwise accumulates until the disk fills.
    """
    if spec.transport == "http":
        client = HTTPClient(spec.url, timeout=opts.timeout)
        try:
            yield client
        finally:
            client.close()
        return

    if spec.transport == "local":
        # Used by the offline demo and the test suite. It runs code WITHOUT a
        # sandbox, so it is restricted to paths inside this repository and is
        # off unless explicitly enabled.
        if not opts.allow_local:
            raise MCPError("local transport requires allow_local=True")
        target = Path(spec.args[1]).resolve() if len(spec.args) > 1 else None
        root = opts.repo_root.resolve()
        if target is None or root not in target.parents and target != root:
            raise MCPError(f"local server {target} is outside the repo; refusing")
        client = StdioClient(spec.args, timeout=opts.timeout)
        try:
            client.start()
            yield client
        finally:
            client.close()
        return

    # stdio: the untrusted case. Sandbox it.
    from . import sandbox

    prepared = sandbox.prepare(spec, install_timeout=opts.install_timeout)
    client = StdioClient(prepared.argv, timeout=opts.timeout)
    try:
        client.start()
        yield client
    finally:
        client.close()
        sandbox.cleanup(prepared)


# --------------------------------------------------------------------------
# the scan
# --------------------------------------------------------------------------


def _instructions_as_tool(text: str) -> Tool:
    """
    The `instructions` field from initialize also lands in the model's context.
    Scanning it means wrapping it in the shape the detectors already accept —
    cheaper and less error-prone than a second code path.
    """
    return Tool(name="<server instructions>", description=text, input_schema={})


def analyse(
    tools: list[Tool],
    previous: dict[str, Tool],
    instructions: str = "",
    opts: ScanOptions | None = None,
) -> list[Finding]:
    """
    Pure function: tools in, findings out. No network, no disk, no clock.

    Keeping it pure is what makes the detector tests fast and deterministic —
    they never start a subprocess.
    """
    opts = opts or ScanOptions()
    findings: list[Finding] = []

    findings += static_rules.run_static(tools)

    if instructions.strip():
        findings += static_rules.check_description_injection(
            _instructions_as_tool(instructions)
        )

    findings += rug_pull.check_rug_pull(tools, previous)

    if opts.use_llm:
        from .detectors import llm_judge

        flagged = {f.tool_name for f in findings}
        findings += llm_judge.run_llm(tools, flagged, model=opts.llm_model)

    # Worst first: a human reading the report should not have to scroll to
    # find the CRITICAL.
    order = {s: i for i, s in enumerate(
        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])}
    findings.sort(key=lambda f: (order[f.severity], f.tool_name, f.rule_id))
    return findings


def scan_server(spec: ServerSpec, store: Store,
                opts: ScanOptions | None = None) -> ScanResult:
    """Scan one server and persist the result."""
    opts = opts or ScanOptions()
    result = ScanResult(server_id=spec.id, scanner_version=SCANNER_VERSION)

    store.upsert_server(
        spec.id,
        display_name=spec.name or spec.id,
        transport=spec.transport,
        runtime=spec.runtime,
        package=spec.package,
        url=spec.url,
        homepage=spec.homepage,
        source=spec.source,
    )

    # Read history BEFORE recording today's. See the module docstring.
    previous = store.previous_tools(spec.id)

    instructions = ""
    try:
        with _connect(spec, opts) as client:
            info = client.initialize()          # type: ignore[attr-defined]
            result.server_version = info.version
            instructions = info.instructions
            result.tools = client.list_tools()  # type: ignore[attr-defined]
    except MCPError as e:
        result.errors.append(str(e)[:500])
    except Exception as e:  # sandbox failures, docker missing, etc.
        result.errors.append(f"{type(e).__name__}: {e}"[:500])

    if result.tools:
        result.findings = analyse(result.tools, previous, instructions, opts)
        store.record_tools(spec.id, result.tools)

    store.record_scan(result)
    return result


def scan_all(
    specs: list[ServerSpec],
    store: Store,
    opts: ScanOptions | None = None,
    on_progress=None,
) -> list[ScanResult]:
    """
    Sequential on purpose.

    Parallelism here would mean N Docker containers pulling packages at once
    on a free GitHub Actions runner with 2 cores and 14 GB of disk. The
    nightly job has hours and no user waiting on it; it does not need to race.
    """
    results = []
    for i, spec in enumerate(specs, 1):
        t0 = time.monotonic()
        result = scan_server(spec, store, opts)
        if on_progress:
            on_progress(i, len(specs), spec, result, time.monotonic() - t0)
        results.append(result)
    return results
