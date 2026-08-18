"""
Command line interface.

argparse, not Typer or Click, and that is deliberate: `mcpaudit` then has
ZERO required third-party dependencies. `git clone && python -m mcpaudit demo`
works on a fresh machine with nothing but Python. Every dependency you add is
a step where someone trying your project gives up.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import ServerSpec
from .storage import Store

# ANSI, degraded gracefully when piped.
_TTY = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


GRADE_CODE = {"A": "32", "B": "32", "C": "33", "D": "31", "F": "31;1"}
SEV_CODE = {"critical": "31;1", "high": "31", "medium": "33", "low": "90", "info": "90"}


def _print_result(r, verbose: bool = True) -> None:
    grade = _c(f" {r.grade} ", GRADE_CODE.get(r.grade, "0"))
    print(f"{grade} {r.server_id}  score={r.score}  tools={len(r.tools)}  "
          f"findings={len(r.findings)}")
    for err in r.errors:
        print(f"    {_c('error', '31')}: {err}")
    if not verbose:
        return
    for f in r.findings:
        sev = _c(f.severity.value.upper().ljust(8), SEV_CODE.get(f.severity.value, "0"))
        print(f"    {sev} {f.rule_id}  {f.tool_name}: {f.title}")
        for line in f.evidence.splitlines()[:6]:
            print(f"             {line[:150]}")


def _progress(i, n, spec, result, secs):
    print(f"[{i}/{n}] ", end="")
    _print_result(result, verbose=False)


# --------------------------------------------------------------------------


def cmd_scan(a) -> int:
    from . import registry
    from .scanner import ScanOptions, scan_all

    specs = registry.resolve(use_registry=a.registry, seed_path=a.seed, limit=a.limit)
    if a.only:
        specs = [s for s in specs if s.id in set(a.only)]
    if not specs:
        print("no servers to scan", file=sys.stderr)
        return 1

    store = Store(a.db)
    opts = ScanOptions(timeout=a.timeout, install_timeout=a.install_timeout,
                       use_llm=a.llm, allow_local=a.allow_local,
                       repo_root=Path.cwd())
    print(f"scanning {len(specs)} servers -> {a.db}")
    results = scan_all(specs, store, opts, on_progress=_progress)

    bad = sum(1 for r in results if r.grade in ("D", "F"))
    failed = sum(1 for r in results if not r.scanned_ok)
    print(f"\ndone: {len(results)} scanned, {bad} graded D/F, {failed} could not be reached")
    return 0


def cmd_demo(a) -> int:
    """Scan the bundled fixture servers. No Docker, no network, no API key."""
    from . import registry, site
    from .scanner import ScanOptions, scan_all

    specs = registry.load_seed(a.seed)
    store = Store(a.db)
    opts = ScanOptions(allow_local=True, repo_root=Path.cwd(), timeout=15)
    results = scan_all(specs, store, opts)
    for r in results:
        _print_result(r)
    info = site.build(store, a.out)
    print(f"\nsite written to {info['out']}/index.html "
          f"({info['servers']} servers, {info['findings']} findings)")
    return 0


def cmd_check(a) -> int:
    """One-off scan of a server that is not in the registry."""
    from .scanner import ScanOptions, scan_server

    if a.url:
        spec = ServerSpec(id=f"http:{a.url}", name=a.url, transport="http",
                          url=a.url, source="adhoc")
    elif a.npm:
        spec = ServerSpec(id=f"npm:{a.npm}", name=a.npm, runtime="node",
                          package=a.npm, args=a.args, source="adhoc")
    elif a.pypi:
        spec = ServerSpec(id=f"pypi:{a.pypi}", name=a.pypi, runtime="python",
                          package=a.pypi, args=a.args, source="adhoc")
    else:
        print("give one of --url / --npm / --pypi", file=sys.stderr)
        return 2

    store = Store(a.db)
    r = scan_server(spec, store, ScanOptions(timeout=a.timeout,
                                             install_timeout=a.install_timeout))
    _print_result(r)
    # Exit non-zero on a bad grade so this is usable as a CI gate.
    return 1 if r.grade in ("D", "F") else 0


def cmd_site(a) -> int:
    from . import site

    info = site.build(Store(a.db), a.out)
    print(f"{info['servers']} servers -> {info['out']}/index.html")
    return 0


def cmd_report(a) -> int:
    store = Store(a.db)
    row = store.latest_scan(a.server_id)
    if not row:
        print(f"no scan for {a.server_id}", file=sys.stderr)
        return 1
    import json

    from .models import Finding

    findings = [Finding.from_dict(x) for x in json.loads(row["findings_json"])]
    print(f"{row['grade']}  {a.server_id}  score={row['score']}  "
          f"scanned {row['scanned_at']}")
    for f in findings:
        print(f"  [{f.rule_id}/{f.severity.value}] {f.tool_name}: {f.title}")
        print(f"      {f.remediation}")
    hist = store.tool_history(a.server_id)
    print(f"\ntool versions on record: {len(hist)}")
    for h in hist:
        print(f"  {h['tool_name']:<28} {h['fingerprint']}  "
              f"{h['first_seen'][:10]} -> {h['last_seen'][:10]}")
    return 0


def cmd_export(a) -> int:
    n = Store(a.db).export_jsonl(a.out)
    print(f"{n} tool versions -> {a.out}")
    return 0


def cmd_stats(a) -> int:
    print(Store(a.db).stats())
    return 0


def cmd_prune(a) -> int:
    from . import sandbox

    print(f"removed {sandbox.prune()} leftover sandbox images")
    return 0


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcpaudit",
        description="Security scanner and trust registry for MCP servers.",
    )
    p.add_argument("--db", default="data/mcpaudit.db", help="SQLite database path")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan servers from the seed file / registry")
    s.add_argument("--seed", default="data/seed_servers.json")
    s.add_argument("--registry", action="store_true", help="also pull the public MCP registry")
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--only", nargs="*", help="scan only these server ids")
    s.add_argument("--llm", action="store_true", help="enable the optional LLM judge (costs money)")
    s.add_argument("--allow-local", action="store_true", help="permit repo-local fixture servers")
    s.add_argument("--timeout", type=float, default=30.0)
    s.add_argument("--install-timeout", type=int, default=300)
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("demo", help="scan the bundled examples and build the site")
    d.add_argument("--seed", default="data/demo_servers.json")
    d.add_argument("--out", default="site")
    d.set_defaults(func=cmd_demo)

    c = sub.add_parser("check", help="one-off scan of a single server")
    c.add_argument("--url", help="http/sse endpoint")
    c.add_argument("--npm", help="npm package name")
    c.add_argument("--pypi", help="pypi package name")
    c.add_argument("args", nargs="*", help="extra args passed to the server")
    c.add_argument("--timeout", type=float, default=30.0)
    c.add_argument("--install-timeout", type=int, default=300)
    c.set_defaults(func=cmd_check)

    b = sub.add_parser("site", help="regenerate the static site from the database")
    b.add_argument("--out", default="site")
    b.set_defaults(func=cmd_site)

    r = sub.add_parser("report", help="print the latest report for one server")
    r.add_argument("server_id")
    r.set_defaults(func=cmd_report)

    x = sub.add_parser("export", help="write the git-diffable history file")
    x.add_argument("--out", default="data/history.jsonl")
    x.set_defaults(func=cmd_export)

    sub.add_parser("stats", help="database counts").set_defaults(func=cmd_stats)
    sub.add_parser("prune", help="delete leftover sandbox images").set_defaults(func=cmd_prune)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
