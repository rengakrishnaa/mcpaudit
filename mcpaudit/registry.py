"""
Where the list of servers to scan comes from.

Two sources, deliberately:

  1. data/seed_servers.json — a hand-curated file committed to the repo.
     This is the source of truth for the demo. It always works, offline, on
     any machine, forever. No API key, no rate limit, no upstream outage.

  2. The official MCP registry API (optional, --from-registry).
     Useful for scale, but it is someone else's uptime. The scanner degrades
     to the seed file rather than failing.

The upstream schema has moved more than once. Everything here is defensive:
unknown shapes are skipped with a warning, never crash the nightly job.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import ServerSpec

REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"

SEED_PATH = Path("data/seed_servers.json")


# --------------------------------------------------------------------------
# seed file
# --------------------------------------------------------------------------


def load_seed(path: str | Path = SEED_PATH) -> list[ServerSpec]:
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    servers = data["servers"] if isinstance(data, dict) else data
    return [ServerSpec.from_dict(d) for d in servers]


def save_seed(specs: Iterable[ServerSpec], path: str | Path = SEED_PATH) -> int:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    items = sorted({s.id: s for s in specs}.values(), key=lambda s: s.id)
    p.write_text(
        json.dumps({"servers": [s.to_dict() for s in items]}, indent=2) + "\n",
        encoding="utf-8",
    )
    return len(items)


# --------------------------------------------------------------------------
# upstream registry
# --------------------------------------------------------------------------


def _http_get(url: str, timeout: float = 20.0) -> dict:
    try:
        import httpx  # type: ignore

        r = httpx.get(url, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "mcpaudit/0.1"})
        r.raise_for_status()
        return r.json()
    except ImportError:
        import urllib.request

        req = urllib.request.Request(url, headers={"User-Agent": "mcpaudit/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))


_SLUG = re.compile(r"[^a-z0-9._@/-]+")


def _slug(s: str) -> str:
    return _SLUG.sub("-", (s or "").strip().lower()).strip("-")


def _spec_from_registry_entry(entry: dict[str, Any]) -> ServerSpec | None:
    """
    Map one upstream record to a ServerSpec.

    Upstream wraps the useful bits differently across versions, so we probe a
    couple of shapes and give up quietly on anything we don't recognise.
    """
    server = entry.get("server") or entry
    name = server.get("name") or ""
    if not name:
        return None
    homepage = server.get("repository", {}).get("url", "") if isinstance(
        server.get("repository"), dict) else ""

    # Remote (HTTP/SSE) servers.
    for remote in server.get("remotes") or []:
        url = remote.get("url")
        if url:
            return ServerSpec(
                id=f"http:{_slug(name)}",
                name=name,
                transport="http",
                url=url,
                source="registry",
                homepage=homepage,
            )

    # Package-based (stdio) servers.
    for pkg in server.get("packages") or []:
        registry_name = (pkg.get("registryType") or pkg.get("registry_name")
                         or pkg.get("registry") or "").lower()
        identifier = (pkg.get("identifier") or pkg.get("name") or "")
        if not identifier:
            continue
        if registry_name in ("npm", "npmjs"):
            runtime, prefix = "node", "npm"
        elif registry_name in ("pypi", "pip"):
            runtime, prefix = "python", "pypi"
        else:
            continue

        env = {}
        for e in (pkg.get("environmentVariables") or pkg.get("environment_variables") or []):
            key = e.get("name") if isinstance(e, dict) else None
            if key:
                env[key] = ""

        args = []
        for a in (pkg.get("runtimeArguments") or []):
            if isinstance(a, dict) and a.get("value"):
                args.append(str(a["value"]))

        return ServerSpec(
            id=f"{prefix}:{identifier}",
            name=name,
            transport="stdio",
            runtime=runtime,
            package=identifier,
            args=args,
            env=env,
            source="registry",
            homepage=homepage,
        )
    return None


def fetch_registry(limit: int = 200, max_pages: int = 10) -> list[ServerSpec]:
    """Best effort. Returns [] rather than raising, so the nightly job survives."""
    specs: list[ServerSpec] = []
    cursor: str | None = None
    for _ in range(max_pages):
        url = f"{REGISTRY_URL}?limit={min(limit, 100)}"
        if cursor:
            url += f"&cursor={cursor}"
        try:
            data = _http_get(url)
        except Exception:
            break
        entries = data.get("servers") or data.get("data") or []
        for e in entries:
            spec = _spec_from_registry_entry(e)
            if spec:
                specs.append(spec)
        meta = data.get("metadata") or {}
        cursor = meta.get("nextCursor") or meta.get("next_cursor")
        if not cursor or len(specs) >= limit:
            break
    return specs[:limit]


def resolve(
    use_registry: bool = False,
    seed_path: str | Path = SEED_PATH,
    limit: int = 200,
) -> list[ServerSpec]:
    """Seed file first; upstream entries appended, deduped by id."""
    by_id: dict[str, ServerSpec] = {s.id: s for s in load_seed(seed_path)}
    if use_registry:
        for s in fetch_registry(limit=limit):
            by_id.setdefault(s.id, s)
    return list(by_id.values())
