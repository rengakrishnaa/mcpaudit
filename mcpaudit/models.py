"""
Core data model.

Everything the scanner produces flows through these types. Keeping them in one
place with no dependencies means the detectors, the storage layer and the site
generator all agree on what a "finding" is.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """How bad is it. The weights drive the score, so they are policy, not cosmetics."""

    CRITICAL = "critical"   # an active attack is present in the server's metadata
    HIGH = "high"           # credential/exfiltration capability, or a rug pull
    MEDIUM = "medium"       # excessive scope, weak boundaries
    LOW = "low"             # hygiene
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            "critical": 40,
            "high": 20,
            "medium": 8,
            "low": 3,
            "info": 0,
        }[self.value]


@dataclass(frozen=True)
class Tool:
    """
    One entry from an MCP server's tools/list response.

    The MCP wire format is:
        {"name": str, "description": str, "inputSchema": {...json schema...}}

    These three fields are exactly what a client injects into the model's
    context, which is why they are exactly what we fingerprint and scan.
    """

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_mcp(d: dict[str, Any]) -> Tool:
        """Build from the raw JSON-RPC payload (camelCase on the wire)."""
        return Tool(
            name=d.get("name", ""),
            description=d.get("description") or "",
            input_schema=d.get("inputSchema") or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    def fingerprint(self) -> str:
        """
        Stable hash of everything the MODEL sees.

        This is the primitive behind rug-pull detection (MCP007). If any of the
        three fields changes, the hash changes, and we know the tool the model
        is being shown today is not the tool it was shown yesterday.

        sort_keys=True matters: dict ordering must not affect the hash.
        """
        payload = json.dumps(
            {"n": self.name, "d": self.description, "s": self.input_schema},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class Finding:
    """One detected problem, attached to one tool."""

    rule_id: str
    severity: Severity
    tool_name: str
    title: str
    evidence: str          # the exact substring or value that triggered it
    remediation: str
    confidence: float = 1.0  # 1.0 deterministic rule; <1.0 heuristic or LLM

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Finding:
        return Finding(
            rule_id=d["rule_id"],
            severity=Severity(d["severity"]),
            tool_name=d["tool_name"],
            title=d["title"],
            evidence=d["evidence"],
            remediation=d["remediation"],
            confidence=d.get("confidence", 1.0),
        )


@dataclass
class ScanResult:
    """The output of scanning one server, once."""

    server_id: str
    tools: list[Tool] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scanner_version: str = "0.1.0"
    server_version: str | None = None

    @property
    def score(self) -> int:
        """
        100 down to 0.

        Deterministic and versioned: the same tools + the same scanner version
        always produce the same score. That matters because maintainers will
        argue about grades, and "your server changed" vs "my rules changed"
        has to be answerable.
        """
        penalty = sum(f.severity.weight * f.confidence for f in self.findings)
        return max(0, round(100 - penalty))

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    @property
    def scanned_ok(self) -> bool:
        """Did we actually get a tool list? An errored scan is not a clean scan."""
        return not self.errors and bool(self.tools)

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "score": self.score,
            "grade": self.grade,
            "scanned_ok": self.scanned_ok,
            "tool_count": len(self.tools),
            "tools": [t.to_dict() for t in self.tools],
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.counts_by_severity(),
            "errors": self.errors,
            "scanner_version": self.scanner_version,
            "server_version": self.server_version,
        }


@dataclass
class ServerSpec:
    """
    How to reach one MCP server.

    `transport` decides everything downstream:
      "stdio"  -> we must install and run code, so it goes in a sandbox
      "http"   -> we just POST to a URL, no code runs on our side
    """

    id: str                       # stable slug, e.g. "npm:@modelcontextprotocol/server-github"
    name: str = ""
    transport: str = "stdio"      # stdio | http
    runtime: str = "node"         # node | python  (stdio only)
    package: str = ""             # npm or pypi package name (stdio only)
    args: list[str] = field(default_factory=list)
    url: str = ""                 # http only
    env: dict[str, str] = field(default_factory=dict)
    source: str = "seed"          # where we learned about it
    homepage: str = ""

    @staticmethod
    def from_dict(d: dict[str, Any]) -> ServerSpec:
        return ServerSpec(
            id=d["id"],
            name=d.get("name") or d["id"],
            transport=d.get("transport", "stdio"),
            runtime=d.get("runtime", "node"),
            package=d.get("package", ""),
            args=list(d.get("args") or []),
            url=d.get("url", ""),
            env=dict(d.get("env") or {}),
            source=d.get("source", "seed"),
            homepage=d.get("homepage", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
