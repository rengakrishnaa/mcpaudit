"""
MCP007 — rug-pull detection.

THIS IS THE DIFFERENTIATOR.

Every other rule in this project looks at a single snapshot. A local scanner can
do that. What a local scanner structurally cannot do is tell you that the tool
description a server is showing the model TODAY is different from the one you
approved LAST MONTH -- because it holds no history and sees only your machine.

The mechanism is deliberately simple:
    fingerprint = sha256(name + description + inputSchema)
If it changes between scans, the model is being shown something different.

Severity is graded by what changed:
    - a description that gained an imperative instruction  -> CRITICAL
    - any description change at all                        -> HIGH
    - schema-only change                                   -> MEDIUM
    - a brand-new tool appearing                           -> MEDIUM
because "the docs got clearer" and "the tool now asks for your SSH key" are not
the same event.
"""
from __future__ import annotations

import difflib

from ..models import Finding, Severity, Tool
from .static_rules import _EXFIL, _IMPERATIVE, _SENSITIVE


def _short_diff(old: str, new: str, max_lines: int = 6) -> str:
    """A compact unified diff. This is what makes a rug-pull report readable."""
    diff = list(difflib.unified_diff(
        old.splitlines() or [""],
        new.splitlines() or [""],
        fromfile="before",
        tofile="after",
        lineterm="",
        n=0,
    ))
    body = [ln for ln in diff if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))]
    if not body:
        return f"- {old[:120]}\n+ {new[:120]}"
    out = body[:max_lines]
    if len(body) > max_lines:
        out.append(f"... {len(body) - max_lines} more changed lines")
    return "\n".join(out)


def _severity_for_change(old_desc: str, new_desc: str) -> tuple[Severity, str]:
    """Grade the change by what the new text gained."""
    gained_injection = bool(_IMPERATIVE.search(new_desc)) and not _IMPERATIVE.search(old_desc)
    gained_exfil = bool(_EXFIL.search(new_desc)) and not _EXFIL.search(old_desc)
    gained_secrets = bool(_SENSITIVE.search(new_desc)) and not _SENSITIVE.search(old_desc)

    if gained_injection:
        return Severity.CRITICAL, "description gained model-directed instructions"
    if gained_exfil:
        return Severity.CRITICAL, "description gained an exfiltration instruction"
    if gained_secrets:
        return Severity.HIGH, "description gained references to credential material"
    return Severity.HIGH, "description changed after publication"


def check_rug_pull(current: list[Tool], previous: dict[str, Tool]) -> list[Finding]:
    """
    Compare this scan's tools against the last known state.

    Args:
        current:  tools from this scan
        previous: {tool_name: Tool} from the most recent previous scan

    Returns findings for changed, added and removed tools.
    """
    if not previous:
        return []  # first scan -- nothing to compare against

    out: list[Finding] = []
    current_by_name = {t.name: t for t in current}

    # --- changed tools ------------------------------------------------------
    for name, new_tool in current_by_name.items():
        old_tool = previous.get(name)
        if old_tool is None:
            continue
        if old_tool.fingerprint() == new_tool.fingerprint():
            continue

        desc_changed = old_tool.description != new_tool.description
        schema_changed = old_tool.input_schema != new_tool.input_schema

        if desc_changed:
            sev, why = _severity_for_change(old_tool.description, new_tool.description)
            out.append(Finding(
                rule_id="MCP007",
                severity=sev,
                tool_name=name,
                title=f"RUG PULL: {why}",
                evidence=_short_diff(old_tool.description, new_tool.description),
                remediation=(
                    "A tool's description changed after you approved it. Re-review before "
                    "the next run and pin the server version. Approval is not permanent if "
                    "the thing you approved can be silently replaced."
                ),
            ))
        elif schema_changed:
            out.append(Finding(
                rule_id="MCP007",
                severity=Severity.MEDIUM,
                tool_name=name,
                title="Tool input schema changed after publication",
                evidence=_short_diff(str(old_tool.input_schema), str(new_tool.input_schema)),
                remediation="Re-review the argument surface. New parameters can widen scope.",
            ))

    # --- new tools ----------------------------------------------------------
    for name in sorted(set(current_by_name) - set(previous)):
        out.append(Finding(
            rule_id="MCP007",
            severity=Severity.MEDIUM,
            tool_name=name,
            title="New tool appeared since the last scan",
            evidence=f"'{name}' was not present in the previous scan",
            remediation="A server can add capability after approval. Re-review the tool set.",
        ))

    # --- removed tools ------------------------------------------------------
    for name in sorted(set(previous) - set(current_by_name)):
        out.append(Finding(
            rule_id="MCP007",
            severity=Severity.INFO,
            tool_name=name,
            title="Tool removed since the last scan",
            evidence=f"'{name}' is no longer offered",
            remediation="Informational. Check nothing depends on it.",
        ))

    return out
