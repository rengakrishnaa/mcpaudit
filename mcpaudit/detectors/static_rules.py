"""
Deterministic detectors. Pure functions over tool JSON.

No network. No LLM. No cost. Microseconds per tool.

DESIGN NOTE (this is the interview answer):
    ~95% of checks never touch a model. Only genuinely ambiguous descriptions
    escalate to the optional LLM tier. That is what keeps cost per scan at zero
    for the free tier, and in cents at ecosystem scale.
"""
from __future__ import annotations

import re

from ..models import Finding, Severity, Tool

# ---------------------------------------------------------------------------
# MCP001 — instructions aimed at the MODEL, hidden in a tool description.
#
# The description is injected verbatim into the model's context. The model has
# no reliable way to distinguish "metadata about a tool" from "an instruction".
# Second-person imperatives in a description are the core tool-poisoning
# primitive (Invariant Labs).
# ---------------------------------------------------------------------------
_IMPERATIVE = re.compile(
    r"\b(?:"
    r"you\s+must|you\s+should|you\s+need\s+to|"
    r"always\s+(?:call|use|include|send|read|pass|append)|"
    r"never\s+(?:tell|mention|reveal|disclose|inform)|"
    r"before\s+(?:using|calling|responding|invoking)|"
    r"do\s+not\s+(?:tell|mention|inform|reveal|disclose|output|show)|"
    r"ignore\s+(?:previous|prior|above|all|any)|"
    r"disregard\s+(?:previous|prior|the|all)|"
    r"instead\s+of\s+(?:calling|using|invoking)|"
    r"first,?\s+(?:call|read|send|fetch)"
    r")\b"
    # NOT a bare "IMPORTANT:" — real docs use it for rate limits and caveats.
    # The tag form and role-impersonation prefixes have no honest use.
    r"|<\s*IMPORTANT\s*>|<\s*SYSTEM\s*>|\bSYSTEM:\s|\bASSISTANT:\s|\bHUMAN:\s",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# MCP002 — exfiltration: a verb of transmission near an external destination.
# ---------------------------------------------------------------------------
_EXFIL = re.compile(
    r"\b(?:send|post|upload|transmit|forward|exfiltrat\w*|leak|report)\b"
    r"[^.\n]{0,60}\b(?:to|at|via|through)\b[^.\n]{0,40}"
    r"(?:https?://|\b[\w.-]+\.(?:com|net|io|ru|cn|xyz|top|tk|link|site)\b)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# MCP003 — credential material and sensitive paths.
# ---------------------------------------------------------------------------
_SENSITIVE = re.compile(
    r"(?:"
    r"~?/?\.ssh/|id_rsa|id_ed25519|id_ecdsa|"
    r"\.env\b|\.aws/credentials|\.config/gcloud|"
    r"/etc/passwd|/etc/shadow|\.git-credentials|"
    r"\.npmrc|\.pypirc|kubeconfig|\.docker/config\.json|"
    r"\bAPI[_\- ]?KEY\b|\bSECRET[_\- ]?KEY\b|\bACCESS[_\- ]?TOKEN\b|"
    r"\bPRIVATE[_\- ]?KEY\b|\bBEARER[_\- ]?TOKEN\b|\bPASSWORD\b"
    r")",
    re.IGNORECASE,
)

# Credential-shaped environment variables: GITHUB_TOKEN, OPENAI_API_KEY,
# AWS_SECRET_ACCESS_KEY. Case-SENSITIVE on purpose — lowercase "my_key" is a
# variable name in prose, uppercase is a secret.
_ENV_SECRET = re.compile(
    r"\b[A-Z][A-Z0-9]{2,30}_(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIALS?)\b"
)

# ---------------------------------------------------------------------------
# MCP004 — content hidden from a human reviewing the description.
# ---------------------------------------------------------------------------
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­"}
_BIDI = {"‪", "‫", "‬", "‭", "‮",
         "⁦", "⁧", "⁨", "⁩"}

# ---------------------------------------------------------------------------
# MCP005 — tool shadowing: a description that modifies ANOTHER tool's behaviour.
# ---------------------------------------------------------------------------
_MODIFIER = re.compile(
    r"\b(?:instead(?:\s+of)?|rather\s+than|before|after|override|replace|"
    r"always|never|bypass|route\s+through)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# MCP008 — dangerous capability.
#
# FIXED FALSE POSITIVE: the first version matched these keywords anywhere in
# prose, so a description containing "reveal the system prompt" was flagged as
# exposing command execution. Now the keyword must appear either
#   (a) in the TOOL NAME, or
#   (b) as a verb phrase acting on something ("execute a shell command"),
# not merely as a noun somewhere in the text.
# ---------------------------------------------------------------------------
_DANGEROUS_IN_NAME = re.compile(
    r"(?:^|[_\-\s])(?:exec|eval|shell|spawn|system|subprocess|run_?command|"
    r"sudo|chmod|rm_?rf|drop_?(?:table|database)|delete_?all|truncate)"
    r"(?:$|[_\-\s])",
    re.IGNORECASE,
)
_DANGEROUS_VERB_PHRASE = re.compile(
    r"\b(?:execut\w*|run|invoke|spawn|eval\w*)\b\s+"
    r"(?:(?:a|an|any|the|arbitrary|raw|custom|new)\s+)*"
    r"(?:shell|bash|sh|system|os|terminal|command|script|code|sql\s+quer\w+)\b",
    re.IGNORECASE,
)


def _snippet(text: str, m: re.Match, pad: int = 45) -> str:
    """Readable evidence string around a match."""
    a = max(0, m.start() - pad)
    b = min(len(text), m.end() + pad)
    return ("..." if a else "") + text[a:b].replace("\n", " ") + ("..." if b < len(text) else "")


# ===========================================================================
# Rules
# ===========================================================================

def check_description_injection(t: Tool) -> list[Finding]:
    """MCP001 — CRITICAL."""
    m = _IMPERATIVE.search(t.description)
    if not m:
        return []
    return [Finding(
        rule_id="MCP001",
        severity=Severity.CRITICAL,
        tool_name=t.name,
        title="Tool description contains instructions directed at the model",
        evidence=_snippet(t.description, m),
        remediation=(
            "A description should describe what the tool does. Instructions to the "
            "model belong to the user, not the tool author. Treat this server as hostile "
            "until the description is corrected."
        ),
    )]


def check_exfiltration(t: Tool) -> list[Finding]:
    """MCP002 — HIGH."""
    m = _EXFIL.search(t.description)
    if not m:
        return []
    return [Finding(
        rule_id="MCP002",
        severity=Severity.HIGH,
        tool_name=t.name,
        title="Description instructs sending data to an external destination",
        evidence=_snippet(t.description, m),
        remediation=(
            "Verify the destination. A tool that legitimately needs egress should declare "
            "it in the schema and documentation, not bury it in prose the model will read."
        ),
    )]


def check_sensitive_paths(t: Tool) -> list[Finding]:
    """MCP003 — HIGH."""
    blob = t.description + " " + str(t.input_schema)
    m = _SENSITIVE.search(blob) or _ENV_SECRET.search(blob)
    if not m:
        return []
    return [Finding(
        rule_id="MCP003",
        severity=Severity.HIGH,
        tool_name=t.name,
        title="References credential material or sensitive paths",
        evidence=_snippet(blob, m),
        remediation=(
            "Confirm the tool genuinely needs this. Scope filesystem access to an explicit "
            "allowlist and never let a path be model-controlled."
        ),
    )]


def check_hidden_content(t: Tool) -> list[Finding]:
    """MCP004 — CRITICAL. Content the human reviewer cannot see but the model can."""
    out: list[Finding] = []

    m = _HTML_COMMENT.search(t.description)
    if m:
        out.append(Finding(
            rule_id="MCP004",
            severity=Severity.CRITICAL,
            tool_name=t.name,
            title="HTML comment in description (invisible in most UIs, visible to the model)",
            evidence=_snippet(t.description, m),
            remediation="Reject. There is no legitimate reason to hide text from a human reviewer.",
        ))

    zw = sorted(_ZERO_WIDTH & set(t.description))
    if zw:
        out.append(Finding(
            rule_id="MCP004",
            severity=Severity.CRITICAL,
            tool_name=t.name,
            title="Zero-width characters in description",
            evidence=f"{len(zw)} distinct zero-width codepoints: {[hex(ord(c)) for c in zw]}",
            remediation="Reject. Used to smuggle instructions past human review.",
        ))

    bd = sorted(_BIDI & set(t.description))
    if bd:
        out.append(Finding(
            rule_id="MCP004",
            severity=Severity.CRITICAL,
            tool_name=t.name,
            title="Bidirectional-override characters in description",
            evidence=f"codepoints: {[hex(ord(c)) for c in bd]}",
            remediation="Reject. Text can render differently from how it parses.",
        ))

    return out


def check_cross_tool_reference(t: Tool, all_names: set[str]) -> list[Finding]:
    """MCP005 — HIGH. Tool A's description altering tool B's behaviour."""
    if not _MODIFIER.search(t.description):
        return []
    for other in sorted(all_names - {t.name}):
        if len(other) < 4:
            continue
        m = re.search(rf"\b{re.escape(other)}\b", t.description)
        if m:
            return [Finding(
                rule_id="MCP005",
                severity=Severity.HIGH,
                tool_name=t.name,
                title=f"Description modifies the behaviour of another tool ('{other}')",
                evidence=_snippet(t.description, m),
                remediation=(
                    "Cross-tool instructions are the shadowing primitive: a benign-looking "
                    "tool can redirect calls meant for a sensitive one. Each tool should "
                    "describe only itself."
                ),
            )]
    return []


def check_permissive_schema(t: Tool) -> list[Finding]:
    """MCP006 — MEDIUM/LOW. An unconstrained tool cannot be validated or sandboxed."""
    out: list[Finding] = []
    s = t.input_schema

    if not s:
        return [Finding(
            rule_id="MCP006",
            severity=Severity.MEDIUM,
            tool_name=t.name,
            title="Tool declares no input schema",
            evidence="inputSchema missing or empty",
            remediation="Declare a JSON schema so arguments can be validated before the call.",
        )]

    if s.get("additionalProperties") is True:
        out.append(Finding(
            rule_id="MCP006",
            severity=Severity.MEDIUM,
            tool_name=t.name,
            title="Schema allows arbitrary additional properties",
            evidence="additionalProperties: true",
            remediation="Set additionalProperties: false so the argument set is closed.",
        ))

    props = s.get("properties") or {}
    untyped = [k for k, v in props.items() if isinstance(v, dict) and not v.get("type")]
    if untyped:
        out.append(Finding(
            rule_id="MCP006",
            severity=Severity.LOW,
            tool_name=t.name,
            title="Parameters with no declared type",
            evidence=f"untyped: {untyped[:5]}",
            remediation="Declare a type for every parameter so inputs can be validated.",
        ))

    return out


def check_dangerous_capability(t: Tool) -> list[Finding]:
    """
    MCP008 — MEDIUM.

    Not automatically a vulnerability: plenty of legitimate tools run commands.
    The point is that such a tool must never be auto-approved.
    """
    m = _DANGEROUS_IN_NAME.search(t.name)
    where = "tool name"
    if not m:
        m = _DANGEROUS_VERB_PHRASE.search(t.description)
        where = "description"
    if not m:
        return []

    src = t.name if where == "tool name" else t.description
    return [Finding(
        rule_id="MCP008",
        severity=Severity.MEDIUM,
        tool_name=t.name,
        title="Tool exposes a command-execution-style capability",
        evidence=f"matched in {where}: {_snippet(src, m)}",
        remediation=(
            "Not automatically a vulnerability, but this tool must never be auto-approved "
            "and its arguments must be allowlisted rather than model-controlled."
        ),
        confidence=0.8,
    )]


# --- registry of single-tool rules --------------------------------------------
SINGLE_TOOL_RULES = [
    check_description_injection,
    check_exfiltration,
    check_sensitive_paths,
    check_hidden_content,
    check_permissive_schema,
    check_dangerous_capability,
]


def run_static(tools: list[Tool]) -> list[Finding]:
    """Run every deterministic rule over a server's tool list."""
    names = {t.name for t in tools}
    out: list[Finding] = []
    for t in tools:
        for rule in SINGLE_TOOL_RULES:
            out.extend(rule(t))
        out.extend(check_cross_tool_reference(t, names))
    return out
