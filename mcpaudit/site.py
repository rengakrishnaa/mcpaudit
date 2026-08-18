"""
Static site generator — the free-forever hosting decision.

Why a static site and not FastAPI on a free tier:

  * A free web dyno sleeps. An interviewer opening your link gets a 30-second
    cold start, or a 502, or "this app has been suspended". That is worse than
    no link.
  * Free Postgres tiers expire (90 days is typical) and then the site is a
    stack trace forever.
  * GitHub Pages is free with no card on file, has no cold start, and serves
    from a CDN. The scan runs in GitHub Actions once a night, writes HTML and
    JSON, and pushes. Nothing is running the rest of the day, so nothing can
    fall over or bill you.

The tradeoff you should be able to defend out loud: no live "scan this URL
for me" box. The answer is that the registry's value is HISTORY, which is
inherently precomputed, and anyone who wants a live scan runs the CLI. If the
site ever needs interactivity, the JSON API here is already the backend.

Output tree:
    site/
      index.html                 leaderboard
      server/<slug>.html         one page per server: findings + timeline
      api/index.json             every server, latest scan
      api/server/<slug>.json     full detail
      api/badge/<slug>.json      shields.io endpoint (free badges)
"""
from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from .detectors.rug_pull import _short_diff
from .models import Finding, Severity
from .storage import Store

GRADE_COLOR = {"A": "#3fb950", "B": "#a5d16a", "C": "#d29922",
               "D": "#f0883e", "F": "#f85149"}

SEV_COLOR = {"critical": "#f85149", "high": "#f0883e", "medium": "#d29922",
             "low": "#8b949e", "info": "#6e7681"}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug(server_id: str) -> str:
    return _SLUG_RE.sub("-", server_id.lower()).strip("-")


def e(x) -> str:
    return html.escape(str(x if x is not None else ""))


CSS = """
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--dim:#8b949e;--acc:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 80px}
header h1{font-size:26px;margin:0 0 6px}
header p{color:var(--dim);margin:0 0 4px;max-width:70ch}
.stats{display:flex;gap:28px;flex-wrap:wrap;margin:26px 0;padding:16px 20px;
 background:var(--panel);border:1px solid var(--border);border-radius:8px}
.stat b{display:block;font-size:24px;line-height:1.2}
.stat.small b{font-size:14px;font-weight:600;padding-top:9px}
.stat span{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
input[type=search]{width:100%;padding:10px 14px;margin:18px 0;background:var(--panel);
 border:1px solid var(--border);border-radius:8px;color:var(--fg);font-size:15px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--dim);font-weight:600;font-size:12px;
 text-transform:uppercase;letter-spacing:.06em;padding:8px 10px;border-bottom:1px solid var(--border)}
td{padding:11px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tr:hover td{background:#161b2280}
.grade{display:inline-block;width:26px;height:26px;line-height:26px;text-align:center;
 border-radius:6px;font-weight:700;color:#0d1117;font-size:14px}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;
 font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:#0d1117}
.finding{background:var(--panel);border:1px solid var(--border);border-left-width:4px;
 border-radius:8px;padding:14px 16px;margin:12px 0}
.finding h3{margin:0 0 6px;font-size:15px}
.finding .meta{color:var(--dim);font-size:12px;margin-bottom:8px}
pre{background:#010409;border:1px solid var(--border);border-radius:6px;
 padding:10px 12px;overflow-x:auto;font-size:12.5px;margin:8px 0 0;white-space:pre-wrap;
 word-break:break-word}
pre .add{color:#3fb950}pre .del{color:#f85149}
.rem{color:var(--dim);font-size:13px;margin-top:8px}
code{background:#010409;padding:1px 5px;border-radius:4px;font-size:12.5px}
footer{margin-top:60px;padding-top:20px;border-top:1px solid var(--border);
 color:var(--dim);font-size:13px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.badge-note{color:var(--dim);font-size:12px}
"""


def _layout(title: str, body: str, depth: int = 0) -> str:
    up = "../" * depth
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="Security scores and tool-definition history for Model Context Protocol servers.">
<style>{CSS}</style>
</head><body><div class="wrap">
<header><h1><a href="{up}index.html" style="color:inherit">MCPAudit</a></h1></header>
{body}
<footer>
Scanned automatically once a day by a GitHub Actions job. Static site — no server, no database.
&middot; <a href="{up}api/index.json">JSON API</a>
&middot; <a href="https://github.com/rengakrishnaa/mcpaudit">Source</a>
</footer>
</div></body></html>
"""


def _grade_span(grade: str) -> str:
    return (f'<span class="grade" style="background:{GRADE_COLOR.get(grade, "#8b949e")}">'
            f'{e(grade)}</span>')


def _diff_html(text: str) -> str:
    out = []
    for line in text.splitlines():
        cls = "add" if line.startswith("+") else "del" if line.startswith("-") else ""
        out.append(f'<span class="{cls}">{e(line)}</span>' if cls else e(line))
    return "\n".join(out)


def _finding_html(f: Finding) -> str:
    color = SEV_COLOR.get(f.severity.value, "#8b949e")
    conf = "" if f.confidence >= 1.0 else f" &middot; confidence {f.confidence:.0%}"
    return f"""<div class="finding" style="border-left-color:{color}">
  <h3>{e(f.title)}</h3>
  <div class="meta"><span class="pill" style="background:{color}">{e(f.severity.value)}</span>
    &nbsp;<span class="mono">{e(f.rule_id)}</span> &middot; tool <code>{e(f.tool_name)}</code>{conf}</div>
  <pre>{_diff_html(f.evidence)}</pre>
  <div class="rem"><b>Fix:</b> {e(f.remediation)}</div>
</div>"""


# --------------------------------------------------------------------------


def build(store: Store, out_dir: str | Path = "site") -> dict:
    out = Path(out_dir)
    (out / "server").mkdir(parents=True, exist_ok=True)
    (out / "api" / "server").mkdir(parents=True, exist_ok=True)
    (out / "api" / "badge").mkdir(parents=True, exist_ok=True)

    rows = store.all_latest_scans()
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    total_findings = sum(len(r["findings"]) for r in rows)
    criticals = sum(1 for r in rows for f in r["findings"]
                    if f.severity is Severity.CRITICAL)
    failing = sum(1 for r in rows if r["grade"] in ("D", "F"))

    # ---- index ----------------------------------------------------------
    trs = []
    for r in rows:
        sid = r["server_id"]
        counts = {s.value: 0 for s in Severity}
        for f in r["findings"]:
            counts[f.severity.value] += 1
        chips = " ".join(
            f'<span class="pill" style="background:{SEV_COLOR[k]}">{v} {k[:4]}</span>'
            for k, v in counts.items() if v
        ) or '<span style="color:var(--dim)">clean</span>'
        status = "" if r["scanned_ok"] else ' <span style="color:var(--dim)">(scan failed)</span>'
        trs.append(f"""<tr data-name="{e(sid.lower())}">
  <td>{_grade_span(r['grade'])}</td>
  <td><a href="server/{slug(sid)}.html">{e(r.get('display_name') or sid)}</a>{status}
      <div class="mono" style="color:var(--dim)">{e(sid)}</div></td>
  <td>{r['score']}</td>
  <td>{r['tool_count']}</td>
  <td>{chips}</td>
</tr>""")

    index_body = f"""
<p>Security scores and <b>tool-definition history</b> for Model Context Protocol servers.</p>
<p>An MCP client injects every tool's name, description and JSON schema straight into the
model's context. A tool description is therefore untrusted input arriving with system
authority. MCPAudit reads what each server tells the model, checks it against eight
attack classes, and — the part a local scanner structurally cannot do —
<b>fingerprints every tool on every scan</b>, so a server that ships clean descriptions,
gets adopted, then quietly rewrites them gets caught.</p>

<div class="stats">
  <div class="stat"><b>{len(rows)}</b><span>servers scanned</span></div>
  <div class="stat"><b>{total_findings}</b><span>findings</span></div>
  <div class="stat"><b>{criticals}</b><span>critical</span></div>
  <div class="stat"><b>{failing}</b><span>graded D or F</span></div>
  <div class="stat small"><b>{e(generated)}</b><span>last scan</span></div>
</div>

<input type="search" id="q" placeholder="Filter servers…" autocomplete="off">
<table><thead><tr>
  <th>Grade</th><th>Server</th><th>Score</th><th>Tools</th><th>Findings</th>
</tr></thead><tbody id="rows">
{''.join(trs) or '<tr><td colspan="5">No scans yet.</td></tr>'}
</tbody></table>

<script>
const q=document.getElementById('q');
q.addEventListener('input',()=>{{const v=q.value.toLowerCase();
for(const tr of document.querySelectorAll('#rows tr'))
  tr.style.display=(tr.dataset.name||'').includes(v)?'':'none';}});
</script>
"""
    (out / "index.html").write_text(_layout("MCPAudit — MCP server trust registry",
                                            index_body), encoding="utf-8")

    # ---- per-server pages ------------------------------------------------
    for r in rows:
        sid = r["server_id"]
        sl = slug(sid)
        history = store.tool_history(sid)

        findings_html = "".join(_finding_html(f) for f in r["findings"]) or (
            '<p style="color:var(--dim)">No findings. This server\'s tool definitions '
            'contain nothing the rules flag.</p>')

        errs = ""
        if r["errors"]:
            errs = ('<div class="finding" style="border-left-color:#6e7681">'
                    '<h3>Scan did not complete</h3><pre>'
                    + e("\n".join(r["errors"])) + "</pre></div>")

        # Tools with more than one recorded version get the diff rendered inline.
        # This is what keeps a rug pull VISIBLE on the site permanently: the
        # MCP007 finding only appears on the scan that caught the change, but
        # the history is the durable record, and a record you have to diff
        # yourself is a record nobody reads.
        by_tool: dict[str, list[dict]] = {}
        for h in history:
            by_tool.setdefault(h["tool_name"], []).append(h)

        hist_rows_list = []
        for h in history[:200]:
            versions = by_tool[h["tool_name"]]
            idx = versions.index(h)
            hist_rows_list.append(
                f"<tr><td><code>{e(h['tool_name'])}</code>"
                + (f" <span style='color:var(--dim)'>v{idx + 1}</span>" if len(versions) > 1 else "")
                + f"</td><td class='mono'>{e(h['fingerprint'])}</td>"
                f"<td class='mono'>{e(h['first_seen'][:10])}</td>"
                f"<td class='mono'>{e(h['last_seen'][:10])}</td></tr>"
            )
            if idx > 0:
                d = _short_diff(versions[idx - 1]["description"], h["description"])
                if d:
                    hist_rows_list.append(
                        f"<tr><td colspan='4' style='padding-top:0'>"
                        f"<div style='color:var(--dim);font-size:12px;margin-bottom:4px'>"
                        f"changed from v{idx} &rarr; v{idx + 1}:</div>"
                        f"<pre>{_diff_html(d)}</pre></td></tr>"
                    )
        hist_rows = "".join(hist_rows_list) or (
            "<tr><td colspan='4' style='color:var(--dim)'>First scan — no history yet.</td></tr>")

        n_versions = len(history)
        n_tools = len({h["tool_name"] for h in history})
        drift = (f"{n_versions} recorded versions of {n_tools} tools"
                 if n_tools else "no tools recorded")

        meta_bits = []
        if r.get("package"):
            meta_bits.append(f"package <code>{e(r['package'])}</code>")
        if r.get("url"):
            meta_bits.append(f"endpoint <code>{e(r['url'])}</code>")
        if r.get("homepage"):
            meta_bits.append(f'<a href="{e(r["homepage"])}">source</a>')
        if r.get("server_version"):
            meta_bits.append(f"server version {e(r['server_version'])}")

        body = f"""
<p><a href="../index.html">&larr; all servers</a></p>
<h2 style="margin-bottom:4px">{_grade_span(r['grade'])} &nbsp;{e(r.get('display_name') or sid)}</h2>
<p class="mono" style="color:var(--dim);margin-top:0">{e(sid)}</p>
<p style="color:var(--dim)">{' &middot; '.join(meta_bits)}</p>

<div class="stats">
  <div class="stat"><b>{r['score']}</b><span>score / 100</span></div>
  <div class="stat"><b>{r['tool_count']}</b><span>tools</span></div>
  <div class="stat"><b>{len(r['findings'])}</b><span>findings</span></div>
  <div class="stat"><b>{n_versions}</b><span>tool versions seen</span></div>
</div>

{errs}
<h2>Findings</h2>
{findings_html}

<h2>Tool fingerprint history</h2>
<p style="color:var(--dim)">Every scan hashes each tool's name + description + schema.
A second row for the same tool means the definition the model is shown changed
after we first recorded it. {e(drift)}.</p>
<table><thead><tr><th>Tool</th><th>Fingerprint</th><th>First seen</th><th>Last seen</th></tr></thead>
<tbody>{hist_rows}</tbody></table>

<h2>Badge</h2>
<p class="badge-note">Paste into a README:</p>
<pre>![MCPAudit](https://img.shields.io/endpoint?url=https://rengakrishnaa.github.io/mcpaudit/api/badge/{sl}.json)</pre>
"""
        (out / "server" / f"{sl}.html").write_text(
            _layout(f"{sid} — MCPAudit", body, depth=1), encoding="utf-8")

        # per-server JSON
        detail = {
            "server_id": sid,
            "display_name": r.get("display_name"),
            "grade": r["grade"],
            "score": r["score"],
            "scanned_at": r["scanned_at"],
            "scanned_ok": bool(r["scanned_ok"]),
            "scanner_version": r["scanner_version"],
            "tool_count": r["tool_count"],
            "findings": [f.to_dict() for f in r["findings"]],
            "errors": r["errors"],
            "history": history,
        }
        (out / "api" / "server" / f"{sl}.json").write_text(
            json.dumps(detail, indent=2), encoding="utf-8")

        # shields.io endpoint badge — free hosting for the badge too
        (out / "api" / "badge" / f"{sl}.json").write_text(
            json.dumps({
                "schemaVersion": 1,
                "label": "mcpaudit",
                "message": f"{r['grade']} ({r['score']})",
                "color": GRADE_COLOR.get(r["grade"], "lightgrey"),
            }, indent=2),
            encoding="utf-8",
        )

    # ---- index JSON ------------------------------------------------------
    (out / "api" / "index.json").write_text(
        json.dumps({
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "scanner_version": rows[0]["scanner_version"] if rows else None,
            "server_count": len(rows),
            "servers": [
                {
                    "server_id": r["server_id"],
                    "display_name": r.get("display_name"),
                    "grade": r["grade"],
                    "score": r["score"],
                    "tool_count": r["tool_count"],
                    "finding_count": len(r["findings"]),
                    "scanned_ok": bool(r["scanned_ok"]),
                    "detail": f"api/server/{slug(r['server_id'])}.json",
                }
                for r in rows
            ],
        }, indent=2),
        encoding="utf-8",
    )

    # Tell GitHub Pages not to run Jekyll: it silently drops files starting
    # with an underscore, which is a genuinely confusing way to lose a page.
    (out / ".nojekyll").write_text("", encoding="utf-8")

    return {"servers": len(rows), "findings": total_findings, "out": str(out)}
