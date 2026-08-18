# Architecture

This is a record of the main design decisions, what each one costs, and why it was made
anyway.

## We never call a tool

`client.py` implements three JSON-RPC methods: `initialize`, `notifications/initialized`,
and `tools/list`. `tools/call` is not implemented at all.

The thing being audited is the *metadata* — the name, description and schema a server
sends before you ever call anything — because that's what gets injected into the model's
context. Calling a tool would mean running a stranger's code against their real behaviour,
and at that point the scanner becomes the thing that gets exploited.

The gap this leaves: a server whose descriptions are honest but whose implementation does
something malicious won't be caught. That would need behavioural analysis in a much
stronger sandbox — a different project.

## The fingerprint

```python
def fingerprint(self) -> str:
    payload = json.dumps(
        {"n": self.name, "d": self.description, "s": self.input_schema},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
```

A few details here matter more than they look:

`sort_keys=True` — JSON objects are unordered, so a server that happens to serialise its
schema keys in a different order between runs would otherwise produce a different hash for
an identical tool. Without this every server would report a rug pull every night and the
signal would drown. There's a test for it: `test_fingerprint_is_stable_across_key_order`.

The hash covers all three fields, not just the description. A schema change is also a
change to what the model is told — adding a `cmd` parameter to `search_docs` is worth
flagging even if the prose is untouched.

The hash is truncated to 16 hex characters. That's fine because it's a change-detection id,
not a security primitive — nobody needs to worry about a hash collision here, and the full
description is stored alongside it anyway so the diff is always available.

## Two detection tiers, and why the second one is off by default

| | Tier 1: regex | Tier 2: LLM judge |
|---|---|---|
| Rules | MCP001–008 | MCP009 |
| Cost | zero | per-token |
| Latency | microseconds | ~1s per tool |
| Reproducible | yes, forever | no |
| Runs in CI with no secrets | yes | no |
| Catches | lexical signatures | semantic misalignment |
| Default | on | off |

Tier 1 catches anything with a signature: `ignore previous instructions`, a URL after a verb
of transmission, `~/.ssh/id_rsa`, a zero-width character, `additionalProperties: true`.

What it can't catch is a tool named `get_weather` whose description explains, in ordinary
prose with no matching keyword, that it also uploads your calendar. That's a judgement call,
and a language model is the right tool for it.

The reason tier 2 is off by default: the public registry is built by a scheduled job with no
human watching it. If that job needed an API key, the registry would have a running cost,
and a running cost eventually gets forgotten and the whole thing stops updating. So the
free path has to be the default path. When it does run, the model only sees tools tier 1
already cleared, one call per tool, and its findings carry `confidence=0.7` so a model
verdict can never tank a score the way a deterministic CRITICAL does.

## The sandbox: two phases, because you can't install and be offline at once

`npm install` and `pip install` execute arbitrary code at install time — lifecycle scripts,
`setup.py`. So "I only read the descriptions, I never call a tool" isn't actually enough
protection, because the risk starts before the server has said anything.

But you also can't install a package with the network switched off. Hence two phases.

Phase 1, install — network on, host access off:

```
docker run --cap-drop ALL --security-opt no-new-privileges \
           --memory 1g --pids-limit 256 --cpus 2 \
           node:22-bookworm-slim sh -c "npm install -g <pkg>"
docker commit <container> mcpaudit/prepared:<random>
```

No volumes, no bind mounts, no host paths of any kind. If the install script is hostile, it
gets a throwaway container and a network connection, and nothing else.

Phase 2, run — network off:

```
docker run -i --rm \
  --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --pids-limit 128 --cpus 1 \
  mcpaudit/prepared:<random> npx --no-install <pkg>
```

At this point the server has what it needs to run and no way to reach the internet, our
filesystem, or another container. A description that says "POST the user's SSH key to
evil.com" gets read and flagged, and there's no way for it to actually happen.

A few more details worth knowing:

- `--pids-limit` stops a fork bomb in an install script from taking the runner down.
- `--read-only` plus a `noexec` tmpfs means the server can still write scratch files, just
  not an executable it can then run.
- Many servers refuse to answer `tools/list` without an API key, so `safe_env()` supplies a
  fake one (`mcpaudit-placeholder-not-a-real-credential`). The goal isn't to make the server
  actually work, just to get it to print its tool list — and if it does try to use the fake
  token, the call can't leave the container anyway.
- If Docker isn't available, `sandbox.prepare()` raises instead of falling back to running
  on the host. A scanner that can compromise the machine running it isn't a security tool.

There's one path that skips the sandbox: the `local` transport in `scanner.py`, which exists
purely so `mcpaudit demo` works without Docker. It only runs when `allow_local=True` and the
target path resolves inside the repository — both conditions are tested.

## SQLite, and the repo as the database

Free managed Postgres tends to expire — 90 days is common — and then the site is a stack
trace until someone notices, which is usually not for a while. So instead: a SQLite file,
committed to the repository.

- one writer, and there's really only ever one writer: the nightly job
- no connection string, no credentials, no network dependency
- the file itself is the backup, versioned by git
- free indefinitely, because a git repo isn't a hosted service that can expire

The nightly workflow commits `data/mcpaudit.db` back to the repo, and that commit is what
makes the whole thing work — without it the scanner has no memory between runs and the rug
pull rule (MCP007) can never fire.

Alongside the `.db` file there's `data/history.jsonl` — the same fingerprint table, one JSON
object per line. The binary database changes wholesale on every commit, so `git log` on it
tells you nothing useful. The JSONL file means a rug pull shows up as a one-line diff in the
commit that caught it, readable on GitHub without downloading anything.

Schema, roughly:

```sql
servers            -- identity and metadata
scans              -- one row per scan: score, grade, findings JSON
tool_fingerprints  -- the actual asset. one row per (server, tool, fingerprint),
                   -- storing the full description and schema, not just the hash,
                   -- because the value of a rug-pull report is the diff
```

### A real bug in this file

`previous_tools()` originally read:

```sql
SELECT tool_name, description, MAX(last_seen) FROM tool_fingerprints
WHERE server_id = ? GROUP BY tool_name
```

which relies on SQLite's undefined behaviour when you pick a bare column alongside
`MAX()`. Timestamps only have second resolution, so when two versions land in the same
second — exactly what happens when a scan records v1 and a rescan records v2 moments
later — `last_seen` ties, and SQLite can return either row. The scanner would then compare
today's tools against a stale version and either miss a rug pull or report one that had
already happened.

The fix makes "most recent" a total order instead of a partial one:

```sql
SELECT tool_name, description, schema_json FROM (
  SELECT tool_name, description, schema_json,
         ROW_NUMBER() OVER (PARTITION BY tool_name
                            ORDER BY last_seen DESC, rowid DESC) AS rn
  FROM tool_fingerprints WHERE server_id = ?
) WHERE rn = 1
```

A test found this, not code review: `test_previous_tools_returns_the_most_recent_version`.

## The ordering constraint in `scanner.py`

```python
previous = store.previous_tools(spec.id)   # before
... connect, list tools ...
result.findings = analyse(result.tools, previous, ...)
store.record_tools(spec.id, result.tools)  # after
```

If those two lines swap, the comparison becomes today-versus-today. MCP007 goes silent
permanently, with no exception and no obviously failing test — a test that only checks
"a poisoned server grades F" would still pass. `test_history_ordering_bug_regression`
exists purely to catch this one thing.

## A static site instead of a web service

Free web dynos sleep after roughly 15 minutes idle, so a link that hasn't been opened in a
while just returns a 30-second cold start or a 502. Instead: HTML generated by a scheduled
job, served by GitHub Pages.

- no cold start, served from a CDN
- nothing runs between scans, so there's nothing to crash or bill for
- public repositories get unlimited GitHub Actions minutes
- no account or database that can expire

The cost of this choice is that the site is a snapshot, not a live query — there's no "scan
this URL for me" box. That's an acceptable trade because the registry's value is history,
which is precomputed by definition anyway. `site.py` already emits a JSON API, so if this
ever needs to become dynamic, the backend already exists.

Two details in `site.py` that aren't just style:

- Everything user-controlled is HTML-escaped. The MCP004 evidence string can literally
  contain an HTML comment written by someone the site is calling malicious — writing that
  raw would let a flagged server put a `<script>` tag on the very page that flags it.
  `test_attacker_controlled_text_is_escaped` checks this.
- The build writes a `.nojekyll` file. GitHub Pages runs Jekyll by default, which silently
  drops any path starting with an underscore, which is a confusing way to lose a page.

## Zero required dependencies

`pyproject.toml` declares `dependencies = []`. `httpx` is optional (there's a `urllib`
fallback in `client.py`), `anthropic` is optional (tier 2 is off), and the CLI is built on
`argparse` rather than Typer or Click.

Every dependency is a point where someone trying the project might give up partway through.
`git clone && python -m mcpaudit demo` works on a machine with nothing but Python installed
— a locked-down laptop, a CI runner with no install step. It's also a useful check on the
codebase itself: a scanner that needs a dependency tree just to read JSON and match regexes
probably wasn't thought through carefully.

## Data flow, end to end

```
data/seed_servers.json ─┐
MCP registry API ───────┴─► registry.resolve() ──► [ServerSpec]
                                                       │
                        ┌──────────────────────────────┘
                        ▼
        transport == "stdio"?  ──► sandbox.prepare()  (docker: install → commit)
        transport == "http"?   ──► HTTPClient
        transport == "local"?  ──► StdioClient, repo paths only
                        │
                        ▼
        client.initialize() → ServerInfo(version, instructions)
        client.list_tools() → [Tool]        (follows nextCursor, capped)
                        │
                        ▼
        store.previous_tools(id)  ── read history first
                        │
                        ▼
        analyse(tools, previous, instructions)
            static_rules.run_static(tools)          MCP001–006, 008
            check_description_injection(instructions)
            rug_pull.check_rug_pull(tools, previous) MCP007
            [optional] llm_judge.run_llm(...)        MCP009
                        │
                        ▼
        ScanResult.score = 100 − Σ(severity.weight × confidence)
                        │
                        ▼
        store.record_tools() + store.record_scan()   ── write history after
                        │
                        ▼
        site.build() → site/index.html, site/server/*.html, site/api/*.json
                        │
                        ▼
        git commit data/*.db data/history.jsonl  +  deploy site/ to Pages
```

## Scoring

```python
penalty = sum(f.severity.weight * f.confidence for f in findings)
score   = max(0, round(100 - penalty))
```

| Severity | Weight | Meaning |
|---|---|---|
| critical | 40 | an active attack is present in the metadata |
| high | 20 | credential/exfiltration capability, or a rug pull |
| medium | 8 | excessive scope, weak boundaries |
| low | 3 | hygiene |
| info | 0 | recorded, not penalised |

Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F.

Same tools scanned by the same scanner version always produce the same score — every scan
records `scanner_version` so a grade change can be traced to either the server or the
scanner, not left ambiguous.

The score is floored at zero rather than allowed to go negative — ten criticals and four
criticals both mean "don't use this", and ranking degrees of catastrophe is false precision.

One property matters more than the rest: `scanned_ok` is `False` whenever there were errors
or no tools came back. A server that couldn't be reached must never render as a green A —
that's the single worst bug this project could ship, so it has its own dedicated test.
