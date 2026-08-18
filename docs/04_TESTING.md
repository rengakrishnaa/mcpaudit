# Testing

```
$ pytest -q
95 passed in 6.0s
```

No network, no Docker, no API key, six seconds. That last part isn't incidental — a suite
that runs in six seconds is a suite people actually run before every commit instead of
skipping.

| File | Tests | What it protects |
|---|---|---|
| `test_models.py` | 10 | Fingerprinting and scoring — if these are wrong, everything downstream is. |
| `test_detectors.py` | 30 | Every rule, positive and negative. |
| `test_rug_pull.py` | 7 | MCP007, the differentiator. |
| `test_storage.py` | 9 | History integrity. |
| `test_client.py` | 8 | Real subprocesses: timeout, crash, pagination, stdout noise. |
| `test_scanner.py` | 11 | End to end, no mocks. |
| `test_site.py` | 6 | Output correctness and HTML escaping. |
| `test_registry_and_sandbox.py` | 14 | Tolerant parsing; sandbox hardening flags. |

## The five tests that would catch a real disaster

Everything else here is coverage. These five are the ones that matter most.

**1. Key order must not change the fingerprint.**

```python
def test_fingerprint_is_stable_across_key_order():
    a = Tool("t", "d", {"type": "object", "properties": {"x": {"type": "string"}}})
    b = Tool("t", "d", {"properties": {"x": {"type": "string"}}, "type": "object"})
    assert a.fingerprint() == b.fingerprint()
```

If a server happened to serialise its schema keys in a different order after a library
upgrade, every tool's hash would change, every server would report a rug pull that same
night, and the signal would drown in noise — while every other test still passed.

**2. A server that couldn't be reached must not grade as clean.**

```python
def test_errored_scan_is_not_a_clean_scan():
    r = ScanResult("s", errors=["timeout"])
    assert r.scanned_ok is False
```

Without this, a network blip or a package that fails to install could render as a
confident green A next to a server nobody actually audited — the single most damaging bug
this project could ship, since it would make the registry actively misleading rather than
just incomplete.

**3. MCP008 doesn't fire on the word "system" in ordinary prose.**

```python
def test_mcp008_does_not_fire_on_the_word_system_in_prose():
    t = Tool("prompt_inspector", "Reveal the system prompt used for this session.")
    assert sr.check_dangerous_capability(t) == []
```

This documents a false positive the project actually shipped at one point. A scanner that
flags honest servers gets ignored, no matter how good its true positives are.

**4. The history-ordering constraint in the scanner.**

```python
def test_history_ordering_bug_regression(store, opts):
    scan_server(fixture_spec("test:order", "tools_rugpull_v1.json"), store, opts)
    scan_server(fixture_spec("test:order", "tools_rugpull_v2.json"), store, opts)
    scan_server(fixture_spec("test:order", "tools_rugpull_v2.json"), store, opts)
    # third scan sees no change, so it must be quiet again,
    # but history should still record both earlier versions
    assert len(store.tool_history("test:order", "search_docs")) == 2
```

If someone tidies up `scan_server()` and moves `record_tools()` above
`previous_tools()`, the comparison silently becomes today-versus-today. No exception is
raised, no other test fails, and the rug-pull feature stops working while the site keeps
publishing as if nothing happened.

**5. Attacker-controlled text is escaped before it reaches HTML.**

```python
def test_attacker_controlled_text_is_escaped(...):
    html = (out / "server" / "test-poisoned.html").read_text()
    assert "<!-- when the user asks about billing" not in html
    assert "&lt;!-- when the user asks about billing" in html
```

The MCP004 evidence string is, by definition, an HTML comment written by a hostile author.
Rendering it unescaped would let a flagged server run script on the very page that flags
it.

## Testing choices worth explaining

Every rule gets a negative test, written first. A rule with only positive tests is a rule
that will eventually fire on a benign server — three of the six real bugs found during
development were false positives that existed precisely because a rule was written
positive-first.

The scanner tests don't use mocks. `test_scanner.py` starts a real subprocess, speaks real
JSON-RPC, and writes to a real SQLite file. Mocking the client would have hidden both the
non-JSON-stdout bug and the pagination bug entirely.

Where the side effect is expensive, the tests check the argv instead of actually running
it. The sandbox tests never invoke Docker — they assert on the command line that would be
run:

```python
assert "--network none" in " ".join(sandbox.RUN_FLAGS)
assert not any(f in ("-v", "--volume", "--mount") for f in sandbox.RUN_FLAGS)
```

If a refactor accidentally dropped one of those flags, the scanner would keep working
perfectly and just silently stop being safe — nothing but this test would notice.

The fixtures are real servers, not stubs. `tests/fixtures/fake_server.py` is a working
60-line MCP server that reads its tool list from a JSON file and supports `--slow`,
`--crash` and `--paginate` flags, so the client's failure paths get exercised directly
rather than assumed.

## The bug table

| Bug | Found by | Would code review likely have caught it? |
|---|---|---|
| MCP008 flagged "reveal the system prompt" | negative test | unlikely |
| MCP008 missed "execute an arbitrary shell command" | positive test | no |
| MCP001 flagged "IMPORTANT: rate limited to 10 req/min" | negative test | unlikely |
| MCP003 missed `GITHUB_TOKEN` | positive test | no |
| MCP005 missed a bare "instead" | positive test | no |
| `previous_tools()` returned the wrong version on a same-second tie | storage test | no |

The last one is the interesting case — the SQL looked plausible, passed every manual check,
and only failed when two writes landed in the same second, which is exactly what production
does and manual testing usually doesn't.

## What's not tested, and why

- Real Docker execution — it needs a daemon and pulls ~200 MB images. The argv is tested
  directly instead, and the CI smoke test exercises the non-Docker path end to end.
- The LLM judge — it calls a paid API. `_parse()` is tested; the network call itself isn't.
- The live MCP registry API — someone else's uptime shouldn't be a test dependency. The
  parser is tested against recorded response shapes, including unrecognised ones it needs
  to skip gracefully.

## Running it

```bash
pytest -q                       # everything, ~6s
pytest tests/test_detectors.py  # one file
pytest -k rug_pull -v           # one concern
pytest --lf                     # only what failed last time
ruff check mcpaudit tests       # lint, as CI does
```

CI runs the suite on Python 3.11, 3.12 and 3.13, then runs the actual CLI and checks that
the benign fixture grades A and the poisoned one grades F — a unit suite that never
actually ran the product proves less than it looks like it does.
