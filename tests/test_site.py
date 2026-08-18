"""
The generated site.

Two things matter and nothing else: the numbers on the page are the numbers in
the database, and no attacker-controlled string is ever written to HTML raw.
"""
import json
from pathlib import Path

from conftest import fixture_spec

from mcpaudit.scanner import ScanOptions, scan_server
from mcpaudit.site import build, slug


def _built(store, repo_root, tmp_path) -> Path:
    opts = ScanOptions(allow_local=True, repo_root=repo_root, timeout=15)
    scan_server(fixture_spec("test:benign", "tools_benign.json"), store, opts)
    scan_server(fixture_spec("test:poisoned", "tools_poisoned.json"), store, opts)
    out = tmp_path / "site"
    build(store, out)
    return out


def test_pages_and_api_are_written(store, repo_root, tmp_path):
    out = _built(store, repo_root, tmp_path)
    assert (out / "index.html").exists()
    assert (out / ".nojekyll").exists()             # or Pages eats underscore paths
    for sid in ("test:benign", "test:poisoned"):
        assert (out / "server" / f"{slug(sid)}.html").exists()
        assert (out / "api" / "server" / f"{slug(sid)}.json").exists()
        assert (out / "api" / "badge" / f"{slug(sid)}.json").exists()


def test_index_json_matches_the_database(store, repo_root, tmp_path):
    out = _built(store, repo_root, tmp_path)
    data = json.loads((out / "api" / "index.json").read_text())
    grades = {s["server_id"]: s["grade"] for s in data["servers"]}
    assert grades == {"test:benign": "A", "test:poisoned": "F"}
    assert data["server_count"] == 2


def test_attacker_controlled_text_is_escaped(store, repo_root, tmp_path):
    """
    Tool descriptions come from people we are calling malicious. Writing one
    into HTML unescaped would let a flagged server put a <script> tag on the
    page that flags it. The evidence for MCP004 literally contains an HTML
    comment, so this is not hypothetical.
    """
    out = _built(store, repo_root, tmp_path)
    html = (out / "server" / f"{slug('test:poisoned')}.html").read_text()
    assert "<!-- when the user asks about billing" not in html
    assert "&lt;!-- when the user asks about billing" in html
    assert "&lt;IMPORTANT&gt;" in html


def test_badge_endpoint_is_shields_compatible(store, repo_root, tmp_path):
    out = _built(store, repo_root, tmp_path)
    badge = json.loads((out / "api" / "badge" / f"{slug('test:poisoned')}.json").read_text())
    assert badge["schemaVersion"] == 1
    assert badge["label"] == "mcpaudit"
    assert badge["message"].startswith("F")


def test_rug_pull_diff_is_rendered_with_colour_classes(store, repo_root, tmp_path):
    opts = ScanOptions(allow_local=True, repo_root=repo_root, timeout=15)
    scan_server(fixture_spec("test:rug", "tools_rugpull_v1.json"), store, opts)
    scan_server(fixture_spec("test:rug", "tools_rugpull_v2.json"), store, opts)
    out = tmp_path / "site"
    build(store, out)
    html = (out / "server" / f"{slug('test:rug')}.html").read_text()
    assert 'class="del"' in html and 'class="add"' in html
    assert "RUG PULL" in html


def test_empty_database_still_produces_a_page(store, tmp_path):
    """A first run with nothing scanned must not crash the deploy job."""
    out = tmp_path / "site"
    info = build(store, out)
    assert info["servers"] == 0
    assert "No scans yet" in (out / "index.html").read_text()
