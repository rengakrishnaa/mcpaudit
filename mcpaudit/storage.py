"""
Storage. SQLite by design.

WHY SQLITE AND NOT POSTGRES:
    The registry is read-mostly and updated once a night by a batch job. A
    hosted Postgres adds a bill, a credential, a network hop and an expiring
    free tier -- for a workload that is one writer and a few thousand rows.
    SQLite is a file. It can be committed to the repo, downloaded by CI,
    written to, and committed back. Total cost: zero, forever.

    If this ever needs concurrent writers, swapping to Postgres is a change in
    this file only -- nothing above it knows what the storage is.

THE IMPORTANT TABLE IS tool_fingerprints. Everything else is replaceable; the
fingerprint history is the thing nobody else has.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding, ScanResult, Tool

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    id            TEXT PRIMARY KEY,
    display_name  TEXT,
    description   TEXT,
    homepage      TEXT,
    transport     TEXT,          -- stdio | http | local
    runtime       TEXT,          -- node | python
    package       TEXT,          -- npm or pypi identifier
    url           TEXT,          -- http transport only
    source        TEXT,          -- seed | registry | demo
    first_seen    TEXT NOT NULL,
    last_scanned  TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id       TEXT NOT NULL REFERENCES servers(id),
    scanned_at      TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    server_version  TEXT,
    score           INTEGER NOT NULL,
    grade           TEXT NOT NULL,
    tool_count      INTEGER NOT NULL,
    scanned_ok      INTEGER NOT NULL,
    findings_json   TEXT NOT NULL,
    errors_json     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_server ON scans(server_id, scanned_at DESC);

-- THE PRODUCT. Rug-pull detection is impossible without this.
CREATE TABLE IF NOT EXISTS tool_fingerprints (
    server_id     TEXT NOT NULL REFERENCES servers(id),
    tool_name     TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    description   TEXT NOT NULL,   -- keep the TEXT, not just the hash: the value
    schema_json   TEXT NOT NULL,   -- of a rug pull report is the DIFF
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    PRIMARY KEY (server_id, tool_name, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_fp_lookup
    ON tool_fingerprints(server_id, tool_name, last_seen DESC);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path = "data/mcpaudit.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- servers ------------------------------------------------------------
    def upsert_server(self, server_id: str, **fields) -> None:
        with self._conn() as c:
            existing = c.execute("SELECT id FROM servers WHERE id=?", (server_id,)).fetchone()
            if existing:
                if fields:
                    sets = ", ".join(f"{k}=?" for k in fields)
                    c.execute(f"UPDATE servers SET {sets} WHERE id=?",
                              (*fields.values(), server_id))
            else:
                cols = ["id", "first_seen", *fields.keys()]
                c.execute(
                    f"INSERT INTO servers ({','.join(cols)}) "
                    f"VALUES ({','.join('?' * len(cols))})",
                    (server_id, _now(), *fields.values()),
                )

    def list_servers(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM servers ORDER BY id")]

    # -- fingerprints (the important part) ----------------------------------
    def previous_tools(self, server_id: str) -> dict[str, Tool]:
        """
        Most recent known state of each tool, for rug-pull comparison.

        One row per (server, tool, fingerprint) -- so we take the latest
        fingerprint per tool name.
        """
        # BUG FIXED HERE. The first version was
        #     SELECT tool_name, description, MAX(last_seen) ... GROUP BY tool_name
        # which relies on SQLite's bare-column behaviour. With two versions
        # recorded in the same SECOND -- exactly what happens when a scan
        # records v1 and a rescan records v2 moments later -- last_seen ties
        # and SQLite is free to return EITHER row. The scanner would then
        # compare today's tools against a stale version and either miss a rug
        # pull or report one that already happened. ROW_NUMBER with an
        # explicit rowid tiebreak makes "most recent" total, not partial.
        with self._conn() as c:
            rows = c.execute(
                """
                SELECT tool_name, description, schema_json FROM (
                    SELECT tool_name, description, schema_json,
                           ROW_NUMBER() OVER (
                               PARTITION BY tool_name
                               ORDER BY last_seen DESC, rowid DESC
                           ) AS rn
                    FROM tool_fingerprints
                    WHERE server_id = ?
                ) WHERE rn = 1
                """,
                (server_id,),
            ).fetchall()
        return {
            r["tool_name"]: Tool(
                name=r["tool_name"],
                description=r["description"],
                input_schema=json.loads(r["schema_json"]),
            )
            for r in rows
        }

    def record_tools(self, server_id: str, tools: list[Tool]) -> None:
        """Insert new fingerprints, or bump last_seen on ones we've seen before."""
        now = _now()
        with self._conn() as c:
            for t in tools:
                fp = t.fingerprint()
                hit = c.execute(
                    "SELECT 1 FROM tool_fingerprints "
                    "WHERE server_id=? AND tool_name=? AND fingerprint=?",
                    (server_id, t.name, fp),
                ).fetchone()
                if hit:
                    c.execute(
                        "UPDATE tool_fingerprints SET last_seen=? "
                        "WHERE server_id=? AND tool_name=? AND fingerprint=?",
                        (now, server_id, t.name, fp),
                    )
                else:
                    c.execute(
                        "INSERT INTO tool_fingerprints "
                        "(server_id, tool_name, fingerprint, description, schema_json, "
                        " first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
                        (server_id, t.name, fp, t.description,
                         json.dumps(t.input_schema, sort_keys=True), now, now),
                    )

    def tool_history(self, server_id: str, tool_name: str | None = None) -> list[dict]:
        """Every version of every tool. This powers the public diff view."""
        q = ("SELECT * FROM tool_fingerprints WHERE server_id=? "
             + ("AND tool_name=? " if tool_name else "")
             + "ORDER BY tool_name, first_seen, rowid")
        args = (server_id, tool_name) if tool_name else (server_id,)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, args)]

    # -- scans --------------------------------------------------------------
    def record_scan(self, result: ScanResult) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO scans (server_id, scanned_at, scanner_version, server_version, "
                "score, grade, tool_count, scanned_ok, findings_json, errors_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (result.server_id, _now(), result.scanner_version, result.server_version,
                 result.score, result.grade, len(result.tools), int(result.scanned_ok),
                 json.dumps([f.to_dict() for f in result.findings]),
                 json.dumps(result.errors)),
            )
            c.execute("UPDATE servers SET last_scanned=? WHERE id=?", (_now(), result.server_id))
            return cur.lastrowid

    def latest_scan(self, server_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute(
                "SELECT * FROM scans WHERE server_id=? ORDER BY scanned_at DESC LIMIT 1",
                (server_id,),
            ).fetchone()
        return dict(r) if r else None

    def all_latest_scans(self) -> list[dict]:
        """One row per server: its most recent scan. Drives the index page."""
        with self._conn() as c:
            rows = c.execute(
                """
                SELECT s.*, sv.display_name, sv.description AS server_description,
                       sv.homepage, sv.transport, sv.runtime, sv.package,
                       sv.url, sv.source
                FROM scans s
                JOIN servers sv ON sv.id = s.server_id
                WHERE s.id IN (
                    SELECT MAX(id) FROM scans GROUP BY server_id
                )
                ORDER BY s.score ASC, s.server_id
                """
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["findings"] = [Finding.from_dict(x) for x in json.loads(d.pop("findings_json"))]
            d["errors"] = json.loads(d.pop("errors_json"))
            out.append(d)
        return out

    def stats(self) -> dict:
        with self._conn() as c:
            servers = c.execute("SELECT COUNT(*) n FROM servers").fetchone()["n"]
            scans = c.execute("SELECT COUNT(*) n FROM scans").fetchone()["n"]
            fps = c.execute("SELECT COUNT(*) n FROM tool_fingerprints").fetchone()["n"]
        return {"servers": servers, "scans": scans, "tool_versions": fps}

    # -- export -------------------------------------------------------------
    def export_jsonl(self, path: str | Path) -> int:
        """
        Append-only, human-readable mirror of the fingerprint table.

        Why both a .db and a .jsonl in the repo: a binary SQLite file changes
        wholesale on every commit, so `git log` on it tells you nothing and the
        repo grows fast. The JSONL is sorted and line-oriented, so a rug pull
        shows up as a one-line diff in the commit that caught it — reviewable
        on GitHub without downloading anything. The .db is the working copy;
        the .jsonl is the record.
        """
        rows = []
        with self._conn() as c:
            for r in c.execute(
                "SELECT server_id, tool_name, fingerprint, description, schema_json, "
                "first_seen, last_seen FROM tool_fingerprints "
                "ORDER BY server_id, tool_name, first_seen, rowid"
            ):
                rows.append(dict(r))
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
        return len(rows)
