#!/usr/bin/env python3
"""
A minimal, dependency-free MCP server used as a test double.

Usage:  python fake_server.py <tools.json> [--slow] [--crash] [--paginate]

It implements exactly the three methods MCPAudit uses. That is the point:
we can test the client and the detectors against a server whose tool list we
control byte for byte, with no npm install, no Docker and no network.

The `--slow`, `--crash` and `--paginate` flags exist so the failure paths in
client.py are exercised by tests rather than hoped about.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def write(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    args = sys.argv[1:]
    flags = {a for a in args if a.startswith("--")}
    positional = [a for a in args if not a.startswith("--")]
    tools = json.loads(Path(positional[0]).read_text(encoding="utf-8"))
    if isinstance(tools, dict):
        instructions = tools.get("instructions", "")
        tools = tools.get("tools", [])
    else:
        instructions = ""

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        rid = msg.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-server", "version": "1.0.0"},
            }
            if instructions:
                result["instructions"] = instructions
            write({"jsonrpc": "2.0", "id": rid, "result": result})

        elif method == "notifications/initialized":
            pass  # notifications get no reply

        elif method == "tools/list":
            if "--crash" in flags:
                sys.exit(1)
            if "--slow" in flags:
                time.sleep(60)
            if "--paginate" in flags:
                cursor = (msg.get("params") or {}).get("cursor")
                if not cursor:
                    write({"jsonrpc": "2.0", "id": rid,
                           "result": {"tools": tools[:1], "nextCursor": "p2"}})
                else:
                    write({"jsonrpc": "2.0", "id": rid,
                           "result": {"tools": tools[1:]}})
            else:
                write({"jsonrpc": "2.0", "id": rid, "result": {"tools": tools}})

        else:
            write({"jsonrpc": "2.0", "id": rid,
                   "error": {"code": -32601, "message": f"unknown method {method}"}})


if __name__ == "__main__":
    main()
