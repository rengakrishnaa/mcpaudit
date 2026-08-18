"""
MCP client.

An MCP server speaks JSON-RPC 2.0. Two transports matter in practice:

  stdio  — the server is a local process; we write requests to its stdin and
           read responses from its stdout, one JSON object per line.
  http   — the server is a URL; we POST JSON-RPC and read the response body
           (the "streamable HTTP" transport). Some servers answer with SSE.

We only ever call three things:

    initialize                -> handshake, tells us the server's name/version
    notifications/initialized -> required by spec before normal traffic
    tools/list                -> THE payload we scan

We never call tools/call. MCPAudit reads what the server *tells the model*;
it does not exercise the server's behaviour. That single decision is why the
scanner is safe to point at 5,000 untrusted servers.
"""
from __future__ import annotations

import contextlib
import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .models import Tool

PROTOCOL_VERSION = "2025-06-18"

CLIENT_INFO = {"name": "mcpaudit", "version": "0.1.0"}


class MCPError(RuntimeError):
    """Anything that stopped us getting a tool list."""


@dataclass
class ServerInfo:
    """What the server said about itself during initialize."""

    name: str = ""
    version: str | None = None
    protocol_version: str | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    instructions: str = ""   # servers may inject text here too — we scan it


# --------------------------------------------------------------------------
# stdio transport
# --------------------------------------------------------------------------


class StdioClient:
    """
    Speak JSON-RPC to a subprocess over stdin/stdout.

    Why a reader thread and not just readline()?
    A hostile or broken server can simply never write a byte. readline() on a
    pipe blocks forever and no amount of signal handling in the main thread
    reliably interrupts it on every platform. A daemon thread pushing lines
    into a Queue lets the caller do q.get(timeout=...) and give up cleanly.
    The thread dies with the process.
    """

    def __init__(
        self,
        argv: list[str],
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 30.0,
    ):
        self.argv = argv
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self._out: queue.Queue[str] = queue.Queue()
        self._stderr: list[str] = []
        self._id = 0

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> StdioClient:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> None:
        try:
            self.proc = subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                env={**os.environ, **(self.env or {})},
                text=True,
                bufsize=1,          # line buffered
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as e:
            raise MCPError(f"command not found: {self.argv[0]}") from e
        except OSError as e:
            raise MCPError(f"could not start server: {e}") from e

        threading.Thread(target=self._pump_stdout, daemon=True).start()
        threading.Thread(target=self._pump_stderr, daemon=True).start()

    def _pump_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            self._out.put(line)
        self._out.put("")   # sentinel: stream closed

    def _pump_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            # Bounded: a server that spams stderr must not eat our memory.
            if len(self._stderr) < 200:
                self._stderr.append(line.rstrip())

    def close(self) -> None:
        if not self.proc:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.proc.wait(timeout=3)
        self.proc = None

    @property
    def stderr_tail(self) -> str:
        return "\n".join(self._stderr[-15:])

    # -- protocol ----------------------------------------------------------

    def _send(self, payload: dict[str, Any]) -> None:
        if not self.proc or not self.proc.stdin:
            raise MCPError("server is not running")
        line = json.dumps(payload, separators=(",", ":")) + "\n"
        try:
            self.proc.stdin.write(line)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise MCPError(f"server closed its input: {e}") from e

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def request(self, method: str, params: dict | None = None) -> dict:
        """Send a request and wait for the matching response id."""
        rid = self._next_id()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params or {}})

        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPError(f"timeout waiting for response to {method}")
            try:
                line = self._out.get(timeout=remaining)
            except queue.Empty as err:
                raise MCPError(f"timeout waiting for response to {method}") from err

            if line == "":
                raise MCPError(
                    f"server exited before answering {method}. "
                    f"stderr: {self.stderr_tail[:400] or '(empty)'}"
                )
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                # Servers that print banners to stdout are common and broken.
                # Skip non-JSON rather than failing the whole scan.
                continue

            # Notifications and unrelated ids: ignore, keep reading.
            if msg.get("id") != rid:
                continue
            if "error" in msg:
                err = msg["error"]
                raise MCPError(
                    f"{method} -> [{err.get('code')}] {err.get('message')}"
                )
            return msg.get("result", {}) or {}

    def notify(self, method: str, params: dict | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self) -> ServerInfo:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        self.notify("notifications/initialized")
        si = result.get("serverInfo") or {}
        return ServerInfo(
            name=si.get("name", ""),
            version=si.get("version"),
            protocol_version=result.get("protocolVersion"),
            capabilities=result.get("capabilities") or {},
            instructions=result.get("instructions") or "",
        )

    def list_tools(self, max_pages: int = 20) -> list[Tool]:
        """
        tools/list, following the cursor.

        max_pages is a leash, not a guess: a malicious server can hand back an
        endless cursor chain and keep us in the loop forever.
        """
        tools: list[Tool] = []
        cursor: str | None = None
        for _ in range(max_pages):
            params = {"cursor": cursor} if cursor else {}
            result = self.request("tools/list", params)
            for raw in result.get("tools") or []:
                if isinstance(raw, dict):
                    tools.append(Tool.from_mcp(raw))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools


# --------------------------------------------------------------------------
# HTTP transport
# --------------------------------------------------------------------------


class HTTPClient:
    """
    Streamable-HTTP MCP. Uses httpx if available, urllib otherwise, so the
    core package has no hard third-party dependency.
    """

    def __init__(self, url: str, timeout: float = 30.0,
                 headers: dict[str, str] | None = None):
        self.url = url
        self.timeout = timeout
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **(headers or {}),
        }
        self.session_id: str | None = None
        self._id = 0

    def __enter__(self) -> HTTPClient:
        return self

    def __exit__(self, *exc) -> None:
        return None

    def close(self) -> None:
        return None

    @property
    def stderr_tail(self) -> str:
        return ""

    def _post(self, payload: dict) -> tuple[str, dict[str, str]]:
        body = json.dumps(payload).encode("utf-8")
        headers = dict(self.headers)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        try:
            import httpx  # type: ignore

            r = httpx.post(self.url, content=body, headers=headers,
                           timeout=self.timeout, follow_redirects=True)
            return r.text, {k.lower(): v for k, v in r.headers.items()}
        except ImportError:
            import urllib.error
            import urllib.request

            req = urllib.request.Request(self.url, data=body, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    text = resp.read().decode("utf-8", "replace")
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    return text, hdrs
            except urllib.error.HTTPError as e:
                raise MCPError(f"HTTP {e.code} from {self.url}") from e
            except Exception as e:
                raise MCPError(f"HTTP transport error: {e}") from e
        except Exception as e:
            raise MCPError(f"HTTP transport error: {e}") from e

    @staticmethod
    def _extract_json(text: str) -> dict:
        """
        Accept both a bare JSON body and an SSE stream of `data:` lines.
        We take the last data frame that parses and carries a result/error.
        """
        text = text.strip()
        if text.startswith("{"):
            return json.loads(text)
        best: dict = {}
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            chunk = line[5:].strip()
            if not chunk or chunk == "[DONE]":
                continue
            try:
                obj = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and ("result" in obj or "error" in obj):
                best = obj
        if not best:
            raise MCPError("no JSON-RPC payload in HTTP response")
        return best

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        text, headers = self._post(
            {"jsonrpc": "2.0", "id": self._id, "method": method,
             "params": params or {}}
        )
        if headers.get("mcp-session-id"):
            self.session_id = headers["mcp-session-id"]
        try:
            msg = self._extract_json(text)
        except json.JSONDecodeError as e:
            raise MCPError(f"invalid JSON from server: {e}") from e
        if "error" in msg:
            err = msg["error"]
            raise MCPError(f"{method} -> [{err.get('code')}] {err.get('message')}")
        return msg.get("result", {}) or {}

    def notify(self, method: str, params: dict | None = None) -> None:
        # Notifications are fire-and-forget: the spec says no response, and a
        # server that rejects one must not fail the scan.
        with contextlib.suppress(MCPError):
            self._post({"jsonrpc": "2.0", "method": method, "params": params or {}})

    initialize = StdioClient.initialize
    list_tools = StdioClient.list_tools
