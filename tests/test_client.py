"""
The MCP client, tested against a real subprocess.

These are the tests most projects skip, and they cover the failure modes that
actually happen when you point a scanner at 5,000 strangers' servers: the one
that hangs, the one that dies, the one that paginates, the one that prints a
banner to stdout before speaking JSON.
"""
import json
import sys
from pathlib import Path

import pytest

from mcpaudit.client import MCPError, StdioClient

FIXTURES = Path(__file__).parent / "fixtures"


def argv(tools_file: str, *flags: str) -> list[str]:
    return [sys.executable, str(FIXTURES / "fake_server.py"),
            str(FIXTURES / tools_file), *flags]


def test_initialize_and_list_tools():
    with StdioClient(argv("tools_benign.json"), timeout=15) as c:
        info = c.initialize()
        assert info.name == "fake-server" and info.version == "1.0.0"
        tools = c.list_tools()
    assert [t.name for t in tools] == ["list_notes", "read_note"]


def test_instructions_are_captured():
    """The `instructions` string also lands in the model's context, so we scan it."""
    with StdioClient(argv("tools_benign.json"), timeout=15) as c:
        info = c.initialize()
    assert "notes" in info.instructions.lower()


def test_pagination_is_followed():
    with StdioClient(argv("tools_benign.json", "--paginate"), timeout=15) as c:
        c.initialize()
        tools = c.list_tools()
    assert len(tools) == 2


def test_timeout_does_not_hang_forever():
    """
    A server that never answers must cost us `timeout` seconds, not the
    lifetime of the process. This is why client.py uses a reader thread and a
    Queue instead of a bare readline().
    """
    with StdioClient(argv("tools_benign.json", "--slow"), timeout=1.5) as c:
        c.initialize()
        with pytest.raises(MCPError, match="timeout"):
            c.list_tools()


def test_server_crash_is_reported_not_swallowed():
    with StdioClient(argv("tools_benign.json", "--crash"), timeout=10) as c:
        c.initialize()
        with pytest.raises(MCPError):
            c.list_tools()


def test_missing_command_raises_cleanly():
    with pytest.raises(MCPError, match="not found"):
        StdioClient(["definitely-not-a-real-binary-xyz"]).start()


def test_non_json_stdout_noise_is_skipped(tmp_path):
    """
    Plenty of real servers print a banner or a deprecation warning to stdout
    before the protocol starts. Failing on that would drop honest servers from
    the registry, so we skip unparseable lines instead.
    """
    noisy = tmp_path / "noisy.py"
    noisy.write_text(
        "import sys\n"
        "print('Welcome to My MCP Server v2!')\n"
        "sys.stdout.flush()\n"
        f"exec(open({str(FIXTURES / 'fake_server.py')!r}).read())\n"
    )
    tools = tmp_path / "t.json"
    tools.write_text(json.dumps({"tools": [{"name": "a", "description": "d"}]}))
    with StdioClient([sys.executable, str(noisy), str(tools)], timeout=15) as c:
        c.initialize()
        assert [t.name for t in c.list_tools()] == ["a"]


def test_close_is_safe_to_call_twice():
    c = StdioClient(argv("tools_benign.json"), timeout=10)
    c.start()
    c.close()
    c.close()
