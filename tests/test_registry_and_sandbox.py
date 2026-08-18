"""
Registry parsing (tolerant) and sandbox construction (paranoid).

The sandbox tests never call Docker. They assert on the ARGV we would run,
which is the thing that is actually easy to get wrong and impossible to notice
once it is wrong.
"""

import pytest

from mcpaudit import registry, sandbox
from mcpaudit.models import ServerSpec

# --- registry --------------------------------------------------------------

def test_npm_package_entry_is_parsed():
    spec = registry._spec_from_registry_entry({
        "server": {
            "name": "io.github.foo/bar",
            "repository": {"url": "https://github.com/foo/bar"},
            "packages": [{"registryType": "npm", "identifier": "@foo/bar",
                          "environmentVariables": [{"name": "FOO_TOKEN"}]}],
        }
    })
    assert spec.id == "npm:@foo/bar"
    assert spec.runtime == "node"
    assert "FOO_TOKEN" in spec.env


def test_remote_entry_becomes_an_http_spec():
    spec = registry._spec_from_registry_entry(
        {"server": {"name": "x", "remotes": [{"url": "https://x.dev/mcp"}]}})
    assert spec.transport == "http" and spec.url == "https://x.dev/mcp"


def test_unknown_package_registry_is_skipped_not_crashed():
    """
    Upstream adds registry types (oci, nuget, mcpb). An unknown one must be
    ignored quietly — a nightly job that dies on a schema change is a nightly
    job that stops running and nobody notices for a month.
    """
    assert registry._spec_from_registry_entry(
        {"server": {"name": "x", "packages": [
            {"registryType": "nuget", "identifier": "z"}]}}) is None


def test_entry_with_no_name_is_skipped():
    assert registry._spec_from_registry_entry({"server": {}}) is None


def test_seed_round_trip(tmp_path):
    path = tmp_path / "seed.json"
    specs = [ServerSpec(id="npm:b", package="b"), ServerSpec(id="npm:a", package="a")]
    assert registry.save_seed(specs, path) == 2
    loaded = registry.load_seed(path)
    assert [s.id for s in loaded] == ["npm:a", "npm:b"]   # sorted, deterministic diff


def test_missing_seed_file_is_empty_not_an_exception(tmp_path):
    assert registry.load_seed(tmp_path / "nope.json") == []


# --- sandbox ---------------------------------------------------------------

def test_run_flags_contain_every_hardening_control():
    """
    If any of these silently disappears, the scanner still works and the
    project quietly stops being safe. That is exactly the kind of regression a
    test has to catch, because nothing else will.
    """
    joined = " ".join(sandbox.RUN_FLAGS)
    assert "--network none" in joined            # no exfiltration path
    assert "--read-only" in joined               # immutable root filesystem
    assert "--cap-drop ALL" in joined            # no Linux capabilities
    assert "no-new-privileges" in joined         # no setuid escalation
    assert "--pids-limit" in joined              # fork bombs bounded
    assert "--memory" in joined


def test_install_phase_has_no_host_mounts():
    assert not any(f in ("-v", "--volume", "--mount") for f in sandbox.INSTALL_FLAGS)
    assert not any(f in ("-v", "--volume", "--mount") for f in sandbox.RUN_FLAGS)


def test_placeholder_credentials_are_never_real():
    spec = ServerSpec(id="npm:x", package="x", env={"GITHUB_TOKEN": ""})
    value = sandbox.safe_env(spec)["GITHUB_TOKEN"]
    assert "placeholder" in value
    assert "ghp_" not in value


def test_node_server_runs_without_network_install():
    """`npx --no-install` must never reach the registry from the sealed container."""
    spec = ServerSpec(id="npm:x", package="@foo/bar", args=["--root", "/tmp"])
    cmd = sandbox._server_command(spec)
    assert cmd[:2] == ["npx", "--no-install"]


def test_python_server_uses_its_console_script():
    spec = ServerSpec(id="pypi:mcp_server_git", package="mcp_server_git",
                      runtime="python")
    assert sandbox._server_command(spec) == ["mcp-server-git"]


def test_prepare_refuses_http_specs():
    with pytest.raises(sandbox.SandboxError):
        sandbox.prepare(ServerSpec(id="http:x", transport="http", url="https://x"))


def test_prepare_refuses_when_docker_is_missing(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    with pytest.raises(sandbox.SandboxError, match="Docker"):
        sandbox.prepare(ServerSpec(id="npm:x", package="x"))


def test_demo_seed_file_is_valid():
    """The file the README tells people to run must actually parse."""
    specs = registry.load_seed("data/demo_servers.json")
    assert len(specs) == 3
    assert all(s.transport == "local" for s in specs)
