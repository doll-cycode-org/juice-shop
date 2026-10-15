#!/usr/bin/env python3
"""
Internal network-diagnostics helper – do not expose publicly.

OS Command Injection vulnerability – CWE-78

Dataflow:

  [HTTP layer]       Flask route  /ping?host=<input>
                           |
                     request.args.get("host")    <- TAINTED SOURCE
                           |
  [Service layer]    NetworkService.ping(host)
                           |
                     value forwarded unchanged   <- PROPAGATION
                           |
  [Command layer]    CommandRunner.run(cmd)
                           |
                     host embedded in shell cmd  <- SINK (injection)
                           |
  [OS layer]         os.system / subprocess      <- EFFECT
"""

import os
import subprocess

# ---------------------------------------------------------------------------
# Fake HTTP request helper (stands in for Flask's request.args)
# ---------------------------------------------------------------------------

class FakeRequest:
    def __init__(self, params: dict):
        self._params = params

    def get(self, key: str) -> str:
        return self._params.get(key, "")


# ---------------------------------------------------------------------------
# Command runner (sink)
# ---------------------------------------------------------------------------

class CommandRunner:
    """Executes shell commands built from caller-supplied strings."""

    def run(self, cmd: str) -> str:
        """
        VULNERABLE – `cmd` is executed directly by the shell.

        Safe alternatives:
          subprocess.run(["ping", "-c", "1", host], shell=False)  # list form
          shlex.quote(host)  used when shell=True is unavoidable
        """
        print(f"[OS]  Executing: {cmd}")
        # shell=True passes the full string to /bin/sh – injection-ready.
        result = subprocess.run(
            cmd,
            shell=True,          # ← the dangerous flag
            capture_output=True,
            text=True,
        )
        return result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Service layer (propagation)
# ---------------------------------------------------------------------------

class NetworkService:
    """Business-logic wrapper around diagnostic commands."""

    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def ping(self, host: str) -> str:
        """
        Builds the ping command by concatenating the caller-supplied `host`
        with no validation or escaping.  Taint flows unchanged from the
        HTTP layer into the command string.
        """
        # ── SINK ──────────────────────────────────────────────────────
        # `host` is attacker-controlled.  Appending shell metacharacters
        # (;  &&  |  $()  ``) lets an attacker chain arbitrary commands.
        cmd = f"ping -c 1 {host}"
        return self._runner.run(cmd)

    def traceroute(self, host: str) -> str:
        """Second sink – same pattern, different command."""
        cmd = f"traceroute -m 5 {host}"
        return self._runner.run(cmd)

    def nslookup(self, host: str) -> str:
        """Third sink – DNS lookup."""
        cmd = "nslookup " + host   # classic string concatenation form
        return self._runner.run(cmd)


# ---------------------------------------------------------------------------
# HTTP controller (tainted source)
# ---------------------------------------------------------------------------

class NetworkController:
    """Simulates Flask route handlers for /ping, /traceroute, /nslookup."""

    def __init__(self, service: NetworkService):
        self._service = service

    def ping(self, request: FakeRequest) -> str:
        host = request.get("host")   # ← TAINTED SOURCE
        return self._service.ping(host)

    def traceroute(self, request: FakeRequest) -> str:
        host = request.get("host")   # ← TAINTED SOURCE
        return self._service.traceroute(host)

    def nslookup(self, request: FakeRequest) -> str:
        host = request.get("host")   # ← TAINTED SOURCE
        return self._service.nslookup(host)


# ---------------------------------------------------------------------------
# PoC
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    runner     = CommandRunner()
    service    = NetworkService(runner)
    controller = NetworkController(service)

    print("=== OS Command Injection dataflow demo (CWE-78) ===\n")

    # -- Case 1: Legitimate use ----------------------------------------
    print("-- Case 1: benign host --")
    print(controller.ping(FakeRequest({"host": "127.0.0.1"})))

    # -- Case 2: Semicolon chaining – run a second command after ping --
    # Injected shell string:  ping -c 1 127.0.0.1; id
    print("-- Case 2: semicolon injection  (host=127.0.0.1; id) --")
    print(controller.ping(FakeRequest({"host": "127.0.0.1; id"})))

    # -- Case 3: Logical-AND chaining – second command runs only if   --
    # ping succeeds, making the payload more reliable in real attacks. --
    # Injected shell string:  ping -c 1 127.0.0.1 && whoami
    print("-- Case 3: && injection  (host=127.0.0.1 && whoami) --")
    print(controller.ping(FakeRequest({"host": "127.0.0.1 && whoami"})))

    # -- Case 4: Pipe – silence the real command, only show injected   --
    # Injected shell string:  ping -c 1 127.0.0.1 | cat /etc/hostname
    print("-- Case 4: pipe injection  (host=127.0.0.1 | cat /etc/hostname) --")
    print(controller.ping(FakeRequest({"host": "127.0.0.1 | cat /etc/hostname"})))

    # -- Case 5: Subshell – works even when the host is mid-argument   --
    # Injected shell string:  ping -c 1 $(whoami)
    print("-- Case 5: subshell injection  (host=$(whoami)) --")
    print(controller.ping(FakeRequest({"host": "$(whoami)"})))

    # -- Case 6: nslookup sink with backtick form -----------------------
    # Injected shell string:  nslookup `id`
    print("-- Case 6: backtick injection via nslookup  (host=`id`) --")
    print(controller.nslookup(FakeRequest({"host": "`id`"})))
