#!/usr/bin/env python3
"""
Amazon Q Developer CLI preToolUse hook — intrupt approval gate.

Reads a tool-call payload from stdin, POSTs to the intrupt API to create a
pending approval (which notifies the approver via Slack), then polls until a
human decides.

Amazon Q hook contract (preToolUse — see docs/hooks.md):
  - Registered inside an agent config's hooks.preToolUse array.
  - stdin  : JSON with hook_event_name, cwd, tool_name, tool_input.
             Shell tool is "execute_bash" (tool_input.command). File writes are
             "fs_write" (tool_input.path / .command sub-op). AWS CLI is
             "use_aws".
  - BLOCK  : exit code 2, with the reason written to STDERR (Q returns STDERR to
             the LLM). Exit 0 = allow.

  ⚠️  CRITICAL (Q-specific fail-OPEN semantics, like goose): "Other exit codes:
  show STDERR warning to user, ALLOW tool execution." A crash, a non-2 exit, or
  a hook TIMEOUT all let the tool run. Therefore this hook:
    * blocks ONLY via exit 2 (never a bare non-zero),
    * converts EVERY error into an explicit exit-2 block (a leaked exit-1
      traceback would be treated as Allow), and
    * lets its own AEGMIS_TIMEOUT fire an exit-2 block BEFORE Q's hook timeout
      kills the process. Q's DEFAULT hook timeout is only 30s, so the agent
      config sets timeout_ms=630000 and AEGMIS_TIMEOUT (600) stays below it.

Environment variables (required):
  AEGMIS_BASE_URL   Base URL of the intrupt approval API (e.g. https://api.aegmis.com)
  AEGMIS_API_KEY    API key from Account → API Keys (org ID is extracted automatically)

Optional:
  AEGMIS_GATED_TOOLS     Comma-separated tool names to gate.
                           Default: execute_bash,fs_write
  AEGMIS_FORWARD_ALL     If true (default), forward every gated call to the
                           policy engine (unmatched auto-approve). If false, use
                           the local SHELL_GATE_PATTERNS pre-filter for shell.
  AEGMIS_TIMEOUT         Max seconds to wait. Default: 600. MUST be <
                           timeout_ms/1000 in the agent config (default 630).
  AEGMIS_POLL_INTERVAL   Seconds between status polls. Default: 5
  AEGMIS_BYPASS_PATTERNS Comma-separated regex for shell commands that skip
                           approval (allow-list). Applied in both modes.
"""

import json
import os
import re
import sys
import time
import uuid
import urllib.request
import urllib.error
from typing import Optional

# ── Configuration ─────────────────────────────────────────────────────────────

BASE_URL       = os.environ.get("AEGMIS_BASE_URL", "https://api.aegmis.com").rstrip("/")
API_KEY        = os.environ.get("AEGMIS_API_KEY", "")
TIMEOUT        = int(os.environ.get("AEGMIS_TIMEOUT", "600"))
POLL_INTERVAL  = int(os.environ.get("AEGMIS_POLL_INTERVAL", "5"))
FORWARD_ALL    = os.environ.get("AEGMIS_FORWARD_ALL", "true").lower() in ("1", "true", "yes")

# Kill switch: AEGMIS_APPROVAL=false disables the gate entirely (allow all).
APPROVAL_ENABLED = os.environ.get("AEGMIS_APPROVAL", "true").lower() not in ("0", "false", "no", "off", "disable", "disabled")

SHELL_TOOL = "execute_bash"
WRITE_TOOL = "fs_write"
AWS_TOOL   = "use_aws"

GATED_TOOLS = {
    t.strip()
    for t in os.environ.get("AEGMIS_GATED_TOOLS", "execute_bash,fs_write").split(",")
    if t.strip()
}

SHELL_GATE_PATTERNS: list[str] = [
    # Catastrophic deletions only — home/root/system dirs or a bare */./..  Routine
    # and project-local deletes (rm file, rm -rf node_modules/build) pass through.
    r"\brm\b[\s\S]*\s(~/?(\s|$)|\$\{?HOME\}?/?(\s|$)|/(\s|$)|/\*|/(Users|home)/[^/\s]+/?(\s|$)|/(etc|usr|var|bin|sbin|opt|System|Library|private|boot|dev|lib|sys|proc)(/|\s|$)|\*(\s|$)|\.(\s|$)|\.\.(/|\s|$))",
    r"\bgit\s+push\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgh\s+pr\s+merge\b",
    r"\bgh\s+release\b",
    r"\bnpm\s+publish\b",
    r"\bdeploy\b",
    r"\bkubectl\s+delete\b",
    r"\bkubectl\s+apply\b",
    r"\bterraform\s+apply\b",
    r"\bterraform\s+destroy\b",
    r"DROP\s+TABLE",
    r"TRUNCATE\s+TABLE",
    r"\bdd\s+if=",
    r"\bmkfs\b",
    r"\bsudo\b",
    r"\bchmod\s+[0-7]*7[0-7][0-7]\b",
    r"\bchown\b.*root",
    r"\bcurl\b.*\|\s*(ba)?sh\b",
    r"\bwget\b.*-O\s*-\b.*\|\s*(ba)?sh\b",
]
# User-defined protected paths (AEGMIS_PROTECTED_PATHS) — also gate `rm` of each
# listed path and anything under it, on top of the built-in catastrophic targets.
for _pp in os.environ.get("AEGMIS_PROTECTED_PATHS", "").split(","):
    _pp = _pp.strip()
    if _pp and not _pp.startswith("re:"):   # literal entry -> raw-command fallback pattern
        SHELL_GATE_PATTERNS.append(r"\brm\b[\s\S]*\s" + re.escape(_pp.rstrip("/")) + r"(/|\s|$)")

_COMPILED = [re.compile(p, re.IGNORECASE) for p in SHELL_GATE_PATTERNS]

# Protected paths (AEGMIS_PROTECTED_PATHS) resolved for cwd-aware matching — this
# catches relative rm targets (./ok, ok, ../x) that literal patterns would miss.
_STATE = {"cwd": ""}
# Each AEGMIS_PROTECTED_PATHS entry is a LITERAL dir (dir + everything under it) or,
# when prefixed "re:", a REGEX tested against the resolved absolute rm target (anchor
# with ^...$ to match a dir exactly; alternation / lookahead supported).
_PROTECTED_LITERAL = []
_PROTECTED_REGEX = []
for _pp in os.environ.get("AEGMIS_PROTECTED_PATHS", "").split(","):
    _pp = _pp.strip()
    if not _pp:
        continue
    if _pp.startswith("re:"):
        try:
            _PROTECTED_REGEX.append(re.compile(_pp[3:]))
        except re.error as _exc:
            print(f"[intrupt hook] ignoring invalid AEGMIS_PROTECTED_PATHS regex {_pp[3:]!r}: {_exc}",
                  file=sys.stderr)
    else:
        _PROTECTED_LITERAL.append(os.path.normpath(os.path.expanduser(_pp.rstrip("/"))))


def _rm_hits_protected(command: str) -> bool:
    """True if an rm target (resolved against cwd) matches a protected literal path
    (dir + subtree) or a protected `re:` regex (against the resolved absolute path)."""
    if (not _PROTECTED_LITERAL and not _PROTECTED_REGEX) or not re.search(r"\brm\b", command):
        return False
    for tok in command.split():
        t = tok.strip("'\"")
        if not t or t in ("rm", "sudo", "--") or t.startswith("-"):
            continue
        t = os.path.expanduser(t)
        cand = t if os.path.isabs(t) else os.path.normpath(os.path.join(_STATE["cwd"] or ".", t))
        cand = os.path.normpath(cand).rstrip("/")
        for prot in _PROTECTED_LITERAL:
            if cand == prot or cand.startswith(prot + "/"):
                return True
        for _rx in _PROTECTED_REGEX:
            if _rx.search(cand):
                return True
    return False


_BYPASS_RAW = os.environ.get("AEGMIS_BYPASS_PATTERNS", "")
_BYPASS = [re.compile(p, re.IGNORECASE) for p in _BYPASS_RAW.split(",") if p.strip()]

_PATH_KEYS = ("path", "file_path", "filename", "file")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_org_id(api_key: str) -> str:
    if not api_key.startswith("sk_org_"):
        _die("Invalid AEGMIS_API_KEY format — expected 'sk_org_{org_id}_{hash}'")
    after_prefix = api_key[7:]
    last_underscore = after_prefix.rfind("_")
    if last_underscore == -1:
        _die("Invalid AEGMIS_API_KEY format — expected 'sk_org_{org_id}_{hash}'")
    org_id = after_prefix[:last_underscore]
    if not org_id.startswith("org_"):
        _die(f"Could not extract org ID from API key — got '{org_id}'")
    return org_id


def _api(method: str, path: str, body: Optional[dict] = None) -> dict:
    url  = f"{BASE_URL}{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {API_KEY}",
            "User-Agent":    "intrupt-hook/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        _die(f"intrupt API {method} {path} → HTTP {exc.code}: {body_text}")
    except urllib.error.URLError as exc:
        _die(f"intrupt API unreachable ({exc.reason}). Is AEGMIS_BASE_URL correct?")


def _allow() -> None:
    """Allow the tool call — exit 0."""
    sys.exit(0)


def _block(reason: str) -> None:
    """
    Deny the tool call. Q blocks on exit 2 and returns STDERR to the LLM.
    NEVER exit with any other non-zero code: Q treats that as Allow.
    """
    print(reason, file=sys.stderr, flush=True)
    sys.exit(2)


def _die(msg: str) -> None:
    """Fatal error — deny the tool call (fail closed)."""
    _block(f"[intrupt hook error] {msg}")


def _first(d: dict, keys) -> Optional[str]:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _bypassed(command: str) -> bool:
    return any(b.search(command) for b in _BYPASS)


def _should_gate_shell(command: str) -> bool:
    if _bypassed(command):
        return False
    if _rm_hits_protected(command):
        return True
    return any(p.search(command) for p in _COMPILED)


# ── Main ────────────────────────────────────────────────────────────────────────

def main() -> None:
    raw = sys.stdin.read()
    if not APPROVAL_ENABLED:
        _allow()  # AEGMIS_APPROVAL disabled — allow without gating
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        _die("Could not parse hook payload from stdin")

    _STATE["cwd"] = payload.get("cwd") or payload.get("working_dir") or ""

    tool_name  = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except json.JSONDecodeError:
            tool_input = {"raw": tool_input}
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}

    if tool_name not in GATED_TOOLS:
        _allow()

    if tool_name == SHELL_TOOL:
        command = tool_input.get("command", "")
        if FORWARD_ALL:
            if _bypassed(command):
                _allow()
        else:
            if not _should_gate_shell(command):
                _allow()
        action  = "bash_command"
        message = f"Run: `{command.splitlines()[0][:120] if command else ''}`"

    elif tool_name == WRITE_TOOL:
        path = _first(tool_input, _PATH_KEYS) or "unknown"
        subcommand = tool_input.get("command", "")
        action  = "edit_file"
        label   = f" (`{subcommand}`)" if subcommand else ""
        message = f"Write file{label}: `{path}`"

    elif tool_name == AWS_TOOL:
        svc = tool_input.get("service_name") or tool_input.get("service") or ""
        op  = tool_input.get("operation_name") or tool_input.get("operation") or ""
        action  = "aws_call"
        message = f"AWS CLI: `{svc} {op}`".strip()

    else:
        action  = tool_name.lower()
        message = f"Amazon Q wants to call `{tool_name}`"

    if not API_KEY:
        _die("AEGMIS_API_KEY is not set")
    org_id = _extract_org_id(API_KEY)

    thread_id = str(uuid.uuid4())

    resp = _api("POST", f"/org/{org_id}/approval", {
        "thread_id":   thread_id,
        "action":      action,
        "message":     message,
        "channel":     "slack",
        "tool_name":   tool_name,
        "tool_kwargs": tool_input,
        "adapter":     "amazon_q",
    })

    status = resp.get("status", "pending")
    if status == "approved":
        _allow()
    if status in ("rejected", "denied"):
        _block(f"Approval rejected (status={status})")

    approval_id = resp.get("approval_id") or resp.get("audit_id")
    if not approval_id:
        _die(f"API did not return approval_id/audit_id: {resp}")

    # Our timeout MUST fire (exit 2) before Q's hook timeout, otherwise Q kills
    # us → treated as Allow.
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        status_resp = _api("GET", f"/org/{org_id}/approval/{approval_id}")
        status = status_resp.get("status", "pending")
        if status == "approved":
            _allow()
        if status in ("rejected", "denied"):
            _block(f"Approval rejected by approver (approval_id={approval_id})")

    _block(
        f"Approval timed out after {TIMEOUT}s — tool call blocked "
        f"(approval_id={approval_id}). Approve or reject it in the dashboard."
    )


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 — fail closed on ANY crash
        # Q treats a bare non-zero exit (e.g. uncaught traceback → exit 1) as
        # ALLOW. Force an explicit exit-2 block instead.
        _block(f"[intrupt hook error] unexpected failure: {exc!r}")
