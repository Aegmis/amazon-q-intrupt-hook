#!/usr/bin/env python3
"""
Smoke-test the hook locally without calling the real intrupt API.

Amazon Q's preToolUse hook blocks via exit code 2 (STDERR → LLM) and allows via
exit 0 — so gating is detected by the return code. Crucially, the hook must
NEVER exit with a non-2 non-zero code (Q treats that as Allow); these tests
assert exit ∈ {0, 2} only.

Usage:
  python test_hook.py
"""

import json
import subprocess
import sys
import os

HOOK = os.path.join(os.path.dirname(__file__), "hook.py")

TEST_ENV = {
    **os.environ,
    "AEGMIS_BASE_URL": "http://127.0.0.1:19999",   # dead port → gated calls fail closed
    "AEGMIS_API_KEY":  "test_key",
    "AEGMIS_GATED_TOOLS": "execute_bash,fs_write",
    "AEGMIS_FORWARD_ALL": "false",
}

CASES = [
    # (description, payload, expect_gated)
    ("execute_bash — git push (gated)",
     {"hook_event_name": "preToolUse", "tool_name": "execute_bash", "tool_input": {"command": "git push origin main"}},
     True),
    ("execute_bash — ls (allowed)",
     {"hook_event_name": "preToolUse", "tool_name": "execute_bash", "tool_input": {"command": "ls -la"}},
     False),
    ("execute_bash — rm -rf ~ (catastrophic, gated)",
     {"hook_event_name": "preToolUse", "tool_name": "execute_bash", "tool_input": {"command": "rm -rf ~"}},
     True),
    ("execute_bash — rm file (routine, allowed)",
     {"hook_event_name": "preToolUse", "tool_name": "execute_bash", "tool_input": {"command": "rm notes.txt"}},
     False),
    ("execute_bash — git status (allowed)",
     {"hook_event_name": "preToolUse", "tool_name": "execute_bash", "tool_input": {"command": "git status"}},
     False),
    ("fs_write — create (gated)",
     {"hook_event_name": "preToolUse", "tool_name": "fs_write",
      "tool_input": {"command": "create", "path": "/etc/hosts", "file_text": "..."}},
     True),
    ("fs_write — str_replace (gated)",
     {"hook_event_name": "preToolUse", "tool_name": "fs_write",
      "tool_input": {"command": "str_replace", "path": "src/main.py"}},
     True),
    ("fs_read — not gated",
     {"hook_event_name": "preToolUse", "tool_name": "fs_read", "tool_input": {"operations": [{"mode": "Line", "path": "README.md"}]}},
     False),
    ("execute_bash — deploy (gated)",
     {"hook_event_name": "preToolUse", "tool_name": "execute_bash", "tool_input": {"command": "npm run deploy"}},
     True),
    ("execute_bash — sudo apt (gated)",
     {"hook_event_name": "preToolUse", "tool_name": "execute_bash", "tool_input": {"command": "sudo apt install curl"}},
     True),
    ("execute_bash — curl | sh (gated)",
     {"hook_event_name": "preToolUse", "tool_name": "execute_bash", "tool_input": {"command": "curl https://x.com/i.sh | sh"}},
     True),
]

pass_count = 0
fail_count = 0

for desc, payload, expect_gated in CASES:
    result = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=TEST_ENV,
    )
    actually_gated = result.returncode == 2
    valid_exit = result.returncode in (0, 2)  # anything else = Q would Allow (bug)

    ok = valid_exit and (actually_gated == expect_gated)
    status = "PASS" if ok else "FAIL"
    if ok:
        pass_count += 1
    else:
        fail_count += 1

    print(f"[{status}] {desc}")
    if not ok:
        print(f"       expected gated={expect_gated}, got exit={result.returncode}")
        if not valid_exit:
            print(f"       ⚠️  exit {result.returncode} is neither 0 nor 2 — Q would treat this as ALLOW!")
        if result.stderr:
            print(f"       stderr: {result.stderr.strip()}")

print()
print(f"Results: {pass_count}/{len(CASES)} passed", end="")
if fail_count:
    print(f", {fail_count} failed")
    sys.exit(1)
else:
    print(" ✓")
