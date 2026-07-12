# amazon-q-intrupt-hook

An Amazon Q Developer CLI `preToolUse` hook that gates high-risk tool calls behind a human approval. Before Q runs a destructive shell command (`execute_bash`) or writes a file (`fs_write`), it pauses, notifies your approver via Slack (or any intrupt channel), and waits. The tool only runs if a human clicks **Approve**.

```
Amazon Q CLI
  └─ wants to run: git push origin main
        │
        ▼
  preToolUse hook fires
        │
        ▼
  POST /org/{id}/approval  ──►  intrupt API  ──►  Slack message
        │                                              │
        │  poll every 5s                     human clicks Approve / Reject
        │                                              │
        ▼                                              ▼
  GET /approval/{id}  ◄──────────────────────  status = "approved"
        │
        ▼
  exit 0  →  Q continues
  exit 2  →  Q blocks the tool (STDERR reason returned to the model)
```

---

## ⚠️ Read this first — Amazon Q fails OPEN

Per Q's hook contract ([docs/hooks.md](https://github.com/aws/amazon-q-developer-cli/blob/main/docs/hooks.md)):

> **preToolUse** — Exit `0`: allow. Exit `2`: block, return STDERR to LLM. **Other exit codes: show STDERR warning to user, ALLOW tool execution.**

So a crash, a non-2 exit, **or a hook timeout all let the tool run** — and Q's **default hook timeout is only 30 s**. This plugin is engineered around that:

- It blocks **only** via exit 2 (STDERR = reason to the model).
- **Every** error path is converted to an explicit exit-2 block — it never leaks an exit-1 traceback (which Q would treat as Allow).
- The bundled agent sets **`timeout_ms: 630000`** (630 s) and **`AEGMIS_TIMEOUT` (600 s) stays below it**, so the hook denies on its own timeout *before* Q kills it.

Do a **one-time live check** after install (`q chat --agent intrupt`, ask it to `git push`, confirm it blocks) to validate the block path on your Q build.

---

## Prerequisites

- Amazon Q Developer CLI with `preToolUse` hooks (recent build)
- Python 3.10+
- An [Aegmis](https://aegmis.com) account with an API key
- Slack workspace connected to your Aegmis org (for the default channel)

---

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Aegmis/amazon-q-intrupt-hook/main/install.sh | bash
```

<details>
<summary>Prefer to clone first?</summary>

```bash
git clone https://github.com/Aegmis/amazon-q-intrupt-hook.git
cd amazon-q-intrupt-hook
bash install.sh
```

</details>

`install.sh`:

1. Copies `hook.py` to `~/.aws/amazonq/hooks/intrupt_hook.py`
2. Installs a ready-made **`intrupt` agent** to `~/.aws/amazonq/cli-agents/intrupt.json` (with the `preToolUse` gate baked in)
3. Creates `~/.aws/amazonq/.env.intrupt` with placeholder env vars

Then fill in your credentials:

```bash
nano ~/.aws/amazonq/.env.intrupt
source ~/.aws/amazonq/.env.intrupt   # add this to ~/.zshrc or ~/.bashrc too
```

Run the gated agent:

```bash
q chat --agent intrupt
```

> Q inherits its environment from the shell that launches it, so the `AEGMIS_*`
> vars must be exported there (hence the `source` line).

### Adding the gate to your own agent

Q hooks live *inside* an agent config, not a standalone file. To gate your existing agent instead of using the bundled one, merge this into its JSON:

```json
"hooks": {
  "preToolUse": [
    { "matcher": "execute_bash", "command": "python3 ~/.aws/amazonq/hooks/intrupt_hook.py", "timeout_ms": 630000 },
    { "matcher": "fs_write",     "command": "python3 ~/.aws/amazonq/hooks/intrupt_hook.py", "timeout_ms": 630000 }
  ]
}
```

Agent files live in `~/.aws/amazonq/cli-agents/` (global) or `.amazonq/cli-agents/` (workspace).

---

## How it works

Q runs the `preToolUse` hook before matched tools, piping a JSON payload on stdin:

```json
{
  "hook_event_name": "preToolUse",
  "cwd": "/home/you/project",
  "tool_name": "execute_bash",
  "tool_input": { "command": "git push origin main" }
}
```

- **`execute_bash`** → gate the command (`tool_input.command`)
- **`fs_write`** → gate the file write (`tool_input.path`); `fs_read` is a separate tool and is never gated
- **`use_aws`** → optional (add it to `AEGMIS_GATED_TOOLS` and the agent matcher) to gate AWS CLI calls
- anything else → allowed immediately

Shell commands are checked against a risk-pattern list in local mode (**catastrophic `rm`** targeting home/root/system dirs — routine & project-local deletes pass, `git push`, `sudo`, `terraform apply`, `curl … | sh`, etc.). In **forward-all mode** (the default), every gated call is sent to the Aegmis policy engine instead.

| Outcome | Hook | Q |
|---|---|---|
| Human clicks **Approve** | exit 0 | Tool runs normally |
| Human clicks **Reject** | exit 2 | Tool blocked, STDERR reason returned to model |
| Timeout (`AEGMIS_TIMEOUT`) | exit 2 | Tool blocked |
| API unreachable / hook crash | exit 2 | Tool blocked (fail closed) |

> **Note on `execute_bash` toolSettings:** Q also has native `allowedCommands` /
> `deniedCommands` / `denyByDefault` on `execute_bash`. Those are static
> allow/deny lists — complementary to this hook, which adds *dynamic human
> approval*. Use both if you like: static deny for hard bans, the hook for
> "ask a human" cases.

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `AEGMIS_BASE_URL` | yes | — | intrupt API base URL |
| `AEGMIS_API_KEY` | yes | — | API key from Account → API Keys |
| `AEGMIS_APPROVAL` | no | `true` | Master kill switch — set `false` to disable the gate entirely (allow all) |
| `AEGMIS_GATED_TOOLS` | no | `execute_bash,fs_write` | Comma-separated tool names to gate (add `use_aws` to gate AWS calls) |
| `AEGMIS_FORWARD_ALL` | no | `true` | Forward every gated call to the policy engine (unmatched auto-approve) |
| `AEGMIS_TIMEOUT` | no | `600` | Max seconds to wait. **Must be < the agent's `timeout_ms`/1000** |
| `AEGMIS_POLL_INTERVAL` | no | `5` | Seconds between status polls |
| `AEGMIS_BYPASS_PATTERNS` | no | — | Comma-separated regex; matching shell commands skip approval |
| `AEGMIS_PROTECTED_PATHS` | no | `re:^$HOME$` (set by installer) | Comma-separated dir(s) to also gate `rm` on — each dir **and everything under it**, cwd-resolved. List **one or many** (e.g. `~/work,~/secrets`). Prefix an entry with **`re:`** for a regex tested against the resolved absolute path, e.g. `re:^$HOME$` (home dir only) or `re:^$HOME/(work\|important)(/\|$)` |

If you add `use_aws` to `AEGMIS_GATED_TOOLS`, also add a matching `preToolUse` entry (matcher `use_aws`) to the agent.

---

## Example: catastrophic-deletion gate + protecting your own paths

In **local mode** (`AEGMIS_FORWARD_ALL=false`) the hook gates only *catastrophic*
deletions and lets routine ones run untouched:

```bash
rm abc.txt                 # runs   — routine single-file delete
rm -rf node_modules        # runs   — project-local
rm -rf ~                   # ⛔ approval — wipes home
rm -rf /                   # ⛔ approval — wipes root
rm *                       # ⛔ approval — bare glob
```

To also require approval before deleting **specific dirs of yours**, list them:

```bash
export AEGMIS_PROTECTED_PATHS=/Users/you/work,/Users/you/important
```

### `AEGMIS_PROTECTED_PATHS` — literal paths and `re:` regexes

Comma-separated entries — each a **literal** dir or a **`re:`**-prefixed **regex** (the regex is tested against the resolved absolute `rm` target):

| Entry | Effect |
|---|---|
| `re:^$HOME$` | gate `rm` of the **home dir itself only** — `rm -rf ~` gates, but `rm -rf ~/project` and `rm ~/notes.txt` run free *(installer default)* |
| `re:^$HOME/(work\|important)(/\|$)` | gate the `work` + `important` **subtrees** |
| `~/work,re:^$HOME$` | **mixed** — literal `work` subtree *and* regex home-exact both gate; anything else runs free |
| `~/work` | plain **literal** — that dir and everything under it |

Anchor a regex with `^…$` to match a dir exactly (not its contents). Invalid regexes are skipped with a stderr warning.

**Worked examples** (write these as `AEGMIS_PROTECTED_PATHS` entries; `$HOME` expands when the env file is sourced):

| Intent | Entry |
|---|---|
| Protect **only the home dir itself**, not its contents | `re:^$HOME$` |
| Protect `work` + `important` (and their subtrees) | `re:^$HOME/(work\|important)(/\|$)` |
| Protect `project/demo` **except** `project/demo/scratch` | `re:^$HOME/project/demo/(?!scratch(/\|$)).*` |
| Protect any `.env` / secrets file anywhere under home | `re:^$HOME/.*(\.env(\|\.)\|/secrets?/)` |
| Multiple, mixed with literal | `$HOME/work,re:^$HOME$` |


Targets are resolved against the command's working directory, so relative refs are
caught too:

```bash
# with AEGMIS_PROTECTED_PATHS=/Users/you/work
cd /Users/you && rm -rf ./work     # ⛔ approval  (./work → /Users/you/work)
rm -rf /Users/you/work/build       # ⛔ approval  (under a protected dir)
rm -rf /Users/you/other            # runs        — not protected
```

---

## Testing

```bash
python3 test_hook.py
```

Expected output:

```
[PASS] execute_bash — git push (gated)
[PASS] execute_bash — ls (allowed)
[PASS] execute_bash — rm -rf ~ (catastrophic, gated)
[PASS] execute_bash — git status (allowed)
[PASS] fs_write — create (gated)
[PASS] fs_write — str_replace (gated)
[PASS] fs_read — not gated
[PASS] execute_bash — deploy (gated)
[PASS] execute_bash — sudo apt (gated)
[PASS] execute_bash — curl | sh (gated)

Results: 10/10 passed ✓
```

The tests also assert the hook's exit code is always `0` or `2` — never another
non-zero code, which Q would silently treat as **Allow**.

---

## Security notes

- **Fails closed** on reject / timeout / unreachable API / crash — always via exit 2.
- The one residual fail-open risk is Q killing the hook on **its** timeout; the `AEGMIS_TIMEOUT` < `timeout_ms/1000` ordering is what closes it. Keep that ordering if you tune either value.
- `AEGMIS_API_KEY` is a `Bearer` token — keep it in `.env.intrupt` with `600` permissions, not in shell history.

---

## Project structure

```
amazon-q-intrupt-hook/
├── hook.py              # preToolUse hook script (zero runtime dependencies)
├── agent.json           # ready-to-use "intrupt" agent with the gate baked in
├── test_hook.py         # smoke tests for gating logic
├── install.sh           # one-line installer
├── policies.example.sh  # example Aegmis approval policies
├── .env.example         # environment variable template
└── README.md
```

---

## Uninstalling

```bash
rm ~/.aws/amazonq/hooks/intrupt_hook.py
rm ~/.aws/amazonq/cli-agents/intrupt.json
```

(Or, if you merged the hooks into your own agent, remove the `preToolUse` block from it.)
