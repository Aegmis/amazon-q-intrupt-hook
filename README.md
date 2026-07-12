# amazon-q-intrupt-hook

An Amazon Q Developer CLI `preToolUse` hook that gates high-risk tool calls behind a human approval. Before Q runs a destructive shell command (`execute_bash`) or writes a file (`fs_write`), it pauses, notifies your approver via Slack (or any intrupt channel), and waits. The tool only runs if a human clicks **Approve**.

```
Amazon Q CLI
  │
  ├─ rm -rf /home/user          (matches AEGMIS_BLOCKED_PATHS)
  │     ⇒  ⛔ denied locally — no API call, no Slack
  │
  └─ kubectl delete pod nginx   (matches a risk pattern)
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

## Quick start

```bash
# 1. Install
curl -fsSL https://raw.githubusercontent.com/Aegmis/amazon-q-intrupt-hook/main/install.sh | bash

# 2. Set your API key, then load the env
nano ~/.aws/amazonq/.env.intrupt          # set AEGMIS_API_KEY=sk_org_...
source ~/.aws/amazonq/.env.intrupt        # also add this line to ~/.zshrc or ~/.bashrc

# 3. Restart Amazon Q — done. High-risk actions now pause for Slack approval.
```

Installer defaults: **local mode**, **shell-only** gating, and deleting the home
dir itself routes to approval (`AEGMIS_PROTECTED_PATHS=re:^$HOME$`). To make a path
**impossible to delete** — denied instantly, never sent to a human — add it to
`AEGMIS_BLOCKED_PATHS` (e.g. `export AEGMIS_BLOCKED_PATHS=re:^$HOME$` in your env file).

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
  "tool_input": { "command": "rm -rf /home/user" }
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

## What gets gated

Two tiers, evaluated in **local mode** (`AEGMIS_FORWARD_ALL=false`, the installer default):

**Hard-blocked — denied instantly, never sent to a human** (`AEGMIS_BLOCKED_PATHS`)

Only an `rm` whose target (resolved against the command's cwd, so relative paths
count) matches a `AEGMIS_BLOCKED_PATHS` entry. Denied locally with no approval
round-trip. Opt-in — nothing is hard-blocked unless you list it.

**Gated — paused for Slack approval**

The hook ships **20 built-in risk patterns**, identical across all 9 hooks. Several are families (one pattern, many commands), so they cover **30+ distinct dangerous commands**:

| Category | Matches | Passes through |
|---|---|---|
| Catastrophic `rm` | `rm -rf ~`, `rm -rf /`, `rm -rf /Users/you`, `rm *`, `rm -rf .` | `rm file.txt`, `rm -rf node_modules`, `rm -rf build` |
| Protected paths | `rm` of any dir in `AEGMIS_PROTECTED_PATHS` (default `re:^$HOME$`) + its subtree | anything not listed |
| Git | `git push` (incl. `--force`), `git reset --hard` | `git status`, `git commit`, `git pull` |
| Publish / release | `gh pr merge`, `gh release`, `npm publish`, `deploy` | builds, tests |
| Infra | `kubectl delete`/`apply`, `terraform apply`/`destroy` | `kubectl get`, `terraform plan` |
| Database | `DROP TABLE`, `TRUNCATE TABLE` | `SELECT`, `INSERT` |
| Disk | `dd if=`, `mkfs` | — |
| Privilege / perms | `sudo`, `chmod 777`, `chown … root` | `chmod 644` |
| Remote-to-shell | `curl … \| sh`, `wget -O- … \| sh` | plain `curl`/`wget` downloads |

Plus any **file write/edit** tool call is gated whenever that tool is in
`AEGMIS_GATED_TOOLS` — the installer default gates the **shell only**, so file
writes run free out of the box until you add them.

Everything else — reads, listings, `ls`, routine deletes — runs untouched. In
**forward-all mode** (`AEGMIS_FORWARD_ALL=true`) these local patterns are bypassed
and every gated tool call is sent to the **server-side policy engine** instead,
where your Aegmis policies decide — any command you write a policy for. The
`policies.example.sh` reference ships **~23 more** ready-to-use destructive-action
regexes (`find -delete`, `shred`, `docker push`, `crontab -r`, cloud-CLI deletes,
`kill`/`shutdown`, and more).

---

## Guarding your paths (approval vs hard-block)

Two env vars control what happens when the agent tries to `rm` a path you care
about. Both take a comma-separated list of **literal dirs** or **`re:`-prefixed
regexes**, resolved against the command's cwd (so relative targets like `./work`
are caught too).

| Variable | A matching `rm`… | Reach for it when |
|---|---|---|
| `AEGMIS_PROTECTED_PATHS` | pauses for **Slack approval** — a human can still allow it | the path matters but is *sometimes* legitimately deleted |
| `AEGMIS_BLOCKED_PATHS` | is **denied locally, instantly** — no Slack, nothing to approve | the path must **never** be deleted by the agent |

If a path matches **both**, the hard block wins — it's checked first, before any
approval round-trip. Both are **local-mode** features (`AEGMIS_FORWARD_ALL=false`,
the installer default).

### Minimal steps

1. Open your env file: `~/.aws/amazonq/.env.intrupt`
2. Add either variable — one path or many, comma-separated:

   ```bash
   # Ask a human before deleting these  →  approval
   export AEGMIS_PROTECTED_PATHS="$HOME/work,$HOME/important"

   # Never let the agent delete these   →  hard block (no approval)
   export AEGMIS_BLOCKED_PATHS="re:^$HOME$,$HOME/.ssh"
   ```
3. Reload it: `source ~/.aws/amazonq/.env.intrupt` (or restart Amazon Q).

### Examples

| Goal | Entry |
|---|---|
| Approve before wiping the home dir itself | `AEGMIS_PROTECTED_PATHS=re:^$HOME$` |
| Approve deletes of `work` + `important` (and their subtrees) | `AEGMIS_PROTECTED_PATHS=re:^$HOME/(work\|important)(/\|$)` |
| Hard-block `~/.ssh` and everything under it | `AEGMIS_BLOCKED_PATHS=$HOME/.ssh` |
| Hard-block the home dir itself (its contents still run free) | `AEGMIS_BLOCKED_PATHS=re:^$HOME$` |
| Mix — approve `work`, hard-block `~/.ssh` | `AEGMIS_PROTECTED_PATHS=$HOME/work` · `AEGMIS_BLOCKED_PATHS=$HOME/.ssh` |

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
| `AEGMIS_CHANNEL` | no | `slack` | Where the approval request is delivered — `slack` or `email` |
| `AEGMIS_BYPASS_PATTERNS` | no | — | Comma-separated regex; matching shell commands skip approval |
| `AEGMIS_PROTECTED_PATHS` | no | `re:^$HOME$` (set by installer) | Comma-separated dir(s) to also gate `rm` on — each dir **and everything under it**, cwd-resolved. List **one or many** (e.g. `~/work,~/secrets`). Prefix an entry with **`re:`** for a regex tested against the resolved absolute path, e.g. `re:^$HOME$` (home dir only) or `re:^$HOME/(work\|important)(/\|$)` |
| `AEGMIS_BLOCKED_PATHS` | no | — | Same syntax as `AEGMIS_PROTECTED_PATHS`, but an `rm` hitting one is **denied locally with no approval round-trip** — never sent to a human. Use for paths that must *never* be deleted. **Local mode only** (`AEGMIS_FORWARD_ALL=false`); the hook blocks it via exit 2 with an `AEGMIS_BLOCKED_PATHS` reason. |

**Approval channel:** requests go to **Slack** by default. To deliver them over **email** instead, set `AEGMIS_CHANNEL=email` in your env file.

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
