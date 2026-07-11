#!/usr/bin/env bash
#
# Example Aegmis policies for the Amazon Q Developer CLI preToolUse hook.
#
# The hook POSTs an approval with:
#   tool_name  = "execute_bash" | "fs_write" | "use_aws"
#   action     = "bash_command" | "edit_file" | "aws_call"
#   tool_kwargs = { "command": ... }              for execute_bash
#                 { "path": ..., "command": ... }  for fs_write (command = sub-op)
#                 { "service_name": ..., "operation_name": ... }  for use_aws
# Conditions below match against those tool_kwargs keys.
#
# Conditions use the engine's nested schema:
#   "conditions": { "logic": "AND", "rules": { "<key>": { "<op>": <val> } } }
# Operators: >, <, ==, regex, in.  Keys are matched against tool_kwargs.
#
# Group approvers dispatch to Slack channel  #approvals-{approver_id}.
#
# Usage:
#   export AEGMIS_BASE_URL=https://api.aegmis.com
#   export AEGMIS_API_KEY=sk_org_xxxx_yyyy
#   export ORG_ID=org_xxxx
#   ./policies.example.sh

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# ⚠️  REGEX ANCHORING — READ BEFORE WRITING A "command"/path REGEX.
# The Aegmis policy engine anchors each regex at the START of the value
# (re.match-style) — it is NOT a free substring search. A pattern only fires
# when the value BEGINS with it, so anything BEFORE the match makes it MISS:
#   "\bgit\s+push\b"  matches "git push origin"  but MISSES " git push"
#                     (leading space), "\ngit push", "bash -lc 'git push'",
#                     and "cd x && git push".
#   "Delete File"     MISSES "*** Begin Patch\n*** Delete File: ...".
#
# RULE OF THUMB: prefix EVERY command/path regex with  [\s\S]*  unless you
# truly want starts-with behaviour. In the JSON write it double-escaped as
#  [\\s\\S]*  (JSON decodes it to the regex [\s\S]*). Use [\s\S]* NOT .*
#  — .* does not cross newlines and patch bodies are multi-line. Wrap the
# whole alternation:  "regex": "[\\s\\S]*(\\brm\\s+|\\bgit\\s+push\\b|...)"
#
# The patterns below already do this. Patterns that INTENTIONALLY anchor at the
# start (e.g. ^(Delete|Terminate|Remove).* on an operation name) are left as-is.
# ─────────────────────────────────────────────────────────────────────────────

: "${AEGMIS_BASE_URL:?set AEGMIS_BASE_URL}"
: "${AEGMIS_API_KEY:?set AEGMIS_API_KEY}"
: "${ORG_ID:?set ORG_ID}"

create_policy() {
  curl -sS -X POST "$AEGMIS_BASE_URL/org/$ORG_ID/policies" \
    -H "Authorization: Bearer $AEGMIS_API_KEY" \
    -H "Content-Type: application/json" \
    -H "User-Agent: intrupt-hook/1.0" \
    -d "$1"
  echo
}

# ══════════════════════════════════════════════════════════════════════════════
#  DESTRUCTIVE-ACTION REFERENCE — copy a regex into conditions.rules.<key>.regex.
#  Shown JSON-escaped (paste as-is) and already [\s\S]*-anchor-safe (see rule above).
#  KEY: cmd = match tool_kwargs.command on your agent's SHELL tool
#         (Bash · execute_bash · developer__shell · run_shell_command · bash);
#       patch = tool "apply_patch" (codex);  path = key file_path OR path;
#       aws   = tool "use_aws" (STARTS-WITH on purpose — this row has NO prefix).
# ──────────────────────────────────────────────────────────────────────────────
#  KEY    ACTION                   EXAMPLE / HINT                regex (JSON-escaped)
#  --------------------------------------------------------------------------------------------------------
#  cmd    Delete file(s)           rm x · rm -rf d · rm -f -- x  "[\\s\\S]*\\brm\\s+\\S"
#  cmd    Delete via find          find . -name '*.o' -delete    "[\\s\\S]*\\bfind\\b[\\s\\S]*-delete\\b"
#  cmd    Secure erase / unlink    shred -u x · unlink x         "[\\s\\S]*\\b(shred|unlink)\\b"
#  cmd    Truncate / empty file    truncate -s0 x · : > x        "[\\s\\S]*(\\btruncate\\b|:?\\s*>\\s*\\S)"
#  cmd    Disk write / format      dd if=.. · mkfs · wipefs      "[\\s\\S]*(\\bdd\\s+if=|\\bmkfs\\b|\\bwipefs\\b|\\bfdisk\\b|>\\s*/dev/)"
#  cmd    Git push (any / force)   git push · git push --force   "[\\s\\S]*\\bgit\\s+push\\b"
#  cmd    Git history rewrite      reset --hard · clean -fd      "[\\s\\S]*\\bgit\\s+(reset\\s+--hard|rebase|clean\\s+-[a-z]*f|branch\\s+-D|filter-branch)\\b"
#  cmd    Privilege escalation     sudo ...                      "[\\s\\S]*\\bsudo\\b"
#  cmd    World-writable perms     chmod 777 · chmod -R 777      "[\\s\\S]*\\bchmod\\s+[0-7]*7[0-7][0-7]\\b"
#  cmd    Chown to root            chown root:root x             "[\\s\\S]*\\bchown\\b[\\s\\S]*root"
#  cmd    Pipe remote to shell     curl url | sh · wget|bash     "[\\s\\S]*\\b(curl|wget)\\b[\\s\\S]*\\|\\s*(ba|z|k)?sh\\b"
#  cmd    Publish package          npm publish · twine upload    "[\\s\\S]*\\b(npm\\s+publish|twine\\s+upload|cargo\\s+publish|gem\\s+push|poetry\\s+publish)\\b"
#  cmd    Docker destructive       docker push · system prune    "[\\s\\S]*\\bdocker\\s+(push|rmi|system\\s+prune|volume\\s+rm)\\b"
#  cmd    Terraform apply/destroy  terraform destroy             "[\\s\\S]*\\bterraform\\s+(apply|destroy)\\b"
#  cmd    K8s / helm mutate        kubectl delete · helm del     "[\\s\\S]*\\b(kubectl\\s+(delete|apply)|helm\\s+(delete|uninstall))\\b"
#  cmd    Cloud CLI delete         aws .. terminate · gcloud     "[\\s\\S]*\\b(aws|gcloud|az)\\b[\\s\\S]*\\b(delete|terminate|destroy|rb|rm)\\b"
#  cmd    Kill / power             kill -9 · shutdown · reboot   "[\\s\\S]*\\b(kill\\s+-9|pkill|killall|shutdown|reboot|halt|poweroff|systemctl\\s+(stop|disable))\\b"
#  cmd    Crontab wipe             crontab -r                    "[\\s\\S]*\\bcrontab\\s+-r\\b"
#  cmd    SQL destructive          DROP TABLE · TRUNCATE         "[\\s\\S]*(DROP\\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\\s+TABLE|DELETE\\s+FROM)"
#  --------------------------------------------------------------------------------------------------------
#  patch  File delete              tool "apply_patch"            "[\\s\\S]*Delete File"
#  patch  Any file write           tool "apply_patch"            "[\\s\\S]*(Add|Update|Delete) File"
#  --------------------------------------------------------------------------------------------------------
#  path   Secrets / prod files     key file_path OR path         "[\\s\\S]*((^|/)\\.env($|\\.)|/secrets?/|/\\.ssh/|/prod/|credentials)"
#  --------------------------------------------------------------------------------------------------------
#  aws    Destructive AWS op       key operation_name            "^(Delete|Terminate|Remove|Stop|Disable|Put|Update)"
#  --------------------------------------------------------------------------------------------------------
#  Tip: to gate EVERY call of a mutating tool, drop the command condition and match
#  on trigger_tool_names alone (e.g. all apply_patch, all fs_write, all write/edit).
# ══════════════════════════════════════════════════════════════════════════════

# ── Priority 5 — destructive shell (route to SRE) ────────────────────────────
create_policy '{
  "name": "amazonq-destructive-shell",
  "description": "Any rm — rm -rf and plain rm <file> — plus dd, mkfs",
  "trigger_tool_names": ["execute_bash"],
  "conditions": {
    "logic": "AND",
    "rules": {
      "command": { "regex": "[\\s\\S]*(\\brm\\s+.*-[a-z]*[rf]|\\brm\\s+|\\bmkfs\\b|\\bdd\\s+if=)" }
    }
  },
  "approver_type": "group",
  "approver_id": "sre-team",
  "priority": 5
}'

# ── Priority 10 — deploys & infra ────────────────────────────────────────────
create_policy '{
  "name": "amazonq-deploy-and-infra",
  "description": "git push, terraform apply/destroy, kubectl apply/delete, deploy",
  "trigger_tool_names": ["execute_bash"],
  "conditions": {
    "logic": "AND",
    "rules": {
      "command": { "regex": "[\\s\\S]*(\\bgit\\s+push\\b|\\bterraform\\s+(apply|destroy)\\b|\\bkubectl\\s+(apply|delete)\\b|\\bdeploy\\b|\\bnpm\\s+publish\\b)" }
    }
  },
  "approver_type": "group",
  "approver_id": "platform-team",
  "priority": 10
}'

# ── Priority 15 — writes to secrets / prod config ────────────────────────────
create_policy '{
  "name": "amazonq-protect-secrets",
  "description": "fs_write to .env, secrets, or prod config",
  "trigger_tool_names": ["fs_write"],
  "conditions": {
    "logic": "AND",
    "rules": {
      "path": { "regex": "[\\s\\S]*((^|/)\\.env($|\\.)|/secrets?/|/prod/)" }
    }
  },
  "approver_type": "user",
  "approver_id": "U_AMIT_SLACK_ID",
  "priority": 15
}'

# ── Optional: gate destructive AWS calls (add use_aws to AEGMIS_GATED_TOOLS) ─
# create_policy '{
#   "name": "amazonq-destructive-aws",
#   "description": "Delete/terminate/remove AWS operations",
#   "trigger_tool_names": ["use_aws"],
#   "conditions": {
#     "logic": "AND",
#     "rules": {
#       "operation_name": { "regex": "^(Delete|Terminate|Remove|Stop|Disable).*" }
#     }
#   },
#   "approver_type": "group",
#   "approver_id": "sre-team",
#   "priority": 8
# }'

# NOTE: In forward-all mode (AEGMIS_FORWARD_ALL=true), EVERY gated call reaches
# the policy engine. Do NOT add a catch-all policy — unmatched calls auto-approve,
# which keeps routine commands friction-free.
