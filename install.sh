#!/usr/bin/env bash
# Installs the intrupt preToolUse hook into Amazon Q Developer CLI.
#
# One-line install (no clone needed):
#   curl -fsSL https://raw.githubusercontent.com/Aegmis/amazon-q-intrupt-hook/main/install.sh | bash
#
# Or, after cloning:
#   bash install.sh

set -euo pipefail

REPO_RAW="${AEGMIS_REPO_RAW:-https://raw.githubusercontent.com/Aegmis/amazon-q-intrupt-hook/main}"

Q_DIR="$HOME/.aws/amazonq"
HOOKS_DIR="$Q_DIR/hooks"
AGENTS_DIR="$Q_DIR/cli-agents"
HOOK_DEST="$HOOKS_DIR/intrupt_hook.py"
AGENT_DEST="$AGENTS_DIR/intrupt.json"
ENV_FILE="$Q_DIR/.env.intrupt"

if [ -n "${BASH_SOURCE:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR=""
fi

fetch() {
  local rel="$1" dest="$2"
  mkdir -p "$(dirname "$dest")"
  if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$rel" ]; then
    cp "$SCRIPT_DIR/$rel" "$dest"
  elif command -v curl &>/dev/null; then
    curl -fsSL "$REPO_RAW/$rel" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -qO "$dest" "$REPO_RAW/$rel"
  else
    echo "✗ Need curl or wget to download $rel" >&2
    exit 1
  fi
}

echo "→ Installing hook script into $HOOKS_DIR"
mkdir -p "$HOOKS_DIR"
fetch "hook.py" "$HOOK_DEST"
chmod +x "$HOOK_DEST"

echo "→ Installing 'intrupt' agent into $AGENTS_DIR"
mkdir -p "$AGENTS_DIR"
if [ -f "$AGENT_DEST" ]; then
  echo "   $AGENT_DEST already exists — leaving it untouched."
  echo "   (Delete it and re-run, or merge the hooks block manually — see README.)"
else
  fetch "agent.json" "$AGENT_DEST"
  echo "   Installed."
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "→ Creating env file at $ENV_FILE"
  cat > "$ENV_FILE" <<'EOF'
# intrupt hook configuration — sourced by your shell profile
export AEGMIS_BASE_URL=https://api.aegmis.com
export AEGMIS_API_KEY=sk_org_xxxx_yyyy      # replace with your API key
export AEGMIS_APPROVAL=true            # set false to disable the gate entirely
export AEGMIS_FORWARD_ALL=false        # local mode: the hook decides (no server round-trip)
export AEGMIS_GATED_TOOLS=execute_bash   # gate shell only (not fs_write)
export AEGMIS_PROTECTED_PATHS="re:^$HOME$"  # gate rm of the home dir ITSELF (not its contents)
export AEGMIS_TIMEOUT=600
export AEGMIS_POLL_INTERVAL=5
EOF
  echo ""
  echo "   Edit $ENV_FILE and fill in your AEGMIS_API_KEY."
  echo "   Then add  source $ENV_FILE  to ~/.zshrc (or ~/.bashrc)."
  echo ""
fi

echo ""
echo "✓ Installation complete."
echo ""
echo "  Hook:  $HOOK_DEST"
echo "  Agent: $AGENT_DEST"
echo "  Env:   $ENV_FILE"
echo ""
echo "  Next steps:"
echo "  1. Edit $ENV_FILE with your API key"
echo "  2. Add  source $ENV_FILE  to ~/.zshrc (or ~/.bashrc) so Q inherits it"
echo "  3. Run the gated agent:   q chat --agent intrupt"
echo "     (or add the hooks block to your own agent — see README)"
echo ""
echo "  IMPORTANT (Q fail-OPEN semantics): Q's DEFAULT hook timeout is 30s and a"
echo "  timeout / non-2 exit = ALLOW. The agent sets timeout_ms=630000; keep"
echo "  AEGMIS_TIMEOUT (600) below it. Do a one-time live check: ask Q to"
echo "  'git push' under --agent intrupt and confirm it blocks pending approval."
echo ""
