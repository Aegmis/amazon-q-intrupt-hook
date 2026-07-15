# Changelog

All notable changes to `amazon-q-intrupt-hook` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com); dates are ISO-8601.

## [0.0.1-beta.4] - 2026-07-15

### Fixed
- **Fail-closed hardening for Amazon Q's fail-OPEN default.** Q treats a non-2 exit or a
  hook timeout as *Allow*, so every error, rejection, and timeout path now forces an
  explicit exit-2 block, and a top-level crash guard converts any unhandled exception
  (which would otherwise exit 1 → Allow) into an exit-2 block.

### Added
- **Whole-project delete gate** — `rm` / `find` targeting the working dir, an ancestor,
  or `/` is gated (`rm -rf .`, `rm -rf "$HOME"`, `$PWD`, `..`); a subdir delete runs free.
- **Protected-path WRITE gate** — a write/create verb (`touch`, `tee`, `cp`, `mv`,
  `install`, `dd`, `ln`, or `>` / `>>`) into an `AEGMIS_PROTECTED_PATHS` dir is gated
  (also force-gates the `fs_write` tool into a protected path). Opt-in and
  directory-scoped; writes elsewhere and all reads run free.
- **Self-protection** — mutating commands touching the hook's own config
  (`~/.aws/amazonq/…`, `.git/hooks`) are always gated, regardless of `AEGMIS_GATED_TOOLS`.
- Broader denylist: exfiltration (`gh repo/gist create`, `git remote add/set-url`,
  `curl --data-binary/-T/-F`, `scp`, `rsync host:`, `nc`), mass-delete (`find -delete`,
  `git clean -f`, `rsync --delete`, `shred`), and obfuscation (pipe-to-shell, `base64 -d`,
  `eval`, `sh -c`, `xargs rm`).

### Changed
- **Command chains split** on `&&`, `||`, `;`, `|`, each segment judged independently;
  bypass matches per-segment. **Shell-aware parsing** (`shlex` + `~`/`$HOME`/`$PWD`
  expansion) closes evasions like quoted `rm -rf "$HOME"` and `rm -rf ./`.
- `AEGMIS_BLOCKED_PATHS` and the workspace / self-protect gates apply in **both** modes.

## [0.0.1-beta.3] - 2026-07-12

### Added
- `AEGMIS_BLOCKED_PATHS` — **hard local deny** for `rm`: a matching deletion is blocked
  instantly with no approval round-trip (never sent to a human), a stronger sibling of
  `AEGMIS_PROTECTED_PATHS`. Same syntax (literal dir + subtree, or `re:` regex tested
  against the resolved absolute target); **local mode only**, and checked *before* the
  approval gate, so a hard block wins if a path is in both lists.
- `AEGMIS_CHANNEL` — approval delivery channel: `slack` (default) or `email`.

### Changed
- Installer ships a commented `AEGMIS_BLOCKED_PATHS` opt-in line and sets
  `AEGMIS_CHANNEL=slack` in the env template.
- README substantially expanded: a **Quick start**, a **What gets gated** two-tier
  reference (hard-block vs approval, plus the 20 built-in risk patterns), a two-branch
  flow diagram (local deny vs Slack approval), and a **Guarding your paths** section
  with minimal steps and `AEGMIS_PROTECTED_PATHS` / `AEGMIS_BLOCKED_PATHS` examples.

## [0.0.1-beta.2] - 2026-07-11

### Added
- `AEGMIS_PROTECTED_PATHS` now supports **`re:`-prefixed regex** entries, tested against
  the resolved absolute deletion target. Anchor with `^…$` to protect a dir *exactly*
  (not its contents), or use alternation / negative-lookahead to include or exempt
  subtrees. Literal paths keep working; invalid regexes are skipped with a stderr warning.

### Changed
- Installer defaults tuned for a quiet, safe local setup: local mode
  (`AEGMIS_FORWARD_ALL=false`), `AEGMIS_PROTECTED_PATHS=re:^$HOME$` (gate the home dir
  itself, not everything under it), and — where the hook reads it — `AEGMIS_GATED_TOOLS`
  scoped to the shell tool only.
- README gains an entry-format table and worked-examples for `AEGMIS_PROTECTED_PATHS`;
  `.env.example` updated to match.

## [0.0.1-beta.1] - 2026-07-11

First (beta) release.

> ⚠️ **Beta.** The underlying agent's hook API is still evolving — do a one-time
> live check that the block path fires on your build before relying on it.

### Added
- Amazon Q Developer CLI `preToolUse` hook in agent config (Python) that gates **execute_bash / fs_write** behind a human Slack approval via the Aegmis
  intrupt API. Forward-all and local modes, fail-closed on reject/timeout/error,
  `policies.example.sh`, one-line `install.sh`, and offline smoke tests.
  Block signal: exit 2 + stderr.
- `AEGMIS_APPROVAL` — master kill switch (default `true`; set `false` to disable the gate
  entirely and allow everything).
- `AEGMIS_PROTECTED_PATHS` — comma-separated dirs to also gate `rm` on (the dir and
  everything under it), with **cwd-aware resolution** so relative targets (`./ok`, `ok`,
  `../x`) are caught, not just absolute paths.
- Catastrophic-only deletion gate: gates `rm` targeting the home dir, filesystem root, a
  `/Users/<name>` or `/home/<name>` home, a system dir (`/etc`, `/usr`, `/var`, …), or a
  bare `*` / `.` / `..`. Routine and project-local deletes (`rm file`,
  `rm -rf node_modules`, `rm -rf build/`) pass **without** approval.
- `policies.example.sh` documents the engine's **start-anchored** regex matching (prefix
  patterns with `[\s\S]*`) and ships a destructive-action reference table.

Configuration is via `AEGMIS_*` environment variables.
