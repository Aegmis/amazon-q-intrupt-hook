# Changelog

All notable changes to `amazon-q-intrupt-hook` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com); dates are ISO-8601.

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
