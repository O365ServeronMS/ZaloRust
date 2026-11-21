# tools/deploy-local.md

`tools/deploy-local.ps1` (batch 22 Q2) is the one-command local deploy for
the shadow-DB builds: it stops the running app **gracefully** via
`zalors --quit` (batch 22 Q1 — the tray Quit exit path, exit hooks
included), backs the shadow store up, builds the commit from a clean
detached worktree, starts the new exe and polls the diagnostic log for
the four startup markers. It replaces the manual five-step sequence from
`docs/audit/shadow-audit-2026-11-19.md`.

## Usage

```powershell
# plan only: prints every step, performs none of the mutating ones
powershell -NoProfile -File tools\deploy-local.ps1 -Commit <sha|ref> -DryRun -Stop

# real deploy (quits the running app via --quit, builds, restarts)
powershell -NoProfile -File tools\deploy-local.ps1 -Commit <sha|ref> -Stop

# build only: no stop, no start, no poll
powershell -NoProfile -File tools\deploy-local.ps1 -Commit <sha|ref> -NoStart
```

Parameters: `-Commit` (required) · `-Repo` (default the audit worktree) ·
`-TargetDir` (default `D:\ZaloRust\src-tauri\target`, used as
`CARGO_TARGET_DIR`; the exe starts from `<TargetDir>\debug`) · `-StoreDir`
(default `%LOCALAPPDATA%\com.o365serveronms.zalors\shadow`) · `-BackupRoot`
(default `D:\.opencode`) · `-LogFile` (default
`%LOCALAPPDATA%\zalo-web\logs\zalors.log`) · `-Stop` · `-NoStart` ·
`-DryRun` · `-MarkerTimeoutSec` (default 180).

## What the script never does

- **Never kills anything.** The only stop path is
  `<running exe> --quit`; if the app has not exited within 60 s it
  aborts, leaving the app running. No `Stop-Process`, no `taskkill`.
  A pre-batch-22 build ignores `--quit` (it just raises its window);
  the 60 s timeout then fails by design — close it by hand once, and
  every later deploy is one command.
- **Never writes to the real store.** The store is only read (copied
  into the backup dir). The build's temp worktree is always removed in a
  `finally`, build failure included.
- `-DryRun` performs none of the mutating steps: no git worktree, no
  store copy, no build, no `--quit`, no start. Only the two read-only
  probes the plan is printed from run (`git rev-parse`,
  `Get-Process zalors`, and a store-dir *listing*).

## What is printed

- Step banners, the resolved sha, paths, the backup file list as
  `name size match=True|False`, the build result (tail of
  `<deploy dir>\build.txt` on failure), the started PID.
- From the log, and nothing else: each marker `found/missing`
  (`pipeline started`, `cdp: attached`, `ws connection key armed`,
  `rest decode key armed`, only lines whose `[<epoch>]` stamp is at/after
  the start epoch), the latest `shadow rest stages:` line, any
  `shadow rest pending drain` lines (counts-only by design), and the
  **count** of lines containing `error`/`panic`.

## What is never printed

- **No hashes.** Store files are verified with `Get-FileHash` SHA256, but
  only `match=True/False` is printed — the store contains key files.
- No log content beyond the aggregate lines listed above: no message
  shapes, endpoints, download notes, uids, no store file contents.

## Exit codes

- `0` — every marker found; or `-NoStart` (nothing was started, so the
  marker gate does not apply); or an all-clear `-DryRun` listing.
- `1` — aborted at the first failure (with one `deploy-local: FAIL:`
  line naming it), or a marker still missing after `-MarkerTimeoutSec`,
  or a `-DryRun` that found a condition the real run would abort on
  (e.g. the app is running and `-Stop` was not given).

## Restoring from the backup

Every deploy writes
`<BackupRoot>\deploy-<sha7>-<yyyyMMdd-HHmmss>\pre-deploy-backup\` — one
verified copy of every file directly in the store dir, taken while the
app was stopped. To roll a bad deploy back:

1. Quit the app (`zalors --quit`, or tray → Sair). Confirm with
   `Get-Process zalors` that nothing is running.
2. Copy the files from the deploy dir's `pre-deploy-backup\` back into
   the store dir (overwrite; the store is only ever written while the
   app is stopped):
   `Copy-Item <BackupRoot>\deploy-<sha7>-<stamp>\pre-deploy-backup\* $env:LOCALAPPDATA\com.o365serveronms.zalors\shadow\ -Force`
3. Optionally re-verify with `Get-FileHash -Algorithm SHA256` against
   your own records — the deploy already verified the copies at backup
   time.
4. Start the previous exe again (`<TargetDir>\debug\zalors.exe` or the
   build you rolled back to).

The deploy never deletes a backup; prune old `deploy-*` dirs by hand
when the store has been healthy for a few days.
