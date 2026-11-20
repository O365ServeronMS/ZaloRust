<#
tools/post-soak.ps1 -- post-soak deploy readiness runbook (batch 10 J1).

A step-by-step walk-through for the reviewer + user to run AFTER the
24 h soak is over and the app has been closed from its tray menu. The
script NEVER kills anything: if zalors.exe is still running it prints
how to close it and stops. Every step first prints what it will do;
every WRITE step then waits for an interactive `y` (read-only steps
may run behind a single "continue?" prompt). There is NO
auto-confirm switch: the confirm helper always reads an answer and
only an exact `y`/`Y` proceeds -- empty, EOF and a non-interactive
host all mean NO and the write step is skipped with a message. With
-WhatIf nothing runs and nothing is waited for: every command is
printed exactly as it would be executed.

Steps:
  1. zalors process status. If running: instructions + STOP.
  2. Read-only probes on temp COPIES of the live store (the probes
     copy it themselves), in this order:
       probe_e2ee_plain, probe_coverage, probe_attach,
       probe_e2ee_coverage, probe_audit_shapes, probe_backup_restore,
       probe_fts_bench
     run with ZR_GOLDEN_DIR unset, output tee'd to
     <OutDir>\probes-<stamp>.txt.
  3. tools/log-summary.ps1 -> same out dir.
  4. Purge dry-run (audit 1.0-b): maint_purge_e2ee_keyish WITHOUT
     ZR_PURGE_APPLY; ASK; only on `y` re-run with ZR_PURGE_APPLY=1.
     Then the golden replay on the frozen oracle.
  5. Reminder: set own_uid / own_uin_hash (Settings UI after start,
     or the settings file while stopped). Prints WHERE the settings
     file is; never reads or prints its contents.
  6. Build: prints the exact release/debug commands the project uses
     (README + .github/workflows/windows-build.yml; there is no
     package.json) and ASKS before running one.
  7. After the user restarts the app: log-summary.ps1 -Since <restart
     time>, then the audit paragraph 4 acceptance checklist for items
     1.1-1.4 with the exact log lines / probe fields that prove each.

Params:
  -Worktree  the worktree to operate in (default: this script's
             parent directory, i.e. <worktree>\tools).
  -OutDir    where outputs are written. Default
             D:\.opencode\post-soak-<yyyyMMdd>.
  -WhatIf    print every command without running anything.

Exit codes: 0 = walked to the end (or -WhatIf listing complete);
            1 = stopped early (app still running / missing worktree /
            a non-interactive host / a refused step the rest depends
            on).
#>
[CmdletBinding()]
param(
    # -Worktree default is resolved in the body: $PSScriptRoot is not
    # yet populated while param() defaults are evaluated (PS 5.1).
    [string] $Worktree = '',
    [string] $OutDir = "D:\.opencode\post-soak-$(Get-Date -Format yyyyMMdd)",
    [switch] $WhatIf
)

$ErrorActionPreference = 'Continue'
if (-not $Worktree) { $Worktree = Split-Path $PSScriptRoot -Parent }

# --- prelude (the same env the audit and every batch used) -------------------

$env:PATH = "$env:LOCALAPPDATA\Temp\opencode\strawberry-perl\perl\bin;" +
            "$env:LOCALAPPDATA\Temp\opencode\strawberry-perl\c\bin;" +
            "$env:USERPROFILE\.cargo\bin;" + $env:PATH
$env:CARGO_TARGET_DIR = 'D:\ZaloRust\src-tauri\target'

$srcTauri = Join-Path $Worktree 'src-tauri'
$logSummary = Join-Path $Worktree 'tools\log-summary.ps1'
$oracle = 'D:\.opencode\golden-oracle-2026-11-14'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

function Write-Step([string] $title) {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host "STEP: $title" -ForegroundColor Cyan
}

function Write-Plan([string] $what) {
    Write-Host "  will do: $what"
}

# The interactive confirm (write steps: waits for `y`; read-only steps
# use the same helper with a lighter label). -WhatIf never reaches it.
# There is no auto-confirm path: an answer is ALWAYS read, and only an
# exact `y`/`Y` proceeds. Empty input, EOF and non-interactive hosts
# (service context, redirected stdin, -NonInteractive) all mean NO --
# the gated write step is then skipped with a message, never
# auto-approved.
function Test-Interactive {
    try {
        if (-not [Environment]::UserInteractive) { return $false }
        if ([Console]::IsInputRedirected) { return $false }
    } catch { return $false }
    return $true
}

function Confirm-Step([string] $prompt) {
    if (-not (Test-Interactive)) {
        Write-Host '  SKIP (answer NO): this host is non-interactive (service context or redirected stdin) -- write steps are never auto-approved. Re-run from an interactive PowerShell.' -ForegroundColor Yellow
        return $false
    }
    $a = $null
    try { $a = Read-Host "  $prompt [y/N]" } catch { $a = $null }
    return ($a -eq 'y' -or $a -eq 'Y')
}

# Run one cargo test filter, appending to the tee file. Prints the
# exit code so the collected log shows failures as well as output.
function Invoke-Probe([string] $filter, [string] $teePath) {
    Write-Host "  RUN: cargo test --lib $filter -- --ignored --nocapture"
    Push-Location $srcTauri
    cargo test --lib $filter -- --ignored --nocapture 2>&1 |
        Tee-Object -FilePath $teePath -Append
    Write-Host "  (cargo exit code: $LASTEXITCODE)"
    Pop-Location
}

function Invoke-LogSummary([datetime] $since, [string] $teePath) {
    if ($since -eq [datetime]::MinValue) {
        Write-Host "  RUN: powershell -File `"$logSummary`""
        & $logSummary 2>&1 | Tee-Object -FilePath $teePath -Append
    } else {
        Write-Host "  RUN: powershell -File `"$logSummary`" -Since $($since.ToString('yyyy-MM-ddTHH:mm:ss'))"
        & $logSummary -Since $since 2>&1 | Tee-Object -FilePath $teePath -Append
    }
}

Write-Host 'post-soak runbook (batch 10 J1)' -ForegroundColor Green
Write-Host "  worktree: $Worktree"
Write-Host "  src-tauri: $srcTauri (cargo runs from here)"
Write-Host "  out dir:  $OutDir"
Write-Host "  oracle:   $oracle (frozen, read-only)"
if ($WhatIf) {
    Write-Host '  MODE: -WhatIf -- every command below is PRINTED ONLY; nothing runs, nothing is written, no question is asked.' -ForegroundColor Yellow
} else {
    Write-Host '  MODE: interactive -- every write step waits for an exact `y`; a non-interactive host is never auto-approved.' -ForegroundColor Yellow
}

if (-not (Test-Path -LiteralPath (Join-Path $srcTauri 'Cargo.toml') -PathType Leaf)) {
    Write-Host "FAIL: no src-tauri\Cargo.toml under `"$Worktree`" -- pass -Worktree <path>." -ForegroundColor Red
    exit 1
}

# --- step 1: process status (never kills) -------------------------------------

Write-Step '1/7 zalors process status (read-only)'
Write-Plan 'query the zalors.exe process (pid, start time, WS/PM). If it is running, print how to close it from the tray menu and STOP. This script never kills a process.'
if ($WhatIf) {
    Write-Host '  WHAT-IF: Get-Process zalors -ErrorAction SilentlyContinue | Select-Object Id, StartTime, WS, PM'
    Write-Host '  WHAT-IF: if a process is found -> print tray-close instructions, then stop (exit 1).'
} else {
    $p = Get-Process -Name zalors -ErrorAction SilentlyContinue
    if ($p) {
        $p | Select-Object Id, StartTime,
            @{ n = 'WS_MB'; e = { [math]::Round($_.WS / 1MB, 1) } },
            @{ n = 'PM_MB'; e = { [math]::Round($_.PM / 1MB, 1) } } |
            Format-Table -AutoSize | Out-String | Write-Host
        Write-Host 'zalors.exe is STILL RUNNING. The soak app must be closed by hand:' -ForegroundColor Red
        Write-Host '  right-click the Zalo tray icon -> Sair (Quit). Do NOT kill the process.'
        Write-Host 'This script stopped without touching anything. Re-run it after the app has closed.'
        exit 1
    }
    Write-Host '  zalors.exe is not running -- good, the DB has a single writer: nobody.'
}

# From here on every step needs the out dir. In -WhatIf we only ever
# print what would be created.
if (-not $WhatIf) {
    if (-not (Confirm-Step 'create the output dir and start the read-only steps?')) { exit 1 }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}
$probeTee = Join-Path $OutDir "probes-$stamp.txt"
$summaryTee = Join-Path $OutDir "log-summary-$stamp.txt"

# --- step 2: read-only probes on COPIES --------------------------------------

Write-Step '2/7 read-only probes (each opens a temp COPY of the live store)'
Write-Plan "unset ZR_GOLDEN_DIR (and ZR_PURGE_APPLY), then run 7 ignored probes in order; all output tee'd to $probeTee"
if ($WhatIf) {
    Write-Host '  WHAT-IF: Remove-Item Env:\ZR_GOLDEN_DIR, Env:\ZR_PURGE_APPLY (if set)'
    foreach ($f in 'probe_e2ee_plain', 'probe_coverage', 'probe_attach',
                   'probe_e2ee_coverage', 'probe_audit_shapes',
                   'probe_backup_restore', 'probe_fts_bench') {
        Write-Host "  WHAT-IF: cargo test --lib $f -- --ignored --nocapture  (cwd: $srcTauri)"
    }
    Write-Host "  WHAT-IF: each probe's stdout+stderr tee'd to $probeTee"
    Write-Host '  WHAT-IF: note -- ZR_PROBE_SINCE_ID can scope the two coverage probes to rows after a baseline id; unset means the whole 7-day ring.'
} else {
    Remove-Item Env:\ZR_GOLDEN_DIR -ErrorAction SilentlyContinue
    Remove-Item Env:\ZR_PURGE_APPLY -ErrorAction SilentlyContinue
    Write-Host '  ZR_GOLDEN_DIR / ZR_PURGE_APPLY unset for the probes.'
    Write-Host "  tee: $probeTee"
    "== post-soak probes $stamp (read-only, on temp copies) ==" | Set-Content -LiteralPath $probeTee
    foreach ($f in 'probe_e2ee_plain', 'probe_coverage', 'probe_attach',
                   'probe_e2ee_coverage', 'probe_audit_shapes',
                   'probe_backup_restore', 'probe_fts_bench') {
        "== $f ==" | Add-Content -LiteralPath $probeTee
        Invoke-Probe $f $probeTee
    }
    Write-Host '  probes done. Read the tee for the AC fields the checklist in step 7 names.'
}

# --- step 3: log summary (read-only) ------------------------------------------

Write-Step '3/7 diagnostic log summary (read-only)'
Write-Plan "tools/log-summary.ps1 over %LOCALAPPDATA%\zalo-web\logs\zalors.log -> $summaryTee"
if ($WhatIf) {
    Write-Host "  WHAT-IF: powershell -File `"$logSummary`" | Tee-Object $summaryTee"
} else {
    Invoke-LogSummary ([datetime]::MinValue) $summaryTee
}

# --- step 4: purge dry-run -> ASK -> apply; then golden -----------------------

Write-Step '4/7 key-material purge (audit 1.0-b): dry-run, then ASK'
Write-Plan 'dry-run maint_purge_e2ee_keyish WITHOUT ZR_PURGE_APPLY (read-only, counts only); only on an explicit `y` re-run with ZR_PURGE_APPLY=1 (destructive, app must be stopped); then the golden replay on the frozen oracle.'
if ($WhatIf) {
    Write-Host '  WHAT-IF: cargo test --lib maint_purge_e2ee_keyish -- --ignored --nocapture   (dry-run: ZR_PURGE_APPLY unset)'
    Write-Host '  WHAT-IF: ask y/N -- only on y:'
    Write-Host '  WHAT-IF:   $env:ZR_PURGE_APPLY="1"; cargo test --lib maint_purge_e2ee_keyish -- --ignored --nocapture; Remove-Item Env:\ZR_PURGE_APPLY'
    Write-Host '  WHAT-IF: then the golden replay on the frozen oracle:'
    Write-Host "  WHAT-IF:   `$env:ZR_GOLDEN_DIR='$oracle'; cargo test --lib golden_replay -- --ignored --nocapture; Remove-Item Env:\ZR_GOLDEN_DIR"
} else {
    if (Confirm-Step 'run the purge DRY-RUN now? (read-only: prints what it would delete, changes nothing)') {
        "== maint_purge dry-run $stamp ==" | Add-Content -LiteralPath $probeTee
        Invoke-Probe 'maint_purge_e2ee_keyish' $probeTee
        if (Confirm-Step 'APPLY the purge now? This DELETES the key-shaped e2ee raw rows (secure_delete + VACUUM). It is not reversible. Type y to apply.') {
            $env:ZR_PURGE_APPLY = '1'
            "== maint_purge APPLY $stamp ==" | Add-Content -LiteralPath $probeTee
            Invoke-Probe 'maint_purge_e2ee_keyish' $probeTee
            Remove-Item Env:\ZR_PURGE_APPLY -ErrorAction SilentlyContinue
            Write-Host '  ZR_PURGE_APPLY removed again.'
        } else {
            Write-Host '  purge NOT applied (dry-run only).'
        }
    } else { Write-Host '  purge dry-run skipped.' }

    if (Confirm-Step 'run the golden replay on the frozen oracle now? (read-only: copies the oracle to a temp dir)') {
        $env:ZR_GOLDEN_DIR = $oracle
        "== golden_replay $stamp ==" | Add-Content -LiteralPath $probeTee
        Invoke-Probe 'golden_replay' $probeTee
        Remove-Item Env:\ZR_GOLDEN_DIR -ErrorAction SilentlyContinue
    } else { Write-Host '  golden replay skipped.' }
}

# --- step 5: own uid / uin hash reminder (print-only) ------------------------

Write-Step '5/7 reminder: own_uid / own_uin_hash (print-only)'
$settingsFile = Join-Path $env:APPDATA 'com.o365serveronms.zalors\settings.json'
Write-Host '  The Phase-1 writer semantics need the account identity configured.'
Write-Host '  EITHER set them in the Settings UI after the app starts (Armazenamento shadow section):'
Write-Host '    own uid       = the Zalo userId of this account (5-32 digits)'
Write-Host '    UIN hash      = sha256(UIN) truncated to 12 lowercase hex chars'
Write-Host '  OR edit the settings file while the app is STOPPED. Its path on this machine:'
Write-Host "    $settingsFile"
Write-Host '  This script never reads or prints that file''s contents.'
if ($WhatIf) { Write-Host '  WHAT-IF: nothing to run -- this step only prints the reminder.' }

# --- step 6: build (print + ASK) ----------------------------------------------

Write-Step '6/7 build the new app (prints the project''s own commands, asks first)'
Write-Host '  The project has no package.json; the build commands come from README.md and'
Write-Host '  .github/workflows/windows-build.yml (what CI itself runs):'
Write-Host '    release installer (CI release job):'
Write-Host '      cargo install tauri-cli --version "~2.12" --locked   (only if cargo tauri is missing)'
Write-Host '      cargo tauri build --bundles nsis                   (from the worktree root)'
Write-Host '    debug binary (README "cargo tauri dev" path / plain cargo):'
Write-Host "      cargo build --bin zalors                            (from $srcTauri)"
if ($WhatIf) {
    Write-Host '  WHAT-IF: ask which to run, then:'
    Write-Host '  WHAT-IF:   cargo tauri build --bundles nsis   (release, on y)'
    Write-Host '  WHAT-IF:   cargo build --bin zalors           (debug, on y)'
} else {
    if (Confirm-Step 'RUN the release build now? (cargo tauri build --bundles nsis; writes the installer under src-tauri\target)') {
        Push-Location $Worktree
        cargo tauri build --bundles nsis
        Write-Host "  (cargo exit code: $LASTEXITCODE)"
        Pop-Location
    } elseif (Confirm-Step 'RUN the debug build instead? (cargo build --bin zalors)') {
        Push-Location $srcTauri
        cargo build --bin zalors
        Write-Host "  (cargo exit code: $LASTEXITCODE)"
        Pop-Location
    } else {
        Write-Host '  no build run -- run one by hand before restarting the app with the new code.'
    }
}

# --- step 7: restart + log summary since + acceptance checklist ---------------

Write-Step '7/7 restart the app, then the paragraph-4 acceptance checklist'
Write-Plan 'wait for the app restart, then log-summary -Since <restart time>, then print the 1.1-1.4 checklist with the exact log lines / probe fields that prove each item.'
if ($WhatIf) {
    Write-Host '  WHAT-IF: Read-Host "start the app now, press Enter once it is up" -> $restart = Get-Date'
    Write-Host "  WHAT-IF: powershell -File `"$logSummary`" -Since <restart> | Tee-Object log-summary-after-restart-$stamp.txt"
    Write-Host '  WHAT-IF: print the 1.1-1.4 checklist below.'
} else {
    Read-Host '  Start the app now (new build). Press Enter AFTER the window/tray is up'
    $restart = Get-Date
    $afterTee = Join-Path $OutDir "log-summary-after-restart-$stamp.txt"
    Invoke-LogSummary $restart $afterTee
}

Write-Host ''
Write-Host ('=' * 72) -ForegroundColor DarkGray
Write-Host 'ACCEPTANCE CHECKLIST (audit paragraph 4, items 1.1-1.4)' -ForegroundColor Cyan
Write-Host 'Which log line / probe field proves each item:'
Write-Host ''
Write-Host '1.1 REST capture (H2)'
Write-Host '  log  "shadow rest stages: seen=.. delivered=.. decoded=.. undecoded=.. no_key=.. (cumulative)"'
Write-Host '       -> delivered and decoded grow while the app is used; no_key stops growing right after'
Write-Host '          a "rest decode key armed" line (also counted by log-summary).'
Write-Host '  probe probe_coverage            -> rest_endpoints_with_query=0'
Write-Host '  probe probe_audit_shapes        -> REST endpoints (safe names) include get-last-msgs AND getmg-v2;'
Write-Host '                                        contacts>=1 and groups>=1 in the integrity block.'
Write-Host ''
Write-Host '1.2 Writer semantics (H3/H4)'
Write-Host '  log  log-summary "shadow write errors:" -> lines=0 kinds=(none) after the restart.'
Write-Host '  probe probe_coverage integrity block -> self_sent_sender_null=0, msgs_without_conv_row=0,'
Write-Host '                                        convs_lastmsg_not_newest=0, rev_gt0_by_source only real edits,'
Write-Host '                                        type_100_by_msgType only genuinely unknown msgTypes.'
Write-Host '  gold  step 4 golden_replay -> GOLDEN: PASS on the frozen oracle.'
Write-Host ''
Write-Host '1.3 msgType + attachments + media (H1/KQ1/KQ9)'
Write-Host '  log  "shadow media: cycle reported ok=.. failed=.. blocked_host=.. blocked_redirect=.. ref_encrypted=.."'
Write-Host '       (blocked_host > 0 proves the allowlist; ref_encrypted > 0 is the honest E2EE-ciphertext case).'
Write-Host '  probe probe_attach -> "downloaded file check:" must end with sha_mismatch=0 size_mismatch=0'
Write-Host '                        file_missing=0 magic_bad=0; per-status rows show ref/downloaded/failed.'
Write-Host '  extra audit 1.3 verify command (run by hand if wanted, read-only):'
Write-Host "        Get-ChildItem '<media_store>' -Recurse -File | Get-FileHash -Algorithm SHA256 | ? { `$_.Hash.ToLower() -ne `$_.Path.Split('\')[-1] }"
Write-Host '        (expect nothing back: file name == sha256.)'
Write-Host ''
Write-Host '1.4 Own-uid (KQ2)'
Write-Host '  log  log-summary "own uid configured" count >= 1 (len 19 for this install),'
Write-Host '       "own uid mismatch" count 0.'
Write-Host '  probe probe_audit_shapes -> self_sent_sender_null=0 in the integrity block.'
Write-Host ''
Write-Host 'Done. Collect from the out dir:' $OutDir
Write-Host "  $probeTee"
Write-Host "  $summaryTee (and a log-summary-after-restart-$stamp.txt from step 7)"
exit 0
