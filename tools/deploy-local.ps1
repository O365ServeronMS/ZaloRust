<#
tools/deploy-local.ps1 -- one-command local deploy (batch 22 Q2).

Automates the manual deploy sequence used for the shadow-DB builds
(docs/audit/shadow-audit-2026-11-19.md): stop the app GRACEFULLY via the
new `zalors --quit` (batch 22 Q1: the tray Quit exit path, run by the app
itself), back the shadow store up and verify every copy, build the commit
from a clean DETACHED worktree, start the new exe, and poll the
diagnostic log for the four startup markers. Usage and restore steps:
docs/deploy-local.md.

HARD PROPERTIES (same doc has the long form):
  - NEVER kills the app. The only stop path is `<running exe> --quit`;
    if the app has not exited within 60 s the script ABORTS, leaving it
    running. No Stop-Process, no taskkill, anywhere.
  - NEVER writes to the real store. The store is only READ (copied into
    the backup dir and hash-verified). Restore is a copy in the other
    direction, run by hand.
  - The temp worktree is ALWAYS removed (a finally), build failure
    included.
  - Prints NO hashes and NO log content beyond the explicitly allowed
    lines: per-store-file name/size/match=True|False, marker
    found/missing lines, the LATEST `shadow rest stages:` line,
    `shadow rest pending drain` lines (counts-only by design), and a
    COUNT of lines containing `error`/`panic`.

Steps (each aborts with a clear message + exit 1 at the first failure):
  1. Resolve -Commit to a full sha: git rev-parse --verify <c>^{commit}.
  2. Get-Process zalors. Running + no -Stop -> abort. Running + -Stop ->
     `<running exe> --quit`, then wait <= 60 s for every zalors process
     to exit (abort, still running, if any is left).
  3. Copy every file DIRECTLY in -StoreDir to
     <BackupRoot>\deploy-<sha7>-<stamp>\pre-deploy-backup; verify each
     copy with Get-FileHash SHA256 (the hash itself is never printed).
  4. git worktree add --detach <Repo>\..\deploy-<sha7> <sha>; verify
     `git status --porcelain` is empty there.
  5. $env:USERPROFILE\.cargo\bin first on PATH; cargo build in
     <worktree>\src-tauri with CARGO_TARGET_DIR=<-TargetDir>, output ->
     <deploy dir>\build.txt; on failure print the tail (last 40 lines).
  6. git worktree remove the temp worktree -- ALWAYS, in a finally.
  7. Unless -NoStart: Start-Process <TargetDir>\debug\zalors.exe
     -WorkingDirectory <its dir> -PassThru; the start epoch is recorded
     BEFORE the launch so no first line of the fresh session is missed.
  8. Poll -LogFile until -MarkerTimeoutSec, considering only lines whose
     [<epoch>] prefix is >= the start epoch. The app truncates the log at
     launch and rotates it at 1 MiB (dlog.rs: current ->
     <stem>.previous.log), so a missing current file is waited out and
     the .previous.log is scanned every round too; each raw line is
     processed once across rounds. Report each marker found/missing:
     `pipeline started`, `cdp: attached`, `ws connection key armed`,
     `rest decode key armed`; plus the latest `shadow rest stages:`
     line, every `shadow rest pending drain` line, and the error/panic
     line count -- nothing else from the log, ever.
  9. Summary: sha, backup dir, build result, PID, markers.

-DryRun prints every step it would take and performs NONE of the
mutating ones (no git worktree, no store copy, no build, no --quit, no
start). The two READ-ONLY probes the printout is built from do run:
`git rev-parse` (the sha names the real paths) and `Get-Process zalors` /
a store-dir listing (so the plan names the real exe and files). A
condition that would make the real run abort is printed as one and ends
the listing with exit 1.

-NoStart skips steps 7-8: nothing is started, so there is nothing to
poll and the marker gate does not apply (documented in the doc file).

Exit codes: 0 = every marker found (or -NoStart / an all-clear -DryRun);
            1 = aborted at the first failure, or a marker missing.

PowerShell 5.1 compatible: no `&&`, no `??`, no ternary.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Commit,
    [string] $Repo = 'D:\ZaloRust\.claude\worktrees\zalorust-shadow-db-audit-09d328',
    [string] $TargetDir = 'D:\ZaloRust\src-tauri\target',
    [string] $StoreDir = (Join-Path $env:LOCALAPPDATA 'com.o365serveronms.zalors\shadow'),
    [string] $BackupRoot = 'D:\.opencode',
    [string] $LogFile = (Join-Path $env:LOCALAPPDATA 'zalo-web\logs\zalors.log'),
    [switch] $Stop,
    [switch] $NoStart,
    [switch] $DryRun,
    [ValidateRange(1, 3600)] [int] $MarkerTimeoutSec = 180
)

$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    # One clear line, a non-zero exit. Runs through finally blocks, so a
    # created temp worktree is still removed on the way out.
    Write-Host "deploy-local: FAIL: $Message" -ForegroundColor Red
    exit 1
}

# A DryRun-detected condition that would abort the real run: end the
# listing honestly (exit 1) without claiming anything was performed.
function FailDry([string] $Message) {
    Write-Host "deploy-local: DRY-RUN: the real run would ABORT here: $Message" -ForegroundColor Red
    exit 1
}

function Write-Step([string] $Title) {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host "STEP: $Title" -ForegroundColor Cyan
}

Write-Host 'deploy-local (batch 22 Q2)' -ForegroundColor Green
Write-Host "  repo:      $Repo"
Write-Host "  target:   $TargetDir (CARGO_TARGET_DIR; the exe starts from <target>\debug)"
Write-Host "  store:     $StoreDir (read-only for this script)"
Write-Host "  backup:    $BackupRoot"
Write-Host "  log:       $LogFile"
if ($DryRun) {
    Write-Host '  MODE: -DryRun -- every step is PRINTED ONLY; no worktree, no store copy, no build, no --quit, no start.' -ForegroundColor Yellow
} else {
    if ($Stop)  { Write-Host '  MODE: real run, -Stop: a RUNNING app will be asked to quit via --quit (never killed).' -ForegroundColor Yellow }
    else        { Write-Host '  MODE: real run. A running app aborts the deploy (pass -Stop to quit it gracefully).' -ForegroundColor Yellow }
    if ($NoStart) { Write-Host '  MODE: -NoStart: the new exe will NOT be started; marker polling is skipped.' -ForegroundColor Yellow }
}

# --- step 1: resolve the commit -----------------------------------------------

Write-Step '1/9 resolve -Commit to a full sha (read-only)'
if (-not (Test-Path -LiteralPath $Repo)) {
    Fail "Repo not found: $Repo"
}
$sha = & git -C $Repo rev-parse --verify "$Commit^{commit}"
if ($LASTEXITCODE -ne 0 -or -not $sha) {
    Fail "cannot resolve commit '$Commit' in $Repo (git rev-parse --verify $Commit^{commit})"
}
$sha = ([string] $sha).Trim()
$sha7 = $sha.Substring(0, 7)
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$deployDir = Join-Path $BackupRoot "deploy-$sha7-$stamp"
$backupDir = Join-Path $deployDir 'pre-deploy-backup'
# <Repo>\..: the .claude\worktrees parent, next to the audit worktrees.
$worktree = Join-Path (Split-Path $Repo -Parent) "deploy-$sha7"
Write-Host "  commit:     $sha ($sha7)"
Write-Host "  deploy dir: $deployDir (would be created)"
Write-Host "  worktree:   $worktree (would be created, removed at the end)"

# --- step 2: running check -----------------------------------------------------

Write-Step '2/9 running-instance check (never kills)'
$running = @(Get-Process -Name zalors -ErrorAction SilentlyContinue)
if ($DryRun) {
    if ($running.Count -eq 0) {
        Write-Host '  DRY-RUN: no zalors.exe is running; nothing to quit, the deploy would continue.'
    } elseif (-not $Stop) {
        FailDry "zalors.exe is running ($($running.Count) process(es)) and -Stop was not given."
    } else {
        $exePath = $running[0].Path
        if (-not $exePath) { FailDry 'cannot read the running zalors.exe path (access denied?).' }
        Write-Host "  DRY-RUN: $($running.Count) zalors.exe running from: $exePath"
        Write-Host "  DRY-RUN: would run: & `"$exePath`" --quit   (graceful: the tray Quit exit path, run by the app)"
        Write-Host '  DRY-RUN: would wait up to 60 s for every zalors process to exit; would abort (leaving it running) if any is left.'
        Write-Host '  DRY-RUN: note -- a build WITHOUT batch 22 Q1 ignores --quit; then this step fails by design and the app stays up.'
    }
} elseif ($running.Count -eq 0) {
    Write-Host '  zalors.exe is not running -- nothing to stop.'
} elseif (-not $Stop) {
    Fail "zalors.exe is running ($($running.Count) process(es)) and -Stop was not given. Close it by hand (tray -> Sair) or pass -Stop."
} else {
    $exePath = $running[0].Path
    if (-not $exePath) { Fail 'cannot read the running zalors.exe path (access denied?) -- refusing to guess which exe to ask.' }
    Write-Host "  running: $($running.Count) zalors.exe from $exePath"
    Write-Host '  asking it to quit: --quit (the tray Quit exit path, including the exit backup hook)'
    # The second process forwards the flag to the running instance and
    # exits by itself (single-instance plugin); PowerShell waits for it.
    & $exePath --quit
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (@(Get-Process -Name zalors -ErrorAction SilentlyContinue).Count -eq 0) { break }
        Start-Sleep -Seconds 2
    }
    $left = @(Get-Process -Name zalors -ErrorAction SilentlyContinue)
    if ($left.Count -gt 0) {
        Fail "the app did not exit within 60 s ($($left.Count) process(es) left). It was left RUNNING -- no kill was attempted. Either close it by hand (tray -> Sair) or it is a pre-batch-22 build that does not understand --quit."
    }
    Write-Host '  every zalors process has exited (gracefully).'
}

# --- step 3: store backup -------------------------------------------------------

Write-Step '3/9 back up the store (copy + SHA256 verify; hashes are never printed)'
if (-not (Test-Path -LiteralPath $StoreDir -PathType Container)) {
    $msg = "store dir not found: $StoreDir"
    if ($DryRun) { FailDry $msg } else { Fail $msg }
}
$storeFiles = @(Get-ChildItem -LiteralPath $StoreDir -File)
if ($storeFiles.Count -eq 0) {
    $msg = "no files directly in $StoreDir -- nothing to back up; check -StoreDir."
    if ($DryRun) { FailDry $msg } else { Fail $msg }
}
if ($DryRun) {
    Write-Host "  DRY-RUN: would create: $backupDir"
    foreach ($f in $storeFiles) {
        Write-Host ("  DRY-RUN: would copy + SHA256-verify {0}  ({1} bytes)  (print: name, size, match=True/False only)" -f $f.Name, $f.Length)
    }
} else {
    New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
    if (-not (Test-Path -LiteralPath $backupDir -PathType Container)) {
        Fail "cannot create the backup dir: $backupDir"
    }
    foreach ($f in $storeFiles) {
        $dst = Join-Path $backupDir $f.Name
        Copy-Item -LiteralPath $f.FullName -Destination $dst -Force
        # Verified with Get-FileHash SHA256 as the manual deploy was; the
        # hash VALUES are computed and compared but never printed.
        $srcHash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        $dstHash = (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash
        $match = ($srcHash -eq $dstHash)
        Write-Host ("  {0}  size={1}  match={2}" -f $f.Name, $f.Length, $match)
        if (-not $match) {
            Fail "backup mismatch on $($f.Name) -- aborting (the partial backup is in $backupDir)"
        }
    }
    Write-Host "  backup ok: $($storeFiles.Count) file(s) in $backupDir"
}

# --- steps 4-6: worktree + build + ALWAYS remove (finally) -----------------------

$buildTxt = Join-Path $deployDir 'build.txt'
$worktreeAdded = $false
try {
    Write-Step '4/9 clean detached worktree'
    if ($DryRun) {
        if (Test-Path -LiteralPath $worktree) {
            FailDry "worktree path already exists: $worktree (leftover from an earlier deploy?)."
        }
        Write-Host "  DRY-RUN: would run: git -C `"$Repo`" worktree add --detach `"$worktree`" $sha"
        Write-Host '  DRY-RUN: would verify: git status --porcelain is empty there (abort if not).'
    } else {
        if (Test-Path -LiteralPath $worktree) {
            Fail "worktree path already exists: $worktree (leftover from an earlier deploy?) -- remove it by hand first."
        }
        git -C $Repo worktree add --detach $worktree $sha
        if ($LASTEXITCODE -ne 0) {
            Fail "git worktree add failed for $worktree (commit $sha)"
        }
        $worktreeAdded = $true
        $porcelain = git -C $worktree status --porcelain
        if ($LASTEXITCODE -ne 0) {
            Fail "git status failed in $worktree"
        }
        if ($porcelain) {
            foreach ($l in @($porcelain)) { Write-Host "    $l" }
            Fail "the fresh worktree is not clean: $worktree"
        }
        Write-Host "  worktree clean: $worktree ($sha7)"
    }

    Write-Step '5/9 cargo build (clean worktree, CARGO_TARGET_DIR=-TargetDir)'
    if ($DryRun) {
        Write-Host '  DRY-RUN: would run: $env:PATH = "$env:USERPROFILE\.cargo\bin;" + $env:PATH'
        Write-Host "  DRY-RUN: would run: cargo build   (cwd: $(Join-Path $worktree 'src-tauri'))"
        Write-Host "  DRY-RUN: with CARGO_TARGET_DIR=$TargetDir"
        Write-Host "  DRY-RUN: build output -> $buildTxt; would print the tail (last 40 lines) and abort on failure."
        Write-Step '6/9 remove the temp worktree (always)'
        Write-Host "  DRY-RUN: would ALWAYS remove it after the build -- git -C `"$Repo`" worktree remove `"$worktree`""
        Write-Host '  DRY-RUN: (--force as the fallback) -- after a successful OR failed build alike, before anything else runs.'
    } else {
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
            Fail 'cargo not found (looked on PATH after prepending $env:USERPROFILE\.cargo\bin).'
        }
        $env:PATH = "$env:USERPROFILE\.cargo\bin;" + $env:PATH
        $env:CARGO_TARGET_DIR = $TargetDir
        New-Item -ItemType Directory -Force -Path $deployDir | Out-Null
        $srcTauri = Join-Path $worktree 'src-tauri'
        if (-not (Test-Path -LiteralPath (Join-Path $srcTauri 'Cargo.toml') -PathType Leaf)) {
            Fail "no src-tauri\Cargo.toml in the worktree: $srcTauri"
        }
        # Native stderr + a strict ErrorActionPreference do not mix in
        # PS 5.1 (the 2>&1 redirect turns stderr lines into error
        # records); relax it for the one statement that needs the pipe.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            Push-Location $srcTauri
            try {
                & cargo build 2>&1 | Out-File -FilePath $buildTxt -Encoding utf8
                $buildCode = $LASTEXITCODE
            } finally {
                Pop-Location
            }
        } finally {
            $ErrorActionPreference = $prevEap
        }
        if ($buildCode -ne 0) {
            Write-Host "  build FAILED (exit $buildCode) -- tail of $(Split-Path $buildTxt -Leaf):" -ForegroundColor Red
            if (Test-Path -LiteralPath $buildTxt -PathType Leaf) {
                Get-Content -LiteralPath $buildTxt -Tail 40 | ForEach-Object { Write-Host "    $_" }
            }
            Fail "cargo build failed; full output: $buildTxt"
        }
        Write-Host '  build ok.'
        Write-Host "  build log: $buildTxt"
    }
} finally {
    # Step 6: ALWAYS remove the temp worktree -- also on Fail/throw,
    # because `exit` unwinds through finally. git refuses a dirty
    # worktree, and a build regenerates ignored files only, so a plain
    # remove normally suffices; --force is the fallback, and a remaining
    # failure is reported with the manual command rather than ignored.
    if ($worktreeAdded) {
        Write-Step '6/9 remove the temp worktree (always)'
        git -C $Repo worktree remove $worktree
        if ($LASTEXITCODE -ne 0) {
            git -C $Repo worktree remove --force $worktree
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  WARNING: could not remove the temp worktree -- run by hand:" -ForegroundColor Yellow
                Write-Host "    git -C `"$Repo`" worktree remove --force `"$worktree`""
            }
        }
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  worktree removed: $worktree"
        }
    }
}

# --- step 7: start the new exe ---------------------------------------------------

$exe = Join-Path $TargetDir 'debug\zalors.exe'
$appPid = $null
$startEpoch = $null
Write-Step '7/9 start the new app'
if ($NoStart) {
    Write-Host '  -NoStart: NOT starting the app (step 8 is skipped; there is nothing to poll).'
} elseif ($DryRun) {
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        Write-Host "  DRY-RUN: NOTE: the exe is not there yet: $exe (the real run aborts if the build did not produce it)."
    }
    Write-Host "  DRY-RUN: would record the start epoch, then run:"
    Write-Host "  DRY-RUN:   Start-Process `"$exe`" -WorkingDirectory `"$(Split-Path $exe -Parent)`" -PassThru"
} else {
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        Fail "built exe not found: $exe (did CARGO_TARGET_DIR point where the build ran?)"
    }
    # BEFORE the launch: the epoch filter in step 8 must not miss the
    # first lines of the fresh session. The app truncates the log at
    # launch, so the file only ever holds the new session; the epoch is
    # the belt-and-suspenders half against a mid-write read.
    $startEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $p = Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe -Parent) -PassThru
    $appPid = $p.Id
    Write-Host "  started: PID $appPid (start epoch $startEpoch)"
}

# --- step 8: poll the log for the startup markers --------------------------------

$markerNames = @(
    'pipeline started',
    'cdp: attached',
    'ws connection key armed',
    'rest decode key armed'
)
$markersFound = $null
if ($DryRun) {
    Write-Step '8/9 poll the log for the startup markers'
    Write-Host "  DRY-RUN: would poll $LogFile (and its rotation target, every 2 s) for up to $MarkerTimeoutSec s:"
    foreach ($m in $markerNames) { Write-Host "  DRY-RUN:   marker: $m" }
    Write-Host '  DRY-RUN: only lines whose [<epoch>] prefix is >= the start epoch would count.'
    Write-Host '  DRY-RUN: would also print: the latest shadow rest stages: line, every shadow rest pending drain line,'
    Write-Host '  DRY-RUN: and the COUNT of lines containing error/panic -- no other log content.'
} elseif (-not $NoStart) {
    Write-Step '8/9 poll the log for the startup markers'
    # dlog.rs line shape: "[<unix-seconds>] message"; the current file is
    # truncated at launch and rotated to <stem>.previous.log at 1 MiB, so
    # BOTH files are scanned every round and a missing current file is
    # just "not started yet". $seen makes re-reads idempotent.
    $logDir = Split-Path $LogFile -Parent
    $logStem = [System.IO.Path]::GetFileNameWithoutExtension($LogFile)
    $previousLog = Join-Path $logDir "$($logStem).previous.log"
    Write-Host "  log: $LogFile"
    Write-Host "  rotation target also scanned: $previousLog"
    Write-Host "  start epoch: $startEpoch (timeout: $MarkerTimeoutSec s)"

    $found = @{}
    foreach ($m in $markerNames) { $found[$m] = $null }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $lastRest = $null
    $drain = @()
    $errPanic = 0

    $deadline = (Get-Date).AddSeconds($MarkerTimeoutSec)
    $pollStart = Get-Date
    $nextHeartbeat = $pollStart.AddSeconds(10)
    while ($true) {
        # previous first: its lines are the older ones, so "latest
        # shadow rest stages" stays in real order across a rotation.
        foreach ($f in @($previousLog, $LogFile)) {
            if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
            $lines = $null
            try { $lines = [System.IO.File]::ReadAllLines($f) } catch { continue }
            foreach ($raw in @($lines)) {
                if (-not $seen.Add($raw)) { continue }
                if ($raw -notmatch '^\[(\d+)\]\s?(.*)$') { continue }
                $epoch = [long] $Matches[1]
                if ($epoch -lt $startEpoch) { continue }
                $msg = $Matches[2]
                foreach ($m in $markerNames) {
                    if ($null -eq $found[$m] -and $msg.Contains($m)) { $found[$m] = $epoch }
                }
                if ($msg.StartsWith('shadow rest stages:')) { $lastRest = $msg }
                if ($msg.StartsWith('shadow rest pending drain')) { $drain += $raw }
                if ($msg -match 'error|panic') { $errPanic++ }
            }
        }
        $markersFound = @($markerNames | Where-Object { $null -ne $found[$_] }).Count
        if ($markersFound -eq $markerNames.Count) { break }
        if ((Get-Date) -ge $deadline) { break }
        if ((Get-Date) -ge $nextHeartbeat) {
            $elapsed = [int] ((Get-Date) - $pollStart).TotalSeconds
            Write-Host ("  waiting: {0}/{1} markers after {2} s" -f $markersFound, $markerNames.Count, $elapsed)
            $nextHeartbeat = $nextHeartbeat.AddSeconds(10)
        }
        Start-Sleep -Seconds 2
    }

    foreach ($m in $markerNames) {
        if ($null -ne $found[$m]) {
            Write-Host ("  marker: {0}: found (epoch {1})" -f $m, $found[$m])
        } else {
            Write-Host ("  marker: {0}: MISSING" -f $m)
        }
    }
    # The only verbatim log lines ever printed -- counts-only by design.
    if ($null -ne $lastRest) { Write-Host "  $lastRest" }
    else { Write-Host '  shadow rest stages: (none in the window)' }
    if ($drain.Count -eq 0) {
        Write-Host '  shadow rest pending drain: (none in the window)'
    } else {
        Write-Host '  shadow rest pending drain:'
        foreach ($d in $drain) { Write-Host "    $d" }
    }
    Write-Host ("  lines containing error/panic in the window: {0} (count only)" -f $errPanic)
} else {
    Write-Step '8/9 poll the log for the startup markers'
    Write-Host '  skipped (-NoStart): nothing was started, so there is no fresh session to poll.'
}

# --- step 9: summary + exit gate --------------------------------------------------

Write-Step '9/9 summary'
Write-Host "  commit:     $sha"
Write-Host "  backup dir: $deployDir  (pre-deploy-backup\ + build.txt)"
if ($DryRun) {
    Write-Host '  build:      (not run)'
    Write-Host '  app pid:    (not started)'
    Write-Host '  markers:    (not polled)'
    Write-Host ''
    Write-Host 'DRY-RUN complete: every step above was PRINTED ONLY.' -ForegroundColor Yellow
    Write-Host '  read-only probes that DID run: git rev-parse, Get-Process zalors, the store-dir listing.'
    Write-Host '  NOT performed: no git worktree, no store copy, no build, no --quit, no start.'
    exit 0
}
Write-Host "  build:      ok (cargo build in a clean detached worktree of $sha7; log: $buildTxt)"
if ($null -ne $appPid) {
    Write-Host "  app pid:    $appPid"
} else {
    Write-Host '  app pid:    (not started: -NoStart)'
}
if ($null -ne $markersFound) {
    Write-Host ("  markers:    {0}/{1} found" -f $markersFound, $markerNames.Count)
    if ($markersFound -lt $markerNames.Count) {
        Fail ("markers missing: " + (@($markerNames | Where-Object { $null -eq $found[$_] }) -join ', '))
    }
} else {
    Write-Host '  markers:    skipped (-NoStart: nothing was started to observe)'
}
Write-Host 'deploy-local: OK' -ForegroundColor Green
exit 0
