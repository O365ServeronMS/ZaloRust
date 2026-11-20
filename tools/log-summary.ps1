<#
tools/log-summary.ps1 -- acceptance read-out for the zalors diagnostic
log (audit §4 items 1.1/1.4/1.5: the counters the soak ACs are judged
on). Reads the log `dlog` writes — one `[<unix-seconds>] message` line
per event — and prints ONLY:

  - the LAST occurrence of each aggregate counter line:
      `shadow rest stages:`  (REST capture stage counters, audit H2)
      `shadow ws stages:`    (WS frame stage counters, audit M4)
      `shadow e2ee:`        (bridge e2ee admission counters, audit C1)
    Those three lines are safe by construction (counts only), so they
    are the ONLY lines ever printed verbatim.
  - `shadow write errors:` -> the number of such lines and the UNION of
    the error kinds they carry (`<tag>:<sqlite kind>` tokens); the lines
    themselves are never echoed.
  - a count (0 means absent) for each marker the ACs name:
      own uid configured / own uid mismatch / accounts row skipped
      (KQ2, audit 1.4) · rest decode key armed / ws connection key armed
      (audit 1.1/1.5) · pipeline started · FAILED (any line).

Anything else in the log (message shapes, endpoints, download notes…)
is counted, if at all, and never printed.

Params:
  -Path   the log file. Default: %LOCALAPPDATA%\zalo-web\logs\zalors.log
          (dlog.rs). The synthetic test always passes its own temp file.
  -Since  optional [datetime]; only lines stamped at/after it count.

Exit codes: 0 = summary printed; 1 = no readable log file.
#>
[CmdletBinding()]
param(
    [string] $Path = (Join-Path (Join-Path $env:LOCALAPPDATA 'zalo-web\logs') 'zalors.log'),
    [datetime] $Since = [datetime]::MinValue
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Write-Output "log-summary: FAIL: no log file at $Path"
    exit 1
}

# dlog line shape: "[<unix-seconds>] message" (dlog.rs::log).
$sinceSec = if ($Since -eq [datetime]::MinValue) { [long]::MinValue }
             else { ([DateTimeOffset]$Since).ToUnixTimeSeconds() }

$lastRest = $null
$lastWs   = $null
$lastE2ee = $null
$writeErrLines = 0
$writeErrKinds = @()
# A static name array (NOT the hashtable's .Keys view): incrementing a
# hashtable entry invalidates key enumeration on Windows PowerShell.
$markerNames = @(
    'own uid configured',
    'own uid mismatch',
    'accounts row skipped',
    'rest decode key armed',
    'ws connection key armed',
    'pipeline started',
    'FAILED'
)
$markerCount = @{}
foreach ($n in $markerNames) { $markerCount[$n] = 0 }
$considered = 0

# `shadow write errors: 2 (kinds: message:sqlite_X/787 x1, media:sqlite_Y/5132 x1)`
function Parse-ErrKinds([string] $line) {
    if ($line -match '\(kinds:\s*([^)]*)\)') {
        $parts = $Matches[1] -split ','
        foreach ($p in $parts) {
            $tok = $p.Trim() -replace ' x\d+$', ''
            if ($tok) { $tok }
        }
    }
}

foreach ($raw in [System.IO.File]::ReadLines($Path)) {
    if ($raw -notmatch '^\[(\d+)\]\s?(.*)$') { continue }   # no/invalid timestamp
    if ([long]$Matches[1] -lt $sinceSec) { continue }
    $msg = $Matches[2]
    $considered++

    if     ($msg.StartsWith('shadow rest stages:')) { $lastRest = $msg }
    elseif ($msg.StartsWith('shadow ws stages:'))   { $lastWs   = $msg }
    elseif ($msg.StartsWith('shadow e2ee:'))        { $lastE2ee = $msg }
    elseif ($msg.StartsWith('shadow write errors:')) {
        $writeErrLines++
        $writeErrKinds += @(Parse-ErrKinds $msg | Where-Object { $_ -notin $writeErrKinds })
    }
    else {
        foreach ($m in $markerNames) {
            if ($msg.Contains($m)) { $markerCount[$m]++ }
        }
    }
}

Write-Output "log-summary: $Path"
if ($Since -eq [datetime]::MinValue) { Write-Output "lines considered: $considered (all)" }
else { Write-Output ("lines considered: {0} (since {1:yyyy-MM-ddTHH:mm:ssZ})" -f $considered, $Since.ToUniversalTime()) }

# The three aggregate counter lines — the only verbatim output.
# (Each stored message already begins with its own `shadow … stages:`/
# `shadow e2ee:` prefix; printed as-is, labelled only when absent.)
if ($null -ne $lastRest) { Write-Output $lastRest } else { Write-Output 'shadow rest stages: (none)' }
if ($null -ne $lastWs)   { Write-Output $lastWs }   else { Write-Output 'shadow ws stages: (none)' }
if ($null -ne $lastE2ee) { Write-Output $lastE2ee } else { Write-Output 'shadow e2ee: (none)' }

$kinds = ($writeErrKinds | Sort-Object -Unique) -join ', '
Write-Output ("shadow write errors: lines={0} kinds={1}" -f $writeErrLines, $(if ($kinds) { $kinds } else { '(none)' }))
foreach ($m in $markerNames) {
    Write-Output ("{0}: {1}" -f $m, $markerCount[$m])
}
exit 0
