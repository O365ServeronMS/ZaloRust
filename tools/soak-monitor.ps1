<#
tools/soak-monitor.ps1 -- hourly RSS monitor for a running zalors (audit
docs/audit/shadow-audit-2026-11-19.md §4 item 1.5 AC vi: "RSS app không
tăng tuyến tính (leak M4) — ghi Get-Process zalors mỗi giờ").

Every -IntervalMin minutes it appends ONE CSV line to -Out:

    utc_iso,pid,start_time_iso,ws_mb,pm_mb,handles,threads

for the process named -ProcessName (default zalors). When the process
is absent the line is `utc_iso,absent`, so a soak restart is visible as
a gap in pid/start_time. It ends after -Minutes minutes of wall time.

H-rules honored by design:
- it NEVER kills, restarts or otherwise touches the process — the only
  contact is Get-Process (read-only counters);
- it never opens the shadow DB or the settings file;
- the CSV carries process metrics only — no uids, no keys, no text,
  no URLs, no file names from the media store.

Fast mode for SYNTHETIC test runs: -IntervalMin 0 (or negative) samples
every 1 second instead of every hour, so `-Minutes 1 -IntervalMin 0`
writes ~60 lines and exits. Point -ProcessName at a process that
certainly exists (pwsh/powershell) to test without touching the soak.

The three "state" columns repeat on every line (pid and start_time of
the process seen at that sample) — a plain CSV stays self-describing
when it is read days later, after the soak process is gone.
#>
[CmdletBinding()]
param(
    [int] $Minutes = 1440,
    [int] $IntervalMin = 60,
    [string] $Out = (Join-Path $env:TEMP 'zalors-soak.csv'),
    # Only for synthetic test runs; the real soak target is zalors.
    [string] $ProcessName = 'zalors'
)

$ErrorActionPreference = 'Stop'

if ($Minutes -lt 1) {
    Write-Output "soak-monitor: FAIL: -Minutes must be >= 1"
    exit 1
}
# IntervalMin <= 0 is the documented fast mode: 1-second sampling.
$intervalSec = if ($IntervalMin -gt 0) { $IntervalMin * 60 } else { 1 }

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$Header = 'utc_iso,pid,start_time_iso,ws_mb,pm_mb,handles,threads'
$needHeader = -not (Test-Path -LiteralPath $Out) -or (Get-Item -LiteralPath $Out).Length -eq 0
if ($needHeader) {
    [System.IO.File]::AppendAllText($Out, $Header + "`r`n", $Utf8NoBom)
}

function Format-Iso([DateTime] $t) { $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function Sample-Line {
    # Get-Process only — never Stop-Process, never anything that writes.
    $procs = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    $utc = Format-Iso ([DateTime]::Now)
    if ($procs.Count -eq 0) {
        return "$utc,absent"
    }
    # Deterministic pick when several match: lowest pid. (WebView2
    # children have other names, so zalors itself is normally unique.)
    $p = $procs | Sort-Object Id | Select-Object -First 1
    try { $startIso = Format-Iso $p.StartTime } catch { $startIso = '' }
    '{0},{1},{2},{3},{4},{5},{6}' -f $utc, $p.Id, $startIso,
        [Math]::Round($p.WorkingSet64 / 1MB, 1),
        [Math]::Round($p.PrivateMemorySize64 / 1MB, 1),
        $p.HandleCount, $p.Threads.Count
}

Write-Output ("soak-monitor: target={0} interval={1}s minutes={2} out={3}" -f `
    $ProcessName, $intervalSec, $Minutes, $Out)

$deadline = [DateTime]::UtcNow.AddMinutes($Minutes)
$lines = 0
while ([DateTime]::UtcNow -lt $deadline) {
    $line = Sample-Line
    [System.IO.File]::AppendAllText($Out, $line + "`r`n", $Utf8NoBom)
    $lines++
    $remaining = ($deadline - [DateTime]::UtcNow).TotalSeconds
    if ($remaining -le 0) { break }
    Start-Sleep -Seconds ([Math]::Min([int]$intervalSec, [Math]::Ceiling($remaining)))
}

$absent = 0
if (Test-Path -LiteralPath $Out) {
    $absent = @(Select-String -LiteralPath $Out -Pattern ',absent$' -SimpleMatch:$false).Count
}
Write-Output ("soak-monitor: done, wrote {0} sample line(s) to {1} (absent rows so far: {2})" -f `
    $lines, $Out, $absent)
exit 0
