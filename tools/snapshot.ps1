<#
tools/snapshot.ps1 -- cold-snapshot copier for the Zalo Desktop DB tree.

Batch 6 F5 (docs/audit/shadow-audit-2026-11-19.md, phase 2 item 2.1 / KQ4).
The import (`zalors import --from-snapshot`, shadow/import.rs F3) refuses
any directory without the snapshot-manifest.json this script writes.

What it does, in order:
  1. Refuses to run while Zalo Desktop runs (exact process-name match
     from an explicit list, default just `Zalo` — never a wildcard,
     never `zalors`; a snapshot of a live DB would be torn). -Force
     skips ONLY this check, and only for SYNTHETIC test runs (both
     dirs under $env:TEMP): never use -Force against the real Desktop
     data.
  2. Refuses a -Dest that already exists, and a -Dest on a different
     volume than -Source (the D9 hardlink step later needs one volume).
  3. Records a manifest of -Source: rel path, size, LastWriteTimeUtc
     (epoch ms) and sha256-12 of every file.
  4. Copies EVERYTHING (including -wal/-shm sidecars) Source -> Dest.
     Copy-Item preserves LastWriteTime, so the copies match the manifest.
  5. Re-records the -Source manifest and FAILS if anything changed
     (proof of zero writes to the source).
  6. Writes <Dest>\snapshot-manifest.json in the shape the import needs:
       { "created": <epoch ms>,        # when the snapshot was made
         "source_root_sha12": "<12 hex>",   # sha256-12 of the absolute
                                            # -Source path (UTF-8)
         "files": [ { "rel": ..., "size": ..., "mtime": <epoch ms> } ... ] }

It does NOT checkpoint any DB: the checkpoint happens later, on the COPY,
in Rust (KQ4). Media folders are never touched -- point -Source at the
Desktop DB tree only.

SYNTHETIC TEST FIRST: run it on dirs you created under $env:TEMP. The
real run needs the user to quit Zalo Desktop first (the script enforces
that itself).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Source,
    [Parameter(Mandatory = $true)] [string] $Dest,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    Write-Output "snapshot: FAIL: $Message"
    exit 1
}

function Remove-DestIfPresent {
    if (Test-Path -LiteralPath $script:destFull) {
        Remove-Item -LiteralPath $script:destFull -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- guards ---------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
    Fail "Source directory not found: $Source"
}

# Process guard (M1): refuse while the DESKTOP app runs, and only that.
# $desktopProcessNames is the EXACT image-name list: `Zalo` is the single
# Desktop process the audit observed (PID 11604, 2026-11-19); no Desktop
# helper process names were ever observed, so none are listed. `Get-Process
# -Name <no-wildcard-chars>` is an exact (case-insensitive) name match,
# so 'Zalo' can never match 'zalors' -- the user's own zalors.exe (this
# app) is allowed to run while a snapshot is made. NEVER use a wildcard
# here: 'zalo*' would refuse on zalors.exe.
$desktopProcessNames = @('Zalo')
$zalo = @()
foreach ($name in $desktopProcessNames) {
    $zalo += @(Get-Process -Name $name -ErrorAction SilentlyContinue)
}
if ($zalo.Count -gt 0 -and -not $Force) {
    $zaloMsg = "Zalo Desktop is running (" + $zalo.Count + " process(es)) - quit it first; " +
        "a snapshot of the live DB would be torn. (-Force skips this check for " +
        "SYNTHETIC test runs only.)"
    Fail $zaloMsg
}

$script:sourceFull = [System.IO.Path]::GetFullPath($Source)
$script:destFull   = [System.IO.Path]::GetFullPath($Dest)
if (Test-Path -LiteralPath $script:destFull) {
    Fail "Dest already exists: $script:destFull (the snapshot dir must be fresh)"
}
$sourceRoot = [System.IO.Path]::GetPathRoot($script:sourceFull)
$destRoot   = [System.IO.Path]::GetPathRoot($script:destFull)
if (-not $sourceRoot.Equals($destRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail ("Dest ($destRoot) is on a different volume than Source ($sourceRoot) - " +
          "the D9 hardlink step later needs one volume")
}

# --- manifest helper -------------------------------------------------------
function Get-TreeManifest([string] $Root) {
    # rel / size / mtime (epoch ms from LastWriteTimeUtc) / sha256-12 of
    # every file under $Root, sorted by rel so two recordings are
    # directly comparable.
    $prefixLen = $Root.Length + 1
    $rows = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | ForEach-Object {
        $hashHex = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
        [pscustomobject] @{
            rel   = $_.FullName.Substring($prefixLen)
            size  = [long] $_.Length
            mtime = [long] ([DateTimeOffset]$_.LastWriteTimeUtc).ToUnixTimeMilliseconds()
            sha12 = $hashHex.Substring(0, 12)
        }
    })
    if ($rows.Count -eq 0) { Fail "Source contains no files: $Root" }
    $rows | Sort-Object -Property rel
}

Write-Output "snapshot: source=$script:sourceFull"
Write-Output "snapshot: dest=$script:destFull (volume $destRoot)"

# --- 1) record the source --------------------------------------------------
Write-Output "snapshot: recording source manifest (rel, size, mtime, sha256-12)..."
$before = Get-TreeManifest -Root $script:sourceFull
$totalBytes = ($before | Measure-Object -Property size -Sum).Sum
Write-Output ("snapshot: recorded {0} files, {1} bytes" -f $before.Count, $totalBytes)

# --- 2) copy everything incl. -wal/-shm ------------------------------------
New-Item -ItemType Directory -Path $script:destFull | Out-Null
try {
    Copy-Item -Path (Join-Path $script:sourceFull '*') -Destination $script:destFull -Recurse -Force
} catch {
    Remove-DestIfPresent
    Fail ("copy failed: " + $_.Exception.Message)
}
Write-Output ("snapshot: copied {0} files (including -wal/-shm sidecars)" -f $before.Count)

# --- 3) zero-write proof ----------------------------------------------------
try {
    $after = Get-TreeManifest -Root $script:sourceFull
} catch {
    Remove-DestIfPresent
    Fail ("re-recording the source manifest failed: " + $_.Exception.Message)
}
$diff = Compare-Object -ReferenceObject $before -DifferenceObject $after -Property rel, size, mtime, sha12
if ($null -ne $diff) {
    foreach ($d in $diff) {
        Write-Output ("snapshot: source changed during copy: " + $d.InputObject)
    }
    Remove-DestIfPresent
    Fail "SOURCE CHANGED during the copy - zero-write proof failed; partial Dest removed"
}
Write-Output "snapshot: source unchanged after the copy (zero-write proof passed)"

# --- 4) write the F3-shape manifest ----------------------------------------
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $rootPath = $script:sourceFull.TrimEnd('\')
    $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rootPath))
    $rootSha12 = ([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLower().Substring(0, 12)
} finally {
    $sha256.Dispose()
}

$files = @(
    foreach ($f in $after) {
        [ordered] @{ rel = $f.rel; size = [long] $f.size; mtime = [long] $f.mtime }
    }
)
$manifest = [ordered] @{
    created           = [long] ([DateTimeOffset]::UtcNow).ToUnixTimeMilliseconds()
    source_root_sha12 = $rootSha12
    files             = $files
}
$manifestPath = Join-Path $script:destFull 'snapshot-manifest.json'
try {
    $json = $manifest | ConvertTo-Json -Depth 5
    # UTF8Encoding($false): no BOM -- shadow/import.rs parses this file
    # with a strict JSON parser (it tolerates one, but keep it clean).
    [System.IO.File]::WriteAllText($manifestPath, $json, [System.Text.UTF8Encoding]::new($false))
} catch {
    Remove-DestIfPresent
    Fail ("writing snapshot-manifest.json failed: " + $_.Exception.Message)
}

Write-Output "snapshot: wrote $manifestPath"
Write-Output "snapshot: OK (no checkpoint performed - that happens on the copy, in Rust)"
exit 0
