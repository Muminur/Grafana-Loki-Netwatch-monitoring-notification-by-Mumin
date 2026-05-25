#requires -Version 5.1
<#
.SYNOPSIS
  Cold-restart the BSCCL NetWatch server: stop the running instance, start a fresh one.

.DESCRIPTION
  1. Stops every NetWatch uvicorn process (matched by command line "uvicorn ... src.main:app")
     and frees the target port. Unrelated Python processes are NOT touched.
  2. Starts a brand-new detached uvicorn process, logging to logs\netwatch.log.
  3. Waits for /health to confirm it came up.

  The SQLite database is PRESERVED by default. Pass -ResetDb to wipe alert history too.

.PARAMETER Port
  TCP port to bind (default 8080).

.PARAMETER Reload
  Start with uvicorn --reload (dev auto-reload). Default off = stable single process.

.PARAMETER ResetDb
  DESTRUCTIVE. Delete bsccl_netwatch.db* before starting (erases all stored alerts/incidents).

.EXAMPLE
  .\scripts\restart_netwatch.ps1

.EXAMPLE
  .\scripts\restart_netwatch.ps1 -Port 8080 -Reload
#>
[CmdletBinding()]
param(
    [int]$Port = 8080,
    [switch]$Reload,
    [switch]$ResetDb
)

$ErrorActionPreference = 'Stop'

# --- Locate project root (this script lives in <root>\scripts) -----------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

# --- Choose interpreter: prefer .venv, fall back to system python --------
$VenvPython = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$Python = if (Test-Path $VenvPython) { $VenvPython } else { (Get-Command python).Source }

Write-Host "== NetWatch restart ==" -ForegroundColor Cyan
Write-Host "Project : $ProjectRoot"
Write-Host "Python  : $Python"
Write-Host "Port    : $Port"

# --- 1. Stop existing NetWatch server(s) ---------------------------------
Write-Host "`n[1/3] Stopping running NetWatch server ..." -ForegroundColor Yellow
$stopped = New-Object System.Collections.Generic.List[int]

# (a) by command line — catches reload parent + workers on any port; only OUR app
Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
    Where-Object {
        $_.CommandLine -and (
            ($_.CommandLine -match 'uvicorn' -and $_.CommandLine -match 'src\.main:app') -or
            ($_.CommandLine -match 'multiprocessing\.spawn')
        )
    } |
    ForEach-Object {
        try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $stopped.Add([int]$_.ProcessId) } catch { }
    }

# (b) by port — kill any process (or orphaned child) holding the port
Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique |
    ForEach-Object {
        $portPid = $_
        # Try killing the owner directly
        try { Stop-Process -Id $portPid -Force -ErrorAction Stop; $stopped.Add([int]$portPid) } catch { }
        # Also kill any child processes that inherited the socket
        Get-CimInstance Win32_Process -Filter "ParentProcessId = $portPid" -ErrorAction SilentlyContinue |
            ForEach-Object {
                try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $stopped.Add([int]$_.ProcessId) } catch { }
            }
    }

# (c) netstat fallback — catches ghost PIDs that Get-NetTCPConnection maps to dead parents
$netstatPids = netstat -ano 2>$null |
    Select-String ":$Port\s.*LISTENING" |
    ForEach-Object { if ($_ -match '\s(\d+)\s*$') { $Matches[1] } } |
    Sort-Object -Unique
foreach ($nPid in $netstatPids) {
    try { Stop-Process -Id ([int]$nPid) -Force -ErrorAction Stop; $stopped.Add([int]$nPid) } catch { }
    # Kill children of the netstat PID too
    Get-CimInstance Win32_Process -Filter "ParentProcessId = $nPid" -ErrorAction SilentlyContinue |
        ForEach-Object {
            try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $stopped.Add([int]$_.ProcessId) } catch { }
        }
}

if ($stopped.Count -gt 0) {
    Write-Host ("  Stopped PID(s): " + (($stopped | Sort-Object -Unique) -join ', '))
} else {
    Write-Host "  No running NetWatch process found."
}

# wait up to 5s for the port to free
for ($i = 0; $i -lt 20; $i++) {
    if (-not (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 250
}

# --- optional: wipe the database (opt-in, destructive) -------------------
if ($ResetDb) {
    Write-Host "  -ResetDb: deleting bsccl_netwatch.db* (alert history will be lost) ..." -ForegroundColor Red
    Get-ChildItem -Path $ProjectRoot -Filter 'bsccl_netwatch.db*' -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# --- 2. Start a fresh instance, detached, logging to file ----------------
Write-Host "`n[2/3] Starting fresh NetWatch server ..." -ForegroundColor Yellow
$LogDir = Join-Path $ProjectRoot 'logs'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$OutLog = Join-Path $LogDir 'netwatch.log'
$ErrLog = Join-Path $LogDir 'netwatch.err.log'

$uvArgs = @('-m', 'uvicorn', 'src.main:app', '--host', '0.0.0.0', '--port', "$Port")
if ($Reload) { $uvArgs += '--reload' }

$proc = Start-Process -FilePath $Python -ArgumentList $uvArgs `
    -WorkingDirectory $ProjectRoot `
    -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog `
    -WindowStyle Hidden -PassThru

Start-Sleep -Seconds 3
if ($proc.HasExited) {
    Write-Host "  Server exited immediately (exit code $($proc.ExitCode)). Last error lines:" -ForegroundColor Red
    if (Test-Path $ErrLog) { Get-Content $ErrLog -Tail 20 }
    exit 1
}
Write-Host "  Started PID $($proc.Id)  ->  http://localhost:$Port"
Write-Host "  Logs: $OutLog"

# --- 3. Health check -----------------------------------------------------
Write-Host "`n[3/3] Waiting for /health ..." -ForegroundColor Yellow
$ok = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Milliseconds 600
    try {
        $h = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 3
        Write-Host ("  OK: " + ($h | ConvertTo-Json -Compress)) -ForegroundColor Green
        $ok = $true; break
    } catch { }
}
if (-not $ok) {
    Write-Host "  Health not responding yet. Tail logs with:  Get-Content `"$OutLog`" -Wait" -ForegroundColor Red
    exit 1
}

Write-Host "`nNetWatch is running. Re-run this script anytime; it stops the old process first." -ForegroundColor Cyan
