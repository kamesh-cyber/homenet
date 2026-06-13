<#
  HomeScope - one-shot Windows installer / launcher.

  Does everything automatically:
    1. Re-launches itself as Administrator (UAC prompt) so capture/sinkhole/
       firewall can actually run.
    2. Creates a .venv and pip-installs requirements.txt (FastAPI, scapy, dnslib).
    3. Installs the Npcap packet-capture driver if it is missing (pip cannot -
       it is a kernel driver - so we download the official installer here).
    4. Optionally installs the net-snmp CLI (-WithSnmp) for SNMPv3.
    5. Starts HomeScope at http://127.0.0.1:8788.

  Usage (from a normal PowerShell - it elevates itself):
    powershell -ExecutionPolicy Bypass -File .\setup.ps1
    powershell -ExecutionPolicy Bypass -File .\setup.ps1 -WithSnmp
    powershell -ExecutionPolicy Bypass -File .\setup.ps1 -NoRun   # install only
  Or just double-click setup.bat.
#>
[CmdletBinding()]
param(
    [switch]$WithSnmp,   # also try to install the net-snmp CLI (only needed for SNMPv3)
    [switch]$NoRun       # set up everything but do not launch the app
)

$ErrorActionPreference = "Stop"
$NpcapVersion = "1.82"   # bump if a newer Npcap is out (https://npcap.com)

# Windows PowerShell 5.1 defaults to old TLS; npcap.com needs TLS 1.2 to download.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Info($m) { Write-Host $m -ForegroundColor Cyan }
function Ok($m)   { Write-Host $m -ForegroundColor Green }
function Warn($m) { Write-Host $m -ForegroundColor Yellow }

# 1. Self-elevate to Administrator
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Warn "Requesting Administrator privileges (needed for capture, sinkhole, firewall)..."
    $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($WithSnmp) { $a += "-WithSnmp" }
    if ($NoRun)    { $a += "-NoRun" }
    Start-Process powershell -Verb RunAs -ArgumentList $a
    exit
}

Set-Location -Path $PSScriptRoot
Ok "Running as Administrator in $PSScriptRoot"

# 2. Python venv + dependencies
$py = $null
foreach ($c in @("py", "python")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break }
}
if (-not $py) {
    Write-Host "Python not found. Install Python 3.9+ from https://www.python.org/downloads/ (tick 'Add to PATH'), then re-run." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Info "Creating virtual environment (.venv)..."
    & $py -m venv .venv
}
$venvPy = ".\.venv\Scripts\python.exe"

Info "Installing Python dependencies from requirements.txt..."
& $venvPy -m pip install --upgrade pip --quiet
& $venvPy -m pip install -r requirements.txt
Ok "Python dependencies installed."

# 3. Npcap packet-capture driver
function Test-Npcap {
    if (Get-Service -Name npcap -ErrorAction SilentlyContinue) { return $true }
    if (Test-Path "$env:WINDIR\System32\Npcap\wpcap.dll") { return $true }
    if (Test-Path "$env:WINDIR\System32\wpcap.dll") { return $true }
    return $false
}

if (Test-Npcap) {
    Ok "Npcap already installed."
} else {
    $url = "https://npcap.com/dist/npcap-$NpcapVersion.exe"
    $exe = Join-Path $env:TEMP "npcap-$NpcapVersion.exe"
    try {
        Info "Downloading Npcap $NpcapVersion ..."
        Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
        Info "Installing Npcap (trying silent mode)..."
        Start-Process -FilePath $exe -ArgumentList "/S","/winpcap_mode=yes","/loopback_support=yes" -Wait -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        if (-not (Test-Npcap)) {
            Warn "Silent install unavailable (free Npcap needs a click-through). Launching the installer - click Next/Install and keep 'WinPcap API-compatible Mode' checked."
            Start-Process -FilePath $exe -Wait
        }
        if (Test-Npcap) { Ok "Npcap installed." }
        else { Warn "Npcap still not detected. Install manually from https://npcap.com then re-run." }
    } catch {
        Warn ("Could not download/install Npcap automatically: " + $_.Exception.Message)
        Warn "Install it manually from https://npcap.com (one-time)."
    }
}

# 4. net-snmp CLI (optional; only needed for SNMPv3 - v1/v2c is pure-Python)
if ($WithSnmp) {
    if (Get-Command snmpwalk -ErrorAction SilentlyContinue) {
        Ok "net-snmp already on PATH."
    } else {
        Info "Attempting net-snmp install via winget..."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            try {
                winget install --id NetSnmp.NetSnmp -e --accept-package-agreements --accept-source-agreements
            } catch {}
        }
        if (-not (Get-Command snmpwalk -ErrorAction SilentlyContinue)) {
            Warn "net-snmp not installed automatically. It is optional (only SNMPv3 needs it). Get it from https://www.net-snmp.org and add to PATH."
        }
    }
}

# 5. Launch
if ($NoRun) {
    Ok "Setup complete. Run later with:  .\.venv\Scripts\python.exe app.py"
} else {
    Ok "Starting HomeScope -> http://127.0.0.1:8788   (Ctrl+C to stop)"
    & $venvPy app.py
}
