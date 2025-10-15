<# 
ChildShield Forensics – setup & build (Windows)
Usage:
  powershell -ExecutionPolicy Bypass -File .\setup.ps1 -PythonVersion 3.11.9 -Build
#>

param(
  [string] $PythonVersion = "3.11.9",
  [switch] $Build = $true
)

$ErrorActionPreference = "Stop"
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT

function Get-PyMatch {
  try {
    $cmd = Get-Command py -ErrorAction SilentlyContinue
    if ($cmd) { return "py -$($PythonVersion.Substring(0,4))" } # e.g. 3.11
  } catch {}
  $cmd = Get-Command python -ErrorAction SilentlyContinue
  if ($cmd) { return "python" }
  return $null
}

function Ensure-Python {
  $py = Get-PyMatch
  if ($py) { return $py }

  Write-Host "==> Installing Python $PythonVersion (or latest 3.$($PythonVersion.Split('.')[1])) via winget…" -ForegroundColor Cyan
  $minor = $PythonVersion.Split('.')[1]
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install -e --id Python.Python.3.$minor --accept-source-agreements --accept-package-agreements --silent
  } else {
    $url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
    $tmp = Join-Path $env:TEMP "python-$PythonVersion-amd64.exe"
    Invoke-WebRequest $url -OutFile $tmp
    & $tmp /quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1
  }
  Start-Sleep -Seconds 5
  return (Get-PyMatch)
}

$py = Ensure-Python
if (-not $py) { throw "Python not found after install." }
Write-Host "==> Using Python: $py"

# venv
& $py -m venv .venv
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip wheel
& ".\.venv\Scripts\pip.exe" install -r ".\requirements.txt" pyinstaller

# Optional tools (ffmpeg via winget)
try {
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install -e --id Gyan.FFmpeg --silent | Out-Null
  }
} catch {}

if ($Build) {
  Write-Host "==> Building executables…" -ForegroundColor Cyan
  $PYI = ".\.venv\Scripts\pyinstaller.exe"
  # Windows uses ';' in --add-data
  & $PYI --noconfirm --clean `
    --name childshield_cli `
    --add-data "policy;policy" `
    --add-data "plugins;plugins" `
    .\cli\main.py

  & $PYI --noconfirm --clean --windowed `
    --name childshield_gui `
    --add-data "policy;policy" `
    --add-data "plugins;plugins" `
    .\gui\main_gui.py

  Write-Host "==> Done. Binaries in dist\ (childshield_cli.exe, childshield_gui.exe)" -ForegroundColor Green
}
