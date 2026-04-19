# Patch-Learner dashboard launcher (Windows PowerShell)
# Usage: cd D:\Task\4\project\web ; .\run.ps1
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Test-Path .\.venv)) {
    Write-Host "[run] creating venv..."
    python -m venv .venv
}

Write-Host "[run] activating venv..."
. .\.venv\Scripts\Activate.ps1

Write-Host "[run] installing requirements..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

Write-Host "[run] launching http://127.0.0.1:8787 ..."
python app.py
