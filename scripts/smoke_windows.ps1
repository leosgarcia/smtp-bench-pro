param(
    [string]$Version = "1.0.0-rc1",
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$exe = Join-Path $ProjectRoot "dist\SMTP-Bench-Pro-$Version-Windows-x64\SMTP Bench Pro.exe"
if (-not (Test-Path $exe)) {
    throw "Executable not found: $exe"
}

$expectedDir = Join-Path $env:APPDATA "WL Tech\SMTP Bench Pro"
$expectedLog = Join-Path $expectedDir "logs\smtp-bench-pro.log"
$expectedDb = Join-Path $expectedDir "smtp-bench-pro.db"

$proc = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5

if ($proc.HasExited) {
    throw "SMTP Bench Pro exited during smoke test."
}

Stop-Process -Id $proc.Id -Force
Start-Sleep -Seconds 1

if (-not (Test-Path $expectedDir)) {
    throw "AppData directory was not created at expected location: $expectedDir"
}

if (-not (Test-Path $expectedLog) -and -not (Test-Path $expectedDb)) {
    throw "Neither log nor database was created in AppData at: $expectedDir"
}

if (Test-Path (Join-Path $ProjectRoot "SMTP Bench Pro.exe")) {
    throw "Executable was written beside the source tree, which should not happen."
}

Write-Host "Smoke test passed."
