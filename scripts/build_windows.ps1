param(
    [string]$Version = "1.0.0",
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$buildDir = Join-Path $ProjectRoot "build"
$distDir = Join-Path $ProjectRoot "dist"
$outputDir = Join-Path $distDir "SMTP-Bench-Pro-$Version-Windows-x64"
$specFile = Join-Path $ProjectRoot "packaging\smtp-bench-pro.spec"

Remove-Item -LiteralPath $buildDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $distDir -Recurse -Force -ErrorAction SilentlyContinue

python -m PyInstaller $specFile --clean --noconfirm --distpath $outputDir --workpath $buildDir

if (-not (Test-Path (Join-Path $outputDir "SMTP Bench Pro.exe"))) {
    throw "PyInstaller build finished without producing SMTP Bench Pro.exe."
}

Write-Host "Build completed: $outputDir"
