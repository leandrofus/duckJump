# Builds the MSI with the WiX Toolset (installed as a .NET tool if missing).
#
#   ./build-msi.ps1 -Version 0.1.0 -Exe dist/duckjump.exe [-AssistExe dist/duckjump-assist.exe] -Out dist/duckjump-0.1.0-x64.msi
param(
  [Parameter(Mandatory)][string]$Version,
  [Parameter(Mandatory)][string]$Exe,
  [string]$AssistExe,
  [Parameter(Mandatory)][string]$Out
)
$ErrorActionPreference = 'Stop'
$wixVersion = '5.0.2'
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  dotnet tool install --global wix --version $wixVersion
  if ($LASTEXITCODE) { throw 'could not install wix' }
  $env:PATH += ";$env:USERPROFILE\.dotnet\tools"
}

$wixArgs = @(
  "$PSScriptRoot\duckjump.wxs",
  "-arch", "x64",
  "-d", "Version=$Version",
  "-d", "Exe=$((Resolve-Path $Exe).Path)",
  "-o", $Out
)
if ($AssistExe -and (Test-Path $AssistExe)) {
  $wixArgs += @("-d", "AssistExe=$((Resolve-Path $AssistExe).Path)")
}

wix build @wixArgs
if ($LASTEXITCODE) { throw "wix build: exit $LASTEXITCODE" }
Get-Item $Out | Format-Table Name, Length
