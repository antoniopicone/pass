#Requires -Version 5.1
<#
.SYNOPSIS
    Builds pass-native-host and registers it as a native messaging host for
    Chromium-based browsers on Windows.

.DESCRIPTION
    The Windows counterpart of install.sh. Unix browsers discover a native
    messaging host from a JSON file dropped in a well-known directory; on
    Windows they read a registry value under HKCU instead, whose default
    value is the full path to that same JSON file. This script writes the
    manifest and creates the registry keys for every Chromium browser it
    finds.

    Nothing here needs administrator rights: everything is written under
    HKEY_CURRENT_USER.

.PARAMETER ExtensionId
    The 32-character extension ID shown on chrome://extensions (or
    brave://extensions) once the unpacked extension has been loaded with
    Developer mode enabled. Re-run this script whenever that ID changes.

.EXAMPLE
    .\install.ps1 -ExtensionId pacnlbehepbfocafbjaemopggmlhcfal
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId
)

$ErrorActionPreference = 'Stop'

$HostName = 'com.antoniopicone.pass_native_host'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

Write-Host 'Building pass-native-host (release)...'
Push-Location $RepoRoot
try {
    cargo build --release -p pass-native-host
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}

$BinaryPath = Join-Path $RepoRoot 'target\release\pass-native-host.exe'
if (-not (Test-Path -LiteralPath $BinaryPath)) {
    throw "Expected binary not found at $BinaryPath"
}

# The manifest must be UTF-8 *without* a BOM: Chromium's JSON parser treats a
# leading BOM as a syntax error and reports the host as simply "not found".
$ManifestPath = Join-Path $PSScriptRoot "$HostName.json"
$manifest = [ordered]@{
    name            = $HostName
    description     = 'Pass password manager native messaging host'
    path            = $BinaryPath
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$ExtensionId/")
}
$json = $manifest | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText($ManifestPath, $json, (New-Object System.Text.UTF8Encoding $false))
Write-Host "Wrote manifest: $ManifestPath"

$browsers = [ordered]@{
    'Chrome'   = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts'
    'Chromium' = 'HKCU:\Software\Chromium\NativeMessagingHosts'
    'Brave'    = 'HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts'
    'Edge'     = 'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts'
}

foreach ($browser in $browsers.GetEnumerator()) {
    $keyPath = Join-Path $browser.Value $HostName
    New-Item -Path $keyPath -Force | Out-Null
    Set-ItemProperty -Path $keyPath -Name '(Default)' -Value $ManifestPath
    Write-Host "Registered for $($browser.Key): $keyPath"
}

Write-Host ''
Write-Host 'Done. Quit the browser completely (every window, so the process'
Write-Host 'actually exits) and reopen it for the change to take effect.'
