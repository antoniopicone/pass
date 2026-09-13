#Requires -Version 5.1
<#
.SYNOPSIS
    Builds pass-syncd and registers it as a Windows Scheduled Task that
    starts at logon and keeps running — the Windows equivalent of
    install-systemd.sh (Linux) / install-launchd.sh (macOS).

.DESCRIPTION
    Nothing here needs administrator rights: the task is created for the
    current user only (schtasks /create without /RU SYSTEM).

.EXAMPLE
    .\install-windows.ps1
#>

$ErrorActionPreference = 'Stop'

$TaskName = 'pass-syncd'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

Write-Host 'Building pass-syncd (release)...'
Push-Location $RepoRoot
try {
    cargo build --release -p pass-syncd
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}

$BinaryPath = Join-Path $RepoRoot 'target\release\pass-syncd.exe'
if (-not (Test-Path -LiteralPath $BinaryPath)) {
    throw "Expected binary not found at $BinaryPath"
}

$Action = New-ScheduledTaskAction -Execute $BinaryPath -Argument 'serve'
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings | Out-Null

Write-Host "Registered scheduled task '$TaskName', starting it now..."
Start-ScheduledTask -TaskName $TaskName

Write-Host ''
Write-Host "Done. pass-syncd will now also start automatically at every logon."
Write-Host "Check status with: Get-ScheduledTask -TaskName $TaskName"
