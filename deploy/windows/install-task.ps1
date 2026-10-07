<#
.SYNOPSIS
    Installs kmitl-authen as a Windows Scheduled Task that starts at boot and
    restarts itself if it ever exits.

.DESCRIPTION
    Task Scheduler is the dependency-free option on Windows. It runs the daemon
    under the SYSTEM account (so it starts before anyone logs in), restarts it
    on failure, and keeps no console window open.

    The watchdog inside the daemon exits with code 70 when a loop iteration
    stalls; the restart settings below are what turn that into a self-heal.
    Without a supervisor, a hung process just stays hung -- which is exactly
    what the old script did.

.EXAMPLE
    # From an elevated PowerShell prompt, in the repo root:
    .\deploy\windows\install-task.ps1 -Username 65010000

.EXAMPLE
    .\deploy\windows\install-task.ps1 -InstallDir 'C:\kmitl-authen' -ControlPort 8777
#>
[CmdletBinding()]
param(
    [string]$TaskName    = 'KMITL-Authen',
    [string]$InstallDir  = 'C:\Program Files\kmitl-authen',
    [string]$StateDir    = 'C:\ProgramData\kmitl-authen',
    [string]$Username    = '',
    [int]   $ControlPort = 8777,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell prompt (Run as administrator).'
}

$python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $python) { $python = (Get-Command py.exe -ErrorAction SilentlyContinue).Source }
if (-not $python) { throw 'Python was not found on PATH. Install Python 3.9+ first.' }
Write-Host "Using Python at $python"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if (-not $SkipInstall) {
    Write-Host "Installing into $InstallDir"
    New-Item -ItemType Directory -Force -Path $InstallDir, $StateDir | Out-Null
    Copy-Item -Recurse -Force (Join-Path $repoRoot 'kmitl_authen') $InstallDir
    foreach ($f in 'requirements.txt', 'pyproject.toml', 'README.md', 'LICENSE',
                   'config.example.json') {
        $src = Join-Path $repoRoot $f
        if (Test-Path $src) { Copy-Item -Force $src $InstallDir }
    }

    $venv = Join-Path $InstallDir '.venv'
    if (-not (Test-Path $venv)) {
        Write-Host 'Creating a virtual environment'
        & $python -m venv $venv
    }
    & (Join-Path $venv 'Scripts\python.exe') -m pip install --upgrade pip --quiet
    & (Join-Path $venv 'Scripts\python.exe') -m pip install -r (Join-Path $InstallDir 'requirements.txt') --quiet
}

$venvPython = Join-Path $InstallDir '.venv\Scripts\pythonw.exe'
if (-not (Test-Path $venvPython)) {
    # pythonw.exe runs with no console window; fall back to python.exe.
    $venvPython = Join-Path $InstallDir '.venv\Scripts\python.exe'
}

$configPath = Join-Path $StateDir 'config.json'
if (-not (Test-Path $configPath)) {
    Write-Host ''
    Write-Host "No config found at $configPath -- creating one now." -ForegroundColor Yellow
    if (-not $Username) { $Username = Read-Host 'Username (student ID, without @kmitl.ac.th)' }
    $securePassword = Read-Host 'Password' -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))

    [ordered]@{
        username           = $Username
        password           = $plain
        heartbeat_interval = 300
        relogin_interval   = 28800
        watchdog_timeout   = 180
        control_port       = $ControlPort
        log_level          = 'INFO'
        no_banner          = $true
    } | ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8

    # The file holds a password: restrict it to SYSTEM and Administrators.
    $acl = Get-Acl $configPath
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $configPath -AclObject $acl
    Write-Host "Wrote $configPath (readable only by SYSTEM and Administrators)."
}

$arguments = @(
    '-m', 'kmitl_authen', 'run',
    '--config',     "`"$configPath`"",
    '--state-dir',  "`"$StateDir`"",
    '--control-port', $ControlPort,
    '--no-banner'
) -join ' '

Write-Host "Registering scheduled task '$TaskName'"
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction -Execute $venvPython -Argument $arguments `
                                  -WorkingDirectory $InstallDir
$triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -AtLogOn)
)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount `
                                        -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -MultipleInstances IgnoreNew `
    -DontStopOnIdleEnd

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
                       -Principal $principal -Settings $settings `
                       -Description 'Keeps this device authenticated on the KMITL network.' | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 5

Write-Host ''
Write-Host 'Installed.' -ForegroundColor Green
Write-Host "  Status:       Invoke-RestMethod http://127.0.0.1:$ControlPort/status"
Write-Host "  Force login:  .\deploy\windows\relogin.ps1"
Write-Host "  Logs:         Get-Content '$StateDir\kmitl-authen.log' -Tail 40 -Wait"
Write-Host "  Stop:         Stop-ScheduledTask -TaskName $TaskName"
Write-Host "  Uninstall:    Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"
