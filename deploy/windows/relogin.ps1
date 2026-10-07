<#
.SYNOPSIS
    Forces a running kmitl-authen daemon to log in to the portal again.

.DESCRIPTION
    Windows has no SIGHUP, so this uses the two portable triggers: the control
    HTTP endpoint first, then the trigger file, which a running daemon picks up
    within a second.

.EXAMPLE
    .\relogin.ps1
.EXAMPLE
    .\relogin.ps1 -ControlPort 8777 -Token 'my-token'
#>
[CmdletBinding()]
param(
    [int]   $ControlPort = 8777,
    [string]$Token       = '',
    [string]$StateDir    = 'C:\ProgramData\kmitl-authen',
    [string]$Reason      = 'powershell'
)

$headers = @{}
if ($Token) { $headers['X-Auth-Token'] = $Token }

try {
    Invoke-RestMethod -Method Post -TimeoutSec 5 -Headers $headers `
        -Uri "http://127.0.0.1:$ControlPort/relogin" | Out-Null
    Write-Host "Re-login requested over the control port." -ForegroundColor Green
    exit 0
} catch {
    Write-Host "Control port unreachable ($($_.Exception.Message)); using the trigger file."
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
$tmp = Join-Path $StateDir 'relogin.tmp'
$final = Join-Path $StateDir 'relogin'
Set-Content -Path $tmp -Value $Reason -Encoding UTF8 -NoNewline
Move-Item -Force $tmp $final          # rename, so the daemon never reads a partial file
Write-Host "Wrote $final; a running daemon picks it up within a second." -ForegroundColor Green
