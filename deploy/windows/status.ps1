<#
.SYNOPSIS
    Prints a running daemon's status, and the tail of its log.
#>
[CmdletBinding()]
param(
    [int]   $ControlPort = 8777,
    [string]$Token       = '',
    [string]$StateDir    = 'C:\ProgramData\kmitl-authen',
    [int]   $Tail        = 20
)

$headers = @{}
if ($Token) { $headers['X-Auth-Token'] = $Token }

try {
    Invoke-RestMethod -TimeoutSec 5 -Headers $headers `
        -Uri "http://127.0.0.1:$ControlPort/status" | Format-List
} catch {
    Write-Warning "Control port $ControlPort unreachable: $($_.Exception.Message)"
}

$log = Join-Path $StateDir 'kmitl-authen.log'
if (Test-Path $log) {
    Write-Host "`n--- last $Tail log lines ---" -ForegroundColor Cyan
    Get-Content $log -Tail $Tail
}
