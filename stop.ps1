param()

Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $ScriptDir "sync-service.pid"

if (!(Test-Path $PidFile)) {
    Write-Host "Error: PID file '$PidFile' not found"
    exit 1
}

$Pid = [int](Get-Content $PidFile)

try {
    $Process = Get-Process -Id $Pid -ErrorAction Stop
    Stop-Process -Id $Process.Id -Force
    Write-Host "Stopped sync-service process $Pid"
}
catch {
    Write-Host "sync-service process $Pid is not running"
}
finally {
    Remove-Item $PidFile -ErrorAction SilentlyContinue
}