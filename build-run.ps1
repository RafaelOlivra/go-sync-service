param(
    [string]$EnvFile = ".env"
)

Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $ScriptDir "sync-service.pid"

if (!(Test-Path $EnvFile)) {
    Write-Host "Error: env file '$EnvFile' not found"
    exit 1
}

$EnvFile = (Resolve-Path $EnvFile).Path

Write-Host "Using env file: $EnvFile"

# Load env variables
Get-Content $EnvFile | ForEach-Object {

    if ($_ -match "^\s*#") {
        return
    }

    if ($_ -match "^\s*$") {
        return
    }

    $parts = $_ -split "=", 2

    if ($parts.Length -eq 2) {
        $name = $parts[0].Trim()
        $value = $parts[1].Trim()

        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

Push-Location $ScriptDir
try {
    $AppMode = [System.Environment]::GetEnvironmentVariable("APP_MODE", "Process")

    if ([string]::IsNullOrWhiteSpace($AppMode)) {
        Write-Host "Error: APP_MODE is not set in $EnvFile"
        exit 1
    }

    Write-Host "Running in $AppMode mode..."

    Write-Host "Building sync-service..."
    go build -o sync-service.exe main.go

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Build failed"
        exit 1
    }

    Write-Host "Running sync-service in the background..."
    $process = Start-Process -FilePath (Join-Path $ScriptDir "sync-service.exe") -ArgumentList "--env", $EnvFile -WorkingDirectory $ScriptDir -WindowStyle Hidden -PassThru
    Set-Content -Path $PidFile -Value $process.Id

    $LogFile = [System.Environment]::GetEnvironmentVariable("LOG_FILE", "Process")
    if ([string]::IsNullOrWhiteSpace($LogFile)) {
        $LogFile = "log.txt"
    }

    Write-Host "Started sync-service with PID $($process.Id)"
    Write-Host "Logs are written to $LogFile"
    Write-Host "Stop with .\stop.ps1"
}
finally {
    Pop-Location
}