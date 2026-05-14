param(
    [string]$EnvFile = ".env"
)

if (!(Test-Path $EnvFile)) {
    Write-Host "Error: env file '$EnvFile' not found"
    exit 1
}

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

Write-Host "Running sync-service..."
./sync-service.exe