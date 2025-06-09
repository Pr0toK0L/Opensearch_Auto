# PowerShell script to install and configure Winlogbeat on Windows
# Tested on Windows Server 2019/2022

# Variables
$WinlogbeatVersion = "8.15.2"
$WinlogbeatUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-oss-$WinlogbeatVersion-windows-x86_64.zip"
$InstallDir = "C:\Program Files\Winlogbeat"
$TempDir = "$env:TEMP\winlogbeat.zip"

# Function to check if running as admin
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check for admin privileges
if (-not (Test-Admin)) {
    Write-Error "This script must be run as an administrator"
    exit 1
}

# Download Winlogbeat
Write-Host "Downloading Winlogbeat..."
Invoke-WebRequest -Uri $WinlogbeatUrl -OutFile $TempDir

# Extract and install
Write-Host "Installing Winlogbeat..."
Expand-Archive -Path $TempDir -DestinationPath "C:\Program Files" -Force
Rename-Item -Path "C:\Program Files\winlogbeat-oss-$WinlogbeatVersion-windows-x86_64" -NewName "Winlogbeat" -Force

# Configure Winlogbeat
Write-Host "Configuring Winlogbeat..."
$ConfigFile = "$InstallDir\winlogbeat.yml"
$ConfigContent = @"
winlogbeat.event_logs:
  - name: Application
  - name: Security
  - name: System
output.logstash:
  hosts: ["<logstash-host>:5044"]
logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
"@
$ConfigContent | Out-File -FilePath $ConfigFile -Encoding utf8

# Install Winlogbeat as a service
Write-Host "Installing Winlogbeat service..."
Set-Location -Path $InstallDir
.\install-service-winlogbeat.ps1

# Start service
Write-Host "Starting Winlogbeat service..."
Start-Service -Name "winlogbeat"

# Verify service
Write-Host "Verifying installation..."
Start-Sleep -Seconds 10
if ((Get-Service -Name "winlogbeat").Status -eq "Running") {
    Write-Host "Winlogbeat is running"
}
else {
    Write-Error "Winlogbeat failed to start"
    exit 1
}

# Clean up
Remove-Item -Path $TempDir

Write-Host "Winlogbeat installation complete! Configured to send logs to Logstash at <logstash-host>:5044"