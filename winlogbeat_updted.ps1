#Requires -RunAsAdministrator

param (
    [switch]$i, # Install
    [string]$v, # Version in format x.x.x
    [switch]$l, # Latest version
    [switch]$a, # Automated config
    [switch]$s  # Start winlogbeat
)

# Variables
$WinlogbeatVersion = ""
$Install = $i
$InstallLatest = $l
$AutomatedConfig = $a
$Start = $s
$InstallDir = "C:\Program Files\Winlogbeat"
$ConfigDir = "C:\ProgramData\Winlogbeat"

function Show-Help {
    Write-Host "Usage: .\Install-Winlogbeat.ps1 [-i] [-v version] [-l] [-a] [-s]"
    Write-Host "  -i : Install Winlogbeat"
    Write-Host "  -v : Version in format x.x.x, x in 0-99"
    Write-Host "  -l : Install latest version"
    Write-Host "  -a : Automated configuration (not recommended)"
    Write-Host "  -s : Start Winlogbeat service"
    Write-Host "Example:"
    Write-Host ".\Install-Winlogbeat.ps1 -i -l : Install latest version with no config"
    exit 1
}

function Test-Version {
    param ([string]$version)
    if (-not ($version -match '^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$')) {
        Write-Host "Error: Version must be in format x.x.x where x is a number from 0-99"
        Show-Help
    }
    $versionParts = $version -split '\.'
    foreach ($part in $versionParts) {
        if ([int]$part -lt 0 -or [int]$part -gt 99) {
            Write-Host "Error: Each version number must be between 0 and 99"
            Show-Help
        }
    }
}

# Validate options
if ($v -and $InstallLatest) {
    Write-Host "Error: Cannot use -v and -l options together"
    Show-Help
}

if ($v) {
    Test-Version $v
    $WinlogbeatVersion = $v
}

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator"
    exit 1
}

function Install-SpecificVersion {
    param ([string]$version)
    Write-Host "Installing Winlogbeat version $version..."

    # Create install directory if it doesn't exist
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download Winlogbeat
    $downloadUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$version-windows-x86_64.zip"
    $tempFile = "$env:TEMP\winlogbeat-$version-windows-x86_64.zip"

    Write-Host "Downloading Winlogbeat $version..."
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -ErrorAction Stop
    } catch {
        Write-Host "Error: Failed to download Winlogbeat $version"
        Remove-Item $tempFile -ErrorAction SilentlyContinue
        exit 1
    }

    # Extract Winlogbeat
    Write-Host "Extracting Winlogbeat..."
    try {
        Expand-Archive -Path $tempFile -DestinationPath $InstallDir -Force -ErrorAction Stop
        # Move contents from extracted folder to InstallDir
        $extractedFolder = Join-Path $InstallDir "winlogbeat-$version-windows-x86_64"
        Get-ChildItem -Path $extractedFolder | Move-Item -Destination $InstallDir -Force
        Remove-Item $extractedFolder -Recurse -Force
    } catch {
        Write-Host "Error: Failed to extract Winlogbeat"
        Remove-Item $tempFile -ErrorAction SilentlyContinue
        exit 1
    }

    # Clean up
    Remove-Item $tempFile -ErrorAction SilentlyContinue

    # Set permissions
    icacls $InstallDir /grant "Everyone:(OI)(CI)F" /T | Out-Null
    if (Test-Path $ConfigDir) {
        icacls $ConfigDir /grant "Everyone:(OI)(CI)F" /T | Out-Null
    }

    # Run automated config if requested
    if ($AutomatedConfig) {
        Set-Configuration
    }

    Write-Host "Winlogbeat $version has been installed successfully in $InstallDir"
}

function Install-LatestVersion {
    Write-Host "Installing latest version..."
    try {
        $response = Invoke-WebRequest -Uri "https://www.elastic.co/downloads/past-releases#winlogbeat" -UseBasicParsing
        # Extract version numbers from the page content
        $versions = $response.Content | Select-String -Pattern 'Winlogbeat (\d+\.\d+\.\d+)' -AllMatches | 
                    ForEach-Object { $_.Matches } | 
                    ForEach-Object { $_.Groups[1].Value } | 
                    Sort-Object -Descending -Property { [version]$_ } | 
                    Select-Object -First 1
        if (-not $versions) {
            Write-Host "Error: Failed to find any Winlogbeat versions on the page"
            exit 1
        }
        $latestVersion = $versions
        Write-Host "Latest version found: $latestVersion"
        Install-SpecificVersion $latestVersion
    } catch {
        Write-Host "Error: Failed to determine latest Winlogbeat version from https://www.elastic.co/downloads/Past-releases#winlogbeat"
        exit 1
    }
}

function Start-Winlogbeat {
    Write-Host "Starting Winlogbeat..."
    try {
        # Install Winlogbeat as a service if not already installed
        $service = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
        if (-not $service) {
            & "$InstallDir\winlogbeat.exe" install-service
        }
        # Start the service
        Start-Service -Name "winlogbeat" -ErrorAction Stop
        Set-Service -Name "winlogbeat" -StartupType Automatic
        Get-Service -Name "winlogbeat" | Select-Object Name, Status, StartType
    } catch {
        Write-Host "Error: Failed to start Winlogbeat service"
        exit 1
    }
}

function Set-Configuration {
    Write-Host "Configuring Winlogbeat automatically..."
    # Create config directory if it doesn't exist
    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    }

    # Basic Winlogbeat configuration
    $configFile = Join-Path $ConfigDir "winlogbeat.yml"
    $configContent = @"
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h

  - name: System

  - name: Security

  - name: Microsoft-Windows-Sysmon/Operational

  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106

  - name: Windows PowerShell
    event_id: 400, 403, 600, 800

  - name: ForwardedEvents
    tags: [forwarded]

setup.template.settings:
  index.number_of_shards: 1
  #index.codec: best_compression
  #_source.enabled: false

output.logstash:
  # The Logstash hosts
  hosts: ["192.168.192.146:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~

"@

    Set-Content -Path $configFile -Value $configContent -Force
    Write-Host "Basic configuration written to $configFile"

    # Set permissions for config file
    icacls $configFile /grant "Everyone:(OI)(CI)F" | Out-Null

    # Validate configuration
    try {
        & "$InstallDir\winlogbeat.exe" test config -c $configFile
        Write-Host "Winlogbeat configuration validated successfully"
    } catch {
        Write-Host "Error: Failed to validate Winlogbeat configuration"
        exit 1
    }
}

# Main logic
if ($Install) {
    if ($WinlogbeatVersion) {
        Install-SpecificVersion $WinlogbeatVersion
    } elseif ($InstallLatest) {
        Install-LatestVersion
    } else {
        Write-Host "Error: Please specify either -v or -l option"
        Show-Help
    }
    if ($AutomatedConfig) {
        Set-Configuration
    }
    if ($Start) {
        Start-Winlogbeat
    }
} else {
    Show-Help
}