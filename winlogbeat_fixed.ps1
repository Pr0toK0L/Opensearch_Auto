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

    # Stop existing service if running
    $service = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Host "Stopping existing Winlogbeat service..."
        Stop-Service -Name "winlogbeat" -Force
    }

    # Create install directory if it doesn't exist
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Download Winlogbeat
    $downloadUrl = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$version-windows-x86_64.zip"
    $tempFile = "$env:TEMP\winlogbeat-$version-windows-x86_64.zip"

    Write-Host "Downloading Winlogbeat $version from $downloadUrl..."
    try {
        # Test if URL exists first
        $response = Invoke-WebRequest -Uri $downloadUrl -Method Head -ErrorAction Stop
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -ErrorAction Stop
        Write-Host "Download completed successfully"
    } catch {
        Write-Host "Error: Failed to download Winlogbeat $version. Please check if version exists."
        Write-Host "Available versions can be found at: https://www.elastic.co/downloads/past-releases#winlogbeat"
        Remove-Item $tempFile -ErrorAction SilentlyContinue
        exit 1
    }

    # Extract Winlogbeat
    Write-Host "Extracting Winlogbeat..."
    try {
        # Remove existing files first
        Get-ChildItem -Path $InstallDir -Exclude "data", "logs" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        
        Expand-Archive -Path $tempFile -DestinationPath $env:TEMP -Force -ErrorAction Stop
        $extractedFolder = Join-Path $env:TEMP "winlogbeat-$version-windows-x86_64"
        
        if (Test-Path $extractedFolder) {
            Get-ChildItem -Path $extractedFolder | Copy-Item -Destination $InstallDir -Recurse -Force
            Remove-Item $extractedFolder -Recurse -Force
        } else {
            throw "Extracted folder not found"
        }
    } catch {
        Write-Host "Error: Failed to extract Winlogbeat - $_"
        Remove-Item $tempFile -ErrorAction SilentlyContinue
        exit 1
    }

    # Clean up
    Remove-Item $tempFile -ErrorAction SilentlyContinue

    # Set permissions
    try {
        icacls $InstallDir /grant "Everyone:(OI)(CI)F" /T | Out-Null
        if (Test-Path $ConfigDir) {
            icacls $ConfigDir /grant "Everyone:(OI)(CI)F" /T | Out-Null
        }
    } catch {
        Write-Host "Warning: Failed to set permissions"
    }

    Write-Host "Winlogbeat $version has been installed successfully in $InstallDir"
}

function Install-LatestVersion {
    Write-Host "Fetching latest version information..."
    try {
        $response = Invoke-WebRequest -Uri "https://www.elastic.co/downloads/past-releases#winlogbeat" -UseBasicParsing -ErrorAction Stop
        
        # Updated regex pattern based on the page content structure
        $versionMatches = $response.Content | Select-String -Pattern 'Winlogbeat (\d+\.\d+\.\d+)' -AllMatches
        
        if ($versionMatches.Matches.Count -eq 0) {
            # Fallback: try OSS version pattern
            $versionMatches = $response.Content | Select-String -Pattern 'Winlogbeat OSS (\d+\.\d+\.\d+)' -AllMatches
        }
        
        if ($versionMatches.Matches.Count -eq 0) {
            Write-Host "Error: Could not find Winlogbeat versions on the page"
            Write-Host "Please visit https://www.elastic.co/downloads/past-releases#winlogbeat to check available versions"
            exit 1
        }
        
        # Extract and sort versions
        $versions = $versionMatches.Matches | ForEach-Object { $_.Groups[1].Value } | 
                    Sort-Object -Unique | 
                    Sort-Object { [version]$_ } -Descending
        
        $latestVersion = $versions | Select-Object -First 1
        Write-Host "Latest version found: $latestVersion"
        Install-SpecificVersion $latestVersion
    } catch {
        Write-Host "Error: Failed to fetch version information - $_"
        Write-Host "Please check your internet connection or specify a version manually with -v"
        exit 1
    }
}

function Start-Winlogbeat {
    Write-Host "Starting Winlogbeat service..."
    try {
        # Check if winlogbeat.exe exists
        $winlogbeatExe = Join-Path $InstallDir "winlogbeat.exe"
        if (-not (Test-Path $winlogbeatExe)) {
            Write-Host "Error: winlogbeat.exe not found in $InstallDir"
            exit 1
        }

        # Install Winlogbeat as a service if not already installed
        $service = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Host "Installing Winlogbeat as Windows service..."
            $configFile = Join-Path $ConfigDir "winlogbeat.yml"
            if (Test-Path $configFile) {
                & "$winlogbeatExe" install-service winlogbeat --path.config="$ConfigDir"
            } else {
                & "$winlogbeatExe" install-service winlogbeat
            }
        }
        
        # Start the service
        Start-Service -Name "winlogbeat" -ErrorAction Stop
        Set-Service -Name "winlogbeat" -StartupType Automatic
        
        $serviceStatus = Get-Service -Name "winlogbeat" | Select-Object Name, Status, StartType
        Write-Host "Winlogbeat service status:"
        $serviceStatus | Format-Table -AutoSize
        
    } catch {
        Write-Host "Error: Failed to start Winlogbeat service - $_"
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

path.config: ${path.home}
path.data: C:\ProgramData\Winlogbeat\data
path.logs: C:\ProgramData\Winlogbeat\logs

"@

    Set-Content -Path $configFile -Value $configContent -Force -Encoding UTF8
    Write-Host "Basic configuration written to $configFile"

    # Set permissions for config file
    try {
        icacls $configFile /grant "Everyone:(OI)(CI)F" | Out-Null
    } catch {
        Write-Host "Warning: Failed to set config file permissions"
    }

    # Validate configuration
    try {
        $winlogbeatExe = Join-Path $InstallDir "winlogbeat.exe"
        Write-Host "Validating configuration..."
        & "$winlogbeatExe" test config -c $configFile
        Write-Host "Winlogbeat configuration validated successfully"
    } catch {
        Write-Host "Warning: Configuration validation failed, but proceeding anyway"
    }
}

# Main logic
if ($Install) {
    if ($WinlogbeatVersion) {
        Install-SpecificVersion $WinlogbeatVersion
    } elseif ($InstallLatest) {
        Install-LatestVersion
    } else {
        Write-Host "Error: Please specify either -v (version) or -l (latest) option"
        Show-Help
    }
    
    if ($AutomatedConfig) {
        Set-Configuration
    }
    
    if ($Start) {
        Start-Winlogbeat
    }
    
    Write-Host "`nInstallation completed successfully!"
    Write-Host "Winlogbeat installed in: $InstallDir"
    if ($AutomatedConfig) {
        Write-Host "Configuration file: $ConfigDir\winlogbeat.yml"
    }
} else {
    Show-Help
}