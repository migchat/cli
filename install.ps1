# MigChat CLI Installation Script for Windows
# Usage: irm https://raw.githubusercontent.com/migchat/cli/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
$ProgressPreference = 'SilentlyContinue'  # Faster downloads

$REPO = "migchat/cli"
$BINARY_NAME = "migchat"
$INSTALL_DIR = "$env:LOCALAPPDATA\migchat\bin"

# Simple output function that works in all contexts
function Write-Info {
    param([string]$Message)
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Red
}

# Detect architecture
function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "aarch64" }
        default {
            Write-Error "Unsupported architecture: $arch"
            exit 1
        }
    }
}

# Get latest version from GitHub
function Get-LatestVersion {
    Write-Info "Fetching latest version..."

    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest" -UseBasicParsing
        $version = $release.tag_name

        if ([string]::IsNullOrEmpty($version)) {
            throw "Failed to fetch latest version"
        }

        Write-Success "Latest version: $version"
        return $version
    }
    catch {
        Write-Error "Failed to fetch latest version: $_"
        exit 1
    }
}

# Download and install binary
function Install-Binary {
    param(
        [string]$Version,
        [string]$Arch
    )

    $platform = "windows-$Arch"
    $downloadUrl = "https://github.com/$REPO/releases/download/$Version/$BINARY_NAME-$platform.exe"
    $exePath = "$INSTALL_DIR\$BINARY_NAME.exe"

    Write-Info "Downloading $BINARY_NAME for $platform..."

    try {
        # Create install directory
        if (-not (Test-Path $INSTALL_DIR)) {
            New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
        }

        # Download binary
        Invoke-WebRequest -Uri $downloadUrl -OutFile $exePath -UseBasicParsing

        Write-Success "Successfully installed $BINARY_NAME to $exePath"
    }
    catch {
        Write-Error "Failed to download binary: $_"
        Write-Warning "URL attempted: $downloadUrl"
        exit 1
    }
}

# Add to PATH
function Add-ToPath {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ($currentPath -notlike "*$INSTALL_DIR*") {
        Write-Info ""
        Write-Warning "Adding $INSTALL_DIR to your PATH..."

        try {
            [Environment]::SetEnvironmentVariable(
                "Path",
                "$currentPath;$INSTALL_DIR",
                "User"
            )

            # Update PATH for current session
            $env:Path = "$env:Path;$INSTALL_DIR"

            Write-Success "Added to PATH successfully"
            Write-Info ""
            Write-Warning "Note: You may need to restart your terminal for PATH changes to take effect"
        }
        catch {
            Write-Error "Failed to update PATH: $_"
            Write-Info ""
            Write-Warning "Please manually add $INSTALL_DIR to your PATH:"
            Write-Warning "1. Open System Properties > Environment Variables"
            Write-Warning "2. Edit your user PATH variable"
            Write-Warning "3. Add: $INSTALL_DIR"
        }
    }
}

# Main installation
function Main {
    Write-Info "======================================="
    Write-Info "      MigChat CLI Installer"
    Write-Info "======================================="
    Write-Info ""

    $arch = Get-Architecture
    Write-Info "Detected architecture: $arch"

    $version = Get-LatestVersion
    Install-Binary -Version $version -Arch $arch
    Add-ToPath

    Write-Info ""
    Write-Success "======================================="
    Write-Success "   Installation Complete!"
    Write-Success "======================================="
    Write-Info ""
    Write-Info "Run '$BINARY_NAME' to get started"
    Write-Info ""
}

# Run installation
try {
    Main
}
catch {
    Write-Error "Installation failed: $_"
    Write-Error "Error details: $($_.Exception.Message)"
    Write-Error "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
