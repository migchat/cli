# MigChat CLI Installation Script for Windows
# Usage: irm https://raw.githubusercontent.com/migchat/cli/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
$ProgressPreference = 'SilentlyContinue'  # Faster downloads

$REPO = "migchat/cli"
$BINARY_NAME = "migchat"
$INSTALL_DIR = "$env:LOCALAPPDATA\migchat\bin"

# Colors - Safe for piped execution
function Write-ColorOutput($ForegroundColor) {
    try {
        if ($host.UI.SupportsVirtualTerminal -or $host.Name -eq "ConsoleHost") {
            $fc = $host.UI.RawUI.ForegroundColor
            $host.UI.RawUI.ForegroundColor = $ForegroundColor
            if ($args) {
                Write-Output $args
            }
            $host.UI.RawUI.ForegroundColor = $fc
        } else {
            # Fallback for piped execution
            if ($args) {
                Write-Output $args
            }
        }
    } catch {
        # Fallback if color output fails
        if ($args) {
            Write-Output $args
        }
    }
}

# Detect architecture
function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "aarch64" }
        default {
            Write-ColorOutput Red "Unsupported architecture: $arch"
            exit 1
        }
    }
}

# Get latest version from GitHub
function Get-LatestVersion {
    Write-ColorOutput Cyan "Fetching latest version..."

    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest"
        $version = $release.tag_name

        if ([string]::IsNullOrEmpty($version)) {
            throw "Failed to fetch latest version"
        }

        Write-ColorOutput Green "Latest version: $version"
        return $version
    }
    catch {
        Write-ColorOutput Red "Failed to fetch latest version: $_"
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

    Write-ColorOutput Cyan "Downloading $BINARY_NAME for $platform..."

    try {
        # Create install directory
        if (-not (Test-Path $INSTALL_DIR)) {
            New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
        }

        # Download binary
        Invoke-WebRequest -Uri $downloadUrl -OutFile $exePath -UseBasicParsing

        Write-ColorOutput Green "✓ Successfully installed $BINARY_NAME to $exePath"
    }
    catch {
        Write-ColorOutput Red "✗ Failed to download binary: $_"
        Write-ColorOutput Yellow "URL attempted: $downloadUrl"
        exit 1
    }
}

# Add to PATH
function Add-ToPath {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ($currentPath -notlike "*$INSTALL_DIR*") {
        Write-ColorOutput Yellow ""
        Write-ColorOutput Yellow "⚠ Adding $INSTALL_DIR to your PATH..."

        try {
            [Environment]::SetEnvironmentVariable(
                "Path",
                "$currentPath;$INSTALL_DIR",
                "User"
            )

            # Update PATH for current session
            $env:Path = "$env:Path;$INSTALL_DIR"

            Write-ColorOutput Green "✓ Added to PATH successfully"
            Write-ColorOutput Yellow ""
            Write-ColorOutput Yellow "Note: You may need to restart your terminal for PATH changes to take effect"
        }
        catch {
            Write-ColorOutput Red "Failed to update PATH: $_"
            Write-ColorOutput Yellow ""
            Write-ColorOutput Yellow "Please manually add $INSTALL_DIR to your PATH:"
            Write-ColorOutput Yellow "1. Open System Properties > Environment Variables"
            Write-ColorOutput Yellow "2. Edit your user PATH variable"
            Write-ColorOutput Yellow "3. Add: $INSTALL_DIR"
        }
    }
}

# Main installation
function Main {
    Write-ColorOutput Cyan "╔═══════════════════════════════════╗"
    Write-ColorOutput Cyan "║     MigChat CLI Installer        ║"
    Write-ColorOutput Cyan "╚═══════════════════════════════════╝"
    Write-Output ""

    $arch = Get-Architecture
    Write-ColorOutput Cyan "Detected architecture: $arch"

    $version = Get-LatestVersion
    Install-Binary -Version $version -Arch $arch
    Add-ToPath

    Write-Output ""
    Write-ColorOutput Green "╔═══════════════════════════════════╗"
    Write-ColorOutput Green "║   Installation Complete! 🎉       ║"
    Write-ColorOutput Green "╚═══════════════════════════════════╝"
    Write-Output ""
    Write-ColorOutput Cyan "Run '$BINARY_NAME' to get started"
    Write-Output ""
}

# Run installation
try {
    Main
}
catch {
    Write-ColorOutput Red "Installation failed: $_"
    exit 1
}
