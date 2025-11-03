#!/bin/bash
set -e

# MigChat CLI Installation Script
# Usage: curl -fsSL https://raw.githubusercontent.com/migchat/cli/main/install.sh | bash

REPO="migchat/cli"
BINARY_NAME="migchat"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Detect OS and architecture
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    case "$os" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="macos"
            ;;
        *)
            echo -e "${RED}Unsupported operating system: $os${NC}"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $arch${NC}"
            exit 1
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
}

# Get the latest release version
get_latest_version() {
    echo -e "${CYAN}Fetching latest version...${NC}"

    # Try to get latest release from GitHub API
    LATEST_VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$LATEST_VERSION" ]; then
        echo -e "${RED}Failed to fetch latest version${NC}"
        exit 1
    fi

    echo -e "${GREEN}Latest version: ${LATEST_VERSION}${NC}"
}

# Download and install binary
install_binary() {
    local download_url="https://github.com/${REPO}/releases/download/${LATEST_VERSION}/${BINARY_NAME}-${PLATFORM}"

    echo -e "${CYAN}Downloading ${BINARY_NAME} for ${PLATFORM}...${NC}"

    # Create install directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"

    # Download binary
    if curl -fsSL "$download_url" -o "${INSTALL_DIR}/${BINARY_NAME}"; then
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
        echo -e "${GREEN}✓ Successfully installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}${NC}"
    else
        echo -e "${RED}✗ Failed to download binary${NC}"
        echo -e "${YELLOW}URL attempted: ${download_url}${NC}"
        exit 1
    fi
}

# Check if binary is in PATH
check_path() {
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo ""
        echo -e "${YELLOW}⚠ Warning: ${INSTALL_DIR} is not in your PATH${NC}"
        echo -e "${CYAN}Add the following line to your shell configuration file:${NC}"
        echo ""

        if [ -f "$HOME/.zshrc" ]; then
            echo -e "  ${GREEN}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc${NC}"
            echo -e "  ${GREEN}source ~/.zshrc${NC}"
        elif [ -f "$HOME/.bashrc" ]; then
            echo -e "  ${GREEN}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc${NC}"
            echo -e "  ${GREEN}source ~/.bashrc${NC}"
        else
            echo -e "  ${GREEN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
        fi
        echo ""
    fi
}

# Main installation process
main() {
    echo -e "${CYAN}╔═══════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     MigChat CLI Installer        ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════╝${NC}"
    echo ""

    detect_platform
    echo -e "${CYAN}Detected platform: ${PLATFORM}${NC}"

    get_latest_version
    install_binary
    check_path

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Installation Complete! 🎉       ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Run '${BINARY_NAME}' to get started${NC}"
    echo ""
}

main
