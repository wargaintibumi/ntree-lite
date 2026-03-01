#!/bin/bash
#
# NTREE Lite Setup Script (Open Source Edition)
# Compatible with: Raspberry Pi 5 (Raspberry Pi OS) and Kali Linux ARM64
# This script installs NTREE with all components in one go
#
# Usage: bash setup.sh [-y|--yes]
#

set -e

VERSION="2.0.0"

# Parse command line arguments
SKIP_CONFIRM=false
for arg in "$@"; do
    case $arg in
        -y|--yes)
            SKIP_CONFIRM=true
            shift
            ;;
    esac
done

# Colors for output
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
MAGENTA=$'\033[0;35m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

# Print banner
print_banner() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║      NTREE - Neura Tactical Red-Team Exploitation Engine     ║"
    echo "║         Setup Script for Raspberry Pi 5 & Kali Linux          ║"
    echo "║                   Version: $VERSION                           ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
}

# Check if running on Raspberry Pi or Kali Linux
check_platform() {
    log_step "Checking platform..."

    # Detect OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "kali" ]]; then
            log_success "Detected: Kali Linux $VERSION (${VERSION_CODENAME})"
            log_info "Kali Linux is fully supported. Many tools are pre-installed."
            return
        fi
    fi

    # Check for Raspberry Pi
    if [[ ! -f /proc/device-tree/model ]]; then
        log_warning "Not running on Raspberry Pi or Kali Linux. Continuing anyway..."
        log_info "Note: This script is designed for Raspberry Pi 5 with Raspberry Pi OS or Kali Linux."
        return
    fi

    MODEL=$(cat /proc/device-tree/model | tr -d '\0')
    if [[ "$MODEL" == *"Raspberry Pi 5"* ]]; then
        log_success "Detected: $MODEL"
    else
        log_warning "Expected Raspberry Pi 5, detected: $MODEL"
        if [[ "$SKIP_CONFIRM" == true ]]; then
            log_info "Non-interactive mode: continuing anyway"
            return
        fi
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Get script directory — also used as NTREE_HOME (runtime directory)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
NTREE_HOME="${NTREE_HOME:-$SCRIPT_DIR}"
log_info "Installation directory: $SCRIPT_DIR"
log_info "Runtime directory (NTREE_HOME): $NTREE_HOME"

# Confirm installation
confirm_installation() {
    if [[ "$SKIP_CONFIRM" == true ]]; then
        log_info "Non-interactive mode: skipping confirmation"
        return
    fi

    echo ""
    log_warning "This script will install:"
    echo "  • NTREE Lite MCP Mode (Claude Code integration)"
    echo "  • NTREE Autonomous SDK Mode"
    echo "  • Security tools (nmap, nikto, gobuster, metasploit, etc.)"
    echo "  • Python dependencies"
    echo "  • Wordlists (~500MB)"
    echo ""
    echo "Estimated time: 30-60 minutes"
    echo "Required disk space: ~10GB"
    echo ""
    read -p "Continue with installation? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installation cancelled"
        exit 0
    fi
}

# Update system
update_system() {
    log_step "Updating system packages..."
    sudo apt update
    log_success "System updated"
}

# Increase swap size for memory-intensive operations (Raspberry Pi OS only)
increase_swap_size() {
    log_step "Checking swap configuration..."

    # Check if dphys-swapfile exists (Raspberry Pi OS specific)
    if ! command -v dphys-swapfile &> /dev/null; then
        log_info "dphys-swapfile not found (not on Raspberry Pi OS), skipping swap resize"
        log_info "Current swap: $(free -h | grep Swap | awk '{print $2}')"
        return
    fi

    # Check if config file exists
    if [[ ! -f /etc/dphys-swapfile ]]; then
        log_warning "/etc/dphys-swapfile not found, skipping swap resize"
        return
    fi

    # Check current swap size
    CURRENT_SWAP=$(grep "^CONF_SWAPSIZE=" /etc/dphys-swapfile 2>/dev/null | cut -d= -f2)

    if [[ "$CURRENT_SWAP" == "2048" ]]; then
        log_info "Swap size already set to 2GB"
        return
    fi

    log_info "Increasing swap size to 2GB for better performance..."

    # Turn off swap
    sudo dphys-swapfile swapoff || true

    # Update swap size in config
    sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=2048/' /etc/dphys-swapfile

    # Setup new swap
    sudo dphys-swapfile setup

    # Turn swap back on
    sudo dphys-swapfile swapon

    log_success "Swap size increased to 2GB"
    log_info "Note: Reboot recommended after installation for optimal performance"
}

# Optimize Raspberry Pi 5 for pentesting (swap, kernel params)
optimize_pi5() {
    log_step "Applying Raspberry Pi 5 optimizations..."

    # Check if actually on Pi 5
    if [[ ! -f /proc/device-tree/model ]]; then
        log_info "Not on Raspberry Pi, skipping Pi 5 optimizations"
        return
    fi

    local model=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
    if [[ "$model" != *"Raspberry Pi 5"* ]]; then
        log_info "Not on Pi 5, skipping Pi 5 specific optimizations"
        return
    fi

    log_info "Detected: $model"

    # Setup swap file (4GB for Pi 5)
    local swap_file="/swapfile"
    local swap_size="4G"

    if swapon --show 2>/dev/null | grep -q "$swap_file"; then
        log_info "Swap file already active: $swap_file"
    else
        # Check available disk space
        local available_gb=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
        if [[ $available_gb -lt 6 ]]; then
            log_warning "Low disk space (${available_gb}GB). Using 2GB swap instead."
            swap_size="2G"
        fi

        log_info "Creating ${swap_size} swap file..."

        # Remove old swap if exists
        if [[ -f "$swap_file" ]]; then
            sudo swapoff "$swap_file" 2>/dev/null || true
            sudo rm -f "$swap_file"
        fi

        # Create swap file
        sudo fallocate -l "$swap_size" "$swap_file" 2>/dev/null || \
            sudo dd if=/dev/zero of="$swap_file" bs=1M count=$((${swap_size%G} * 1024)) status=progress
        sudo chmod 600 "$swap_file"
        sudo mkswap "$swap_file"
        sudo swapon "$swap_file"

        # Make permanent
        if ! grep -q "$swap_file" /etc/fstab; then
            echo "$swap_file none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
            log_success "Swap added to /etc/fstab"
        fi

        log_success "Swap configured: $swap_size"
    fi

    # Configure kernel parameters
    local sysctl_conf="/etc/sysctl.d/99-ntree-optimizations.conf"
    log_info "Configuring kernel parameters..."

    sudo tee "$sysctl_conf" > /dev/null << EOF
# NTREE Raspberry Pi 5 Optimizations
# Generated by setup.sh on $(date)

# Low swappiness - prefer keeping processes in RAM
vm.swappiness=10

# Reduce tendency to swap out processes
vm.vfs_cache_pressure=50

# Increase max file handles for scanning
fs.file-max=100000

# Network optimizations for scanning
net.core.somaxconn=1024
net.core.netdev_max_backlog=5000

# Reduce OOM kill aggressiveness
vm.oom_kill_allocating_task=0
vm.overcommit_memory=0
vm.overcommit_ratio=80
EOF

    sudo sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
    log_success "Kernel parameters configured"

    log_success "Pi 5 optimizations applied"
    log_info "Note: start_pentest.sh auto-detects Pi 5 and applies runtime limits"
}

# Install base dependencies
install_base_deps() {
    log_step "Installing base dependencies..."

    sudo apt install -y \
        build-essential \
        gcc \
        git \
        curl \
        wget \
        python3-pip \
        python3-venv \
        python3-dev \
        libssl-dev \
        libffi-dev \
        python3-dev \
        libldap2-dev \
        libsasl2-dev \
        cargo \
        jq \
        unzip \
        pipx \
        postgresql

    # Ensure pipx path is configured
    pipx ensurepath || true

    log_success "Base dependencies installed"
}

# Install Claude Code
install_claude_code() {
    log_step "Installing Claude Code..."

    if command -v claude &> /dev/null; then
        log_warning "Claude Code already installed"
        claude --version 2>/dev/null || log_warning "Claude Code found but version check failed"
        return
    fi

    # Download and install Claude Code
    log_info "Downloading Claude Code installer..."
    if curl -fsSL https://claude.ai/install-cli.sh | bash; then
        log_info "Claude Code installer completed"
    else
        log_error "Claude Code installer failed (curl or install script error)"
        log_warning "You may need to install Claude Code manually: https://claude.ai/download"
        return
    fi

    # Update PATH for current session
    export PATH="$HOME/.local/bin:$PATH"

    # Verify installation
    if command -v claude &> /dev/null; then
        log_success "Claude Code installed successfully"
        claude --version 2>/dev/null || log_warning "Claude Code installed but version check failed"
    else
        log_warning "Claude Code installation may have failed or requires new shell"
        log_info "Try: exec bash"
        log_info "Or install manually: https://claude.ai/download"
    fi
}

# Install security tools
install_security_tools() {
    log_step "Installing security tools (this may take 15-30 minutes)..."

    # Network scanning tools
    log_info "Installing network scanning tools..."
    sudo apt install -y nmap

    # DNS tools
    log_info "Installing DNS enumeration tools..."
    sudo apt install -y dnsenum dnsutils

    # SMB/Windows tools
    log_info "Installing SMB/Windows tools..."
    sudo apt install -y smbclient cifs-utils ldap-utils

    # Web tools
    log_info "Installing web security tools..."
    sudo apt install -y whatweb wapiti sqlmap

    # Credential testing tools
    log_info "Installing credential testing tools..."
    sudo apt install -y hydra

    # autoremove unneccessary
    sudo apt autoremove -y

    log_success "Core security tools installed"
}

# Note: enum4linux removed - NTREE now uses smbclient, rpcclient, and nmap for SMB enumeration

# Install CrackMapExec using pipx
install_crackmapexec() {
    log_step "Installing CrackMapExec..."

    if command -v crackmapexec &> /dev/null; then
        log_warning "CrackMapExec already installed"
        return
    fi

    # Ensure pipx path is in PATH
    export PATH="$HOME/.local/bin:$PATH"

    # Install crackmapexec
    sudo apt install crackmapexec -y

    # Add to PATH in bashrc if not already there
    if ! grep -q '.local/bin' ~/.bashrc; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    fi

    # Verify installation
    if command -v crackmapexec &> /dev/null; then
        log_success "CrackMapExec installed successfully"
        crackmapexec -h | grep Version || log_warning "CrackMapExec installed but version check failed"
    else
        log_warning "CrackMapExec may not be properly installed"
    fi
}

# Install theHarvester using uv
install_theharvester() {
    log_step "Installing theHarvester..."

    # Install uv if not already installed
    if ! command -v uv &> /dev/null; then
        log_info "Installing uv package manager..."
        curl -LsSf https://astral.sh/uv/install.sh | sh

        # Add uv to PATH for current session
        export PATH="$HOME/.cargo/bin:$PATH"

        # Add to bashrc if not already there
        if ! grep -q '.cargo/bin' ~/.bashrc; then
            echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
        fi
    fi

    # Clone or update theHarvester
    if [[ -d ~/theHarvester ]]; then
        log_warning "theHarvester already installed, updating..."
        cd ~/theHarvester
        git pull
        uv sync
        cd -
    else
        log_info "Cloning theHarvester repository..."
        git clone https://github.com/laramies/theHarvester.git ~/theHarvester
        cd ~/theHarvester

        log_info "Installing dependencies with uv..."
        uv sync
        cd -
    fi

    # Create wrapper script for easy execution
    cat > ~/theHarvester/theharvester-wrapper.sh << 'EOF'
#!/bin/bash
cd ~/theHarvester
uv run theHarvester "$@"
EOF
    chmod +x ~/theHarvester/theharvester-wrapper.sh

    # Create symlink
    sudo ln -sf ~/theHarvester/theharvester-wrapper.sh /usr/local/bin/theharvester

    log_success "theHarvester installed (use: theharvester or cd ~/theHarvester && uv run theHarvester)"
}

# Install Metasploit Framework using official installer
install_metasploit() {
    log_step "Installing Metasploit Framework (this may take 15-30 minutes)..."

    if command -v msfconsole &> /dev/null; then
        log_warning "Metasploit already installed"
        msfconsole --version 2>/dev/null || true
        return
    fi

    # On Kali Linux, Metasploit is often pre-installed or available via apt
    if [[ -f /etc/os-release ]] && grep -q "ID=kali" /etc/os-release; then
        log_info "Detected Kali Linux, checking for Metasploit in repositories..."
        if sudo apt install -y metasploit-framework 2>/dev/null; then
            if command -v msfconsole &> /dev/null; then
                log_success "Metasploit Framework installed from Kali repos"
                msfconsole --version 2>/dev/null || true
                return
            fi
        fi
    fi

    # Download and install using official msfinstall script
    log_info "Downloading Metasploit installer..."
    if ! curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall; then
        log_error "Failed to download Metasploit installer"
        log_warning "You may need to install Metasploit manually: https://metasploit.com"
        return
    fi

    chmod 755 /tmp/msfinstall

    log_info "Running Metasploit installer (this will take a while)..."
    if sudo /tmp/msfinstall; then
        log_info "Metasploit installer completed"
    else
        log_warning "Metasploit installer encountered errors"
    fi

    # Clean up installer
    rm -f /tmp/msfinstall

    # Verify installation
    if command -v msfconsole &> /dev/null; then
        log_success "Metasploit Framework installed successfully"
        msfconsole --version 2>/dev/null || true
    else
        log_warning "Metasploit installation may have failed or requires new shell"
        log_info "Try: exec bash"
        log_info "Or install manually: https://metasploit.com"
    fi
}

# Setup PostgreSQL for Metasploit
setup_metasploit_db() {
    log_step "Setting up PostgreSQL for Metasploit..."

    # Check if PostgreSQL service exists
    if ! systemctl list-unit-files | grep -q postgresql; then
        log_warning "PostgreSQL service not found, skipping database setup"
        return
    fi

    # Enable and start PostgreSQL
    if sudo systemctl enable postgresql 2>/dev/null; then
        log_info "PostgreSQL service enabled"
    else
        log_warning "Could not enable PostgreSQL service"
    fi

    if sudo systemctl start postgresql 2>/dev/null; then
        log_info "PostgreSQL service started"
    else
        log_warning "Could not start PostgreSQL service (may already be running)"
    fi

    # Wait for PostgreSQL to be ready
    sleep 2

    # Initialize Metasploit database
    if command -v msfdb &> /dev/null; then
        log_info "Initializing Metasploit database..."
        if sudo msfdb init 2>/dev/null; then
            log_success "Metasploit database configured"
        else
            log_warning "Metasploit database initialization failed (may already be initialized)"
        fi
    else
        log_warning "msfdb command not found, skipping database initialization"
        log_info "You can run 'sudo msfdb init' manually later"
    fi
}

# Install nuclei
install_nuclei() {
    log_step "Installing nuclei vulnerability scanner..."

    if command -v nuclei &> /dev/null; then
        log_warning "Nuclei already installed"
        return
    fi

    # Detect architecture
    ARCH=$(uname -m)
    if [[ $ARCH == "aarch64" ]]; then
        NUCLEI_ARCH="arm64"
    else
        log_error "Unsupported architecture: $ARCH"
        return
    fi

    # Get latest version
    NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name | sed 's/v//')

    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" -O /tmp/nuclei.zip

    unzip -q /tmp/nuclei.zip -d /tmp/
    sudo mv /tmp/nuclei /usr/local/bin/
    sudo chmod +x /usr/local/bin/nuclei
    rm /tmp/nuclei.zip

    # Update templates
    nuclei -update-templates

    log_success "Nuclei installed"
}

# Install testssl.sh
install_testssl() {
    log_step "Installing testssl.sh..."

    mkdir -p ~/tools

    if [[ -d ~/tools/testssl ]]; then
        log_warning "testssl.sh already installed"
        cd ~/tools/testssl && git pull
        cd -
        return
    fi

    git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools/testssl
    chmod +x ~/tools/testssl/testssl.sh

    # Add to PATH
    if ! grep -q "tools/testssl" ~/.bashrc; then
        echo 'export PATH="$HOME/tools/testssl:$PATH"' >> ~/.bashrc
    fi

    log_success "testssl.sh installed"
}

# Install Python tools
install_python_tools() {
    log_step "Installing Python security tools..."

    # Check Python version (need 3.10+, recommend 3.11+)
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

    if [[ -z "$PYTHON_MAJOR" || -z "$PYTHON_MINOR" ]]; then
        log_error "Failed to detect Python version"
        exit 1
    fi

    if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 10 ]]; then
        log_error "Python 3.10+ required. Found: Python $PYTHON_VERSION"
        log_info "Please upgrade Python: sudo apt install python3.11"
        exit 1
    fi

    if [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 11 ]]; then
        log_warning "Python 3.11+ recommended for best compatibility. Found: Python $PYTHON_VERSION"
    else
        log_success "Python version $PYTHON_VERSION OK"
    fi

    # Create virtual environment
    if [[ ! -d ~/venvs/sectools ]]; then
        python3 -m venv ~/venvs/sectools
    fi

    source ~/venvs/sectools/bin/activate

    # Upgrade pip
    pip install --upgrade pip

    # Install core security tools
    log_info "Installing impacket..."
    pip install impacket

    log_info "Installing MCP server dependencies..."
    pip install "mcp>=1.0.0" "pydantic>=2.0.0" "python-nmap>=0.7.1" "xmltodict>=0.13.0" "aiofiles>=23.0.0" "typing-extensions>=4.0.0"

    log_info "Installing autonomous agent dependencies..."
    pip install "claude-code-sdk>=0.0.25" "python-dotenv>=1.0.0" "colorlog>=6.7.0" "python-json-logger>=2.0.0" "tenacity>=8.2.0"

    log_info "Installing additional Python tools..."
    pip install ldap3 pycryptodome requests beautifulsoup4 sqlalchemy

    deactivate

    # Add alias
    if ! grep -q "ntree-env" ~/.bashrc; then
        echo 'alias ntree-env="source ~/venvs/sectools/bin/activate"' >> ~/.bashrc
    fi

    log_success "Python security tools installed"
}

# Install wordlists
install_wordlists() {
    log_step "Installing RockYou wordlist..."

    mkdir -p ~/wordlists

    # Download rockyou if not exists
    if [[ ! -f ~/wordlists/rockyou.txt ]]; then
        log_info "Downloading rockyou wordlist..."
        if wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O ~/wordlists/rockyou.txt; then
            log_success "RockYou wordlist downloaded"
        else
            log_warning "Failed to download rockyou wordlist"
        fi
    else
        log_warning "RockYou wordlist already exists"
    fi

    # Add environment variable for wordlists path
    if ! grep -q "NTREE_WORDLISTS_PATH" ~/.bashrc; then
        echo 'export NTREE_WORDLISTS_PATH="$HOME/wordlists"' >> ~/.bashrc
    fi

    log_success "RockYou wordlist installed"
    log_info "RockYou path: ~/wordlists/rockyou.txt"
}

# Set up NTREE directory structure
setup_ntree_structure() {
    log_step "Setting up NTREE directory structure..."

    mkdir -p "$NTREE_HOME"/{assessments,templates,tools,logs}

    log_success "NTREE directory structure created at $NTREE_HOME"
}

# Install MCP servers
install_mcp_servers() {
    log_step "Installing NTREE MCP servers..."

    # Verify source exists
    if [[ ! -d "$SCRIPT_DIR/ntree-mcp-servers" ]]; then
        log_error "Source directory not found: $SCRIPT_DIR/ntree-mcp-servers"
        exit 1
    fi

    # Create target directory
    mkdir -p "$NTREE_HOME"

    # Get absolute paths to avoid conflicts
    SOURCE_PATH=$(realpath "$SCRIPT_DIR/ntree-mcp-servers")
    TARGET_PATH=$(realpath "$NTREE_HOME/ntree-mcp-servers" 2>/dev/null || echo "$NTREE_HOME/ntree-mcp-servers")

    # Check if source and target are the same
    if [[ "$SOURCE_PATH" == "$TARGET_PATH" ]]; then
        log_info "MCP servers already in target location, updating in place..."
    else
        # Copy to temporary location first to avoid conflicts
        TEMP_DIR=$(mktemp -d)
        log_info "Copying MCP servers via temp directory..."
        cp -r "$SCRIPT_DIR/ntree-mcp-servers" "$TEMP_DIR/"

        # Remove existing if present
        if [[ -d "$NTREE_HOME/ntree-mcp-servers" ]]; then
            log_info "Removing existing MCP servers installation..."
            rm -rf "$NTREE_HOME/ntree-mcp-servers"
        fi

        # Move from temp to final location
        mv "$TEMP_DIR/ntree-mcp-servers" "$NTREE_HOME/"
        rm -rf "$TEMP_DIR"
    fi

    # Install dependencies
    cd "$NTREE_HOME/ntree-mcp-servers"

    # Remove old venv if it exists to ensure clean install
    if [[ -d venv ]]; then
        rm -rf venv
    fi

    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -e .
    deactivate
    cd -

    log_success "MCP servers installed"
}

# Configure Claude Code MCP servers
configure_mcp_servers() {
    log_step "Configuring Claude Code MCP servers..."

    mkdir -p ~/.config/claude-code

    MCP_CONFIG=~/.config/claude-code/mcp-servers.json
    NTREE_MCP_PATH="$NTREE_HOME/ntree-mcp-servers"

    # Backup existing config
    if [[ -f "$MCP_CONFIG" ]]; then
        cp "$MCP_CONFIG" "${MCP_CONFIG}.backup"
        log_info "Backed up existing config to ${MCP_CONFIG}.backup"
    fi

    # Create new config
    cat > "$MCP_CONFIG" << EOF
{
  "mcpServers": {
    "ntree-scope": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.scope"],
      "env": {
        "NTREE_HOME": "$NTREE_HOME",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-scan": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.scan"],
      "env": {
        "NTREE_HOME": "$NTREE_HOME",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-enum": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.enum"],
      "env": {
        "NTREE_HOME": "$NTREE_HOME",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-vuln": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.vuln"],
      "env": {
        "NTREE_HOME": "$NTREE_HOME",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    },
    "ntree-report": {
      "command": "${NTREE_MCP_PATH}/venv/bin/python",
      "args": ["-m", "ntree_mcp.report"],
      "env": {
        "NTREE_HOME": "$NTREE_HOME",
        "PYTHONPATH": "${NTREE_MCP_PATH}"
      }
    }
  }
}
EOF

    log_success "Claude Code MCP configuration created: $MCP_CONFIG"
}

# Install autonomous SDK mode
install_autonomous_mode() {
    log_step "Installing NTREE Autonomous SDK Mode..."

    # Verify source exists
    if [[ ! -d "$SCRIPT_DIR/ntree-autonomous" ]]; then
        log_error "Source directory not found: $SCRIPT_DIR/ntree-autonomous"
        exit 1
    fi

    # Create target directory
    mkdir -p "$NTREE_HOME"

    # Get absolute paths to avoid conflicts
    SOURCE_PATH=$(realpath "$SCRIPT_DIR/ntree-autonomous")
    TARGET_PATH=$(realpath "$NTREE_HOME/ntree-autonomous" 2>/dev/null || echo "$NTREE_HOME/ntree-autonomous")

    # Check if source and target are the same
    if [[ "$SOURCE_PATH" == "$TARGET_PATH" ]]; then
        log_info "Autonomous SDK mode already in target location, updating in place..."
    else
        # Copy to temporary location first to avoid conflicts
        TEMP_DIR=$(mktemp -d)
        log_info "Copying autonomous SDK mode via temp directory..."
        cp -r "$SCRIPT_DIR/ntree-autonomous" "$TEMP_DIR/"

        # Remove existing if present
        if [[ -d "$NTREE_HOME/ntree-autonomous" ]]; then
            log_info "Removing existing autonomous mode installation..."
            rm -rf "$NTREE_HOME/ntree-autonomous"
        fi

        # Move from temp to final location
        mv "$TEMP_DIR/ntree-autonomous" "$NTREE_HOME/"
        rm -rf "$TEMP_DIR"
    fi

    log_success "Autonomous SDK mode installed"
}

# Copy templates
copy_templates() {
    log_step "Copying templates..."

    mkdir -p "$NTREE_HOME/templates"
    cp "$SCRIPT_DIR/templates/"* "$NTREE_HOME/templates/" 2>/dev/null || true

    log_success "Templates copied"
}

# Configure sudo for security tools
configure_sudo() {
    log_step "Configuring sudo for security tools..."

    SUDOERS_FILE="/etc/sudoers.d/ntree"
    USERNAME=$(whoami)

    sudo bash -c "cat > $SUDOERS_FILE" << EOF
# NTREE security tools - NOPASSWD for specific commands
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/nmap
$USERNAME ALL=(ALL) NOPASSWD: /usr/bin/masscan
$USERNAME ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump
EOF

    sudo chmod 440 $SUDOERS_FILE

    log_success "Sudo configuration complete"
}

# Create helper scripts
create_helper_scripts() {
    log_step "Creating helper scripts..."

    # Create activation script
    cat > "$NTREE_HOME/activate.sh" << EOF
#!/bin/bash
# Activate NTREE environment

# Activate Python virtual environment
source ~/venvs/sectools/bin/activate

# Add pipx tools to PATH
export PATH="\$HOME/.local/bin:\$PATH"

# Add tools to PATH
export PATH="\$HOME/tools/testssl:\$PATH"

# Set NTREE home
export NTREE_HOME="$NTREE_HOME"

# Set wordlist paths
export NTREE_WORDLISTS_PATH="\$HOME/wordlists"

echo "NTREE environment activated"
echo "Python venv: \$(which python)"
echo "NTREE_HOME: \$NTREE_HOME"
EOF

    chmod +x "$NTREE_HOME/activate.sh"

    log_success "Helper scripts created"
}

# Display next steps
show_next_steps() {
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║                                                        ║"
    echo "║              NTREE Installation Complete!              ║"
    echo "║                                                        ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""

    log_success "NTREE is installed in: $NTREE_HOME"
    echo ""

    echo "═══════════════════════════════════════════════════════════════"
    echo "  ${MAGENTA}IMPORTANT: Authentication Required${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Before using NTREE, you MUST authenticate with Claude Code:"
    echo ""
    echo "   ${GREEN}claude auth login${NC}"
    echo ""
    echo "This is required for:"
    echo "  • Interactive Mode (Claude Code + MCP)"
    echo "  • Autonomous SDK Mode"
    echo ""

    echo "═══════════════════════════════════════════════════════════════"
    echo "  ${CYAN}Quick Start${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "1. Authenticate (REQUIRED):"
    echo "   ${GREEN}claude auth login${NC}"
    echo ""
    echo "2. Interactive Mode:"
    echo "   ${GREEN}claude${NC}"
    echo "   Then say: ${YELLOW}\"Start NTREE with scope: $NTREE_HOME/templates/scope_example.txt\"${NC}"
    echo ""
    echo "3. Autonomous SDK Mode:"
    echo "   ${GREEN}$NTREE_HOME/start_pentest.sh --scope $NTREE_HOME/templates/scope_example.txt${NC}"
    echo ""

    echo "═══════════════════════════════════════════════════════════════"
    echo "  ${CYAN}Resources${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    log_info "NTREE Directory: ${GREEN}$NTREE_HOME${NC}"
    log_info "Templates: ${GREEN}$NTREE_HOME/templates/${NC}"
    log_info "Assessments: ${GREEN}$NTREE_HOME/assessments/${NC}"
    log_info "Wordlists: ${GREEN}~/wordlists/${NC}"
    log_info "Documentation: ${GREEN}$SCRIPT_DIR/README.md${NC}"
    echo ""

    log_warning "To apply environment changes, either:"
    echo "  • Open a new terminal window, OR"
    echo "  • Run: ${GREEN}exec bash${NC}"
    echo ""
    log_warning "Reboot recommended for optimal performance: ${GREEN}sudo reboot${NC}"
    echo ""
    log_success "Happy (ethical) hacking! 🎯"
    echo ""
}

# Main installation flow
main() {
    print_banner

    confirm_installation
    check_platform

    echo ""
    log_info "Starting installation..."
    echo ""

    update_system
    increase_swap_size
    optimize_pi5
    install_base_deps
    install_claude_code
    install_security_tools
    install_crackmapexec
    install_theharvester
    install_metasploit
    setup_metasploit_db
    install_nuclei
    install_testssl
    install_python_tools
    install_wordlists
    setup_ntree_structure
    install_mcp_servers
    configure_mcp_servers
    install_autonomous_mode
    copy_templates
    configure_sudo
    create_helper_scripts

    log_success "All components installed successfully!"

    show_next_steps
}

# Run main function
main
