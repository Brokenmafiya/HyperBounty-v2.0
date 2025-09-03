#!/bin/bash
# HyperBounty v2.0 Installation Script

echo "🚀 HyperBounty v2.0 Installation Script"
echo "======================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Some Go installations may not work properly."
        print_info "Consider running as a regular user for Go tool installations."
    fi
}

# Update system packages
update_system() {
    print_status "Updating system packages..."
    sudo apt update && sudo apt upgrade -y
    print_status "System updated successfully!"
}

# Install system dependencies
install_system_packages() {
    print_status "Installing system packages..."

    sudo apt install -y \
        curl \
        wget \
        git \
        nmap \
        python3 \
        python3-pip \
        jq \
        unzip \
        build-essential \
        ca-certificates \
        apt-transport-https \
        software-properties-common

    print_status "System packages installed!"
}

# Install Go language
install_go() {
    print_status "Installing Go language..."

    if command -v go &> /dev/null; then
        print_status "Go is already installed: $(go version)"
        return 0
    fi

    # Download and install Go 1.21
    GO_VERSION="1.21.0"
    GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"

    print_info "Downloading Go ${GO_VERSION}..."
    wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"

    if [ $? -eq 0 ]; then
        print_info "Installing Go..."
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"

        # Add to PATH
        if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        fi

        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

        # Clean up
        rm "/tmp/${GO_TAR}"

        print_status "Go ${GO_VERSION} installed successfully!"
    else
        print_error "Failed to download Go. Please install manually."
        return 1
    fi
}

# Install Python packages
install_python_packages() {
    print_status "Installing Python packages..."

    python3 -m pip install --upgrade pip

    pip3 install \
        requests \
        beautifulsoup4 \
        urllib3 \
        colorama \
        pyyaml \
        dnspython \
        dirsearch

    print_status "Python packages installed!"
}

# Install Go-based security tools
install_go_tools() {
    print_status "Installing Go-based security tools..."

    # Ensure Go is in PATH
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

    if ! command -v go &> /dev/null; then
        print_error "Go not found in PATH. Please restart terminal or run: source ~/.bashrc"
        return 1
    fi

    # ProjectDiscovery tools
    print_info "Installing ProjectDiscovery tools..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

    # TomNomNom tools
    print_info "Installing reconnaissance tools..."
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/tomnomnom/httprobe@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/tomnomnom/gf@latest
    go install github.com/tomnomnom/qsreplace@latest

    # Update nuclei templates
    print_info "Updating Nuclei templates..."
    nuclei -update-templates -silent

    print_status "Go tools installed successfully!"
}

# Create directories and setup
setup_environment() {
    print_status "Setting up environment..."

    # Create directories
    mkdir -p ~/tools/hyperbounty
    mkdir -p ~/wordlists
    mkdir -p ~/.config/hyperbounty

    # Create config file
    cat > ~/.config/hyperbounty/config.yaml << EOF
general:
  max_threads: 10
  timeout: 30
  user_agent: 'HyperBounty/2.0'

scanning:
  subdomain_sources: ['subfinder', 'assetfinder', 'crt.sh']
  common_ports: [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]

nuclei:
  templates: ['cves', 'exposures', 'misconfiguration']
  severity: ['critical', 'high', 'medium']
EOF

    print_status "Environment setup complete!"
}

# Download common wordlists
install_wordlists() {
    print_status "Installing wordlists..."

    # SecLists
    if [ ! -d "/opt/SecLists" ]; then
        print_info "Installing SecLists..."
        sudo git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
        sudo chmod -R 755 /opt/SecLists
    else
        print_info "SecLists already installed"
    fi

    # Create symlinks for easy access
    if [ ! -L ~/wordlists/seclists ]; then
        ln -sf /opt/SecLists ~/wordlists/seclists
    fi

    print_status "Wordlists installed!"
}

# Setup HyperBounty
setup_hyperbounty() {
    print_status "Setting up HyperBounty..."

    # Make executable
    chmod +x hyperbounty_v2.py

    # Create system-wide symlink
    if [ -w /usr/local/bin ]; then
        sudo ln -sf "$(pwd)/hyperbounty_v2.py" /usr/local/bin/hyperbounty
        print_status "HyperBounty installed system-wide as 'hyperbounty'"
    else
        print_warning "Cannot create system-wide link. Run with: ./hyperbounty_v2.py"
    fi

    # Create launcher script
    cat > hyperbounty.sh << 'EOF'
#!/bin/bash
# HyperBounty Launcher Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

python3 hyperbounty_v2.py "$@"
EOF

    chmod +x hyperbounty.sh

    print_status "HyperBounty setup complete!"
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."

    # Check Python
    if command -v python3 &> /dev/null; then
        print_status "Python3: $(python3 --version)"
    else
        print_error "Python3 not found!"
        return 1
    fi

    # Check Go
    if command -v go &> /dev/null; then
        print_status "Go: $(go version)"
    else
        print_error "Go not found!"
        return 1
    fi

    # Check tools
    TOOLS=("subfinder" "httpx" "nuclei" "assetfinder" "waybackurls")

    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_status "$tool: Found"
        else
            print_warning "$tool: Not found in PATH"
        fi
    done

    print_status "Installation verification complete!"
}

# Main installation function
main() {
    echo
    print_info "Starting HyperBounty v2.0 installation..."
    echo

    check_root

    # Installation steps
    update_system
    install_system_packages
    install_go
    install_python_packages
    install_go_tools
    setup_environment
    install_wordlists
    setup_hyperbounty
    verify_installation

    echo
    print_status "🎉 HyperBounty v2.0 installation completed!"
    echo
    print_info "Usage examples:"
    echo "  hyperbounty -t example.com"
    echo "  hyperbounty -t example.com --check-tools"
    echo "  ./hyperbounty_v2.py -t example.com -v"
    echo
    print_warning "Please restart your terminal or run:"
    print_warning "source ~/.bashrc"
    echo
    print_info "Then test with: hyperbounty --check-tools"
    echo
}

# Run main function
main "$@"
