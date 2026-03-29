#!/bin/bash
# Installation script for AI Network Observer

set -e

echo "========================================"
echo "AI Network Observer - Installation"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root. Consider using a non-root user.${NC}"
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS. Please install manually.${NC}"
    exit 1
fi

echo "Detected OS: $OS $VER"
echo ""

# Install system dependencies
echo "Installing system dependencies..."

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    sudo apt-get update
    sudo apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        libpcap-dev \
        tcpdump \
        build-essential \
        git
    
    # Optional: eBPF
    echo ""
    read -p "Install eBPF support? (high performance, requires kernel headers) [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r)
    fi

elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
    sudo dnf install -y \
        python3 \
        python3-pip \
        python3-devel \
        libpcap-devel \
        tcpdump \
        gcc \
        git
    
    # Optional: eBPF
    echo ""
    read -p "Install eBPF support? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo dnf install -y bcc bcc-tools kernel-devel
    fi

else
    echo -e "${YELLOW}Unsupported OS. Please install dependencies manually.${NC}"
    echo "Required: python3, pip, libpcap-dev, tcpdump"
fi

echo -e "${GREEN}✓ System dependencies installed${NC}"
echo ""

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo -e "${GREEN}✓ Virtual environment created${NC}"
echo ""

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}✓ Python dependencies installed${NC}"
echo ""

# Optional: Development dependencies
read -p "Install development dependencies? (for contributing) [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip install -r requirements-dev.txt
    pre-commit install
    echo -e "${GREEN}✓ Development environment configured${NC}"
fi

# Create directories
echo ""
echo "Creating directories..."
mkdir -p output logs config

# Copy configuration template
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file (please edit with your settings)${NC}"
else
    echo -e "${YELLOW}! .env file already exists (not overwriting)${NC}"
fi

if [ ! -f config/config.yaml ]; then
    cp config/config.example.yaml config/config.yaml
    echo -e "${GREEN}✓ Created config.yaml${NC}"
else
    echo -e "${YELLOW}! config.yaml already exists (not overwriting)${NC}"
fi

echo ""
echo "========================================"
echo "Installation Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Edit configuration:"
echo "   nano .env"
echo "   nano config/config.yaml"
echo ""
echo "3. Test installation:"
echo "   python examples/demo.py"
echo ""
echo "4. Run basic capture (requires sudo):"
echo "   sudo venv/bin/python src/main.py -i eth0 --duration 5"
echo ""
echo "5. Run with AI analysis:"
echo "   export ANTHROPIC_API_KEY='your-key'"
echo "   sudo -E venv/bin/python src/main.py -i eth0 --enable-llm"
echo ""
echo "For more information:"
echo "  - README.md - Full documentation"
echo "  - QUICK_START.md - Quick start guide"
echo "  - make help - Available commands"
echo ""
