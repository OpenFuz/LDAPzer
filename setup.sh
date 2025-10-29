#!/bin/bash
# LDAPzer Setup Script for Linux/Mac
# Quick setup for testing environments

set -e

echo "============================================"
echo "  LDAPzer - LDAP Security Testing Tools"
echo "  Setup Script"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check Python version
echo "[1/5] Checking Python version..."
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
    PYTHON_CMD="python"
else
    echo -e "${RED}✗${NC} Python not found. Please install Python 3.7+"
    exit 1
fi

# Check Python version is 3.7+
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 7 ]); then
    echo -e "${RED}✗${NC} Python 3.7+ required, found $PYTHON_VERSION"
    exit 1
fi

# Check if in LDAPzer directory
echo ""
echo "[2/5] Checking directory structure..."
if [ ! -d "tools" ] || [ ! -d "TestingPlan" ]; then
    echo -e "${RED}✗${NC} Not in LDAPzer root directory"
    echo "Please run this script from the LDAPzer root directory"
    exit 1
fi
echo -e "${GREEN}✓${NC} Directory structure verified"

# Optional: Install Scapy
echo ""
echo "[3/5] Optional dependencies..."
read -p "Install Scapy for advanced features? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing Scapy..."
    if command -v pip3 &>/dev/null; then
        pip3 install -r tools/requirements.txt
    elif command -v pip &>/dev/null; then
        pip install -r tools/requirements.txt
    else
        echo -e "${YELLOW}⚠${NC} pip not found, skipping Scapy installation"
        echo "   Install manually: pip install scapy"
    fi
    echo -e "${GREEN}✓${NC} Scapy installed"
else
    echo -e "${YELLOW}⚠${NC} Scapy not installed (optional)"
    echo "   You can install later with: pip install -r tools/requirements.txt"
fi

# Test basic functionality
echo ""
echo "[4/5] Testing basic functionality..."
cd tools
if $PYTHON_CMD preflight_checks/baseline_test.py --help &>/dev/null; then
    echo -e "${GREEN}✓${NC} Tools are working"
else
    echo -e "${RED}✗${NC} Tool test failed"
    exit 1
fi
cd ..

# Display next steps
echo ""
echo "[5/5] Setup complete!"
echo ""
echo "============================================"
echo "  Next Steps"
echo "============================================"
echo ""
echo "1. Review the workflow:"
echo "   cat tools/WORKFLOW.md"
echo ""
echo "2. Run preflight check:"
echo "   cd tools"
echo "   $PYTHON_CMD preflight_checks/baseline_test.py <TARGET_IP>"
echo ""
echo "3. Run security tests:"
echo "   cd test_harness"
echo "   $PYTHON_CMD test_runner.py <TARGET_IP> -o results.json"
echo ""
echo "4. View results:"
echo "   $PYTHON_CMD results_logger.py results.json"
echo ""
echo "For detailed instructions, see:"
echo "  - tools/QUICKSTART.md"
echo "  - tools/WORKFLOW.md"
echo ""
echo -e "${GREEN}Happy testing!${NC}"
echo ""
