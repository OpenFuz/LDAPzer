# LDAPzer Deployment Guide

Quick guide for deploying LDAPzer to your testing environment.

---

## 🚀 Quick Deployment

### Method 1: Git Clone (Recommended)

```bash
# Clone the repository
git clone <YOUR_GIT_URL> LDAPzer
cd LDAPzer

# Run setup script
# Linux/Mac:
./setup.sh

# Windows:
powershell -ExecutionPolicy Bypass -File setup.ps1
```

### Method 2: Manual Download

```bash
# If you don't have git access, download and extract the repository
# Then run setup

cd LDAPzer

# Linux/Mac:
chmod +x setup.sh
./setup.sh

# Windows:
powershell -ExecutionPolicy Bypass -File setup.ps1
```

---

## 📦 What Gets Installed

### Required (Automatic)
- ✅ Python 3.7+ verification
- ✅ Directory structure verification
- ✅ Basic functionality test

### Optional (User Choice)
- ⚪ Scapy (for advanced packet crafting)
- ⚪ PyYAML (for YAML configuration files)

### Not Included
- Python itself (must be pre-installed)
- Npcap (Windows only, for Scapy packet capture)

---

## 🖥️ Platform-Specific Instructions

### Linux

```bash
# 1. Ensure Python 3.7+ is installed
python3 --version

# 2. Clone repository
git clone <YOUR_GIT_URL> LDAPzer
cd LDAPzer

# 3. Run setup
./setup.sh

# 4. Optional: Install with virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r tools/requirements.txt
```

### macOS

```bash
# 1. Ensure Python 3.7+ is installed
python3 --version

# 2. Clone repository
git clone <YOUR_GIT_URL> LDAPzer
cd LDAPzer

# 3. Run setup
./setup.sh

# 4. Optional: Install with virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r tools/requirements.txt
```

### Windows

```powershell
# 1. Ensure Python 3.7+ is installed
python --version

# 2. Clone repository
git clone <YOUR_GIT_URL> LDAPzer
cd LDAPzer

# 3. Run setup
powershell -ExecutionPolicy Bypass -File setup.ps1

# 4. Optional: If using Scapy, install Npcap
# Download from: https://npcap.com/
# Install with "WinPcap API-compatible mode" enabled

# 5. Optional: Use virtual environment
python -m venv venv
.\venv\Scripts\activate
pip install -r tools\requirements.txt
```

---

## 🐳 Docker Deployment (Alternative)

If you prefer containerization:

### Create Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Copy LDAPzer
COPY . /app/

# Install optional dependencies
RUN pip install -r tools/requirements.txt

# Set working directory
WORKDIR /app/tools

# Default command shows help
CMD ["python", "test_harness/test_runner.py", "--help"]
```

### Build and Run

```bash
# Build image
docker build -t ldapzer .

# Run preflight check
docker run --rm ldapzer python preflight_checks/baseline_test.py <TARGET_IP>

# Run fuzzing tests
docker run --rm -v $(pwd)/results:/app/results ldapzer \
  python test_harness/test_runner.py <TARGET_IP> -o /app/results/output.json
```

---

## 🔧 Testing the Deployment

### Verify Installation

```bash
cd LDAPzer/tools

# Test baseline check help
python preflight_checks/baseline_test.py --help

# Test runner help
cd test_harness
python test_runner.py --help

# Test examples
cd ../
python examples/example_usage.py
```

### Run Against Test Server

```bash
# If you have a test LDAP server running
cd tools

# 1. Preflight
python preflight_checks/baseline_test.py localhost

# 2. Fuzz (if preflight passes)
cd test_harness
python test_runner.py localhost -o test_results.json

# 3. Review
python results_logger.py test_results.json
```

---

## 🌐 Network Requirements

### Outbound Access Needed

- **Target LDAP Server**: Port 389 (or custom port)
- **No internet required** for basic functionality
- **Internet optional** for pip installs (Scapy)

### Firewall Rules

Ensure your testing machine can connect to:
- LDAP server on port 389/TCP (or custom port)
- No inbound connections required

### Testing Connectivity

```bash
# Test TCP connectivity to LDAP server
nc -zv <TARGET_IP> 389

# Windows (PowerShell)
Test-NetConnection -ComputerName <TARGET_IP> -Port 389
```

---

## 📁 Portable Deployment

For air-gapped or restricted environments:

### Prepare Offline Package

On internet-connected machine:

```bash
# 1. Clone repository
git clone <YOUR_GIT_URL> LDAPzer

# 2. Download pip packages (optional)
cd LDAPzer/tools
pip download -r requirements.txt -d ../offline_packages

# 3. Create tarball
cd ../..
tar -czf LDAPzer-offline.tar.gz LDAPzer/

# 4. Transfer LDAPzer-offline.tar.gz to target environment
```

On target machine:

```bash
# 1. Extract
tar -xzf LDAPzer-offline.tar.gz
cd LDAPzer

# 2. Install offline packages (optional)
pip install --no-index --find-links=offline_packages -r tools/requirements.txt

# 3. Verify
./setup.sh
```

---

## 🔐 Secure Deployment

### Recommendations

1. **Isolated Network**: Deploy in isolated test network
2. **No Production**: Never deploy on production systems
3. **Clean Logs**: Clear logs after testing
4. **Remove Results**: Don't leave test results on target
5. **Version Control**: Track changes to custom tests

### Security Checklist

- [ ] Deployed in isolated test environment
- [ ] No access to production networks
- [ ] Authorization documented
- [ ] Logging configured
- [ ] Results will be collected and removed
- [ ] Team aware of testing schedule

---

## 🐛 Troubleshooting Deployment

### Python Not Found

```bash
# Install Python 3.7+
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip

# RHEL/CentOS
sudo yum install python3 python3-pip

# macOS (using Homebrew)
brew install python3

# Windows
# Download from https://www.python.org/downloads/
```

### Permission Denied (Linux/Mac)

```bash
# Make setup script executable
chmod +x setup.sh

# Run setup
./setup.sh
```

### Scapy Import Error

```bash
# Ensure Scapy is installed
pip install scapy

# Windows: Install Npcap
# Download from https://npcap.com/

# Linux: May need libpcap-dev
sudo apt-get install libpcap-dev  # Ubuntu/Debian
sudo yum install libpcap-devel    # RHEL/CentOS
```

### Import Errors

```bash
# Ensure you're in the right directory
cd LDAPzer/tools

# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Verify files exist
ls asn1_fuzzer/
ls test_harness/
```

---

## 📊 Deployment Verification Checklist

After deployment, verify:

- [ ] Python 3.7+ installed and working
- [ ] Can run: `python preflight_checks/baseline_test.py --help`
- [ ] Can run: `python test_harness/test_runner.py --help`
- [ ] Can access target LDAP server (connectivity test)
- [ ] Optional: Scapy installed (if using advanced features)
- [ ] Optional: Npcap installed (Windows + Scapy only)
- [ ] Documentation accessible (README.md, WORKFLOW.md)
- [ ] Test with: `python examples/example_usage.py`

---

## 🔄 Updating Deployment

### Pull Latest Changes

```bash
cd LDAPzer
git pull origin main

# Re-run setup if needed
./setup.sh
```

### Manual Update

```bash
# Backup your results/custom tests
cp -r results/ ../results_backup/

# Download new version
# Extract and replace files

# Restore custom content
cp -r ../results_backup/* results/
```

---

## 🗑️ Uninstallation

```bash
# Remove LDAPzer directory
cd ..
rm -rf LDAPzer/

# Optional: Remove pip packages
pip uninstall scapy pyyaml
```

---

## 📞 Deployment Support

- **Setup Issues**: Run `./setup.sh` or `setup.ps1` with verbose output
- **Network Issues**: Test connectivity with `nc` or `Test-NetConnection`
- **Permission Issues**: Check file permissions, run as appropriate user
- **Python Issues**: Verify Python 3.7+ is installed and in PATH

**Need Help?** Check:
- `tools/README.md` - Complete documentation
- `tools/WORKFLOW.md` - Usage workflow
- `tools/QUICKSTART.md` - Quick start guide

---

**Last Updated**: 2025-10-29
**Version**: 1.0.0
