# LDAPzer - LDAP Protocol Security Testing Tools

**Comprehensive security assessment tools for testing LDAP server implementations against RFC 4511 vulnerabilities.**

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![RFC 4511](https://img.shields.io/badge/RFC-4511-orange.svg)](https://tools.ietf.org/html/rfc4511)

---

## 📋 Overview

LDAPzer is a suite of tools designed for security professionals to assess LDAP server implementations for protocol-level vulnerabilities. Currently implements **RFC 4511 Test Cases 1.1.1, 1.1.2, and 1.1.3** focusing on ASN.1/BER encoding violations.

### What's Included

- **16 Pre-built Test Cases** - ASN.1/BER encoding vulnerability tests
- **Socket-based Fuzzer** - Pure Python, no dependencies
- **Scapy Integration** - Advanced packet crafting capabilities
- **Preflight Checks** - Server readiness verification
- **Multi-format Reporting** - JSON, HTML, Markdown, CSV outputs
- **Comprehensive Documentation** - Test plan, usage guides, examples

---

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- Target LDAP server (with authorization to test)
- Network connectivity to LDAP port (default 389)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/LDAPzer.git
cd LDAPzer

# Optional: Install Scapy for advanced features
pip install -r tools/requirements.txt
```

### Basic Usage

```bash
# 1. Verify server is ready
cd tools
python preflight_checks/baseline_test.py <TARGET_IP>

# 2. Run security tests
cd test_harness
python test_runner.py <TARGET_IP> -o results.json

# 3. View results
python results_logger.py results.json
```

**See [WORKFLOW.md](tools/WORKFLOW.md) for complete step-by-step guide.**

---

## 📁 Repository Structure

```
LDAPzer/
├── README.md                     # This file
├── DEVELOPMENT_PROGRESS.md       # Development tracker
├── LICENSE                       # License information
├── .gitignore                    # Git ignore rules
│
├── TestingPlan/                  # RFC 4511 Test Plan
│   └── RFC4511-TestPlan.md       # Complete test plan document
│
└── tools/                        # Testing Tools
    ├── README.md                 # Complete tool documentation
    ├── QUICKSTART.md             # 5-minute getting started
    ├── WORKFLOW.md               # Step-by-step workflow guide
    ├── requirements.txt          # Python dependencies
    │
    ├── asn1_fuzzer/              # ASN.1/BER Fuzzer (16 tests)
    ├── scapy_crafter/            # Scapy packet crafter
    ├── test_harness/             # Test orchestration
    ├── preflight_checks/         # Server readiness tests
    └── examples/                 # Code examples
```

---

## 🎯 What Does It Test?

### Currently Implemented (Phase 1)

**Section 1.1 - ASN.1/BER Encoding Violations** (16 tests)

| Test Suite | Tests | Description |
|------------|-------|-------------|
| **1.1.1** | 6 | Length encoding attacks (indefinite, overflow, beyond boundary) |
| **1.1.2** | 5 | Type encoding violations (invalid tags, constructed/primitive confusion) |
| **1.1.3** | 5 | Value encoding issues (invalid BOOLEAN, malformed INTEGER, out-of-range ENUMERATED) |

### Coming Soon

- Section 2.x - LDAPMessage Envelope Tests
- Section 3.x - Bind Operation Security
- Section 4.x - Search Operation Security
- Section 5.x - Modify/Add/Delete/ModifyDN
- And more... (see [DEVELOPMENT_PROGRESS.md](DEVELOPMENT_PROGRESS.md))

---

## 📚 Documentation

### Getting Started
- **[QUICKSTART.md](tools/QUICKSTART.md)** - Get up and running in 5 minutes
- **[WORKFLOW.md](tools/WORKFLOW.md)** - Complete workflow guide
- **[SERVER_REQUIREMENTS.md](tools/SERVER_REQUIREMENTS.md)** - What you need on the server

### Reference
- **[tools/README.md](tools/README.md)** - Complete tool documentation
- **[TestingPlan/RFC4511-TestPlan.md](TestingPlan/RFC4511-TestPlan.md)** - Full test plan
- **[PROJECT_OVERVIEW.md](tools/PROJECT_OVERVIEW.md)** - Technical overview

### Development
- **[DEVELOPMENT_PROGRESS.md](DEVELOPMENT_PROGRESS.md)** - Development tracker
- **[examples/](tools/examples/)** - Code examples

---

## 🔧 Features

### Core Capabilities

- ✅ **Pure Python** - No dependencies for basic fuzzing
- ✅ **16 Test Cases** - ASN.1/BER encoding vulnerabilities
- ✅ **Two Testing Methods** - Socket-based and Scapy-based
- ✅ **Server Health Monitoring** - Detects crashes and hangs
- ✅ **Multiple Output Formats** - JSON, HTML, Markdown, CSV
- ✅ **Preflight Checks** - Verify server readiness
- ✅ **Comprehensive Logging** - Detailed test results
- ✅ **Configurable** - Timeouts, delays, ports, etc.

### Advanced Features

- 🔍 Response parsing and analysis
- 📊 Summary statistics and findings
- 🎯 Targeted test suite execution
- ⚙️ Configuration file support (JSON/YAML)
- 🔌 Extensible architecture for custom tests
- 📝 Comprehensive documentation

### Fuzzing Modes

LDAPzer supports **four fuzzing modes** for different testing objectives:

- **DEFAULT Mode** - Single run of 16 base test cases (RFC compliance)
- **ITERATION Mode** - Run each test N times (robustness testing, race conditions)
- **MUTATION Mode** - Random/targeted packet mutations (vulnerability discovery)
- **LOAD TEST Mode** - Rapid-fire stress testing (DoS resistance, resource exhaustion)

See [tools/README.md#fuzzing-modes](tools/README.md#fuzzing-modes) for detailed documentation.

---

## 💻 Usage Examples

### Run All Tests (Default Mode)

```bash
cd tools/test_harness
python test_runner.py 192.168.1.100 -o results.json
```

### Run Specific Test Suite

```bash
# Only test length encoding attacks
python test_runner.py 192.168.1.100 --suite 1.1.1
```

### Iteration Mode (Robustness Testing)

```bash
# Run each test 100 times to detect race conditions
python test_runner.py 192.168.1.100 --fuzz-mode iteration --iterations 100
```

### Mutation Mode (Vulnerability Discovery)

```bash
# Generate 500 random mutations to find unknown bugs
python test_runner.py 192.168.1.100 --fuzz-mode mutation --count 500

# Targeted mutations (tag/length/value corruption)
python test_runner.py 192.168.1.100 --fuzz-mode mutation --count 100 --targeted
```

### Load Test Mode (Stress Testing)

```bash
# Rapid-fire tests for 60 seconds to detect DoS conditions
python test_runner.py 192.168.1.100 --fuzz-mode load --duration 60
```

### Generate HTML Report

```bash
python test_runner.py 192.168.1.100 -o report.html
```

### Use Scapy Method

```bash
python test_runner.py 192.168.1.100 --method scapy
```

### Custom Timing

```bash
# 10 second timeout, 1 second delay between tests
python test_runner.py 192.168.1.100 -t 10 -d 1.0
```

**See [tools/WORKFLOW.md](tools/WORKFLOW.md) for complete workflow guide.**

---

## 🔐 Security & Ethics

### Important Notes

⚠️ **Authorization Required** - Only test systems you have written permission to test.

⚠️ **Use Responsibly** - These tools can crash vulnerable servers. Use in test environments.

⚠️ **Document Findings** - Follow responsible disclosure practices for any vulnerabilities found.

### Intended Use Cases

✅ Authorized penetration testing
✅ Security research
✅ Vulnerability assessment
✅ Compliance testing
✅ Educational purposes

❌ Unauthorized testing
❌ Malicious attacks
❌ Production disruption

### Legal Considerations

- Obtain written authorization before testing
- Use isolated test environments
- Follow applicable laws and regulations
- Document all testing activities
- Practice responsible disclosure

---

## 🛠️ Installation & Setup

### System Requirements

- **Python**: 3.7 or higher
- **OS**: Windows, Linux, macOS
- **Network**: Access to target LDAP server

### Basic Installation

```bash
# Clone repository
git clone https://github.com/yourusername/LDAPzer.git
cd LDAPzer

# No additional installation needed for socket-based fuzzing
# Python standard library only
```

### Optional Dependencies (Scapy)

```bash
# Install Scapy for advanced packet crafting
cd tools
pip install -r requirements.txt

# Windows: Also install Npcap from https://npcap.com/
```

### Verify Installation

```bash
cd tools
python preflight_checks/baseline_test.py --help
```

---

## 📊 Test Results

### Expected Behavior (Secure Server)

✅ **Protocol Error (2)** - Server correctly rejects malformed BER
✅ **Quick Response** - Server responds in < 1 second
✅ **No Crashes** - Server remains stable

### Concerning Behavior (Vulnerable Server)

⚠️ **Connection Closed** - Server may have crashed
⚠️ **Timeout** - Server may be hanging
⚠️ **Success (0)** - Server accepted malformed input
⚠️ **Slow Response** - Possible DoS condition

---

## 🤝 Contributing

This project is currently in active development. See [DEVELOPMENT_PROGRESS.md](DEVELOPMENT_PROGRESS.md) for the roadmap.

### Development Priorities

1. Complete Section 2.x (LDAPMessage Envelope Tests)
2. Complete Section 3.x (Bind Operation Security)
3. Complete Section 4.x (Search Operation Security)
4. Add more output formats
5. CI/CD integration

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 References

- **RFC 4511** - Lightweight Directory Access Protocol (LDAP): The Protocol
  https://tools.ietf.org/html/rfc4511

- **RFC 4513** - LDAP Authentication Methods and Security Mechanisms
  https://tools.ietf.org/html/rfc4513

- **ITU-T X.690** - ASN.1 encoding rules (BER, DER, CER)
  https://www.itu.int/rec/T-REC-X.690/

---

## 📞 Support

- **Documentation**: See [tools/README.md](tools/README.md)
- **Workflow Guide**: See [tools/WORKFLOW.md](tools/WORKFLOW.md)
- **Issues**: Open an issue on GitHub
- **Examples**: See [tools/examples/](tools/examples/)

---

## 📈 Project Status

**Current Version**: 1.0.0
**Status**: Active Development
**Completion**: ~5% (16 of 400+ planned test cases)

**Phase 1 Complete**: ✅ ASN.1/BER Encoding Violations (Section 1.1)
**Next Phase**: LDAPMessage Envelope Tests (Section 2.x)

See [DEVELOPMENT_PROGRESS.md](DEVELOPMENT_PROGRESS.md) for detailed progress tracking.

---

## 🎓 Learning Resources

### For Beginners

1. Start with [QUICKSTART.md](tools/QUICKSTART.md)
2. Read [WORKFLOW.md](tools/WORKFLOW.md)
3. Run [examples/example_usage.py](tools/examples/example_usage.py)

### For Advanced Users

1. Review [TestingPlan/RFC4511-TestPlan.md](TestingPlan/RFC4511-TestPlan.md)
2. Read [PROJECT_OVERVIEW.md](tools/PROJECT_OVERVIEW.md)
3. Extend test cases in [tools/asn1_fuzzer/fuzz_generators.py](tools/asn1_fuzzer/fuzz_generators.py)

---

## ⚡ Quick Command Reference

```bash
# Navigate to tools
cd LDAPzer/tools

# Preflight check
python preflight_checks/baseline_test.py <TARGET_IP>

# Run all tests
cd test_harness
python test_runner.py <TARGET_IP> -o results.json

# View results
python results_logger.py results.json

# Generate HTML report
python test_runner.py <TARGET_IP> -o report.html
```

---

**Ready to test?** → [Get Started](tools/QUICKSTART.md)

**Questions?** → [Read the Docs](tools/README.md)

**Want to contribute?** → [Check the roadmap](DEVELOPMENT_PROGRESS.md)

---

<div align="center">

**LDAPzer** - Professional LDAP Security Assessment Tools

Made with 🔒 by security researchers, for security professionals

</div>
