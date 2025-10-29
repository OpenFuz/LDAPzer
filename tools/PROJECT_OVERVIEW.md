# LDAP Protocol Security Testing Tools - Project Overview

**Created**: 2025-10-29
**Purpose**: RFC 4511 Security Assessment - Test Cases 1.1.1, 1.1.2, 1.1.3
**Status**: ✅ Complete and Ready for Use

---

## 📋 Project Summary

This project contains comprehensive security testing tools for LDAP protocol implementations, specifically targeting ASN.1/BER encoding vulnerabilities as outlined in RFC 4511 test cases 1.1.1, 1.1.2, and 1.1.3.

## 🎯 What Was Built

### Two Complementary Testing Approaches

1. **ASN.1 Fuzzer** (Socket-based)
   - Direct socket connections to LDAP server
   - No external dependencies (pure Python stdlib)
   - Generates malformed BER-encoded LDAP messages
   - Includes server health monitoring

2. **Scapy Packet Crafter** (Packet-level)
   - Raw packet manipulation with Scapy
   - Layer 3/4 control for advanced testing
   - Optional dependency (requires `pip install scapy`)
   - Fine-grained packet crafting capabilities

### 16 Pre-Built Test Cases

#### Test Suite 1.1.1 - Length Encoding Attacks (6 tests)
| Test ID | Name | Description |
|---------|------|-------------|
| 1.1.1.1 | Indefinite Length Encoding | Send 0x80 length (prohibited in LDAP) |
| 1.1.1.2 | Length Too Short | Length value shorter than actual data |
| 1.1.1.3 | Length Too Long | Length value longer than actual data |
| 1.1.1.4 | MaxInt Length | Length = 2147483647 |
| 1.1.1.5 | 32-bit Overflow | Length = 0xFFFFFFFF |
| 1.1.1.6 | Beyond Packet | Huge 64-bit length value |

#### Test Suite 1.1.2 - Type Encoding Violations (5 tests)
| Test ID | Name | Description |
|---------|------|-------------|
| 1.1.2.1 | Invalid Tag Number | Reserved tag (0xFF) |
| 1.1.2.2 | Constructed OCTET STRING | Wrong encoding for primitive type |
| 1.1.2.3 | Primitive SEQUENCE | Wrong encoding for constructed type |
| 1.1.2.4 | Unrecognized APPLICATION Tag | Unknown APPLICATION tag (99) |
| 1.1.2.5 | Unknown Context Tag | Invalid context tag in BindRequest |

#### Test Suite 1.1.3 - Value Encoding Issues (5 tests)
| Test ID | Name | Description |
|---------|------|-------------|
| 1.1.3.1 | Invalid BOOLEAN | Value other than 0x00 or 0xFF |
| 1.1.3.2 | INTEGER Leading Zeros | Unnecessary leading zero bytes |
| 1.1.3.3 | Empty INTEGER | Zero-length INTEGER value |
| 1.1.3.4 | Out-of-range ENUMERATED | Invalid scope value (99) |
| 1.1.3.5 | Oversized INTEGER | Unnecessarily long encoding |

---

## 📁 Complete Directory Structure

```
tools/
│
├── README.md                    # Comprehensive documentation (65KB)
├── QUICKSTART.md                # 5-minute getting started guide
├── PROJECT_OVERVIEW.md          # This file - project summary
├── requirements.txt             # Optional dependencies (scapy, pyyaml)
│
├── preflight_checks/            # Server readiness verification
│   ├── __init__.py              # Package initialization
│   └── baseline_test.py         # 4 baseline tests (TCP, bind, search, malformed)
│
├── examples/                    # Example scripts
│   ├── __init__.py              # Package initialization
│   └── example_usage.py         # 6 example scripts demonstrating usage
│
├── asn1_fuzzer/                 # Socket-based ASN.1/BER fuzzer
│   ├── __init__.py              # Package initialization
│   ├── ber_encoder.py           # BER encoding primitives with fuzzing (400+ lines)
│   │                            # - BERTag, BERLength, BEREncoder classes
│   │                            # - Support for malformed encodings
│   │                            # - Integer, Boolean, OctetString, Sequence, etc.
│   │
│   ├── ldap_messages.py         # LDAP protocol message constructors (350+ lines)
│   │                            # - BindRequest, SearchRequest, UnbindRequest
│   │                            # - ExtendedRequest, AbandonRequest
│   │                            # - LDAPMessage wrapper, Controls
│   │
│   ├── fuzz_generators.py       # Test case generators (450+ lines)
│   │                            # - TestCase_1_1_1_LengthEncodingAttacks (6 tests)
│   │                            # - TestCase_1_1_2_TypeEncodingViolations (5 tests)
│   │                            # - TestCase_1_1_3_ValueEncodingIssues (5 tests)
│   │                            # - get_all_test_cases() function
│   │
│   └── fuzzer.py                # Main fuzzing engine (350+ lines)
│                                # - LDAPFuzzer class with socket management
│                                # - FuzzResult dataclass
│                                # - Server health checking
│                                # - Test suite execution
│
├── scapy_crafter/               # Scapy-based packet crafter
│   ├── __init__.py              # Package initialization
│   ├── ldap_layers.py           # Scapy LDAP protocol layers (300+ lines)
│   │                            # - Custom BER field types for Scapy
│   │                            # - LDAP, LDAPRaw packet layers
│   │                            # - Helper functions for packet crafting
│   │
│   ├── packet_crafter.py        # Packet crafting utilities (350+ lines)
│   │                            # - LDAPPacketCrafter class
│   │                            # - ManualCrafter for byte-level control
│   │                            # - Integration with asn1_fuzzer
│   │
│   └── test_sender.py           # Test execution with Scapy (400+ lines)
│                                # - ScapyTestSender class
│                                # - LDAPResponseAnalyzer
│                                # - Response parsing and analysis
│                                # - CLI interface
│
└── test_harness/                # Unified test orchestration
    ├── __init__.py              # Package initialization
    ├── test_runner.py           # Main test runner (300+ lines)
    │                            # - UnifiedTestRunner class
    │                            # - Support for both socket and Scapy methods
    │                            # - Configuration file support (JSON/YAML)
    │                            # - Comprehensive CLI interface
    │
    └── results_logger.py        # Results logging and formatting (450+ lines)
                                 # - ResultsLogger class
                                 # - Export to JSON, CSV, HTML, Markdown
                                 # - Summary statistics
                                 # - Findings generation
```

**Total Code**: ~3,500+ lines of Python across 13 modules

---

## 🚀 How to Use

### Quick Test (Default Socket Method)

```bash
cd tools/test_harness
python test_runner.py 192.168.1.100
```

### Common Usage Patterns

```bash
# Run specific test suite
python test_runner.py 192.168.1.100 --suite 1.1.1

# Generate HTML report
python test_runner.py 192.168.1.100 -o report.html

# Use Scapy method (requires: pip install scapy)
python test_runner.py 192.168.1.100 --method scapy

# Custom timeout and delay
python test_runner.py 192.168.1.100 -t 10 -d 0.5

# Load from config file
python test_runner.py --config config.json
```

### Programmatic Usage

```python
from test_harness.test_runner import UnifiedTestRunner, TestMethod

# Create runner
runner = UnifiedTestRunner(
    target_host='192.168.1.100',
    target_port=389,
    method=TestMethod.SOCKET,
    timeout=5.0
)

# Run all tests
results = runner.run_all_tests()

# Or run specific suite
results = runner.run_test_suite('1.1.1')
```

---

## 🔧 Technical Architecture

### Core Components

#### 1. BER Encoder (`ber_encoder.py`)
- **Purpose**: Low-level BER encoding with fuzzing capabilities
- **Key Classes**:
  - `BERTag`: Tag encoding (universal, application, context)
  - `BERLength`: Length encoding (short form, long form, malformed)
  - `BEREncoder`: Main encoder with methods for all primitive types
- **Features**: Can generate both valid and malformed encodings

#### 2. LDAP Messages (`ldap_messages.py`)
- **Purpose**: High-level LDAP protocol message construction
- **Key Classes**:
  - `BindRequest`: LDAP bind operations (simple & SASL)
  - `SearchRequest`: LDAP search with filters and attributes
  - `ExtendedRequest`: Extended operations (StartTLS, etc.)
  - `LDAPMessage`: Complete message wrapper with controls
- **Features**: RFC 4511 compliant message generation

#### 3. Fuzz Generators (`fuzz_generators.py`)
- **Purpose**: Generate specific test cases for vulnerabilities
- **Key Classes**:
  - `TestCase_1_1_1_LengthEncodingAttacks`: 6 length-based tests
  - `TestCase_1_1_2_TypeEncodingViolations`: 5 type-based tests
  - `TestCase_1_1_3_ValueEncodingIssues`: 5 value-based tests
- **Output**: Dictionary with test_id, name, description, packet, expected

#### 4. Fuzzer Engine (`fuzzer.py`)
- **Purpose**: Socket-based test execution and monitoring
- **Key Classes**:
  - `LDAPFuzzer`: Main fuzzing engine
  - `FuzzResult`: Test result data structure
  - `ServerStatus`: Enum for server response states
- **Features**: Health checks, connection management, timing analysis

#### 5. Scapy Integration (`scapy_crafter/`)
- **Purpose**: Packet-level testing with Scapy
- **Key Features**:
  - Custom LDAP protocol layers for Scapy
  - Raw packet manipulation
  - Response capture and analysis
  - Layer 3/4 control

#### 6. Test Harness (`test_harness/`)
- **Purpose**: Unified interface and results management
- **Key Features**:
  - Single CLI for both testing methods
  - Multi-format output (JSON, CSV, HTML, MD)
  - Configuration file support
  - Summary statistics and findings

---

## 📊 Expected Results

### Secure LDAP Server Behavior

A properly implemented LDAP server should:

✅ **Return Protocol Error (2)** for malformed BER encodings
✅ **Not crash** when receiving invalid input
✅ **Close connections gracefully** if rejecting malformed data
✅ **Respond quickly** (< 1 second typical)
✅ **Not leak information** in error messages

### Concerning Behaviors

🚨 **Server crashes** (connection_closed, connection_refused)
🚨 **Hangs/Timeouts** (no response for extended period)
🚨 **Accepts malformed input** (processes invalid BER)
🚨 **Buffer overflows** (segfaults, memory corruption)
🚨 **Resource exhaustion** (CPU/memory spikes)

---

## 📦 Dependencies

### Required
- **Python 3.7+**
- Standard library only (for socket-based fuzzer)

### Optional
- **Scapy** (`pip install scapy`) - For packet-level testing
- **PyYAML** (`pip install pyyaml`) - For YAML config files
- **Npcap** (Windows only) - For Scapy packet capture

### Installation

```bash
# Install optional dependencies
pip install -r requirements.txt

# Or individually
pip install scapy pyyaml
```

---

## 🧪 Testing Workflow

### 1. Initial Assessment
```bash
# Run all tests to get baseline
python test_runner.py <target> -o baseline.json
```

### 2. Analyze Results
```bash
# Generate HTML report for review
python test_runner.py <target> -o report.html
# Open report.html in browser
```

### 3. Investigate Issues
```bash
# Run problematic suite individually
python test_runner.py <target> --suite 1.1.1 -t 10 -v
```

### 4. Document Findings
- Review which tests caused crashes
- Examine server logs for errors
- Capture packet traces if needed
- Document reproduction steps

### 5. Report Vulnerabilities
- Use provided test IDs for reference
- Include packet hex dumps from results
- Follow responsible disclosure practices

---

## 🔐 Security Considerations

### Authorization Requirements

⚠️ **CRITICAL**: Only test systems you are authorized to test

- Obtain written permission before testing
- Use isolated test environments
- Not for use against production systems without approval
- Follow applicable laws and regulations

### Safe Testing Practices

1. **Isolated Network**: Test on separate network segment
2. **Test Instances**: Use dedicated test servers
3. **Backups**: Ensure recent backups exist
4. **Monitoring**: Watch server during tests
5. **Documentation**: Log all testing activities

### Ethical Use

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security research
- ✅ Vulnerability assessment
- ✅ Compliance testing
- ✅ Educational purposes

Not for:
- ❌ Unauthorized testing
- ❌ Malicious attacks
- ❌ Production disruption
- ❌ Data theft

---

## 🐛 Troubleshooting

### Common Issues

**"Connection refused"**
- Verify LDAP server is running
- Check firewall rules
- Confirm correct IP/port

**"Module not found"**
- Run from `tools/test_harness` directory
- Check Python path configuration

**"Scapy not working"**
- Install: `pip install scapy`
- Windows: Install Npcap
- Linux: May need sudo or capabilities

**"Server crashes"**
- This is a security finding! Document thoroughly
- Note which test case causes crash
- Review server logs
- Attempt to reproduce

---

## 📚 Key Files Reference

### Documentation
- **README.md**: Complete usage documentation (comprehensive)
- **QUICKSTART.md**: 5-minute getting started guide
- **PROJECT_OVERVIEW.md**: This file - project summary
- **examples/example_usage.py**: 6 working code examples

### Configuration
- **requirements.txt**: Python package dependencies
- **config.json** (example): JSON configuration template
- **config.yaml** (example): YAML configuration template

### Main Entry Points
- **test_harness/test_runner.py**: Primary CLI tool
- **asn1_fuzzer/fuzzer.py**: Direct fuzzer usage
- **scapy_crafter/test_sender.py**: Scapy-based testing

### Test Case Definitions
- **asn1_fuzzer/fuzz_generators.py**: All 16 test case implementations

---

## 💡 Future Enhancement Ideas

### Potential Additions
- [ ] Additional RFC 4511 test cases (1.2.x, 1.3.x, etc.)
- [ ] TLS/StartTLS support
- [ ] SASL authentication testing
- [ ] Filter injection test cases
- [ ] Continuous monitoring mode
- [ ] Integration with CI/CD pipelines
- [ ] Docker containerization
- [ ] Web-based dashboard

### Extension Points
- New test cases: Add to `fuzz_generators.py`
- Custom encoders: Extend `ber_encoder.py`
- Output formats: Enhance `results_logger.py`
- Protocol operations: Add to `ldap_messages.py`

---

## 📞 For Future Sessions

### Quick Context

When resuming work on this project, remember:

1. **Purpose**: Testing LDAP servers for RFC 4511 ASN.1/BER vulnerabilities
2. **Status**: Fully functional, 16 test cases implemented
3. **Testing**: Socket-based (no deps) or Scapy-based (requires scapy)
4. **Usage**: `cd tools/test_harness && python test_runner.py <target>`

### Important Locations

- **Main CLI**: `tools/test_harness/test_runner.py`
- **Test Cases**: `tools/asn1_fuzzer/fuzz_generators.py`
- **Documentation**: `tools/README.md`, `tools/QUICKSTART.md`
- **Examples**: `tools/examples/example_usage.py`

### Key Design Decisions

1. **Two methods**: Socket (no deps) and Scapy (advanced) for flexibility
2. **Modular**: Clear separation between encoder, messages, fuzzer, harness
3. **Extensible**: Easy to add new test cases or output formats
4. **Documented**: Comprehensive inline comments and external docs
5. **Parameterized**: All target info passed as parameters (environment-agnostic)

### Testing the Tools

```bash
# Non-destructive test (examples only, no packets sent)
cd tools
python examples/example_usage.py

# Full test against target (requires LDAP server)
cd tools/test_harness
python test_runner.py <YOUR_TARGET_IP> -o test_results.json
```

---

## 📈 Project Statistics

- **Total Files**: 13 Python modules + 4 documentation files
- **Total Lines of Code**: ~3,500+
- **Test Cases**: 16 (6 + 5 + 5 across 3 suites)
- **Output Formats**: 4 (JSON, CSV, HTML, Markdown)
- **Testing Methods**: 2 (Socket, Scapy)
- **Documentation**: 4 comprehensive guides

---

## ✅ Checklist for Use

Before running tests:
- [ ] Have authorization to test target system
- [ ] Target is test/dev environment (not production)
- [ ] Recent backups exist
- [ ] Monitoring is in place
- [ ] Documentation plan ready

After running tests:
- [ ] Review results for crashes/hangs
- [ ] Examine server logs
- [ ] Document all findings
- [ ] Follow up on vulnerabilities
- [ ] Maintain responsible disclosure

---

**Last Updated**: 2025-10-29
**Version**: 1.0.0
**Status**: Production Ready ✅

**Created by**: Claude Code
**Test Plan Reference**: RFC 4511 Security Assessment, Sections 1.1.1, 1.1.2, 1.1.3
