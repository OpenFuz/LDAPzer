# LDAP Protocol Security Testing Tools

Comprehensive tools for testing LDAP server implementations against RFC 4511 security test cases 1.1.1, 1.1.2, and 1.1.3 (ASN.1/BER Encoding Violations).

## Overview

This toolkit provides two complementary approaches for LDAP protocol security testing:

1. **ASN.1 Fuzzer** - Socket-based fuzzer for generating and sending malformed BER-encoded LDAP messages
2. **Scapy Packet Crafter** - Low-level packet crafting with Scapy for maximum control

Both tools implement test cases from the RFC 4511 Security Assessment Plan:
- **Test Case 1.1.1**: Length Encoding Attacks
- **Test Case 1.1.2**: Type Encoding Violations
- **Test Case 1.1.3**: Value Encoding Issues

## Directory Structure

```
tools/
├── asn1_fuzzer/          # ASN.1/BER fuzzing engine
│   ├── ber_encoder.py    # BER encoding primitives
│   ├── ldap_messages.py  # LDAP message constructors
│   ├── fuzz_generators.py # Test case generators
│   └── fuzzer.py         # Main fuzzing engine
│
├── scapy_crafter/        # Scapy-based packet crafter
│   ├── ldap_layers.py    # Scapy LDAP protocol layers
│   ├── packet_crafter.py # Packet crafting utilities
│   └── test_sender.py    # Test execution with Scapy
│
└── test_harness/         # Unified test orchestration
    ├── test_runner.py    # Main test runner
    └── results_logger.py # Results collection and reporting
```

## Installation

### Requirements

**Python 3.7+** required

### Basic Installation (Socket-based fuzzer only)

No additional dependencies required - uses only Python standard library.

### Full Installation (with Scapy support)

```bash
# Install Scapy for packet crafting capabilities
pip install scapy

# Optional: For YAML configuration support
pip install pyyaml
```

### Windows Notes

On Windows, Scapy requires Npcap for packet capture:
1. Download Npcap from https://npcap.com/
2. Install with "WinPcap API-compatible mode" enabled

## Quick Start

### 1. Basic Fuzzing (Socket Method)

Test your LDAP server with all test cases using the socket-based fuzzer:

```bash
cd tools/test_harness
python test_runner.py 192.168.1.100
```

### 2. Run Specific Test Suite

```bash
# Test only length encoding attacks (1.1.1)
python test_runner.py 192.168.1.100 --suite 1.1.1

# Test only type encoding violations (1.1.2)
python test_runner.py 192.168.1.100 --suite 1.1.2

# Test only value encoding issues (1.1.3)
python test_runner.py 192.168.1.100 --suite 1.1.3
```

### 3. Using Scapy Method

```bash
# Use Scapy for packet-level control
python test_runner.py 192.168.1.100 --method scapy
```

### 4. Save Results

```bash
# Export results to JSON
python test_runner.py 192.168.1.100 -o results.json

# Generate HTML report
python test_runner.py 192.168.1.100 -o report.html
```

## Detailed Usage

### ASN.1 Fuzzer (Socket-based)

Direct usage of the ASN.1 fuzzer:

```python
from asn1_fuzzer.fuzzer import LDAPFuzzer

# Create fuzzer instance
fuzzer = LDAPFuzzer(
    target_host='192.168.1.100',
    target_port=389,
    timeout=5.0,
    delay_between_tests=0.1
)

# Run all test cases
results = fuzzer.run_all_test_cases()

# Access results
for suite_id, test_results in results.items():
    print(f"Suite {suite_id}: {len(test_results)} tests")
    for result in test_results:
        print(f"  {result.test_id}: {result.server_status.value}")
```

### Scapy Packet Crafter

Manual packet crafting with Scapy:

```python
from scapy_crafter.packet_crafter import LDAPPacketCrafter

# Create crafter
crafter = LDAPPacketCrafter(
    target_ip='192.168.1.100',
    target_port=389
)

# Craft and send a bind request
bind_msg = crafter.craft_bind_request(
    dn='cn=admin,dc=example,dc=com',
    password='secret'
)
response = crafter.send_packet(bind_msg)

# Craft malformed packet
from asn1_fuzzer.fuzz_generators import TestCase_1_1_1_LengthEncodingAttacks
malformed = TestCase_1_1_1_LengthEncodingAttacks._indefinite_length()
response = crafter.send_packet(malformed)
```

### Test Runner (Unified Interface)

The test runner provides a unified interface for both methods:

```bash
# Full command-line options
python test_runner.py TARGET [OPTIONS]

Options:
  -p, --port PORT          Target port (default: 389)
  -m, --method METHOD      Test method: socket or scapy (default: socket)
  -s, --suite SUITE        Test suite: 1.1.1, 1.1.2, 1.1.3, or all
  -t, --timeout SECONDS    Response timeout (default: 5.0)
  -d, --delay SECONDS      Delay between tests (default: 0.1)
  --no-health-check        Disable server health checks
  --source-ip IP           Source IP for Scapy (optional)
  -o, --output FILE        Output file (JSON, CSV, HTML, or MD)
  -c, --config FILE        Load configuration from file
  -v, --verbose            Verbose output
```

### Configuration File

Create a configuration file to avoid passing parameters each time:

**config.json:**
```json
{
  "target": "192.168.1.100",
  "port": 389,
  "method": "socket",
  "timeout": 5.0,
  "delay": 0.1,
  "output": "results.json"
}
```

**config.yaml:**
```yaml
target: 192.168.1.100
port: 389
method: socket
timeout: 5.0
delay: 0.1
output: results.json
```

Usage:
```bash
python test_runner.py --config config.json
```

## Test Cases

### 1.1.1 - Length Encoding Attacks

Tests server handling of malformed BER length fields:

- **1.1.1.1**: Indefinite length encoding (0x80) - prohibited in LDAP
- **1.1.1.2**: Length value shorter than actual data
- **1.1.1.3**: Length value longer than actual data
- **1.1.1.4**: Length = maxInt (2147483647)
- **1.1.1.5**: Length = 0xFFFFFFFF (32-bit overflow)
- **1.1.1.6**: Huge length value beyond packet boundary

**Expected Results**: Server should reject with `protocolError (2)` and not crash.

### 1.1.2 - Type Encoding Violations

Tests server handling of invalid BER tag encodings:

- **1.1.2.1**: Invalid/reserved tag number (0xFF)
- **1.1.2.2**: Constructed encoding for primitive type (OCTET STRING)
- **1.1.2.3**: Primitive encoding for constructed type (SEQUENCE)
- **1.1.2.4**: Unrecognized APPLICATION tag
- **1.1.2.5**: Unknown context-specific tag

**Expected Results**: Server should reject with `protocolError (2)`.

### 1.1.3 - Value Encoding Issues

Tests server handling of malformed BER value encodings:

- **1.1.3.1**: BOOLEAN with invalid value (not 0x00 or 0xFF)
- **1.1.3.2**: INTEGER with unnecessary leading zeros
- **1.1.3.3**: Empty INTEGER (zero-length)
- **1.1.3.4**: ENUMERATED with out-of-range value
- **1.1.3.5**: Oversized INTEGER encoding

**Expected Results**: Server should reject with `protocolError (2)` or handle gracefully.

## Results Analysis

### Result Formats

The tools support multiple output formats:

#### JSON (Machine-readable)
```json
{
  "metadata": {
    "timestamp": "2025-10-29T10:30:00",
    "test_plan": "RFC 4511 - Test Cases 1.1.1, 1.1.2, 1.1.3"
  },
  "summary": {
    "total_tests": 16,
    "status_counts": {
      "protocol_error": 14,
      "connection_closed": 2
    }
  },
  "results": [...]
}
```

#### CSV (Spreadsheet import)
```csv
test_id,test_name,server_status,result_code,response_time_ms
1.1.1.1,Indefinite Length Encoding,protocol_error,2,12.5
```

#### Markdown (Documentation)
```markdown
# LDAP Protocol Security Assessment Results

## Summary Statistics
- **Total Tests:** 16
- **Protocol Errors:** 14
- **Connection Closed:** 2
```

#### HTML (Visual report)
Full HTML report with tables and styling.

### Converting Between Formats

```bash
# Convert JSON results to other formats
cd test_harness
python results_logger.py results.json -o report.html -f html
python results_logger.py results.json -o report.md -f markdown
python results_logger.py results.json -o results.csv -f csv
```

## Advanced Usage

### Custom Test Case Development

Create custom malformed packets:

```python
from asn1_fuzzer.ber_encoder import BEREncoder, BERLength
from scapy_crafter.packet_crafter import ManualCrafter

# Craft custom BER element with malformed length
tag = 0x30  # SEQUENCE
malformed_length = bytes([0x84, 0xFF, 0xFF, 0xFF, 0xFF])  # Overflow
value = b"test data"

custom_packet = bytes([tag]) + malformed_length + value

# Send it
from scapy_crafter.packet_crafter import LDAPPacketCrafter
crafter = LDAPPacketCrafter('192.168.1.100')
response = crafter.send_packet(custom_packet)
```

### Programmatic Test Execution

Integrate into your own testing framework:

```python
from test_harness.test_runner import UnifiedTestRunner, TestMethod
from test_harness.results_logger import ResultsLogger

# Create runner
runner = UnifiedTestRunner(
    target_host='192.168.1.100',
    method=TestMethod.SOCKET,
    timeout=5.0
)

# Run tests
results = runner.run_all_tests()

# Log results
logger = ResultsLogger('results.json')
logger.log_socket_results(runner.get_results())
logger.save()
logger.print_summary()
```

### Extending Test Cases

Add your own test cases to `fuzz_generators.py`:

```python
class TestCase_1_1_4_CustomTests:
    """Custom test cases"""

    @staticmethod
    def generate_all_tests() -> List[Dict]:
        tests = []

        tests.append({
            'id': '1.1.4.1',
            'name': 'My Custom Test',
            'description': 'Description of what this tests',
            'packet': TestCase_1_1_4_CustomTests._my_custom_packet(),
            'expected': 'Expected server behavior'
        })

        return tests

    @staticmethod
    def _my_custom_packet() -> bytes:
        # Build your custom malformed packet
        return b'...'
```

## Troubleshooting

### Socket Connection Issues

If you see "Connection refused" errors:
```bash
# Verify LDAP server is running
nc -zv 192.168.1.100 389

# Check firewall rules
# Ensure target port (389) is accessible
```

### Scapy Installation Issues

**Windows**: Install Npcap from https://npcap.com/

**Linux**: Run with sudo or configure capabilities:
```bash
sudo setcap cap_net_raw=eip $(which python3)
```

**macOS**: Run with sudo:
```bash
sudo python test_runner.py 192.168.1.100 --method scapy
```

### Server Crashes During Testing

This is a potential security issue! Document:
- Which test case caused the crash
- Server logs at time of crash
- Ability to reproduce

The test runner includes health checks to detect crashes:
```bash
# Run with health checks (default)
python test_runner.py 192.168.1.100

# Disable health checks to run all tests even if server crashes
python test_runner.py 192.168.1.100 --no-health-check
```

## Security Considerations

### Authorization

**IMPORTANT**: Only run these tests against systems you are authorized to test.

- Obtain written permission before testing
- Use isolated test environments when possible
- Document all testing activities
- Follow responsible disclosure for any findings

### Test Environment Best Practices

1. **Isolated Network**: Test on isolated network segment
2. **Test Instances**: Use dedicated test instances, not production
3. **Backups**: Ensure backups before testing
4. **Monitoring**: Monitor server during testing for crashes/hangs
5. **Logging**: Enable detailed server logging to capture issues

## Expected Server Behavior

According to RFC 4511, a compliant LDAP server should:

1. **Reject malformed BER**: Return `protocolError (2)` result code
2. **Not crash**: Continue operating after receiving malformed input
3. **Close gracefully**: If closing connection, do so gracefully
4. **No buffer overflows**: Handle oversized values safely
5. **No information disclosure**: Error messages should not leak sensitive data

## Contributing

To add new test cases or improve existing ones:

1. Add test case generator to `fuzz_generators.py`
2. Update this README with test case documentation
3. Test against reference LDAP implementation (e.g., OpenLDAP)
4. Verify expected results match RFC 4511 requirements

## References

- **RFC 4511**: Lightweight Directory Access Protocol (LDAP): The Protocol
  https://tools.ietf.org/html/rfc4511

- **RFC 4513**: LDAP Authentication Methods and Security Mechanisms
  https://tools.ietf.org/html/rfc4513

- **ITU-T X.690**: ASN.1 encoding rules (BER, DER, CER)
  https://www.itu.int/rec/T-REC-X.690/

## License

This tool is provided for authorized security testing purposes only.

## Support

For issues or questions:
1. Check this README
2. Review the test plan document
3. Examine source code comments
4. Review RFC 4511 specifications

---

**Version**: 1.0.0
**Date**: 2025-10-29
**Test Plan**: RFC 4511 Security Assessment - Test Cases 1.1.1, 1.1.2, 1.1.3
