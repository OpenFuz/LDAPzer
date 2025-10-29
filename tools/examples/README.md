# Examples

Example scripts demonstrating various ways to use the LDAP security testing tools.

## Purpose

These examples show how to:
- Use the fuzzing tools programmatically
- Integrate into your own test scripts
- Craft custom test cases
- Analyze and log results
- Work with both socket and Scapy methods

## Contents

### example_usage.py

Comprehensive example script with 6 demonstrations:

1. **Basic Fuzzing** - Socket-based fuzzer basics
2. **Specific Test Suite** - Run individual test suites
3. **Scapy Packet Crafting** - Manual packet construction
4. **Custom Malformed Packets** - Create your own test cases
5. **Results Logging** - Format and export results
6. **Unified Test Runner** - Using the test harness

## Usage

### Run All Examples (Non-Destructive)

```bash
# From tools directory
python examples/example_usage.py
```

**Safe**: Does not send packets to any server, just demonstrates code.

### Run Against Actual Target

```bash
# This WILL send test packets
python examples/example_usage.py --run-tests <target_ip>

# Example
python examples/example_usage.py --run-tests 192.168.1.100
```

**Warning**: This sends real malformed packets to the target.

## Example Highlights

### Example 1: Basic Fuzzing

Shows how to:
- Create a fuzzer instance
- Configure target and timing
- Run all test cases
- Access results

```python
from asn1_fuzzer.fuzzer import LDAPFuzzer

fuzzer = LDAPFuzzer(
    target_host='192.168.1.100',
    target_port=389,
    timeout=5.0
)

results = fuzzer.run_all_test_cases()
```

### Example 2: Specific Test Suite

Demonstrates:
- Loading specific test cases
- Running a single suite
- Analyzing results

```python
from asn1_fuzzer.fuzz_generators import get_all_test_cases

all_tests = get_all_test_cases()
suite_1_1_1 = all_tests['1.1.1']

results = fuzzer.run_test_suite(suite_1_1_1)
```

### Example 3: Scapy Packet Crafting

Illustrates:
- Manual packet construction with Scapy
- Creating standard LDAP messages
- Sending custom packets

```python
from scapy_crafter.packet_crafter import LDAPPacketCrafter

crafter = LDAPPacketCrafter(target_ip='192.168.1.100')
bind_msg = crafter.craft_bind_request(
    dn='cn=admin,dc=example,dc=com',
    password='secret'
)
```

### Example 4: Custom Malformed Packets

Shows how to:
- Build custom BER encodings
- Create malformed length fields
- Construct attack payloads

```python
from asn1_fuzzer.ber_encoder import BEREncoder

# Create SEQUENCE with malformed length
malformed_length = bytes([0x84, 0xFF, 0xFF, 0xFF, 0xFF])
malformed_packet = sequence_tag + malformed_length + content
```

### Example 5: Results Logging

Demonstrates:
- Logging test results
- Exporting to multiple formats
- Generating summary statistics

```python
from test_harness.results_logger import ResultsLogger

logger = ResultsLogger()
logger.log_socket_results(results)
logger.save('results.json')
logger.print_summary()
```

### Example 6: Unified Test Runner

Shows usage of:
- Unified test runner interface
- Both socket and Scapy methods
- Configuration options

```python
from test_harness.test_runner import UnifiedTestRunner, TestMethod

runner = UnifiedTestRunner(
    target_host='192.168.1.100',
    method=TestMethod.SOCKET
)
results = runner.run_all_tests()
```

## When to Use

**Use these examples when**:
- Learning how to use the tools
- Building custom test scripts
- Integrating into CI/CD pipelines
- Creating custom test cases
- Understanding the API

## Customization

### Creating Your Own Examples

```python
# my_custom_test.py
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from asn1_fuzzer.fuzzer import LDAPFuzzer

# Your custom test logic here
def my_test():
    fuzzer = LDAPFuzzer(target_host='192.168.1.100')
    # ...

if __name__ == "__main__":
    my_test()
```

### Extending Test Cases

Add to `asn1_fuzzer/fuzz_generators.py`:

```python
class TestCase_Custom:
    @staticmethod
    def generate_all_tests():
        tests = []
        tests.append({
            'id': 'custom.1',
            'name': 'My Custom Test',
            'description': 'What it tests',
            'packet': TestCase_Custom._my_packet(),
            'expected': 'Expected behavior'
        })
        return tests
```

## Output

Running the examples produces output like:

```
======================================================================
LDAP Protocol Security Testing Tools - Example Usage
======================================================================

This script demonstrates various ways to use the tools.
Examples are non-destructive and don't require a target server.

NOTE: Some examples are demonstration only and don't actually
      send packets. Uncomment send_packet() calls to enable.

======================================================================
Example 1: Basic Fuzzing with Socket-based Fuzzer
======================================================================

Testing 192.168.1.100:389
Running all test cases (1.1.1, 1.1.2, 1.1.3)...

[Output continues...]
```

## Programmatic API Reference

### Key Classes

- **LDAPFuzzer**: Socket-based fuzzing engine
- **LDAPPacketCrafter**: Scapy packet crafting
- **UnifiedTestRunner**: Unified test interface
- **ResultsLogger**: Results management
- **TestCase_X_Y_Z**: Test case generators

### Key Functions

- `get_all_test_cases()`: Get all test case definitions
- `run_test_suite(cases)`: Run specific test cases
- `craft_bind_request()`: Create BindRequest
- `craft_search_request()`: Create SearchRequest
- `log_socket_results()`: Log fuzzer results

## Dependencies

**Required**: None (Python stdlib)
**Optional**: scapy (for Example 3)

## See Also

- `../README.md` - Complete tool documentation
- `../QUICKSTART.md` - Quick start guide
- `../asn1_fuzzer/` - Fuzzer implementation
- `../scapy_crafter/` - Scapy integration
- `../test_harness/` - Test orchestration

## Tips

1. **Start with non-destructive** - Run without `--run-tests` first
2. **Read the code** - Examples are well-commented
3. **Modify and experiment** - Safe to change and re-run
4. **Check imports** - Shows which modules to use
5. **Follow patterns** - Use as templates for your own scripts

---

**Run examples**: `python examples/example_usage.py`
**Get help**: Read inline comments in `example_usage.py`
