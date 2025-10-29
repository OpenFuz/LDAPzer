# Preflight Checks

Server readiness verification utilities for LDAP security testing.

## Purpose

Run these checks **before** executing fuzzing tests to ensure:
1. The target LDAP server is accessible
2. The server responds to basic LDAP messages
3. The server handles malformed input appropriately
4. Baseline functionality is working

## Contents

### baseline_test.py

Comprehensive baseline test that verifies:
- **TCP Connectivity**: Can connect to LDAP port
- **Anonymous Bind**: Server responds to BindRequest
- **Search Request**: Server responds to SearchRequest
- **Malformed Rejection**: Server handles bad BER encoding

## Usage

```bash
# From tools directory
python preflight_checks/baseline_test.py <target_ip> [options]

# Examples
python preflight_checks/baseline_test.py 192.168.1.100
python preflight_checks/baseline_test.py localhost -p 389
python preflight_checks/baseline_test.py dc.example.com -t 10
```

### Options

- `-p, --port PORT`: Target port (default: 389)
- `-t, --timeout SECONDS`: Timeout in seconds (default: 5.0)

## Expected Output

### Successful Test

```
======================================================================
LDAP Server Baseline Test
======================================================================

Target: 192.168.1.100:389
Purpose: Verify server is ready for fuzzing tests

Running 4 baseline tests...

[1/4] Testing TCP connection to 192.168.1.100:389...
  ✓ TCP connection successful

[2/4] Testing anonymous bind...
  ✓ Anonymous bind successful (result code: 0 - success)

[3/4] Testing search request (root DSE)...
  ✓ Search request successful (response: 245 bytes)

[4/4] Testing malformed BER rejection...
  ✓ Server correctly returned protocolError (2)

======================================================================
BASELINE TEST SUMMARY
======================================================================
  ✓ PASS: TCP Connection
  ✓ PASS: Anonymous Bind
  ✓ PASS: Search Request
  ✓ PASS: Malformed Rejection

Result: 4/4 tests passed

✓ Server is READY for fuzzing tests

You can now run:
  cd test_harness
  python test_runner.py 192.168.1.100 -o results.json
```

### Acceptable Partial Pass

Even if anonymous bind is disabled, the test can still pass:

```
[2/4] Testing anonymous bind...
  ⚠ Anonymous bind returned strongerAuthRequired (8)
    Server may require authentication, but responding correctly

Result: 4/4 tests passed

✓ Server is READY for fuzzing tests
```

## When to Use

**Always run before fuzzing**:
1. Before starting a new assessment
2. After server configuration changes
3. When testing a new LDAP implementation
4. To verify server is still running between test suites

## Troubleshooting

**Connection refused**:
- Verify LDAP server is running
- Check firewall rules
- Confirm correct IP/port

**Timeout**:
- Increase timeout with `-t` flag
- Check network connectivity
- Verify no packet filtering

**All tests fail**:
- Server may not be LDAP compliant
- Check server logs for errors
- Try connecting with standard LDAP client tools

## Notes

- **No authentication required**: Tests use anonymous bind
- **No data needed**: Tests query root DSE which always exists
- **Non-destructive**: Only sends read operations
- **Quick**: Completes in seconds

## See Also

- `../SERVER_REQUIREMENTS.md` - Detailed server requirements
- `../ANSWER_ServerRequirements.md` - FAQ about server setup
- `../test_harness/test_runner.py` - Main fuzzing tool
