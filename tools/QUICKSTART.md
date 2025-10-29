# Quick Start Guide

Get started testing your LDAP server in 5 minutes.

## Prerequisites

- **Python 3.7+** installed
- **Target LDAP server** IP address or hostname
- **Authorization** to test the target system

## Basic Setup

No installation required! The socket-based fuzzer uses only Python standard library.

Optional: For Scapy support:
```bash
pip install scapy
```

---

## 🔄 Complete Workflow

Here's the recommended order for using the tools:

### 1️⃣ Preflight Check (Recommended)
Verify your LDAP server is accessible and ready:
```bash
cd tools
python preflight_checks/baseline_test.py <TARGET_IP>
```
**Why?** Ensures the server is running and responsive before fuzzing.

### 2️⃣ Run Fuzzing Tests
Execute the security tests:
```bash
cd test_harness
python test_runner.py <TARGET_IP> -o results.json
```
**Why?** This runs all 16 test cases against your server.

### 3️⃣ Review Results
Analyze what was found:
```bash
# View in browser
python test_runner.py <TARGET_IP> -o report.html
# Open report.html

# Or print summary
python results_logger.py results.json
```
**Why?** Understand which tests passed/failed and identify vulnerabilities.

### 4️⃣ Learn More (Optional)
See example code:
```bash
cd ../
python examples/example_usage.py
```
**Why?** Learn how to use the tools programmatically or create custom tests.

---

## 📊 Visual Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    Start Here                                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Preflight Check (Recommended)                      │
│  ────────────────────────────────────────────               │
│  python preflight_checks/baseline_test.py <TARGET_IP>       │
│                                                              │
│  ✓ Tests TCP connectivity                                   │
│  ✓ Verifies LDAP responses                                  │
│  ✓ Checks malformed packet handling                         │
└─────────────────────────────────────────────────────────────┘
                            │
                   ┌────────┴────────┐
                   │   Tests Pass?    │
                   └────────┬────────┘
                            │ Yes
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Run Fuzzing Tests                                  │
│  ──────────────────────────────────────                     │
│  cd test_harness                                            │
│  python test_runner.py <TARGET_IP> -o results.json         │
│                                                              │
│  • Runs 16 test cases (1.1.1, 1.1.2, 1.1.3)                │
│  • Tests ASN.1/BER encoding vulnerabilities                 │
│  • Detects crashes, hangs, and errors                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: Review Results                                     │
│  ───────────────────────────                                │
│  Option A: HTML Report (visual)                             │
│    python test_runner.py <TARGET_IP> -o report.html        │
│    open report.html                                         │
│                                                              │
│  Option B: JSON (programmatic)                              │
│    cat results.json                                         │
│                                                              │
│  Option C: Summary (quick)                                  │
│    python results_logger.py results.json                    │
└─────────────────────────────────────────────────────────────┘
                            │
                  ┌─────────┴──────────┐
                  │  Want to learn     │
                  │  more or customize?│
                  └─────────┬──────────┘
                            │ Yes
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 4: Explore Examples (Optional)                        │
│  ────────────────────────────────────────                   │
│  python examples/example_usage.py                           │
│                                                              │
│  • See 6 code examples                                      │
│  • Learn programmatic usage                                 │
│  • Create custom test cases                                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Done! 🎉                                   │
│                                                              │
│  Next steps:                                                │
│  • Document findings                                        │
│  • Report vulnerabilities                                   │
│  • Test other RFC 4511 sections                            │
└─────────────────────────────────────────────────────────────┘
```

---

## Run Your First Test

### Step 1: Navigate to tools directory

```bash
cd tools/test_harness
```

### Step 2: Run all tests

Replace `TARGET_IP` with your LDAP server's IP address:

```bash
python test_runner.py TARGET_IP
```

Example:
```bash
python test_runner.py 192.168.1.100
```

### Step 3: Review output

You'll see output like:
```
======================================================================
Running Test Suite 1.1.1
======================================================================

Running test 1.1.1.1: Indefinite Length Encoding
  Result: protocol_error - Protocol Error (2) (0.012s)

Running test 1.1.1.2: Length Too Short
  Result: connection_closed - Server closed connection (0.001s)

...

Suite 1.1.1 Summary:
  Total tests: 6
  Server responded: 4
  Server crashed/closed: 2
```

## Common Commands

### Test specific suite only

```bash
# Test length encoding attacks only
python test_runner.py 192.168.1.100 --suite 1.1.1

# Test type encoding violations only
python test_runner.py 192.168.1.100 --suite 1.1.2

# Test value encoding issues only
python test_runner.py 192.168.1.100 --suite 1.1.3
```

### Save results to file

```bash
# Save as JSON
python test_runner.py 192.168.1.100 -o results.json

# Save as HTML report
python test_runner.py 192.168.1.100 -o report.html

# Save as Markdown
python test_runner.py 192.168.1.100 -o report.md
```

### Adjust timing

```bash
# Longer timeout (10 seconds)
python test_runner.py 192.168.1.100 -t 10

# Longer delay between tests (1 second)
python test_runner.py 192.168.1.100 -d 1.0

# Both
python test_runner.py 192.168.1.100 -t 10 -d 1.0
```

### Use Scapy method

```bash
# Requires: pip install scapy
python test_runner.py 192.168.1.100 --method scapy
```

## Understanding Results

### Server Status Values

- **responsive**: Server sent a valid LDAP response
- **protocol_error**: Server returned protocolError (2) - **expected for malformed input**
- **connection_closed**: Server closed connection - **may indicate crash**
- **timeout**: No response received - **may indicate hang**
- **connection_refused**: Cannot connect to server

### What's Normal?

**Expected behavior** for a secure LDAP server:
- Most tests should return **protocol_error** (result code 2)
- Server should **not crash** (no connection_closed/refused)
- Server should **respond quickly** (< 1 second)

**Concerning behavior**:
- **Connection closed**: Server may have crashed
- **Timeout**: Server may be hanging
- **No protocol_error**: Server may accept malformed input

## Next Steps

### 1. Review Results

Check which tests caused issues:
```bash
# Generate HTML report for easy viewing
python test_runner.py 192.168.1.100 -o report.html

# Open report.html in browser
```

### 2. Investigate Crashes

If tests cause crashes:
1. Note which test case caused it (e.g., 1.1.1.2)
2. Check server logs
3. Verify server can be restarted
4. Review test case details in README.md

### 3. Run Individual Tests

To isolate an issue, run specific suite:
```bash
python test_runner.py 192.168.1.100 --suite 1.1.1
```

### 4. Customize Tests

See `examples/example_usage.py` for programmatic usage:
```bash
python examples/example_usage.py
```

### 5. Advanced Usage

Read `README.md` for:
- Custom test case development
- Integration with testing frameworks
- Detailed analysis techniques

## Troubleshooting

### "Connection refused"

Server is not running or firewall is blocking:
```bash
# Check if LDAP server is accessible
nc -zv 192.168.1.100 389

# On Windows, use PowerShell:
Test-NetConnection -ComputerName 192.168.1.100 -Port 389
```

### "Module not found"

Ensure you're running from the correct directory:
```bash
cd tools/test_harness
python test_runner.py 192.168.1.100
```

### Scapy not working

Install Scapy:
```bash
pip install scapy
```

On Windows, also install Npcap: https://npcap.com/

### Server keeps crashing

This is a **security vulnerability**! Document:
1. Which test causes crash
2. Server version and configuration
3. Steps to reproduce
4. Server logs

Then report to vendor following responsible disclosure.

## Example Session

Complete example with output:

```bash
$ cd tools/test_harness
$ python test_runner.py 192.168.1.100 -o results.json

======================================================================
LDAP Protocol Security Assessment - RFC 4511 Test Cases 1.1.x
======================================================================
Target: 192.168.1.100:389
Method: SOCKET
Timeout: 5.0s
Delay between tests: 0.1s
======================================================================

======================================================================
Running Test Suite 1.1.1
======================================================================
Running test suite with 6 test cases
Target: 192.168.1.100:389

Running test 1.1.1.1: Indefinite Length Encoding
  Result: protocol_error - Protocol Error (2) (0.012s)
Running test 1.1.1.2: Length Too Short
  Result: protocol_error - Protocol Error (2) (0.010s)
Running test 1.1.1.3: Length Too Long
  Result: timeout - Response timeout (5.001s)
...

Suite 1.1.1 Summary:
  Total tests: 6
  Server responded: 5
  Server crashed/closed: 1

[Similar output for suites 1.1.2 and 1.1.3]

======================================================================
All tests completed in 45.23 seconds
======================================================================

Results saved to results.json

✓ Test execution completed successfully
```

---

## 📋 Quick Reference - Tool Workflow

| Step | Tool | Command | Purpose | Required? |
|------|------|---------|---------|-----------|
| **1** | **Preflight Check** | `python preflight_checks/baseline_test.py <IP>` | Verify server is accessible and responsive | ⭐ Recommended |
| **2** | **Fuzzing Tests** | `python test_harness/test_runner.py <IP> -o results.json` | Run all 16 security test cases | ✅ Required |
| **3** | **Review Results** | `python test_harness/results_logger.py results.json` | Analyze findings and generate reports | ✅ Required |
| **4** | **Examples** | `python examples/example_usage.py` | Learn API and see code examples | ⚪ Optional |

### Common Options

| Option | Flag | Example | Description |
|--------|------|---------|-------------|
| **Output file** | `-o FILE` | `-o results.json` | Save results to file |
| **Test suite** | `--suite ID` | `--suite 1.1.1` | Run specific suite only |
| **Timeout** | `-t SECONDS` | `-t 10` | Response timeout |
| **Delay** | `-d SECONDS` | `-d 0.5` | Delay between tests |
| **Method** | `--method METHOD` | `--method scapy` | Use scapy instead of socket |
| **Port** | `-p PORT` | `-p 10389` | Custom LDAP port |

### Output Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| **JSON** | `.json` | Programmatic analysis, CI/CD integration |
| **HTML** | `.html` | Visual reports, easy browsing |
| **Markdown** | `.md` | Documentation, GitHub/GitLab |
| **CSV** | `.csv` | Spreadsheet import, data analysis |

---

## Safety Reminders

1. **Only test authorized systems**
2. **Use test environments, not production**
3. **Monitor server during testing**
4. **Have backups ready**
5. **Document all findings**

## Getting Help

- Read `README.md` for detailed documentation
- Check `example_usage.py` for code examples
- Review RFC 4511 for protocol details
- Examine test case source code in `fuzz_generators.py`

---

**Ready to test? Run this command:**

```bash
cd tools/test_harness && python test_runner.py YOUR_TARGET_IP -o results.json
```
