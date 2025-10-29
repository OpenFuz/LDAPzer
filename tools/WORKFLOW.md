# LDAP Security Testing Tools - Workflow Guide

**Quick answer**: Follow these 4 steps in order.

---

## 🔄 The Complete Workflow

### Step 1: Preflight Check ⭐ (Recommended)

**Purpose**: Verify the target LDAP server is accessible and ready for testing.

```bash
cd tools
python preflight_checks/baseline_test.py 192.168.1.100
```

**What it does**:
- Tests TCP connectivity (can we connect?)
- Verifies LDAP responses (does it respond?)
- Checks malformed packet handling (does it crash on bad input?)
- Takes ~5 seconds

**Expected result**: 4/4 tests pass → Server is ready

**If it fails**: Check server is running, firewall is open, correct IP/port

---

### Step 2: Run Fuzzing Tests ✅ (Required)

**Purpose**: Execute all security test cases against the target.

```bash
cd test_harness
python test_runner.py 192.168.1.100 -o results.json
```

**What it does**:
- Runs 16 test cases (ASN.1/BER encoding vulnerabilities)
- Tests length encoding attacks (6 tests)
- Tests type encoding violations (5 tests)
- Tests value encoding issues (5 tests)
- Takes ~2-3 minutes (depending on timeout settings)

**Expected result**: Test results saved to `results.json`

**Server behavior**:
- ✅ Good: Server responds with protocolError (2)
- ⚠️ Concerning: Server crashes or hangs

---

### Step 3: Review Results ✅ (Required)

**Purpose**: Analyze findings and identify vulnerabilities.

**Option A - HTML Report** (visual, easy to browse):
```bash
python test_runner.py 192.168.1.100 -o report.html
# Open report.html in browser
```

**Option B - JSON** (programmatic, for scripts):
```bash
cat results.json
# or
python -m json.tool results.json
```

**Option C - Summary** (quick overview):
```bash
python results_logger.py results.json
```

**What to look for**:
- **Protocol errors (2)**: Good - server rejected malformed input
- **Connection closed**: Bad - server may have crashed
- **Timeouts**: Bad - server may be hanging
- **Success (0)**: Bad - server accepted malformed input

---

### Step 4: Learn More ⚪ (Optional)

**Purpose**: Understand the tools better, create custom tests.

```bash
cd ..
python examples/example_usage.py
```

**What it shows**:
- 6 example scripts demonstrating tool usage
- How to use the API programmatically
- How to create custom test cases
- How to integrate into your own scripts

---

## 📊 Visual Workflow Diagram

```
START
  │
  ▼
┌─────────────────────────────────────┐
│ 1. Preflight Check (Recommended)    │
│ ─────────────────────────────────── │
│ baseline_test.py <IP>               │
│                                     │
│ Verifies: Connectivity, Response,   │
│           Malformed handling        │
└─────────────────┬───────────────────┘
                  │
            ┌─────▼─────┐
            │  Pass?    │
            └─────┬─────┘
                  │ Yes
                  ▼
┌─────────────────────────────────────┐
│ 2. Run Fuzzing (Required)           │
│ ─────────────────────────────────── │
│ test_runner.py <IP> -o results.json│
│                                     │
│ Runs: 16 test cases                │
│ Tests: ASN.1/BER vulnerabilities    │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ 3. Review Results (Required)        │
│ ─────────────────────────────────── │
│ results_logger.py results.json      │
│ OR open report.html                 │
│                                     │
│ Analyze: Crashes, errors, findings  │
└─────────────────┬───────────────────┘
                  │
            ┌─────▼─────┐
            │  Want to  │
            │  learn?   │
            └─────┬─────┘
                  │ Yes
                  ▼
┌─────────────────────────────────────┐
│ 4. Examples (Optional)              │
│ ─────────────────────────────────── │
│ example_usage.py                    │
│                                     │
│ Shows: Code examples, custom tests  │
└─────────────────┬───────────────────┘
                  │
                  ▼
                DONE!
```

---

## 📋 Quick Command Reference

### Essential Commands (Copy-Paste Ready)

```bash
# 1. Navigate to tools directory
cd /path/to/01-PingDS/tools

# 2. Run preflight check
python preflight_checks/baseline_test.py <YOUR_LDAP_IP>

# 3. Run fuzzing (if preflight passes)
cd test_harness
python test_runner.py <YOUR_LDAP_IP> -o results.json

# 4. View results
python results_logger.py results.json
# OR generate HTML report
python test_runner.py <YOUR_LDAP_IP> -o report.html
```

### Complete Example Session

```bash
# Set your target
TARGET=192.168.1.100

# Step 1: Preflight
cd tools
python preflight_checks/baseline_test.py $TARGET

# Step 2: Fuzz (assuming preflight passed)
cd test_harness
python test_runner.py $TARGET -o results.json

# Step 3: View results
python results_logger.py results.json

# Step 4: Generate HTML report
python test_runner.py $TARGET -o report.html
```

---

## ⚡ Common Variations

### Test Specific Suite Only

```bash
# Only test length encoding attacks
python test_runner.py 192.168.1.100 --suite 1.1.1

# Only test type encoding violations
python test_runner.py 192.168.1.100 --suite 1.1.2

# Only test value encoding issues
python test_runner.py 192.168.1.100 --suite 1.1.3
```

### Adjust Timing

```bash
# Slower, more thorough (10 second timeout, 1 second delay)
python test_runner.py 192.168.1.100 -t 10 -d 1.0

# Faster (2 second timeout, no delay)
python test_runner.py 192.168.1.100 -t 2 -d 0
```

### Use Scapy Method

```bash
# Requires: pip install scapy
python test_runner.py 192.168.1.100 --method scapy
```

### Custom Port

```bash
# For non-standard LDAP ports (e.g., ApacheDS uses 10389)
python preflight_checks/baseline_test.py localhost -p 10389
python test_runner.py localhost -p 10389
```

---

## 🎯 What Each Tool Does

| Tool | File | Purpose | When to Use |
|------|------|---------|-------------|
| **Preflight Check** | `preflight_checks/baseline_test.py` | Verify server is ready | Before fuzzing |
| **Fuzzer** | `test_harness/test_runner.py` | Run security tests | Main testing phase |
| **Results Logger** | `test_harness/results_logger.py` | Analyze results | After fuzzing |
| **Examples** | `examples/example_usage.py` | Learn the tools | When learning/customizing |

---

## 📂 Where Are The Tools?

```
tools/
├── preflight_checks/
│   └── baseline_test.py          ← Step 1
│
├── test_harness/
│   ├── test_runner.py             ← Step 2
│   └── results_logger.py          ← Step 3
│
└── examples/
    └── example_usage.py           ← Step 4
```

---

## 🚨 Important Notes

### Before You Start

- ✅ **Get authorization** to test the target system
- ✅ **Use test environment** (not production unless authorized)
- ✅ **Have backups** ready
- ✅ **Monitor the server** during testing

### Understanding Results

- **protocolError (2)** = ✅ Good - Server rejected malformed input correctly
- **Connection closed** = ⚠️ Bad - Server may have crashed
- **Timeout** = ⚠️ Bad - Server may be hanging
- **Success (0)** = ⚠️ Bad - Server accepted malformed input

### If Server Crashes

1. Note which test case caused it (e.g., 1.1.1.2)
2. Check server logs
3. Verify you can restart the server
4. Document for vulnerability report
5. This is a security finding!

---

## 📖 More Information

- **QUICKSTART.md** - 5-minute getting started guide
- **README.md** - Complete documentation
- **SERVER_REQUIREMENTS.md** - What you need on the server
- **PROJECT_OVERVIEW.md** - Technical overview
- **DEVELOPMENT_PROGRESS.md** - What's been built so far

---

## 💡 Pro Tips

1. **Always run preflight first** - Saves time if server isn't ready
2. **Start with one suite** - Use `--suite 1.1.1` to test incrementally
3. **Generate HTML reports** - Much easier to review than JSON
4. **Monitor server resources** - Watch CPU/memory during tests
5. **Document everything** - Note which tests cause issues

---

**Ready to start?**

```bash
cd tools
python preflight_checks/baseline_test.py YOUR_LDAP_SERVER_IP
```

**Questions?** Check the README.md or review the examples.

---

**Last Updated**: 2025-10-29
**Version**: 1.0.0
