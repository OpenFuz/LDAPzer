# LDAP Server Requirements and Setup

## Overview

This document explains what's needed on the LDAP server side for the fuzzing tools to work effectively.

## TL;DR - Minimal Requirements

**✅ Good News**: The fuzzing tools work against **any LDAP server with minimal or no configuration**.

**Why?** All test cases target the **BER/ASN.1 parser layer**, which processes packets **BEFORE**:
- Authentication checks
- Authorization checks
- Data access
- Schema validation

The server should reject malformed BER encoding immediately upon receiving the packet.

---

## Detailed Requirements

### 1. TCP Connectivity

**Required**: LDAP server must be accessible on TCP port (default 389)

**How to verify**:
```bash
# Linux/Mac
nc -zv 192.168.1.100 389

# Windows PowerShell
Test-NetConnection -ComputerName 192.168.1.100 -Port 389

# Using Python baseline test
python preflight_checks/baseline_test.py 192.168.1.100
```

### 2. Server Must Be Running

**Required**: LDAP server process must be active and listening

**Common LDAP servers**:
- OpenLDAP
- Active Directory
- 389 Directory Server
- ApacheDS
- OpenDJ/ForgeRock Directory Server
- Any RFC 4511 compliant LDAP server

### 3. Anonymous Bind Support (Preferred)

**Preferred but not required**: Server should accept anonymous bind

**Why?** Our baseline test messages use anonymous bind (empty DN, empty password):
```python
BindRequest.create(version=3, name="", password="")
```

**If anonymous bind is disabled**:
- Server will reject with `authMethodNotSupported (7)` or `strongerAuthRequired (8)`
- **This is fine!** The BER parser still processes the packet
- Fuzzing tests will still work - malformed BER is rejected before auth

**How to enable anonymous bind** (if desired):

**OpenLDAP** - Add to `slapd.conf` or `cn=config`:
```ldif
# Allow anonymous bind
olcAllowAnonymous: TRUE

# Or in slapd.conf
allow bind_v2 bind_anon_cred bind_anon_dn
```

**Active Directory**: Anonymous bind disabled by default (and that's okay for our tests)

### 4. No Pre-Populated Data Needed

**Not required**: Empty directory is fine

**Why?** Test messages are designed to work against an empty directory:
- **BindRequest**: Uses anonymous bind (no user lookup needed)
- **SearchRequest**: Queries root DSE with base DN="" (always exists)
- **Malformed packets**: Rejected at parser level before data access

### 5. No Schema Configuration Needed

**Not required**: Default schema is sufficient

**Why?** We're not testing schema validation - we're testing BER parsing before schema is even evaluated.

### 6. No Special Permissions Needed

**Not required**: No administrative access needed

**Why?** Malformed packets are rejected at the protocol layer, not authorization layer.

---

## What Gets Tested

### Test Flow for Each Fuzzing Test

```
1. TCP Connection established
   ↓
2. Malformed LDAP packet sent
   ✓ (Server receives packet)
   ↓
3. BER/ASN.1 Parser processes packet  ← OUR TEST TARGET
   ✗ (Malformed BER detected)
   ↓
4. Server responds with protocolError (2) or closes connection
   ← EXPECTED BEHAVIOR


NEVER REACHED (for malformed packets):
   ↓
5. Authentication check
6. Authorization check
7. Data access
8. Schema validation
```

### Why This Matters

The fuzzing tools test **layer 1 (BER parsing)**, which happens **before everything else**.

This means:
- ✅ No user accounts needed
- ✅ No directory data needed
- ✅ No special permissions needed
- ✅ Works against hardened production configs
- ✅ Works against fresh installations

---

## Baseline Test

### Purpose

Before running fuzzing tests, verify the server is functioning and responsive.

### Running the Baseline Test

```bash
cd tools
python preflight_checks/baseline_test.py 192.168.1.100
```

### What It Tests

1. **TCP Connection**: Can we connect to the server?
2. **Anonymous Bind**: Does server respond to BindRequest?
3. **Search Request**: Does server respond to SearchRequest?
4. **Malformed Rejection**: Does server handle obviously bad BER?

### Expected Output

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

### If Anonymous Bind Fails

This is **still okay** for fuzzing:

```
[2/4] Testing anonymous bind...
  ⚠ Anonymous bind returned strongerAuthRequired (8)
    Server may require authentication, but responding correctly
```

The important part is that **the server responded**. The BER parser is working, which is what we're testing.

---

## Server-Specific Notes

### OpenLDAP

**Works out of the box**: Default configuration supports anonymous bind

**Minimal setup**:
```bash
# Install
sudo apt-get install slapd ldap-utils  # Ubuntu/Debian
sudo yum install openldap-servers      # RHEL/CentOS

# Start
sudo systemctl start slapd

# Test (default port 389)
python preflight_checks/baseline_test.py localhost
```

### Active Directory

**Works but anonymous bind disabled**: This is fine

**No setup needed**: Just run tests against DC:
```bash
python preflight_checks/baseline_test.py dc.example.com
```

Server will reject anonymous bind but still process packets correctly.

### ApacheDS

**Works out of the box**: Default configuration allows anonymous bind

**Default port**: 10389 (not 389)

```bash
python preflight_checks/baseline_test.py localhost -p 10389
```

### Docker OpenLDAP

**Quick test environment**:

```bash
# Start OpenLDAP in Docker
docker run -d -p 389:389 --name test-ldap \
  -e LDAP_ADMIN_PASSWORD=admin \
  osixia/openldap:latest

# Wait for startup
sleep 5

# Test
python preflight_checks/baseline_test.py localhost

# Cleanup
docker stop test-ldap && docker rm test-ldap
```

---

## Configuration Examples

### If You Want to Set Up Test Users (Optional)

**OpenLDAP LDIF**:
```ldif
# Add base DN
dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
o: Example Organization
dc: example

# Add test user
dn: cn=testuser,dc=example,dc=com
objectClass: person
cn: testuser
sn: User
userPassword: testpass
```

**Add to server**:
```bash
ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin -f test_data.ldif
```

**But remember**: This is **NOT required** for fuzzing tests!

### Enabling Anonymous Bind (If Desired)

**OpenLDAP slapd.conf**:
```
# Allow anonymous binds
allow bind_v2 bind_anon_cred bind_anon_dn
```

**OpenLDAP cn=config**:
```bash
ldapmodify -Y EXTERNAL -H ldapi:/// <<EOF
dn: cn=config
changetype: modify
replace: olcAllowAnonymous
olcAllowAnonymous: TRUE
EOF
```

---

## Troubleshooting

### "Connection refused"

**Problem**: Cannot connect to server

**Solutions**:
1. Verify LDAP server is running
   ```bash
   # Linux
   sudo systemctl status slapd

   # Check listening ports
   netstat -tlnp | grep 389
   ```

2. Check firewall
   ```bash
   # Allow LDAP through firewall
   sudo ufw allow 389/tcp
   ```

3. Verify correct IP/port
   ```bash
   # List all listening services
   sudo ss -tlnp
   ```

### "Connection timeout"

**Problem**: Packets not reaching server

**Solutions**:
1. Check network connectivity
   ```bash
   ping 192.168.1.100
   ```

2. Check routing
   ```bash
   traceroute 192.168.1.100
   ```

3. Verify no intermediate firewalls blocking

### "No response received"

**Problem**: Server not responding to LDAP messages

**Solutions**:
1. Verify it's actually an LDAP server:
   ```bash
   # Try with ldapsearch
   ldapsearch -x -H ldap://192.168.1.100 -b "" -s base
   ```

2. Check server logs for errors

3. Try different port (e.g., 10389 for ApacheDS)

### Server crashes during baseline test

**This is a security vulnerability!**

Document:
- Which test caused crash
- Server version
- Server logs
- How to reproduce

Then proceed with fuzzing to identify specific vulnerabilities.

---

## Security Considerations

### Testing Production Systems

**⚠️ WARNING**: Get authorization before testing production systems

**Better approach**: Set up test environment

**Why?**
- Fuzzing may crash vulnerable servers
- May trigger IDS/IPS alerts
- May consume resources
- Logs will show connection attempts

### Test Environment Best Practices

1. **Isolated network**: Use separate network segment
2. **Test instance**: Dedicated server for testing
3. **Match production**: Same version/config as production
4. **Backups**: Ensure backups before testing
5. **Monitoring**: Watch server during tests

### Logs and Forensics

The server will log fuzzing attempts:

**OpenLDAP** (`/var/log/syslog` or `/var/log/ldap.log`):
```
slapd[1234]: conn=1 fd=12 ACCEPT from IP=192.168.1.200:12345
slapd[1234]: conn=1 op=0 BIND dn="" method=128
slapd[1234]: conn=1 op=0 RESULT tag=97 err=2 text=protocol error
```

Result code 2 (protocol error) is expected for malformed packets.

---

## Summary Checklist

Before running fuzzing tests:

- [ ] LDAP server is installed and running
- [ ] Server is accessible on TCP port (default 389)
- [ ] Firewall allows connections
- [ ] Baseline test passes (run `python baseline_test.py <host>`)
- [ ] You have authorization to test this server
- [ ] Backups exist (if testing non-production)
- [ ] Monitoring is in place

**Optional** (not required):
- [ ] Anonymous bind enabled
- [ ] Test data populated
- [ ] Test users created

---

## Quick Start

```bash
# 1. Verify server is ready
cd tools
python preflight_checks/baseline_test.py 192.168.1.100

# 2. If baseline passes, run fuzzing
cd test_harness
python test_runner.py 192.168.1.100 -o results.json

# 3. Review results
python results_logger.py results.json -o report.html
```

---

## Questions?

**Q: Do I need admin credentials?**
A: No, tests run at protocol level before authentication.

**Q: Do I need directory data?**
A: No, we test BER parsing which happens before data access.

**Q: Will this work against hardened production LDAP?**
A: Yes, we test the parser which processes all packets.

**Q: What if anonymous bind is disabled?**
A: That's fine - BER parser still processes packets.

**Q: Can I test Active Directory?**
A: Yes, but you'll need network access to the DC.

**Q: Will fuzzing damage the directory data?**
A: No, malformed packets are rejected before data operations.

**Q: What if baseline test fails?**
A: Review the specific failures - some are acceptable (e.g., anonymous bind rejection).

---

**Ready to test?** Run the baseline test first:

```bash
python preflight_checks/baseline_test.py YOUR_LDAP_SERVER_IP
```
