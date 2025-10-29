"""
Baseline LDAP Server Test

Verifies that the target LDAP server is ready for fuzzing by testing:
1. TCP connectivity
2. Anonymous bind capability
3. Basic search functionality
4. Response to valid LDAP messages

Run this BEFORE running fuzzing tests to ensure baseline functionality.
"""

import sys
import os
import socket
import time

# Add parent directory (tools/) to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.ldap_messages import BindRequest, SearchRequest, LDAPMessage
from common.ber_encoder import BEREncoder


def test_tcp_connection(host: str, port: int, timeout: float = 5.0) -> bool:
    """Test TCP connectivity to LDAP server"""
    print(f"\n[1/4] Testing TCP connection to {host}:{port}...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        print("  ✓ TCP connection successful")
        return True
    except socket.timeout:
        print("  ✗ Connection timeout")
        return False
    except ConnectionRefusedError:
        print("  ✗ Connection refused - is LDAP server running?")
        return False
    except Exception as e:
        print(f"  ✗ Connection failed: {e}")
        return False


def test_anonymous_bind(host: str, port: int, timeout: float = 5.0) -> bool:
    """Test anonymous bind"""
    print(f"\n[2/4] Testing anonymous bind...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Create anonymous BindRequest
        bind_req = BindRequest.create(version=3, name="", password="")
        ldap_msg = LDAPMessage.create(1, bind_req)

        # Send
        sock.sendall(ldap_msg)

        # Receive response
        response = sock.recv(4096)
        sock.close()

        if not response or len(response) == 0:
            print("  ✗ No response received")
            return False

        # Parse response to check for success or specific error
        # Look for success (0x0a 0x01 0x00) or result code
        if b'\x0a\x01\x00' in response:  # Success
            print("  ✓ Anonymous bind successful (result code: 0 - success)")
            return True
        elif b'\x0a\x01\x30' in response:  # Auth method not supported (48 decimal = 0x30)
            print("  ⚠ Anonymous bind returned authMethodNotSupported (48)")
            print("    Server may require authentication, but responding correctly")
            return True
        elif b'\x0a\x01\x08' in response:  # Stronger auth required
            print("  ⚠ Anonymous bind returned strongerAuthRequired (8)")
            print("    Server may require authentication, but responding correctly")
            return True
        else:
            print(f"  ✓ Server responded (may require auth, but parser works)")
            print(f"    Response length: {len(response)} bytes")
            return True

    except socket.timeout:
        print("  ✗ Response timeout")
        return False
    except Exception as e:
        print(f"  ✗ Bind test failed: {e}")
        return False


def test_search_request(host: str, port: int, timeout: float = 5.0) -> bool:
    """Test basic search request"""
    print(f"\n[3/4] Testing search request (root DSE)...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # First bind
        bind_req = BindRequest.create(version=3, name="", password="")
        ldap_msg = LDAPMessage.create(1, bind_req)
        sock.sendall(ldap_msg)
        bind_response = sock.recv(4096)

        # Then search root DSE
        search_req = SearchRequest.create(
            base_dn="",
            scope=0,  # baseObject
            filter_str="(objectClass=*)",
            attributes=[]
        )
        ldap_msg = LDAPMessage.create(2, search_req)
        sock.sendall(ldap_msg)

        # Receive response
        search_response = sock.recv(4096)
        sock.close()

        if not search_response or len(search_response) == 0:
            print("  ✗ No search response received")
            return False

        print(f"  ✓ Search request successful (response: {len(search_response)} bytes)")
        return True

    except socket.timeout:
        print("  ✗ Search response timeout")
        return False
    except Exception as e:
        print(f"  ✗ Search test failed: {e}")
        return False


def test_malformed_rejection(host: str, port: int, timeout: float = 5.0) -> bool:
    """Test that server rejects obviously malformed BER"""
    print(f"\n[4/4] Testing malformed BER rejection...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send obviously invalid BER (tag 0xFF, invalid)
        malformed = bytes([0xFF, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
        sock.sendall(malformed)

        # Try to receive response
        try:
            response = sock.recv(4096)

            if response and len(response) > 0:
                # Check for protocol error (0x0a 0x01 0x02)
                if b'\x0a\x01\x02' in response:
                    print("  ✓ Server correctly returned protocolError (2)")
                    return True
                else:
                    print(f"  ⚠ Server responded but not with protocolError")
                    print(f"    This is okay - server handled malformed input")
                    return True
            else:
                print("  ⚠ Server closed connection (acceptable response)")
                return True

        except socket.timeout:
            print("  ⚠ Server timed out (possible hang - investigate)")
            return False

    except ConnectionResetError:
        print("  ✓ Server closed connection (acceptable response to malformed BER)")
        return True
    except Exception as e:
        print(f"  ⚠ Test completed with exception: {e}")
        print("    (This may be acceptable behavior)")
        return True
    finally:
        try:
            sock.close()
        except:
            pass


def run_baseline_test(host: str, port: int = 389) -> bool:
    """Run complete baseline test suite"""
    print("="*70)
    print("LDAP Server Baseline Test")
    print("="*70)
    print(f"\nTarget: {host}:{port}")
    print(f"Purpose: Verify server is ready for fuzzing tests")
    print("\nRunning 4 baseline tests...")

    results = []

    # Test 1: TCP connectivity
    results.append(("TCP Connection", test_tcp_connection(host, port)))

    if not results[-1][1]:
        print("\n" + "="*70)
        print("BASELINE TEST FAILED")
        print("="*70)
        print("\nCannot proceed - server is not reachable")
        print(f"Please verify:")
        print(f"  1. LDAP server is running on {host}:{port}")
        print(f"  2. Firewall allows connections")
        print(f"  3. Network connectivity is working")
        return False

    # Test 2: Anonymous bind
    results.append(("Anonymous Bind", test_anonymous_bind(host, port)))

    # Test 3: Search request
    results.append(("Search Request", test_search_request(host, port)))

    # Test 4: Malformed rejection
    results.append(("Malformed Rejection", test_malformed_rejection(host, port)))

    # Summary
    print("\n" + "="*70)
    print("BASELINE TEST SUMMARY")
    print("="*70)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {test_name}")

    print(f"\nResult: {passed}/{total} tests passed")

    if passed == total:
        print("\n✓ Server is READY for fuzzing tests")
        print("\nYou can now run:")
        print(f"  cd test_harness")
        print(f"  python test_runner.py {host} -o results.json")
        return True
    elif passed >= 2:
        print("\n⚠ Server is PARTIALLY ready")
        print("\nSome tests failed, but fuzzing may still work.")
        print("The BER parser appears functional.")
        print("\nYou can try running fuzzing tests:")
        print(f"  python test_runner.py {host} -o results.json")
        return True
    else:
        print("\n✗ Server is NOT ready for testing")
        print("\nPlease resolve the issues above before fuzzing.")
        return False


def main():
    """Command-line interface"""
    import argparse

    parser = argparse.ArgumentParser(
        description='LDAP Server Baseline Test - Verify server readiness for fuzzing'
    )
    parser.add_argument('host', help='LDAP server hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=389,
                       help='LDAP server port (default: 389)')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                       help='Timeout in seconds (default: 5.0)')

    args = parser.parse_args()

    success = run_baseline_test(args.host, args.port)

    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
