"""
Example Usage Script for LDAP Protocol Security Testing Tools

This script demonstrates various ways to use the LDAP testing tools.
"""

import sys
import os

# Add parent directory (tools/) to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def example_1_basic_fuzzing():
    """Example 1: Basic fuzzing with socket-based fuzzer"""
    print("\n" + "="*70)
    print("Example 1: Basic Fuzzing with Socket-based Fuzzer")
    print("="*70)

    from section1_encoding.fuzzer import LDAPFuzzer

    # Configuration
    TARGET_HOST = '192.168.1.100'
    TARGET_PORT = 389

    # Create fuzzer
    fuzzer = LDAPFuzzer(
        target_host=TARGET_HOST,
        target_port=TARGET_PORT,
        timeout=5.0,
        delay_between_tests=0.1
    )

    # Run all test cases
    print(f"\nTesting {TARGET_HOST}:{TARGET_PORT}")
    print("Running all test cases (1.1.1, 1.1.2, 1.1.3)...")

    results = fuzzer.run_all_test_cases(check_server_health=True)

    # Print summary
    print("\nResults Summary:")
    for suite_id, test_results in results.items():
        print(f"\nSuite {suite_id}:")
        for result in test_results:
            print(f"  {result.test_id}: {result.server_status.value}")


def example_2_specific_test_suite():
    """Example 2: Run specific test suite only"""
    print("\n" + "="*70)
    print("Example 2: Run Specific Test Suite (1.1.1)")
    print("="*70)

    from section1_encoding.fuzzer import LDAPFuzzer
    from section1_encoding.fuzz_generators import get_all_test_cases

    TARGET_HOST = '192.168.1.100'

    # Get test cases for suite 1.1.1
    all_tests = get_all_test_cases()
    test_suite_1_1_1 = all_tests['1.1.1']

    fuzzer = LDAPFuzzer(target_host=TARGET_HOST)

    print(f"\nRunning {len(test_suite_1_1_1)} tests from suite 1.1.1")

    results = fuzzer.run_test_suite(test_suite_1_1_1)

    # Analyze results
    protocol_errors = sum(1 for r in results if r.result_code == 2)
    print(f"\nProtocol errors received: {protocol_errors}/{len(results)}")


def example_3_scapy_packet_crafting():
    """Example 3: Manual packet crafting with Scapy"""
    print("\n" + "="*70)
    print("Example 3: Manual Packet Crafting with Scapy")
    print("="*70)

    try:
        from scapy_crafter.packet_crafter import LDAPPacketCrafter
        from common.ldap_messages import BindRequest, LDAPMessage

        TARGET_IP = '192.168.1.100'

        # Create packet crafter
        crafter = LDAPPacketCrafter(target_ip=TARGET_IP)

        # Craft a standard bind request
        print("\n1. Crafting standard BindRequest...")
        bind_msg = crafter.craft_bind_request(
            message_id=1,
            version=3,
            dn='cn=admin,dc=example,dc=com',
            password='secret'
        )
        print(f"   Packet size: {len(bind_msg)} bytes")

        # Send and get response (commented out - requires Scapy and target server)
        # response = crafter.send_packet(bind_msg)
        # print(f"   Response: {response.hex() if response else 'None'}")

        # Craft a search request
        print("\n2. Crafting SearchRequest...")
        search_msg = crafter.craft_search_request(
            message_id=2,
            base_dn='dc=example,dc=com',
            scope=2,  # wholeSubtree
            attributes=['cn', 'mail']
        )
        print(f"   Packet size: {len(search_msg)} bytes")

        # Craft StartTLS request
        print("\n3. Crafting StartTLS ExtendedRequest...")
        starttls_msg = crafter.craft_starttls_request(message_id=3)
        print(f"   Packet size: {len(starttls_msg)} bytes")

        print("\nNote: Uncomment send_packet() calls to actually send packets")

    except ImportError:
        print("\nScapy not installed. Install with: pip install scapy")


def example_4_custom_malformed_packet():
    """Example 4: Create custom malformed packet"""
    print("\n" + "="*70)
    print("Example 4: Create Custom Malformed Packet")
    print("="*70)

    from common.ber_encoder import BEREncoder, BERLength
    from common.ldap_messages import LDAPMessage

    # Create a SEQUENCE with malformed length
    print("\nCreating packet with oversized length field...")

    # Create a simple message ID
    message_id = BEREncoder.encode_integer(1)

    # Create a simple bind request
    version = BEREncoder.encode_integer(3)
    name = BEREncoder.encode_octet_string(b"")
    auth = BEREncoder.encode_context(0, b"", primitive=True)

    bind_content = version + name + auth
    bind_request = BEREncoder.encode_application(0, bind_content)

    # Manually create SEQUENCE with malformed length
    sequence_tag = bytes([0x30])
    # Claim length is 0xFFFFFFFF (huge)
    malformed_length = bytes([0x84, 0xFF, 0xFF, 0xFF, 0xFF])

    malformed_packet = sequence_tag + malformed_length + message_id + bind_request

    print(f"Malformed packet size: {len(malformed_packet)} bytes")
    print(f"First 20 bytes (hex): {malformed_packet[:20].hex()}")
    print("\nThis packet claims to have a length of 4,294,967,295 bytes")
    print("but only contains a few dozen bytes of actual data.")


def example_5_results_logging():
    """Example 5: Log and format results"""
    print("\n" + "="*70)
    print("Example 5: Results Logging and Formatting")
    print("="*70)

    from test_harness.results_logger import ResultsLogger
    from section1_encoding.fuzzer import LDAPFuzzer, FuzzResult, ServerStatus
    import time

    # Create some sample results
    sample_results = [
        FuzzResult(
            test_id='1.1.1.1',
            test_name='Indefinite Length',
            description='Test indefinite length encoding',
            packet_sent=b'\x30\x80\x02\x01\x01',
            response_received=b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x02\x04\x00\x04\x00',
            server_status=ServerStatus.RESPONSIVE,
            response_time=0.012,
            error_message=None,
            timestamp=time.time()
        ),
        FuzzResult(
            test_id='1.1.1.2',
            test_name='Length Too Short',
            description='Send length shorter than data',
            packet_sent=b'\x30\x05\x02\x01\x01',
            response_received=None,
            server_status=ServerStatus.CONNECTION_CLOSED,
            response_time=0.000,
            error_message='Connection closed by peer',
            timestamp=time.time()
        )
    ]

    # Create logger
    logger = ResultsLogger()
    logger.add_metadata('target', '192.168.1.100:389')
    logger.add_metadata('method', 'socket')

    # Log results
    logger.log_socket_results(sample_results)

    # Print summary
    logger.print_summary()

    # Export to different formats
    print("\nJSON output (first 200 chars):")
    json_output = logger.to_json()
    print(json_output[:200] + "...")

    print("\nMarkdown output (first 300 chars):")
    md_output = logger.to_markdown()
    print(md_output[:300] + "...")

    # Save to file
    print("\nSaving to files...")
    logger.save('example_results.json', format='json')
    logger.save('example_results.md', format='markdown')
    print("Saved: example_results.json, example_results.md")


def example_6_unified_test_runner():
    """Example 6: Using the unified test runner"""
    print("\n" + "="*70)
    print("Example 6: Unified Test Runner")
    print("="*70)

    from test_harness.test_runner import UnifiedTestRunner, TestMethod

    TARGET_HOST = '192.168.1.100'

    print("\nUsing Socket method:")
    runner_socket = UnifiedTestRunner(
        target_host=TARGET_HOST,
        method=TestMethod.SOCKET,
        timeout=5.0
    )

    # This would run tests (commented to avoid actual execution in example)
    # results = runner_socket.run_all_tests()

    print("  Runner configured for socket-based testing")

    print("\nUsing Scapy method:")
    try:
        runner_scapy = UnifiedTestRunner(
            target_host=TARGET_HOST,
            method=TestMethod.SCAPY,
            timeout=5.0
        )
        print("  Runner configured for Scapy-based testing")
    except ImportError:
        print("  Scapy not available")

    print("\nTo actually run tests, call:")
    print("  results = runner.run_all_tests()")
    print("  results = runner.run_test_suite('1.1.1')")


def main():
    """Run all examples"""
    print("\n" + "="*70)
    print("LDAP Protocol Security Testing Tools - Example Usage")
    print("="*70)
    print("\nThis script demonstrates various ways to use the tools.")
    print("Examples are non-destructive and don't require a target server.")
    print("\nNOTE: Some examples are demonstration only and don't actually")
    print("      send packets. Uncomment send_packet() calls to enable.")

    # Run examples
    example_1_basic_fuzzing()
    example_2_specific_test_suite()
    example_3_scapy_packet_crafting()
    example_4_custom_malformed_packet()
    example_5_results_logging()
    example_6_unified_test_runner()

    print("\n" + "="*70)
    print("Examples completed!")
    print("="*70)
    print("\nTo run actual tests against a target:")
    print("  cd test_harness")
    print("  python test_runner.py <target_ip> [options]")
    print("\nFor more information, see README.md")


if __name__ == "__main__":
    # Check if user wants to run against actual target
    if len(sys.argv) > 1 and sys.argv[1] == '--run-tests':
        if len(sys.argv) < 3:
            print("Usage: python example_usage.py --run-tests <target_ip>")
            sys.exit(1)

        target = sys.argv[2]
        print(f"\nRunning actual tests against {target}")
        print("WARNING: This will send malformed packets to the target!")

        from test_harness.test_runner import UnifiedTestRunner, TestMethod
        runner = UnifiedTestRunner(target_host=target, method=TestMethod.SOCKET)
        results = runner.run_all_tests()

        from test_harness.results_logger import ResultsLogger
        logger = ResultsLogger('example_results.json')
        logger.add_metadata('target', target)
        logger.log_socket_results(runner.get_results())
        logger.save()
        logger.print_summary()
    else:
        # Just run examples without sending packets
        main()
