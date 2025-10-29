"""
Test Sender and Response Analyzer

Sends test cases using Scapy and analyzes LDAP responses.
Can work with test cases from the ASN.1 fuzzer or custom crafted packets.
"""

import sys
import os
import time
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from scapy.all import IP, TCP, Raw, sr1, send, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from section1_encoding.fuzz_generators import get_all_test_cases


class ResponseAnalysisResult(Enum):
    """Response analysis results"""
    VALID_RESPONSE = "valid_response"
    PROTOCOL_ERROR = "protocol_error"
    CONNECTION_CLOSED = "connection_closed"
    TIMEOUT = "timeout"
    MALFORMED_RESPONSE = "malformed_response"
    SUCCESS = "success"
    OTHER_ERROR = "other_error"


@dataclass
class TestResult:
    """Result of sending a test packet"""
    test_id: str
    test_name: str
    packet_sent: bytes
    response_received: Optional[bytes]
    analysis: ResponseAnalysisResult
    result_code: Optional[int]
    response_time: float
    notes: str


class LDAPResponseAnalyzer:
    """
    Analyze LDAP responses

    Parses BER-encoded LDAP responses and extracts result codes
    """

    @staticmethod
    def parse_ber_length(data: bytes, offset: int = 0) -> Tuple[int, int]:
        """
        Parse BER length field

        Args:
            data: BER-encoded data
            offset: Offset to start parsing

        Returns:
            Tuple of (length_value, bytes_consumed)
        """
        if len(data) <= offset:
            return 0, 0

        first_byte = data[offset]

        if first_byte & 0x80 == 0:
            # Short form
            return first_byte, 1
        elif first_byte == 0x80:
            # Indefinite form
            return -1, 1
        else:
            # Long form
            num_octets = first_byte & 0x7F
            if len(data) < offset + 1 + num_octets:
                return 0, 0

            length = 0
            for i in range(num_octets):
                length = (length << 8) | data[offset + 1 + i]

            return length, 1 + num_octets

    @staticmethod
    def extract_result_code(response: bytes) -> Optional[int]:
        """
        Extract LDAP result code from response

        LDAP responses typically have structure:
        SEQUENCE {
            messageID INTEGER,
            protocolOp [APPLICATION X] SEQUENCE {
                resultCode ENUMERATED,
                ...
            }
        }

        Args:
            response: LDAP response bytes

        Returns:
            Result code or None
        """
        try:
            offset = 0

            # Parse outer SEQUENCE tag
            if len(response) < 2 or response[offset] != 0x30:
                return None

            offset += 1
            seq_length, consumed = LDAPResponseAnalyzer.parse_ber_length(response, offset)
            offset += consumed

            # Parse messageID (INTEGER)
            if len(response) <= offset or response[offset] != 0x02:
                return None

            offset += 1
            msg_id_length, consumed = LDAPResponseAnalyzer.parse_ber_length(response, offset)
            offset += consumed
            offset += msg_id_length  # Skip messageID value

            # Parse protocolOp (APPLICATION tag)
            if len(response) <= offset:
                return None

            # APPLICATION tags: 0x61 (BindResponse), 0x65 (SearchResultDone), etc.
            app_tag = response[offset]
            if (app_tag & 0xC0) != 0x40:  # Check if APPLICATION class
                return None

            offset += 1
            app_length, consumed = LDAPResponseAnalyzer.parse_ber_length(response, offset)
            offset += consumed

            # Parse resultCode (ENUMERATED)
            if len(response) <= offset or response[offset] != 0x0A:
                return None

            offset += 1
            rc_length, consumed = LDAPResponseAnalyzer.parse_ber_length(response, offset)
            offset += consumed

            # Extract result code value
            if len(response) < offset + rc_length:
                return None

            result_code = 0
            for i in range(rc_length):
                result_code = (result_code << 8) | response[offset + i]

            return result_code

        except Exception:
            return None

    @staticmethod
    def analyze_response(response: Optional[bytes]) -> Tuple[ResponseAnalysisResult, Optional[int], str]:
        """
        Analyze an LDAP response

        Args:
            response: LDAP response bytes (or None)

        Returns:
            Tuple of (analysis_result, result_code, notes)
        """
        if response is None:
            return ResponseAnalysisResult.TIMEOUT, None, "No response received (timeout)"

        if len(response) == 0:
            return ResponseAnalysisResult.CONNECTION_CLOSED, None, "Connection closed by server"

        # Try to parse response
        result_code = LDAPResponseAnalyzer.extract_result_code(response)

        if result_code is None:
            return ResponseAnalysisResult.MALFORMED_RESPONSE, None, "Could not parse response"

        # Analyze result code
        if result_code == 0:
            return ResponseAnalysisResult.SUCCESS, result_code, "Success (0)"
        elif result_code == 2:
            return ResponseAnalysisResult.PROTOCOL_ERROR, result_code, "Protocol Error (2)"
        else:
            return ResponseAnalysisResult.OTHER_ERROR, result_code, f"Result code: {result_code}"


class ScapyTestSender:
    """
    Send test cases using Scapy and analyze responses
    """

    def __init__(self,
                 target_ip: str,
                 target_port: int = 389,
                 timeout: float = 5.0,
                 delay_between_tests: float = 0.1,
                 source_ip: Optional[str] = None):
        """
        Initialize test sender

        Args:
            target_ip: Target LDAP server IP
            target_port: Target port (default 389)
            timeout: Response timeout
            delay_between_tests: Delay between test cases
            source_ip: Source IP (optional)
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required. Install with: pip install scapy")

        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.delay_between_tests = delay_between_tests
        self.source_ip = source_ip

        # Disable Scapy verbosity
        conf.verb = 0

        self.results: List[TestResult] = []

    def send_packet(self, ldap_bytes: bytes) -> Optional[bytes]:
        """
        Send LDAP packet and wait for response

        Args:
            ldap_bytes: LDAP message bytes

        Returns:
            Response bytes or None
        """
        # Build packet
        ip_layer = IP(dst=self.target_ip)
        if self.source_ip:
            ip_layer.src = self.source_ip

        tcp_layer = TCP(dport=self.target_port, flags='PA')
        packet = ip_layer / tcp_layer / Raw(load=ldap_bytes)

        # Send and wait for response
        response = sr1(packet, timeout=self.timeout, verbose=False)

        if response and response.haslayer(Raw):
            return bytes(response[Raw].load)
        else:
            return None

    def run_test_case(self, test_case: Dict) -> TestResult:
        """
        Run a single test case

        Args:
            test_case: Test case dictionary

        Returns:
            TestResult object
        """
        test_id = test_case['id']
        test_name = test_case['name']
        packet = test_case['packet']

        print(f"Running test {test_id}: {test_name}")

        start_time = time.time()

        # Send packet
        response = self.send_packet(packet)

        response_time = time.time() - start_time

        # Analyze response
        analysis, result_code, notes = LDAPResponseAnalyzer.analyze_response(response)

        result = TestResult(
            test_id=test_id,
            test_name=test_name,
            packet_sent=packet,
            response_received=response,
            analysis=analysis,
            result_code=result_code,
            response_time=response_time,
            notes=notes
        )

        self.results.append(result)

        print(f"  Result: {analysis.value} - {notes} ({response_time:.3f}s)")

        return result

    def run_test_suite(self, test_cases: List[Dict]) -> List[TestResult]:
        """
        Run a suite of test cases

        Args:
            test_cases: List of test case dictionaries

        Returns:
            List of TestResult objects
        """
        print(f"\nRunning test suite with {len(test_cases)} tests")
        print(f"Target: {self.target_ip}:{self.target_port}\n")

        suite_results = []

        for i, test_case in enumerate(test_cases):
            result = self.run_test_case(test_case)
            suite_results.append(result)

            # Delay between tests
            if i < len(test_cases) - 1:
                time.sleep(self.delay_between_tests)

        return suite_results

    def run_all_tests(self) -> Dict[str, List[TestResult]]:
        """
        Run all test cases from fuzzer (1.1.1, 1.1.2, 1.1.3)

        Returns:
            Dictionary mapping test suite ID to results
        """
        all_tests = get_all_test_cases()
        all_results = {}

        for suite_id, test_cases in all_tests.items():
            print(f"\n{'='*60}")
            print(f"Test Suite {suite_id}")
            print(f"{'='*60}")

            results = self.run_test_suite(test_cases)
            all_results[suite_id] = results

            # Summary
            protocol_errors = sum(1 for r in results
                                 if r.analysis == ResponseAnalysisResult.PROTOCOL_ERROR)
            timeouts = sum(1 for r in results
                          if r.analysis == ResponseAnalysisResult.TIMEOUT)
            closed = sum(1 for r in results
                        if r.analysis == ResponseAnalysisResult.CONNECTION_CLOSED)

            print(f"\nSuite {suite_id} Summary:")
            print(f"  Total: {len(results)}")
            print(f"  Protocol Errors: {protocol_errors}")
            print(f"  Timeouts: {timeouts}")
            print(f"  Connection Closed: {closed}")

        return all_results

    def print_detailed_results(self):
        """Print detailed results of all tests"""
        print("\n" + "="*80)
        print("DETAILED TEST RESULTS")
        print("="*80)

        for result in self.results:
            print(f"\nTest {result.test_id}: {result.test_name}")
            print(f"  Packet Size: {len(result.packet_sent)} bytes")
            print(f"  Response Size: {len(result.response_received) if result.response_received else 0} bytes")
            print(f"  Analysis: {result.analysis.value}")
            print(f"  Result Code: {result.result_code}")
            print(f"  Response Time: {result.response_time:.3f}s")
            print(f"  Notes: {result.notes}")

            if result.response_received and len(result.response_received) > 0:
                print(f"  Response (hex): {result.response_received[:64].hex()}...")

    def export_results_to_dict(self) -> List[Dict]:
        """Export results to list of dictionaries for JSON serialization"""
        return [
            {
                'test_id': r.test_id,
                'test_name': r.test_name,
                'packet_sent_hex': r.packet_sent.hex(),
                'response_received_hex': r.response_received.hex() if r.response_received else None,
                'analysis': r.analysis.value,
                'result_code': r.result_code,
                'response_time': r.response_time,
                'notes': r.notes
            }
            for r in self.results
        ]


# CLI interface
def main():
    """Command-line interface for test sender"""
    import argparse

    parser = argparse.ArgumentParser(description='LDAP Test Sender using Scapy')
    parser.add_argument('target_ip', help='Target LDAP server IP address')
    parser.add_argument('-p', '--port', type=int, default=389, help='Target port (default: 389)')
    parser.add_argument('-t', '--timeout', type=float, default=5.0, help='Response timeout (default: 5.0s)')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between tests (default: 0.1s)')
    parser.add_argument('--source-ip', help='Source IP address (optional)')
    parser.add_argument('--suite', choices=['1.1.1', '1.1.2', '1.1.3', 'all'], default='all',
                       help='Test suite to run (default: all)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')

    args = parser.parse_args()

    if not SCAPY_AVAILABLE:
        print("ERROR: Scapy is not installed. Install with: pip install scapy")
        return 1

    # Create test sender
    sender = ScapyTestSender(
        target_ip=args.target_ip,
        target_port=args.port,
        timeout=args.timeout,
        delay_between_tests=args.delay,
        source_ip=args.source_ip
    )

    # Run tests
    if args.suite == 'all':
        results = sender.run_all_tests()
    else:
        all_tests = get_all_test_cases()
        test_cases = all_tests[args.suite]
        print(f"\n{'='*60}")
        print(f"Test Suite {args.suite}")
        print(f"{'='*60}")
        results = {args.suite: sender.run_test_suite(test_cases)}

    # Print detailed results
    sender.print_detailed_results()

    # Export results
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(sender.export_results_to_dict(), f, indent=2)
        print(f"\nResults exported to {args.output}")

    return 0


if __name__ == "__main__":
    exit(main())
