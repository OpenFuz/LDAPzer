"""
Unified Test Runner

Provides a unified interface to run tests using either:
1. Socket-based ASN.1 fuzzer
2. Scapy-based packet crafter

Orchestrates test execution and aggregates results.
"""

import sys
import os
import argparse
import time
from typing import Dict, List, Optional
from enum import Enum

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from asn1_fuzzer.fuzzer import LDAPFuzzer
from asn1_fuzzer.fuzz_generators import get_all_test_cases


class TestMethod(Enum):
    """Test execution method"""
    SOCKET = "socket"  # Use socket-based fuzzer
    SCAPY = "scapy"    # Use Scapy packet crafter


class UnifiedTestRunner:
    """
    Unified test runner that can use either socket or Scapy

    Provides consistent interface regardless of underlying method
    """

    def __init__(self,
                 target_host: str,
                 target_port: int = 389,
                 method: TestMethod = TestMethod.SOCKET,
                 timeout: float = 5.0,
                 delay_between_tests: float = 0.1,
                 check_server_health: bool = True,
                 source_ip: Optional[str] = None):
        """
        Initialize unified test runner

        Args:
            target_host: Target LDAP server (IP or hostname)
            target_port: Target port (default 389)
            method: Test method (SOCKET or SCAPY)
            timeout: Response timeout
            delay_between_tests: Delay between test cases
            check_server_health: Check server health between tests
            source_ip: Source IP (for Scapy only)
        """
        self.target_host = target_host
        self.target_port = target_port
        self.method = method
        self.timeout = timeout
        self.delay_between_tests = delay_between_tests
        self.check_server_health = check_server_health
        self.source_ip = source_ip

        # Initialize appropriate runner
        if method == TestMethod.SOCKET:
            self.runner = LDAPFuzzer(
                target_host=target_host,
                target_port=target_port,
                timeout=timeout,
                delay_between_tests=delay_between_tests
            )
        elif method == TestMethod.SCAPY:
            try:
                from scapy_crafter.test_sender import ScapyTestSender
                self.runner = ScapyTestSender(
                    target_ip=target_host,
                    target_port=target_port,
                    timeout=timeout,
                    delay_between_tests=delay_between_tests,
                    source_ip=source_ip
                )
            except ImportError:
                raise ImportError("Scapy is required for SCAPY method. Install with: pip install scapy")

    def run_test_suite(self, suite_id: str) -> Dict:
        """
        Run a specific test suite

        Args:
            suite_id: Test suite ID ('1.1.1', '1.1.2', '1.1.3')

        Returns:
            Dictionary of results
        """
        all_tests = get_all_test_cases()

        if suite_id not in all_tests:
            raise ValueError(f"Unknown test suite: {suite_id}")

        test_cases = all_tests[suite_id]

        print(f"\n{'='*70}")
        print(f"Running Test Suite {suite_id} using {self.method.value.upper()} method")
        print(f"Target: {self.target_host}:{self.target_port}")
        print(f"Test Cases: {len(test_cases)}")
        print(f"{'='*70}\n")

        if self.method == TestMethod.SOCKET:
            results = self.runner.run_test_suite(test_cases, self.check_server_health)
        else:  # SCAPY
            results = self.runner.run_test_suite(test_cases)

        return {suite_id: results}

    def run_all_tests(self) -> Dict:
        """
        Run all test suites (1.1.1, 1.1.2, 1.1.3)

        Returns:
            Dictionary mapping suite IDs to results
        """
        print(f"\n{'='*70}")
        print(f"LDAP Protocol Security Assessment - RFC 4511 Test Cases 1.1.x")
        print(f"{'='*70}")
        print(f"Target: {self.target_host}:{self.target_port}")
        print(f"Method: {self.method.value.upper()}")
        print(f"Timeout: {self.timeout}s")
        print(f"Delay between tests: {self.delay_between_tests}s")
        print(f"{'='*70}\n")

        start_time = time.time()

        if self.method == TestMethod.SOCKET:
            all_results = self.runner.run_all_test_cases(self.check_server_health)
        else:  # SCAPY
            all_results = self.runner.run_all_tests()

        elapsed_time = time.time() - start_time

        print(f"\n{'='*70}")
        print(f"All tests completed in {elapsed_time:.2f} seconds")
        print(f"{'='*70}\n")

        return all_results

    def get_results(self):
        """Get results from the runner"""
        if hasattr(self.runner, 'results'):
            return self.runner.results
        else:
            return []


def create_test_config(config_file: str) -> Dict:
    """
    Load test configuration from file

    Args:
        config_file: Path to configuration file (JSON or YAML)

    Returns:
        Configuration dictionary
    """
    import json

    with open(config_file, 'r') as f:
        if config_file.endswith('.json'):
            return json.load(f)
        elif config_file.endswith('.yaml') or config_file.endswith('.yml'):
            try:
                import yaml
                return yaml.safe_load(f)
            except ImportError:
                raise ImportError("PyYAML required for YAML config. Install with: pip install pyyaml")
        else:
            raise ValueError("Config file must be JSON or YAML")


def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description='LDAP Protocol Security Assessment Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests using socket method
  python test_runner.py 192.168.1.100

  # Run specific test suite
  python test_runner.py 192.168.1.100 --suite 1.1.1

  # Use Scapy method
  python test_runner.py 192.168.1.100 --method scapy

  # Custom timeout and delay
  python test_runner.py 192.168.1.100 -t 10 -d 0.5

  # Export results to JSON
  python test_runner.py 192.168.1.100 -o results.json
        """
    )

    parser.add_argument('target', help='Target LDAP server (IP or hostname)')
    parser.add_argument('-p', '--port', type=int, default=389,
                       help='Target port (default: 389)')
    parser.add_argument('-m', '--method', choices=['socket', 'scapy'], default='socket',
                       help='Test method (default: socket)')
    parser.add_argument('-s', '--suite', choices=['1.1.1', '1.1.2', '1.1.3', 'all'], default='all',
                       help='Test suite to run (default: all)')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                       help='Response timeout in seconds (default: 5.0)')
    parser.add_argument('-d', '--delay', type=float, default=0.1,
                       help='Delay between tests in seconds (default: 0.1)')
    parser.add_argument('--no-health-check', action='store_true',
                       help='Disable server health checks between tests')
    parser.add_argument('--source-ip', help='Source IP address (Scapy only)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-c', '--config', help='Load configuration from file (JSON/YAML)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Load config if provided
    if args.config:
        config = create_test_config(args.config)
        # Override with config values
        target = config.get('target', args.target)
        port = config.get('port', args.port)
        method_str = config.get('method', args.method)
        timeout = config.get('timeout', args.timeout)
        delay = config.get('delay', args.delay)
    else:
        target = args.target
        port = args.port
        method_str = args.method
        timeout = args.timeout
        delay = args.delay

    # Create test runner
    method = TestMethod.SOCKET if method_str == 'socket' else TestMethod.SCAPY

    try:
        runner = UnifiedTestRunner(
            target_host=target,
            target_port=port,
            method=method,
            timeout=timeout,
            delay_between_tests=delay,
            check_server_health=not args.no_health_check,
            source_ip=args.source_ip
        )

        # Run tests
        if args.suite == 'all':
            results = runner.run_all_tests()
        else:
            results = runner.run_test_suite(args.suite)

        # Export results
        if args.output:
            from results_logger import ResultsLogger
            logger = ResultsLogger(args.output)

            if method == TestMethod.SOCKET:
                logger.log_socket_results(runner.get_results())
            else:
                logger.log_scapy_results(runner.get_results())

            logger.save()
            print(f"\nResults saved to {args.output}")

        print("\n✓ Test execution completed successfully")
        return 0

    except KeyboardInterrupt:
        print("\n\n⚠ Test execution interrupted by user")
        return 130
    except Exception as e:
        print(f"\n✗ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
