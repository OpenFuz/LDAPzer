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

from section1_encoding.fuzzer import LDAPFuzzer
from section1_encoding.fuzz_generators import get_all_test_cases as get_section1_tests
from section2_envelope.fuzz_generators import get_all_test_cases as get_section2_tests


class TestMethod(Enum):
    """Test execution method"""
    SOCKET = "socket"  # Use socket-based fuzzer
    SCAPY = "scapy"    # Use Scapy packet crafter


def get_test_cases_for_suite(suite_id: str) -> Dict:
    """
    Get test cases for a specific suite or set of suites

    Args:
        suite_id: Suite identifier ('1.1.1', '2.1.1', 'section1', 'section2', 'all')

    Returns:
        Dictionary mapping suite IDs to test case lists
    """
    section1_tests = get_section1_tests()
    section2_tests = get_section2_tests()

    if suite_id == 'all':
        # Combine both sections
        return {**section1_tests, **section2_tests}
    elif suite_id == 'section1':
        return section1_tests
    elif suite_id == 'section2':
        return section2_tests
    elif suite_id in section1_tests:
        return {suite_id: section1_tests[suite_id]}
    elif suite_id in section2_tests:
        return {suite_id: section2_tests[suite_id]}
    else:
        raise ValueError(f"Unknown test suite: {suite_id}")


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
            suite_id: Test suite ID ('1.1.1', '1.1.2', '1.1.3', '2.1.1', '2.1.2', '2.1.3',
                     'section1', 'section2')

        Returns:
            Dictionary of results
        """
        test_suites = get_test_cases_for_suite(suite_id)

        all_results = {}

        for suite_key, test_cases in test_suites.items():
            print(f"\n{'='*70}")
            print(f"Running Test Suite {suite_key} using {self.method.value.upper()} method")
            print(f"Target: {self.target_host}:{self.target_port}")
            print(f"Test Cases: {len(test_cases)}")
            print(f"{'='*70}\n")

            if self.method == TestMethod.SOCKET:
                results = self.runner.run_test_suite(test_cases, self.check_server_health)
            else:  # SCAPY
                results = self.runner.run_test_suite(test_cases)

            all_results[suite_key] = results

        return all_results

    def run_all_tests(self) -> Dict:
        """
        Run all test suites (Sections 1 and 2)

        Returns:
            Dictionary mapping suite IDs to results
        """
        print(f"\n{'='*70}")
        print(f"LDAP Protocol Security Assessment - RFC 4511 Test Cases")
        print(f"{'='*70}")
        print(f"Target: {self.target_host}:{self.target_port}")
        print(f"Method: {self.method.value.upper()}")
        print(f"Timeout: {self.timeout}s")
        print(f"Delay between tests: {self.delay_between_tests}s")
        print(f"{'='*70}\n")

        start_time = time.time()

        # Get all test cases from both sections
        all_test_suites = get_test_cases_for_suite('all')
        all_results = {}

        for suite_id, test_cases in all_test_suites.items():
            print(f"\nRunning Test Suite {suite_id}...")
            if self.method == TestMethod.SOCKET:
                results = self.runner.run_test_suite(test_cases, self.check_server_health)
            else:  # SCAPY
                results = self.runner.run_test_suite(test_cases)
            all_results[suite_id] = results

        elapsed_time = time.time() - start_time

        print(f"\n{'='*70}")
        print(f"All tests completed in {elapsed_time:.2f} seconds")
        print(f"Total suites run: {len(all_results)}")
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
  # Run all tests (Sections 1 and 2) using socket method
  python test_runner.py 192.168.1.100

  # Run Section 1 only (ASN.1/BER encoding tests)
  python test_runner.py 192.168.1.100 --suite section1

  # Run Section 2 only (LDAPMessage envelope tests)
  python test_runner.py 192.168.1.100 --suite section2

  # Run specific test suite (Section 1)
  python test_runner.py 192.168.1.100 --suite 1.1.1

  # Run specific test suite (Section 2)
  python test_runner.py 192.168.1.100 --suite 2.1.2

  # ITERATION MODE: Run each test 100 times
  python test_runner.py 192.168.1.100 --fuzz-mode iteration --iterations 100

  # MUTATION MODE: Generate and run 500 random mutations
  python test_runner.py 192.168.1.100 --fuzz-mode mutation --count 500

  # MUTATION MODE: Run targeted mutations (tag/length/value corruption)
  python test_runner.py 192.168.1.100 --fuzz-mode mutation --count 100 --targeted

  # LOAD TEST MODE: Rapid-fire tests for 60 seconds
  python test_runner.py 192.168.1.100 --fuzz-mode load --duration 60

  # Run Section 2 with iteration mode
  python test_runner.py 192.168.1.100 --suite section2 --fuzz-mode iteration --iterations 50

  # Export results to JSON
  python test_runner.py 192.168.1.100 -o results.json
        """
    )

    parser.add_argument('target', help='Target LDAP server (IP or hostname)')
    parser.add_argument('-p', '--port', type=int, default=389,
                       help='Target port (default: 389)')
    parser.add_argument('-m', '--method', choices=['socket', 'scapy'], default='socket',
                       help='Test method (default: socket)')
    parser.add_argument('-s', '--suite',
                       choices=['1.1.1', '1.1.2', '1.1.3', '2.1.1', '2.1.2', '2.1.3',
                               'section1', 'section2', 'all'],
                       default='all',
                       help='Test suite to run: specific suite (1.1.1-1.1.3, 2.1.1-2.1.3), '
                            'section1 (all Section 1), section2 (all Section 2), or all (default: all)')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                       help='Response timeout in seconds (default: 5.0)')
    parser.add_argument('-d', '--delay', type=float, default=0.1,
                       help='Delay between tests in seconds (default: 0.1)')

    # Fuzzing mode options
    parser.add_argument('--fuzz-mode', choices=['default', 'iteration', 'mutation', 'load'],
                       default='default',
                       help='Fuzzing mode: default (single run), iteration (repeat N times), '
                            'mutation (random mutations), load (rapid-fire stress test)')
    parser.add_argument('--iterations', type=int, default=10,
                       help='Number of iterations per test (iteration mode, default: 10)')
    parser.add_argument('--count', type=int, default=100,
                       help='Number of mutations to generate (mutation mode, default: 100)')
    parser.add_argument('--duration', type=int, default=60,
                       help='Duration in seconds (load mode, default: 60)')
    parser.add_argument('--targeted', action='store_true',
                       help='Use targeted mutations (mutation mode only)')
    parser.add_argument('--rapid-fire', action='store_true', default=True,
                       help='Use rapid-fire mode with minimal delay (load mode, default: True)')

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

        # Determine fuzzing mode and run tests accordingly
        results = None

        if args.fuzz_mode == 'default':
            # DEFAULT MODE: Single run of each test case
            print(f"\n{'='*70}")
            print(f"Running in DEFAULT mode (single run of each test)")
            print(f"{'='*70}\n")

            if args.suite == 'all':
                results = runner.run_all_tests()
            else:
                results = runner.run_test_suite(args.suite)

        elif args.fuzz_mode == 'iteration':
            # ITERATION MODE: Run each test N times
            print(f"\n{'='*70}")
            print(f"Running in ITERATION mode ({args.iterations} iterations per test)")
            print(f"{'='*70}\n")

            if method == TestMethod.SOCKET:
                # Get test cases based on suite selection
                all_test_cases = get_test_cases_for_suite(args.suite)
                test_cases = []
                for suite_tests in all_test_cases.values():
                    test_cases.extend(suite_tests)

                results = runner.runner.run_iteration_mode(
                    test_cases,
                    iterations=args.iterations,
                    check_server_health=not args.no_health_check
                )
            else:
                print("⚠ Iteration mode is currently only supported with socket method")
                print("  Falling back to default mode...")
                results = runner.run_all_tests()

        elif args.fuzz_mode == 'mutation':
            # MUTATION MODE: Generate and run random/targeted mutations
            mutation_type = "TARGETED" if args.targeted else "RANDOM"
            print(f"\n{'='*70}")
            print(f"Running in MUTATION mode ({mutation_type}, {args.count} mutations)")
            print(f"{'='*70}\n")

            if method == TestMethod.SOCKET:
                results = runner.runner.run_mutation_mode(
                    count=args.count,
                    targeted=args.targeted,
                    check_server_health=not args.no_health_check
                )
            else:
                print("⚠ Mutation mode is currently only supported with socket method")
                print("  Falling back to default mode...")
                results = runner.run_all_tests()

        elif args.fuzz_mode == 'load':
            # LOAD TEST MODE: Rapid-fire stress testing
            fire_mode = "RAPID-FIRE" if args.rapid_fire else "NORMAL"
            print(f"\n{'='*70}")
            print(f"Running in LOAD TEST mode ({fire_mode}, {args.duration} seconds)")
            print(f"{'='*70}\n")

            if method == TestMethod.SOCKET:
                results = runner.runner.run_load_test_mode(
                    duration_seconds=args.duration,
                    rapid_fire=args.rapid_fire
                )
            else:
                print("⚠ Load test mode is currently only supported with socket method")
                print("  Falling back to default mode...")
                results = runner.run_all_tests()

        # Export results
        if args.output and results:
            from results_logger import ResultsLogger
            logger = ResultsLogger(args.output)

            # Handle different result formats
            if isinstance(results, list):
                # Flatten results if needed
                flat_results = []
                for item in results:
                    if isinstance(item, dict):
                        # Dictionary of results by suite
                        for suite_results in item.values():
                            flat_results.extend(suite_results)
                    else:
                        flat_results.append(item)

                logger.log_socket_results(flat_results)
            elif isinstance(results, dict):
                # Dictionary format from run_all_tests
                flat_results = []
                for suite_results in results.values():
                    flat_results.extend(suite_results)
                logger.log_socket_results(flat_results)

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
