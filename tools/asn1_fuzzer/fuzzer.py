"""
LDAP Protocol Fuzzer - Main Engine

This module provides the main fuzzing engine that sends test cases to the
target LDAP server and collects results.
"""

import socket
import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ServerStatus(Enum):
    """Server response status"""
    RESPONSIVE = "responsive"
    NO_RESPONSE = "no_response"
    CONNECTION_CLOSED = "connection_closed"
    CONNECTION_REFUSED = "connection_refused"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class FuzzResult:
    """Result of a single fuzz test"""
    test_id: str
    test_name: str
    description: str
    packet_sent: bytes
    response_received: Optional[bytes]
    server_status: ServerStatus
    response_time: float
    error_message: Optional[str]
    timestamp: float

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'test_id': self.test_id,
            'test_name': self.test_name,
            'description': self.description,
            'packet_sent_hex': self.packet_sent.hex(),
            'packet_sent_len': len(self.packet_sent),
            'response_received_hex': self.response_received.hex() if self.response_received else None,
            'response_received_len': len(self.response_received) if self.response_received else 0,
            'server_status': self.server_status.value,
            'response_time_ms': round(self.response_time * 1000, 2),
            'error_message': self.error_message,
            'timestamp': self.timestamp
        }


class LDAPFuzzer:
    """
    Main LDAP Fuzzing Engine

    Handles connection management, packet sending, and response collection
    """

    def __init__(self,
                 target_host: str,
                 target_port: int = 389,
                 timeout: float = 5.0,
                 delay_between_tests: float = 0.1,
                 max_response_size: int = 65536,
                 use_tls: bool = False):
        """
        Initialize the fuzzer

        Args:
            target_host: Target LDAP server hostname or IP
            target_port: Target LDAP server port (default 389)
            timeout: Socket timeout in seconds
            delay_between_tests: Delay between test cases in seconds
            max_response_size: Maximum response size to read
            use_tls: Whether to use TLS (not implemented yet)
        """
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.delay_between_tests = delay_between_tests
        self.max_response_size = max_response_size
        self.use_tls = use_tls

        # Setup logging
        self.logger = logging.getLogger('LDAPFuzzer')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

        self.results: List[FuzzResult] = []

    def _create_connection(self) -> Tuple[Optional[socket.socket], Optional[str]]:
        """
        Create a connection to the target server

        Returns:
            Tuple of (socket, error_message)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, self.target_port))

            if self.use_tls:
                # TODO: Implement TLS/StartTLS
                import ssl
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.target_host)

            return sock, None

        except socket.timeout:
            return None, "Connection timeout"
        except ConnectionRefusedError:
            return None, "Connection refused"
        except Exception as e:
            return None, f"Connection error: {str(e)}"

    def _send_packet(self, sock: socket.socket, packet: bytes) -> Tuple[bool, Optional[str]]:
        """
        Send a packet to the server

        Args:
            sock: Connected socket
            packet: Packet bytes to send

        Returns:
            Tuple of (success, error_message)
        """
        try:
            sock.sendall(packet)
            return True, None
        except Exception as e:
            return False, f"Send error: {str(e)}"

    def _receive_response(self, sock: socket.socket) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Receive response from server

        Args:
            sock: Connected socket

        Returns:
            Tuple of (response_bytes, error_message)
        """
        try:
            # Try to receive response
            response = sock.recv(self.max_response_size)
            return response, None
        except socket.timeout:
            return None, "Response timeout"
        except ConnectionResetError:
            return None, "Connection reset by peer"
        except Exception as e:
            return None, f"Receive error: {str(e)}"

    def _check_server_responsive(self) -> bool:
        """
        Check if server is still responsive with a simple request

        Returns:
            True if server responds, False otherwise
        """
        try:
            from .ldap_messages import BindRequest, LDAPMessage

            sock, error = self._create_connection()
            if sock is None:
                return False

            # Send anonymous bind
            bind_req = BindRequest.create(version=3, name="", password="")
            ldap_msg = LDAPMessage.create(999, bind_req)

            success, error = self._send_packet(sock, ldap_msg)
            if not success:
                sock.close()
                return False

            response, error = self._receive_response(sock)
            sock.close()

            return response is not None and len(response) > 0

        except Exception as e:
            self.logger.error(f"Server health check failed: {e}")
            return False

    def run_test_case(self, test_case: Dict) -> FuzzResult:
        """
        Run a single test case

        Args:
            test_case: Test case dictionary with 'id', 'name', 'description', 'packet'

        Returns:
            FuzzResult object
        """
        test_id = test_case['id']
        test_name = test_case['name']
        description = test_case['description']
        packet = test_case['packet']

        self.logger.info(f"Running test {test_id}: {test_name}")

        start_time = time.time()
        timestamp = time.time()

        # Create connection
        sock, error = self._create_connection()
        if sock is None:
            result = FuzzResult(
                test_id=test_id,
                test_name=test_name,
                description=description,
                packet_sent=packet,
                response_received=None,
                server_status=ServerStatus.CONNECTION_REFUSED if "refused" in error.lower()
                              else ServerStatus.CONNECTION_CLOSED,
                response_time=time.time() - start_time,
                error_message=error,
                timestamp=timestamp
            )
            self.results.append(result)
            return result

        # Send packet
        success, send_error = self._send_packet(sock, packet)
        if not success:
            sock.close()
            result = FuzzResult(
                test_id=test_id,
                test_name=test_name,
                description=description,
                packet_sent=packet,
                response_received=None,
                server_status=ServerStatus.ERROR,
                response_time=time.time() - start_time,
                error_message=send_error,
                timestamp=timestamp
            )
            self.results.append(result)
            return result

        # Receive response
        response, recv_error = self._receive_response(sock)
        response_time = time.time() - start_time

        # Determine server status
        if response and len(response) > 0:
            server_status = ServerStatus.RESPONSIVE
            error_message = None
        elif recv_error and "timeout" in recv_error.lower():
            server_status = ServerStatus.TIMEOUT
            error_message = recv_error
        elif recv_error and "reset" in recv_error.lower():
            server_status = ServerStatus.CONNECTION_CLOSED
            error_message = recv_error
        elif response is not None and len(response) == 0:
            server_status = ServerStatus.CONNECTION_CLOSED
            error_message = "Server closed connection"
        else:
            server_status = ServerStatus.NO_RESPONSE
            error_message = recv_error

        sock.close()

        result = FuzzResult(
            test_id=test_id,
            test_name=test_name,
            description=description,
            packet_sent=packet,
            response_received=response,
            server_status=server_status,
            response_time=response_time,
            error_message=error_message,
            timestamp=timestamp
        )

        self.results.append(result)
        return result

    def run_test_suite(self, test_cases: List[Dict], check_server_health: bool = True) -> List[FuzzResult]:
        """
        Run a suite of test cases

        Args:
            test_cases: List of test case dictionaries
            check_server_health: Whether to check server health between tests

        Returns:
            List of FuzzResult objects
        """
        self.logger.info(f"Starting test suite with {len(test_cases)} test cases")
        self.logger.info(f"Target: {self.target_host}:{self.target_port}")

        suite_results = []

        for i, test_case in enumerate(test_cases):
            # Run the test
            result = self.run_test_case(test_case)
            suite_results.append(result)

            # Log result
            self.logger.info(
                f"Test {result.test_id} completed: "
                f"Status={result.server_status.value}, "
                f"ResponseTime={result.response_time:.3f}s"
            )

            # Check if server crashed
            if result.server_status in [ServerStatus.CONNECTION_CLOSED,
                                       ServerStatus.CONNECTION_REFUSED]:
                self.logger.warning(
                    f"Server may have crashed after test {result.test_id}"
                )

                if check_server_health:
                    self.logger.info("Checking server health...")
                    time.sleep(2)  # Wait before health check

                    if not self._check_server_responsive():
                        self.logger.error(
                            "Server is not responsive! Stopping test suite."
                        )
                        break
                    else:
                        self.logger.info("Server is responsive")

            # Delay between tests
            if i < len(test_cases) - 1:
                time.sleep(self.delay_between_tests)

        self.logger.info(f"Test suite completed. {len(suite_results)} tests run.")
        return suite_results

    def run_all_test_cases(self, check_server_health: bool = True) -> Dict[str, List[FuzzResult]]:
        """
        Run all available test cases (1.1.1, 1.1.2, 1.1.3)

        Args:
            check_server_health: Whether to check server health between tests

        Returns:
            Dictionary mapping test suite ID to list of results
        """
        from .fuzz_generators import get_all_test_cases

        all_tests = get_all_test_cases()
        all_results = {}

        for suite_id, test_cases in all_tests.items():
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Running Test Suite {suite_id}")
            self.logger.info(f"{'='*60}\n")

            results = self.run_test_suite(test_cases, check_server_health)
            all_results[suite_id] = results

            # Summary for this suite
            responsive = sum(1 for r in results if r.server_status == ServerStatus.RESPONSIVE)
            crashed = sum(1 for r in results
                         if r.server_status in [ServerStatus.CONNECTION_CLOSED,
                                               ServerStatus.CONNECTION_REFUSED])

            self.logger.info(f"\nSuite {suite_id} Summary:")
            self.logger.info(f"  Total tests: {len(results)}")
            self.logger.info(f"  Server responded: {responsive}")
            self.logger.info(f"  Server crashed/closed: {crashed}")

        return all_results

    def get_results(self) -> List[FuzzResult]:
        """Get all collected results"""
        return self.results

    def clear_results(self):
        """Clear all stored results"""
        self.results = []
