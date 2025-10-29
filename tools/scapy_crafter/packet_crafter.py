"""
LDAP Packet Crafting Utilities

High-level utilities for crafting LDAP packets with Scapy.
Integrates with the ASN.1 fuzzer to use pre-built test cases.
"""

import sys
import os
from typing import Optional, Dict, List, Tuple

# Add parent directory to path to import asn1_fuzzer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from scapy.all import IP, TCP, Raw, send, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


from common.ber_encoder import BEREncoder, BERLength, BERTag
from common.ldap_messages import (
    LDAPMessage, BindRequest, SearchRequest, UnbindRequest,
    ExtendedRequest, AbandonRequest, LDAPControl
)


class LDAPPacketCrafter:
    """
    High-level LDAP packet crafting interface

    Provides methods to craft LDAP packets with custom/malformed components
    """

    def __init__(self, target_ip: str, target_port: int = 389, source_ip: Optional[str] = None):
        """
        Initialize the packet crafter

        Args:
            target_ip: Target LDAP server IP
            target_port: Target LDAP server port (default 389)
            source_ip: Source IP address (optional)
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required. Install with: pip install scapy")

        self.target_ip = target_ip
        self.target_port = target_port
        self.source_ip = source_ip

        # Disable Scapy verbosity by default
        conf.verb = 0

    def craft_bind_request(self,
                          message_id: int = 1,
                          version: int = 3,
                          dn: str = "",
                          password: str = "",
                          sasl_mechanism: Optional[str] = None,
                          sasl_credentials: Optional[bytes] = None,
                          controls: Optional[List[bytes]] = None) -> bytes:
        """
        Craft a standard LDAP BindRequest

        Args:
            message_id: Message ID
            version: LDAP version (typically 3)
            dn: Distinguished name to bind as
            password: Password for simple bind
            sasl_mechanism: SASL mechanism (if using SASL)
            sasl_credentials: SASL credentials
            controls: Optional list of controls

        Returns:
            Raw LDAP message bytes
        """
        bind_req = BindRequest.create(
            version=version,
            name=dn,
            password=password,
            sasl_mechanism=sasl_mechanism,
            sasl_credentials=sasl_credentials
        )

        ldap_msg = LDAPMessage.create(message_id, bind_req, controls)
        return ldap_msg

    def craft_search_request(self,
                           message_id: int = 1,
                           base_dn: str = "",
                           scope: int = 0,
                           filter_str: str = "(objectClass=*)",
                           attributes: List[str] = None,
                           controls: Optional[List[bytes]] = None) -> bytes:
        """
        Craft a standard LDAP SearchRequest

        Args:
            message_id: Message ID
            base_dn: Base DN for search
            scope: Search scope (0=base, 1=one, 2=sub)
            filter_str: Search filter
            attributes: Attributes to retrieve
            controls: Optional controls

        Returns:
            Raw LDAP message bytes
        """
        search_req = SearchRequest.create(
            base_dn=base_dn,
            scope=scope,
            filter_str=filter_str,
            attributes=attributes or []
        )

        ldap_msg = LDAPMessage.create(message_id, search_req, controls)
        return ldap_msg

    def craft_unbind_request(self, message_id: int = 1) -> bytes:
        """
        Craft an LDAP UnbindRequest

        Args:
            message_id: Message ID

        Returns:
            Raw LDAP message bytes
        """
        unbind_req = UnbindRequest.create()
        ldap_msg = LDAPMessage.create(message_id, unbind_req)
        return ldap_msg

    def craft_extended_request(self,
                             message_id: int = 1,
                             request_name: str = "",
                             request_value: Optional[bytes] = None,
                             controls: Optional[List[bytes]] = None) -> bytes:
        """
        Craft an LDAP ExtendedRequest

        Args:
            message_id: Message ID
            request_name: OID of the extended operation
            request_value: Optional request value
            controls: Optional controls

        Returns:
            Raw LDAP message bytes
        """
        ext_req = ExtendedRequest.create(request_name, request_value)
        ldap_msg = LDAPMessage.create(message_id, ext_req, controls)
        return ldap_msg

    def craft_starttls_request(self, message_id: int = 1) -> bytes:
        """
        Craft a StartTLS ExtendedRequest

        Args:
            message_id: Message ID

        Returns:
            Raw LDAP message bytes
        """
        return self.craft_extended_request(
            message_id=message_id,
            request_name=ExtendedRequest.OID_START_TLS
        )

    def craft_malformed_packet(self, raw_bytes: bytes) -> bytes:
        """
        Use pre-crafted malformed bytes

        Args:
            raw_bytes: Pre-built malformed LDAP message

        Returns:
            The same bytes (pass-through)
        """
        return raw_bytes

    def send_packet(self, ldap_bytes: bytes, wait_response: bool = True, timeout: int = 5) -> Optional[bytes]:
        """
        Send an LDAP packet using Scapy

        Args:
            ldap_bytes: LDAP message bytes to send
            wait_response: Whether to wait for a response
            timeout: Response timeout in seconds

        Returns:
            Response bytes if wait_response=True, else None
        """
        # Build IP/TCP layers
        ip_layer = IP(dst=self.target_ip)
        if self.source_ip:
            ip_layer.src = self.source_ip

        tcp_layer = TCP(dport=self.target_port, flags='PA')  # PSH+ACK

        # Combine with LDAP payload
        packet = ip_layer / tcp_layer / Raw(load=ldap_bytes)

        if wait_response:
            # Send and receive response
            response = sr1(packet, timeout=timeout, verbose=False)

            if response and response.haslayer(Raw):
                return bytes(response[Raw].load)
            else:
                return None
        else:
            # Just send, no response
            send(packet, verbose=False)
            return None

    def send_test_case(self, test_case: Dict, wait_response: bool = True) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        Send a test case from the fuzzer

        Args:
            test_case: Test case dictionary with 'packet' key
            wait_response: Whether to wait for response

        Returns:
            Tuple of (success, response_bytes, error_message)
        """
        try:
            packet = test_case['packet']
            response = self.send_packet(packet, wait_response=wait_response)
            return True, response, None
        except Exception as e:
            return False, None, str(e)


class ManualCrafter:
    """
    Manual byte-level LDAP message crafting

    For crafting specific malformed messages by hand
    """

    @staticmethod
    def craft_custom_ber(tag: int,
                        length: Optional[int],
                        value: bytes,
                        force_length: Optional[bytes] = None) -> bytes:
        """
        Craft a custom BER-encoded element

        Args:
            tag: BER tag byte
            length: Length of value (None to calculate)
            value: Value bytes
            force_length: Force specific length encoding (for fuzzing)

        Returns:
            BER-encoded bytes
        """
        tag_byte = bytes([tag])

        if force_length is not None:
            # Use forced length encoding
            length_bytes = force_length
        else:
            # Calculate length
            actual_length = length if length is not None else len(value)
            length_bytes = BERLength.encode_length(actual_length)

        return tag_byte + length_bytes + value

    @staticmethod
    def craft_sequence(elements: List[bytes],
                      malformed_length: Optional[bytes] = None,
                      use_primitive: bool = False) -> bytes:
        """
        Craft a SEQUENCE with optional malformations

        Args:
            elements: List of BER-encoded elements
            malformed_length: Use malformed length encoding
            use_primitive: Use primitive encoding (invalid for SEQUENCE)

        Returns:
            BER-encoded SEQUENCE
        """
        tag = 0x10 if use_primitive else 0x30

        content = b''.join(elements)

        if malformed_length:
            return bytes([tag]) + malformed_length + content
        else:
            return bytes([tag]) + BERLength.encode_length(len(content)) + content

    @staticmethod
    def craft_ldap_message(message_id_bytes: bytes,
                          protocol_op_bytes: bytes,
                          controls_bytes: Optional[bytes] = None,
                          outer_malformed: bool = False) -> bytes:
        """
        Craft a complete LDAP message with full control

        Args:
            message_id_bytes: Pre-encoded message ID
            protocol_op_bytes: Pre-encoded protocol operation
            controls_bytes: Optional pre-encoded controls
            outer_malformed: Make outer SEQUENCE malformed

        Returns:
            Complete LDAP message
        """
        elements = [message_id_bytes, protocol_op_bytes]

        if controls_bytes:
            elements.append(controls_bytes)

        if outer_malformed:
            # Use primitive SEQUENCE (invalid)
            return ManualCrafter.craft_sequence(elements, use_primitive=True)
        else:
            return ManualCrafter.craft_sequence(elements)

    @staticmethod
    def inject_bytes_at_position(original: bytes, position: int, injection: bytes) -> bytes:
        """
        Inject bytes at a specific position

        Args:
            original: Original bytes
            position: Position to inject at
            injection: Bytes to inject

        Returns:
            Modified bytes
        """
        return original[:position] + injection + original[position:]

    @staticmethod
    def replace_bytes(original: bytes, start: int, end: int, replacement: bytes) -> bytes:
        """
        Replace bytes in a range

        Args:
            original: Original bytes
            start: Start position
            end: End position
            replacement: Replacement bytes

        Returns:
            Modified bytes
        """
        return original[:start] + replacement + original[end:]

    @staticmethod
    def corrupt_length_field(ldap_message: bytes, corruption_type: str = 'overflow') -> bytes:
        """
        Corrupt the length field of an LDAP message

        Args:
            ldap_message: Original LDAP message
            corruption_type: Type of corruption
                - 'overflow': Set to 0xFFFFFFFF
                - 'too_short': Halve the length
                - 'too_long': Double the length
                - 'indefinite': Use indefinite length (0x80)

        Returns:
            Corrupted message
        """
        if len(ldap_message) < 2:
            return ldap_message

        # Assume message starts with SEQUENCE tag (0x30)
        # Length field starts at position 1

        if corruption_type == 'overflow':
            new_length = bytes([0x84, 0xFF, 0xFF, 0xFF, 0xFF])
        elif corruption_type == 'indefinite':
            new_length = bytes([0x80])
        elif corruption_type == 'too_short':
            # Extract original length and halve it
            if ldap_message[1] & 0x80 == 0:
                # Short form
                original_length = ldap_message[1]
                new_length = bytes([original_length // 2])
            else:
                # For simplicity, just use short form
                new_length = bytes([0x10])
        elif corruption_type == 'too_long':
            # Use a very large length
            new_length = bytes([0x82, 0xFF, 0xFF])
        else:
            return ldap_message

        # Replace length field
        # Find where length field ends
        if ldap_message[1] & 0x80 == 0:
            # Short form, 1 byte
            return ldap_message[0:1] + new_length + ldap_message[2:]
        else:
            # Long form
            num_octets = ldap_message[1] & 0x7F
            return ldap_message[0:1] + new_length + ldap_message[2 + num_octets:]


# Example usage
if __name__ == "__main__":
    if SCAPY_AVAILABLE:
        print("LDAP Packet Crafter initialized")
        print("\nExample usage:")
        print("  crafter = LDAPPacketCrafter('192.168.1.100', 389)")
        print("  bind_msg = crafter.craft_bind_request(dn='cn=admin,dc=example,dc=com', password='secret')")
        print("  response = crafter.send_packet(bind_msg)")
    else:
        print("Scapy not available. Install with: pip install scapy")
