"""
Fuzz Test Case Generators for RFC 4511 Section 2

This module contains specific test case generators for:
- Test Case 2.1.1: MessageID Tests
- Test Case 2.1.2: ProtocolOp Field Tests
- Test Case 2.1.3: Controls Tests
"""

from typing import List, Dict, Tuple, Optional
import sys
import os
import struct

# Add parent directory to path for common module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.ber_encoder import BEREncoder, BERLength, BERTag
from common.ldap_messages import (
    LDAPMessage, BindRequest, SearchRequest, UnbindRequest
)


class TestCase_2_1_1_MessageIDTests:
    """
    Test Case 2.1.1: MessageID Tests

    Tests:
    - messageID = 0 (reserved for unsolicited notifications from server)
    - Duplicate messageIDs in concurrent requests
    - MessageID > maxInt (2147483647)
    - Negative messageIDs
    - MessageID reuse before operation completes
    - Sequential vs random messageID patterns
    """

    @staticmethod
    def generate_all_tests() -> List[Dict]:
        """
        Generate all 2.1.1 test cases

        Returns:
            List of test case dictionaries with 'id', 'name', 'description', 'packet', 'expected'
        """
        tests = []

        # Test 1: MessageID = 0 (reserved for server unsolicited notifications)
        tests.append({
            'id': '2.1.1.1',
            'name': 'MessageID Zero (Reserved)',
            'description': 'Send request with messageID=0 (reserved for server unsolicited notifications)',
            'packet': TestCase_2_1_1_MessageIDTests._message_id_zero(),
            'expected': 'protocolError (2) or accept (some servers may allow)'
        })

        # Test 2: Duplicate messageIDs (requires sending multiple packets)
        tests.append({
            'id': '2.1.1.2',
            'name': 'Duplicate MessageIDs',
            'description': 'Send two concurrent requests with same messageID',
            'packet': TestCase_2_1_1_MessageIDTests._duplicate_message_ids(),
            'expected': 'Server should handle gracefully, may reject or process both',
            'multi_packet': True
        })

        # Test 3: MessageID > maxInt
        tests.append({
            'id': '2.1.1.3',
            'name': 'MessageID Greater Than MaxInt',
            'description': 'Send messageID > 2147483647 (maxInt)',
            'packet': TestCase_2_1_1_MessageIDTests._message_id_overflow(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 4: Negative messageID
        tests.append({
            'id': '2.1.1.4',
            'name': 'Negative MessageID',
            'description': 'Send negative messageID value',
            'packet': TestCase_2_1_1_MessageIDTests._negative_message_id(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 5: Extremely large messageID (64-bit)
        tests.append({
            'id': '2.1.1.5',
            'name': 'Extremely Large MessageID (64-bit)',
            'description': 'Send messageID as 64-bit value (0xFFFFFFFFFFFFFFFF)',
            'packet': TestCase_2_1_1_MessageIDTests._huge_message_id(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 6: messageID with leading zeros (malformed encoding)
        tests.append({
            'id': '2.1.1.6',
            'name': 'MessageID with Leading Zeros',
            'description': 'Send messageID with unnecessary leading zero bytes',
            'packet': TestCase_2_1_1_MessageIDTests._message_id_leading_zeros(),
            'expected': 'protocolError (2) or accept (lenient)'
        })

        return tests

    @staticmethod
    def _message_id_zero() -> bytes:
        """Create message with messageID = 0"""
        # Manually encode messageID = 0
        message_id = BEREncoder.encode_integer(0)
        bind_request = BindRequest.create()

        # Construct SEQUENCE manually
        content = message_id + bind_request
        return BEREncoder.encode_sequence([message_id, bind_request[:0]])[:-1] + bind_request

    @staticmethod
    def _duplicate_message_ids() -> List[bytes]:
        """Create two messages with same messageID"""
        # Both messages use messageID=42
        msg1 = LDAPMessage.create(42, BindRequest.create())
        msg2 = LDAPMessage.create(42, BindRequest.create())
        return [msg1, msg2]

    @staticmethod
    def _message_id_overflow() -> bytes:
        """Create message with messageID > maxInt"""
        # messageID = 0xFFFFFFFF (4294967295, exceeds maxInt)
        message_id_tag = bytes([0x02])  # INTEGER tag
        message_id_length = bytes([0x05])
        message_id_value = bytes([0x00]) + struct.pack('>I', 0xFFFFFFFF)
        message_id = message_id_tag + message_id_length + message_id_value

        bind_request = BindRequest.create()

        sequence_content = message_id + bind_request
        sequence_tag = bytes([0x30])
        sequence_length = BERLength.encode_length(len(sequence_content))

        return sequence_tag + sequence_length + sequence_content

    @staticmethod
    def _negative_message_id() -> bytes:
        """Create message with negative messageID"""
        # messageID = -1
        message_id = BEREncoder.encode_integer(-1)
        bind_request = BindRequest.create()

        return LDAPMessage.create(0, bind_request[:0])[: -len(bind_request)] + bind_request

    @staticmethod
    def _huge_message_id() -> bytes:
        """Create message with 64-bit messageID"""
        # messageID = 0xFFFFFFFFFFFFFFFF
        message_id_tag = bytes([0x02])
        message_id_length = bytes([0x08])
        message_id_value = struct.pack('>Q', 0xFFFFFFFFFFFFFFFF)
        message_id = message_id_tag + message_id_length + message_id_value

        bind_request = BindRequest.create()

        sequence_content = message_id + bind_request
        sequence_tag = bytes([0x30])
        sequence_length = BERLength.encode_length(len(sequence_content))

        return sequence_tag + sequence_length + sequence_content

    @staticmethod
    def _message_id_leading_zeros() -> bytes:
        """Create message with messageID having leading zeros"""
        # messageID = 1 but encoded with leading zeros
        message_id_tag = bytes([0x02])
        message_id_length = bytes([0x04])
        message_id_value = bytes([0x00, 0x00, 0x00, 0x01])
        message_id = message_id_tag + message_id_length + message_id_value

        bind_request = BindRequest.create()

        sequence_content = message_id + bind_request
        sequence_tag = bytes([0x30])
        sequence_length = BERLength.encode_length(len(sequence_content))

        return sequence_tag + sequence_length + sequence_content


class TestCase_2_1_2_ProtocolOpTests:
    """
    Test Case 2.1.2: ProtocolOp Field Tests

    Tests:
    - Unrecognized protocolOp tags
    - Missing protocolOp field
    - Multiple protocolOp choices in single message
    - Empty protocolOp
    - Response operations sent as requests
    """

    @staticmethod
    def generate_all_tests() -> List[Dict]:
        """Generate all 2.1.2 test cases"""
        tests = []

        # Test 1: Unrecognized protocolOp tag
        tests.append({
            'id': '2.1.2.1',
            'name': 'Unrecognized ProtocolOp Tag',
            'description': 'Send message with invalid APPLICATION tag (e.g., 99)',
            'packet': TestCase_2_1_2_ProtocolOpTests._unrecognized_protocol_op(),
            'expected': 'protocolError (2)'
        })

        # Test 2: Missing protocolOp field
        tests.append({
            'id': '2.1.2.2',
            'name': 'Missing ProtocolOp Field',
            'description': 'Send LDAP message with messageID but no protocolOp',
            'packet': TestCase_2_1_2_ProtocolOpTests._missing_protocol_op(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 3: Multiple protocolOp in single message
        tests.append({
            'id': '2.1.2.3',
            'name': 'Multiple ProtocolOp Fields',
            'description': 'Send message with two protocolOp choices (e.g., BindRequest + SearchRequest)',
            'packet': TestCase_2_1_2_ProtocolOpTests._multiple_protocol_ops(),
            'expected': 'protocolError (2)'
        })

        # Test 4: Empty protocolOp
        tests.append({
            'id': '2.1.2.4',
            'name': 'Empty ProtocolOp',
            'description': 'Send protocolOp with zero-length content',
            'packet': TestCase_2_1_2_ProtocolOpTests._empty_protocol_op(),
            'expected': 'protocolError (2)'
        })

        # Test 5: Response operation sent as request
        tests.append({
            'id': '2.1.2.5',
            'name': 'Response Operation As Request',
            'description': 'Send BindResponse (APPLICATION 1) from client instead of BindRequest',
            'packet': TestCase_2_1_2_ProtocolOpTests._response_as_request(),
            'expected': 'protocolError (2) or ignore'
        })

        return tests

    @staticmethod
    def _unrecognized_protocol_op() -> bytes:
        """Create message with unrecognized APPLICATION tag"""
        message_id = BEREncoder.encode_integer(1)

        # Use APPLICATION tag 99 (unrecognized)
        unknown_op = BEREncoder.encode_application(99, b"test data")

        return LDAPMessage.create(1, unknown_op)

    @staticmethod
    def _missing_protocol_op() -> bytes:
        """Create message with no protocolOp"""
        # Just messageID, no protocolOp
        message_id = BEREncoder.encode_integer(1)

        # SEQUENCE with only messageID
        sequence_tag = bytes([0x30])
        sequence_length = BERLength.encode_length(len(message_id))

        return sequence_tag + sequence_length + message_id

    @staticmethod
    def _multiple_protocol_ops() -> bytes:
        """Create message with two protocolOp fields"""
        message_id = BEREncoder.encode_integer(1)
        bind_request = BindRequest.create()
        search_request = SearchRequest.create(base_dn="", scope=0)

        # SEQUENCE with messageID + two protocolOps
        content = message_id + bind_request + search_request
        sequence_tag = bytes([0x30])
        sequence_length = BERLength.encode_length(len(content))

        return sequence_tag + sequence_length + content

    @staticmethod
    def _empty_protocol_op() -> bytes:
        """Create message with empty protocolOp"""
        message_id = BEREncoder.encode_integer(1)

        # Empty BindRequest (APPLICATION 0 with zero length)
        empty_op_tag = bytes([0x60])  # APPLICATION 0
        empty_op_length = bytes([0x00])
        empty_op = empty_op_tag + empty_op_length

        content = message_id + empty_op
        return BEREncoder.encode_sequence([message_id, empty_op[:0]])[:-1] + empty_op

    @staticmethod
    def _response_as_request() -> bytes:
        """Send BindResponse (APPLICATION 1) as a request"""
        message_id = BEREncoder.encode_integer(1)

        # BindResponse: SEQUENCE { resultCode, matchedDN, diagnosticMessage }
        result_code = BEREncoder.encode_enumerated(0)
        matched_dn = BEREncoder.encode_octet_string(b"")
        diagnostic = BEREncoder.encode_octet_string(b"")

        bind_response_content = result_code + matched_dn + diagnostic
        bind_response = BEREncoder.encode_application(1, bind_response_content)

        return LDAPMessage.create(1, bind_response)


class TestCase_2_1_3_ControlsTests:
    """
    Test Case 2.1.3: Controls Tests

    Tests:
    - Malformed control structures
    - Unrecognized controlType OIDs
    - Invalid criticality handling
    - Missing controlValue when required
    - Oversized controlValue fields
    - Multiple conflicting controls
    - Controls with wrong operations
    """

    @staticmethod
    def generate_all_tests() -> List[Dict]:
        """Generate all 2.1.3 test cases"""
        tests = []

        # Test 1: Malformed control structure
        tests.append({
            'id': '2.1.3.1',
            'name': 'Malformed Control Structure',
            'description': 'Send control with invalid BER structure',
            'packet': TestCase_2_1_3_ControlsTests._malformed_control(),
            'expected': 'protocolError (2)'
        })

        # Test 2: Unrecognized controlType OID
        tests.append({
            'id': '2.1.3.2',
            'name': 'Unrecognized Control Type OID',
            'description': 'Send control with unrecognized/invalid OID',
            'packet': TestCase_2_1_3_ControlsTests._unrecognized_control_oid(),
            'expected': 'unavailableCriticalExtension (12) if critical, or accept if non-critical'
        })

        # Test 3: Invalid criticality value (non-BOOLEAN)
        tests.append({
            'id': '2.1.3.3',
            'name': 'Invalid Criticality Value',
            'description': 'Send control with invalid criticality value (not TRUE/FALSE)',
            'packet': TestCase_2_1_3_ControlsTests._invalid_criticality(),
            'expected': 'protocolError (2)'
        })

        # Test 4: Missing required controlValue
        tests.append({
            'id': '2.1.3.4',
            'name': 'Missing Required ControlValue',
            'description': 'Send known control type without required controlValue',
            'packet': TestCase_2_1_3_ControlsTests._missing_control_value(),
            'expected': 'unavailableCriticalExtension (12) or protocolError (2)'
        })

        # Test 5: Oversized controlValue
        tests.append({
            'id': '2.1.3.5',
            'name': 'Oversized ControlValue',
            'description': 'Send control with extremely large controlValue field',
            'packet': TestCase_2_1_3_ControlsTests._oversized_control_value(),
            'expected': 'sizeLimitExceeded (4) or protocolError (2)'
        })

        # Test 6: Multiple conflicting controls
        tests.append({
            'id': '2.1.3.6',
            'name': 'Multiple Conflicting Controls',
            'description': 'Send multiple controls with conflicting semantics',
            'packet': TestCase_2_1_3_ControlsTests._conflicting_controls(),
            'expected': 'unavailableCriticalExtension (12) or accept one'
        })

        # Test 7: Controls on UnbindRequest (not allowed)
        tests.append({
            'id': '2.1.3.7',
            'name': 'Controls on UnbindRequest',
            'description': 'Send UnbindRequest with controls (should be rejected per RFC)',
            'packet': TestCase_2_1_3_ControlsTests._controls_on_unbind(),
            'expected': 'Server should ignore (Unbind has no response) or close connection'
        })

        return tests

    @staticmethod
    def _malformed_control() -> bytes:
        """Create message with malformed control"""
        message_id = BEREncoder.encode_integer(1)
        bind_request = BindRequest.create()

        # Malformed control: invalid BER structure
        malformed_control = bytes([0x30, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

        # Controls are CONTEXT 0
        controls_tag = bytes([0xA0])
        controls_length = BERLength.encode_length(len(malformed_control))
        controls = controls_tag + controls_length + malformed_control

        content = message_id + bind_request + controls
        return BEREncoder.encode_sequence([message_id, bind_request[:0], controls[:0]])[:-len(bind_request)-len(controls)] + bind_request + controls

    @staticmethod
    def _unrecognized_control_oid() -> bytes:
        """Create message with unrecognized control OID"""
        message_id = BEREncoder.encode_integer(1)
        bind_request = BindRequest.create()

        # Control with fake OID "9.9.9.9.9"
        control_type = BEREncoder.encode_octet_string(b"9.9.9.9.9")
        criticality = BEREncoder.encode_boolean(True)  # Critical

        control = BEREncoder.encode_sequence([control_type, criticality])
        controls = BEREncoder.encode_context(0, control, primitive=False)

        content = message_id + bind_request + controls
        return BEREncoder.encode_sequence([message_id, bind_request[:0], controls[:0]])[:-len(bind_request)-len(controls)] + bind_request + controls

    @staticmethod
    def _invalid_criticality() -> bytes:
        """Create control with invalid criticality value"""
        message_id = BEREncoder.encode_integer(1)
        bind_request = BindRequest.create()

        # Control with invalid criticality (0x42 instead of 0x00/0xFF)
        control_type = BEREncoder.encode_octet_string(b"1.2.3.4")
        criticality_tag = bytes([0x01])  # BOOLEAN tag
        criticality_length = bytes([0x01])
        criticality_value = bytes([0x42])  # Invalid!
        invalid_criticality = criticality_tag + criticality_length + criticality_value

        control_seq = control_type + invalid_criticality
        control = BEREncoder.encode_sequence([control_seq[:0]])[:-1] + control_seq
        controls = BEREncoder.encode_context(0, control, primitive=False)

        content = message_id + bind_request + controls
        return BEREncoder.encode_sequence([message_id, bind_request[:0], controls[:0]])[:-len(bind_request)-len(controls)] + bind_request + controls

    @staticmethod
    def _missing_control_value() -> bytes:
        """Create control without required controlValue"""
        message_id = BEREncoder.encode_integer(1)
        bind_request = BindRequest.create()

        # Paged Results Control (1.2.840.113556.1.4.319) requires controlValue
        control_type = BEREncoder.encode_octet_string(b"1.2.840.113556.1.4.319")
        criticality = BEREncoder.encode_boolean(True)
        # No controlValue provided

        control = BEREncoder.encode_sequence([control_type, criticality])
        controls = BEREncoder.encode_context(0, control, primitive=False)

        content = message_id + bind_request + controls
        return BEREncoder.encode_sequence([message_id, bind_request[:0], controls[:0]])[:-len(bind_request)-len(controls)] + bind_request + controls

    @staticmethod
    def _oversized_control_value() -> bytes:
        """Create control with oversized controlValue"""
        message_id = BEREncoder.encode_integer(1)
        bind_request = BindRequest.create()

        # Control with huge controlValue (1MB of data)
        control_type = BEREncoder.encode_octet_string(b"1.2.3.4")
        criticality = BEREncoder.encode_boolean(False)
        huge_value = bytes([0x04, 0x84]) + struct.pack('>I', 1024*1024) + (b'A' * 1000)  # Truncated huge value

        control_seq = control_type + criticality + huge_value
        control = BEREncoder.encode_sequence([control_seq[:0]])[:-1] + control_seq
        controls = BEREncoder.encode_context(0, control, primitive=False)

        content = message_id + bind_request + controls
        return BEREncoder.encode_sequence([message_id, bind_request[:0], controls[:0]])[:-len(bind_request)-len(controls)] + bind_request + controls

    @staticmethod
    def _conflicting_controls() -> bytes:
        """Create message with conflicting controls"""
        message_id = BEREncoder.encode_integer(1)
        search_request = SearchRequest.create(base_dn="", scope=0)

        # Two sorting controls with different criteria (conflict)
        control1_type = BEREncoder.encode_octet_string(b"1.2.840.113556.1.4.473")  # Sort Control
        control1_crit = BEREncoder.encode_boolean(True)
        control1 = BEREncoder.encode_sequence([control1_type, control1_crit])

        control2_type = BEREncoder.encode_octet_string(b"1.2.840.113556.1.4.473")  # Same control again
        control2_crit = BEREncoder.encode_boolean(True)
        control2 = BEREncoder.encode_sequence([control2_type, control2_crit])

        controls_seq = control1 + control2
        controls = BEREncoder.encode_context(0, controls_seq, primitive=False)

        content = message_id + search_request + controls
        return BEREncoder.encode_sequence([message_id, search_request[:0], controls[:0]])[:-len(search_request)-len(controls)] + search_request + controls

    @staticmethod
    def _controls_on_unbind() -> bytes:
        """Create UnbindRequest with controls (not allowed per RFC)"""
        message_id = BEREncoder.encode_integer(1)
        unbind_request = UnbindRequest.create()

        # Add control to Unbind (should be rejected)
        control_type = BEREncoder.encode_octet_string(b"1.2.3.4")
        criticality = BEREncoder.encode_boolean(False)
        control = BEREncoder.encode_sequence([control_type, criticality])
        controls = BEREncoder.encode_context(0, control, primitive=False)

        content = message_id + unbind_request + controls
        return BEREncoder.encode_sequence([message_id, unbind_request[:0], controls[:0]])[:-len(unbind_request)-len(controls)] + unbind_request + controls


# Convenience function to get all Section 2 test cases
def get_all_test_cases() -> Dict[str, List[Dict]]:
    """
    Get all Section 2 test cases organized by test suite

    Returns:
        Dictionary mapping test suite ID to list of test cases
    """
    return {
        '2.1.1': TestCase_2_1_1_MessageIDTests.generate_all_tests(),
        '2.1.2': TestCase_2_1_2_ProtocolOpTests.generate_all_tests(),
        '2.1.3': TestCase_2_1_3_ControlsTests.generate_all_tests()
    }
