"""
Fuzz Test Case Generators for RFC 4511 Test Plan

This module contains specific test case generators for:
- Test Case 1.1.1: Length Encoding Attacks
- Test Case 1.1.2: Type Encoding Violations
- Test Case 1.1.3: Value Encoding Issues
"""

from typing import List, Dict, Tuple
from .ber_encoder import BEREncoder, BERLength, BERTag, fuzz_tag
from .ldap_messages import (
    LDAPMessage, BindRequest, SearchRequest, UnbindRequest,
    ExtendedRequest, LDAPProtocolOp
)
import struct


class TestCase_1_1_1_LengthEncodingAttacks:
    """
    Test Case 1.1.1: Length Encoding Attacks

    Tests:
    - Indefinite length encoding (should be rejected per RFC)
    - Incorrect length values (too short, too long)
    - Length values exceeding maxInt (2147483647)
    - 32-bit integer overflow in length fields
    - Length indicating data beyond packet boundary
    """

    @staticmethod
    def generate_all_tests() -> List[Dict]:
        """
        Generate all 1.1.1 test cases

        Returns:
            List of test case dictionaries with 'name', 'packet', 'description'
        """
        tests = []

        # Test 1: Indefinite length encoding
        tests.append({
            'id': '1.1.1.1',
            'name': 'Indefinite Length Encoding',
            'description': 'Send indefinite length encoding (0x80) - should be rejected per RFC 4511',
            'packet': TestCase_1_1_1_LengthEncodingAttacks._indefinite_length(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 2: Length too short
        tests.append({
            'id': '1.1.1.2',
            'name': 'Length Too Short',
            'description': 'Send length value shorter than actual data',
            'packet': TestCase_1_1_1_LengthEncodingAttacks._length_too_short(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 3: Length too long
        tests.append({
            'id': '1.1.1.3',
            'name': 'Length Too Long',
            'description': 'Send length value longer than actual data',
            'packet': TestCase_1_1_1_LengthEncodingAttacks._length_too_long(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 4: Maximum 32-bit integer length
        tests.append({
            'id': '1.1.1.4',
            'name': 'MaxInt Length (2147483647)',
            'description': 'Send length equal to maxInt (2^31-1)',
            'packet': TestCase_1_1_1_LengthEncodingAttacks._max_int_length(),
            'expected': 'protocolError (2), busy (51), or connection close'
        })

        # Test 5: 32-bit overflow length
        tests.append({
            'id': '1.1.1.5',
            'name': '32-bit Integer Overflow',
            'description': 'Send length 0xFFFFFFFF to trigger potential overflow',
            'packet': TestCase_1_1_1_LengthEncodingAttacks._overflow_length(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 6: Length beyond packet boundary
        tests.append({
            'id': '1.1.1.6',
            'name': 'Length Beyond Packet Boundary',
            'description': 'Send huge length value (64-bit) beyond any reasonable packet',
            'packet': TestCase_1_1_1_LengthEncodingAttacks._beyond_packet_length(),
            'expected': 'protocolError (2) or connection close'
        })

        return tests

    @staticmethod
    def _indefinite_length() -> bytes:
        """Create BindRequest with indefinite length encoding"""
        # Manually construct with indefinite length
        message_id = BEREncoder.encode_integer(1)

        # Create BindRequest content
        version = BEREncoder.encode_integer(3)
        name = BEREncoder.encode_octet_string(b"")
        auth = BEREncoder.encode_context(0, b"", primitive=True)
        bind_content = version + name + auth

        # APPLICATION 0 tag with INDEFINITE length (0x80)
        tag = bytes([0x60])  # APPLICATION 0, constructed
        length = bytes([0x80])  # Indefinite length
        bind_request = tag + length + bind_content + bytes([0x00, 0x00])  # End-of-contents

        # Wrap in SEQUENCE with indefinite length
        sequence_tag = bytes([0x30])
        sequence_length = bytes([0x80])
        return sequence_tag + sequence_length + message_id + bind_request + bytes([0x00, 0x00])

    @staticmethod
    def _length_too_short() -> bytes:
        """Create BindRequest with length field too short"""
        message_id = BEREncoder.encode_integer(1)

        # Create BindRequest with actual data
        version = BEREncoder.encode_integer(3)
        name = BEREncoder.encode_octet_string(b"cn=test,dc=example,dc=com")
        auth = BEREncoder.encode_context(0, b"password", primitive=True)
        bind_content = version + name + auth

        # APPLICATION 0 tag but with length that's too short
        tag = bytes([0x60])
        # Actual length is len(bind_content), but we'll say it's half that
        false_length = BERLength.encode_length(len(bind_content) // 2)
        bind_request = tag + false_length + bind_content

        # Wrap in proper SEQUENCE
        sequence_content = message_id + bind_request
        return BEREncoder.encode_sequence([message_id, bind_request])

    @staticmethod
    def _length_too_long() -> bytes:
        """Create BindRequest with length field too long"""
        message_id = BEREncoder.encode_integer(1)

        # Create BindRequest with actual data
        version = BEREncoder.encode_integer(3)
        name = BEREncoder.encode_octet_string(b"")
        auth = BEREncoder.encode_context(0, b"", primitive=True)
        bind_content = version + name + auth

        # APPLICATION 0 tag but with length that's too long
        tag = bytes([0x60])
        # Say length is much longer than actual
        false_length = BERLength.encode_length(len(bind_content) + 1000)
        bind_request = tag + false_length + bind_content

        # Wrap in SEQUENCE with proper length
        return BEREncoder.encode_sequence([message_id, bind_request])

    @staticmethod
    def _max_int_length() -> bytes:
        """Create message with length = 2147483647 (maxInt)"""
        message_id = BEREncoder.encode_integer(1)

        # Create a simple BindRequest
        bind_request = BindRequest.create()

        # Manually construct with maxInt length
        tag = bytes([0x30])  # SEQUENCE tag
        # Length: 0x84 (4 bytes) + 0x7FFFFFFF (2147483647)
        length = bytes([0x84]) + struct.pack('>I', 0x7FFFFFFF)

        # Just send minimal data, length is the attack
        return tag + length + message_id + bind_request

    @staticmethod
    def _overflow_length() -> bytes:
        """Create message with length = 0xFFFFFFFF (overflow attempt)"""
        message_id = BEREncoder.encode_integer(1)
        bind_request = BindRequest.create()

        # Manually construct with overflow length
        tag = bytes([0x30])
        length = bytes([0x84]) + struct.pack('>I', 0xFFFFFFFF)

        return tag + length + message_id + bind_request

    @staticmethod
    def _beyond_packet_length() -> bytes:
        """Create message with absurdly large 64-bit length"""
        message_id = BEREncoder.encode_integer(1)
        bind_request = BindRequest.create()

        # Manually construct with huge length
        tag = bytes([0x30])
        # 8-byte length field
        length = bytes([0x88]) + struct.pack('>Q', 0xFFFFFFFFFFFFFFFF)

        return tag + length + message_id + bind_request


class TestCase_1_1_2_TypeEncodingViolations:
    """
    Test Case 1.1.2: Type Encoding Violations

    Tests:
    - Invalid tag numbers
    - Constructed encoding for primitive types (OCTET STRING)
    - Primitive encoding for constructed types (SEQUENCE)
    - Unrecognized APPLICATION tags
    - Extensibility with future/unknown tags
    """

    @staticmethod
    def generate_all_tests() -> List[Dict]:
        """Generate all 1.1.2 test cases"""
        tests = []

        # Test 1: Invalid tag number
        tests.append({
            'id': '1.1.2.1',
            'name': 'Invalid Tag Number',
            'description': 'Send message with invalid/reserved tag number (0xFF)',
            'packet': TestCase_1_1_2_TypeEncodingViolations._invalid_tag_number(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 2: Constructed OCTET STRING
        tests.append({
            'id': '1.1.2.2',
            'name': 'Constructed OCTET STRING',
            'description': 'Use constructed encoding for primitive type (OCTET STRING)',
            'packet': TestCase_1_1_2_TypeEncodingViolations._constructed_octet_string(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 3: Primitive SEQUENCE
        tests.append({
            'id': '1.1.2.3',
            'name': 'Primitive SEQUENCE',
            'description': 'Use primitive encoding for constructed type (SEQUENCE)',
            'packet': TestCase_1_1_2_TypeEncodingViolations._primitive_sequence(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 4: Unrecognized APPLICATION tag
        tests.append({
            'id': '1.1.2.4',
            'name': 'Unrecognized APPLICATION Tag',
            'description': 'Send unrecognized APPLICATION tag (e.g., 99)',
            'packet': TestCase_1_1_2_TypeEncodingViolations._unrecognized_application_tag(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 5: Unknown context tag
        tests.append({
            'id': '1.1.2.5',
            'name': 'Unknown Context Tag',
            'description': 'Send unknown context-specific tag in BindRequest',
            'packet': TestCase_1_1_2_TypeEncodingViolations._unknown_context_tag(),
            'expected': 'protocolError (2) or connection close'
        })

        return tests

    @staticmethod
    def _invalid_tag_number() -> bytes:
        """Send message with invalid tag (0xFF)"""
        message_id = BEREncoder.encode_integer(1)

        # Create malformed element with invalid tag
        invalid_tag = bytes([0xFF])
        length = bytes([0x05])
        content = b"AAAAA"
        malformed_element = invalid_tag + length + content

        # Wrap in SEQUENCE
        return BEREncoder.encode_sequence([message_id, malformed_element])

    @staticmethod
    def _constructed_octet_string() -> bytes:
        """Create BindRequest with constructed OCTET STRING for name field"""
        message_id = BEREncoder.encode_integer(1)

        version = BEREncoder.encode_integer(3)

        # OCTET STRING with constructed bit set (invalid for OCTET STRING)
        name = BEREncoder.encode_octet_string(b"cn=test,dc=example,dc=com", constructed=True)

        auth = BEREncoder.encode_context(0, b"password", primitive=True)

        bind_content = version + name + auth
        bind_request = BEREncoder.encode_application(0, bind_content)

        return LDAPMessage.create(1, bind_request)

    @staticmethod
    def _primitive_sequence() -> bytes:
        """Create malformed SEQUENCE with primitive encoding"""
        message_id = BEREncoder.encode_integer(1)

        # Create BindRequest elements
        version = BEREncoder.encode_integer(3)
        name = BEREncoder.encode_octet_string(b"")
        auth = BEREncoder.encode_context(0, b"", primitive=True)

        # Encode as SEQUENCE but with primitive flag (malformed)
        bind_content = version + name + auth
        # Manually construct with primitive bit
        tag = bytes([0x10])  # SEQUENCE without constructed bit
        length = BERLength.encode_length(len(bind_content))
        malformed_sequence = tag + length + bind_content

        # Wrap as APPLICATION 0
        bind_tag = bytes([0x60])
        bind_length = BERLength.encode_length(len(malformed_sequence))
        bind_request = bind_tag + bind_length + malformed_sequence

        # Outer sequence
        return BEREncoder.encode_sequence([message_id, bind_request])

    @staticmethod
    def _unrecognized_application_tag() -> bytes:
        """Send unrecognized APPLICATION tag (99)"""
        message_id = BEREncoder.encode_integer(1)

        # Create some content
        content = BEREncoder.encode_integer(12345)

        # Use unrecognized APPLICATION tag
        unknown_op = BEREncoder.encode_application(99, content)

        return LDAPMessage.create(1, unknown_op)

    @staticmethod
    def _unknown_context_tag() -> bytes:
        """Send BindRequest with unknown context tag"""
        message_id = BEREncoder.encode_integer(1)

        version = BEREncoder.encode_integer(3)
        name = BEREncoder.encode_octet_string(b"")

        # Use unknown context tag [99] instead of [0] for auth
        auth = BEREncoder.encode_context(99, b"password", primitive=True)

        bind_content = version + name + auth
        bind_request = BEREncoder.encode_application(0, bind_content)

        return LDAPMessage.create(1, bind_request)


class TestCase_1_1_3_ValueEncodingIssues:
    """
    Test Case 1.1.3: Value Encoding Issues

    Tests:
    - BOOLEAN: Send values other than 0x00 or 0xFF
    - INTEGER: Send malformed multi-byte integers
    - OCTET STRING: Send with constructed encoding
    - ENUMERATED: Send out-of-range values
    - Send default values that should be absent
    """

    @staticmethod
    def generate_all_tests() -> List[Dict]:
        """Generate all 1.1.3 test cases"""
        tests = []

        # Test 1: Invalid BOOLEAN value
        tests.append({
            'id': '1.1.3.1',
            'name': 'Invalid BOOLEAN Value',
            'description': 'Send BOOLEAN with value other than 0x00 or 0xFF (e.g., 0x42)',
            'packet': TestCase_1_1_3_ValueEncodingIssues._invalid_boolean(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 2: Malformed INTEGER (leading zeros)
        tests.append({
            'id': '1.1.3.2',
            'name': 'INTEGER with Leading Zeros',
            'description': 'Send INTEGER with unnecessary leading zero bytes',
            'packet': TestCase_1_1_3_ValueEncodingIssues._integer_leading_zeros(),
            'expected': 'protocolError (2) or accept (lenient)'
        })

        # Test 3: Empty INTEGER
        tests.append({
            'id': '1.1.3.3',
            'name': 'Empty INTEGER',
            'description': 'Send INTEGER with zero-length value',
            'packet': TestCase_1_1_3_ValueEncodingIssues._empty_integer(),
            'expected': 'protocolError (2) or connection close'
        })

        # Test 4: Out-of-range ENUMERATED
        tests.append({
            'id': '1.1.3.4',
            'name': 'Out-of-range ENUMERATED',
            'description': 'Send ENUMERATED with value outside valid range for scope',
            'packet': TestCase_1_1_3_ValueEncodingIssues._out_of_range_enumerated(),
            'expected': 'protocolError (2) or specific error for invalid scope'
        })

        # Test 5: Oversized INTEGER
        tests.append({
            'id': '1.1.3.5',
            'name': 'Oversized INTEGER',
            'description': 'Send INTEGER with unnecessarily many bytes',
            'packet': TestCase_1_1_3_ValueEncodingIssues._oversized_integer(),
            'expected': 'protocolError (2) or accept (lenient)'
        })

        return tests

    @staticmethod
    def _invalid_boolean() -> bytes:
        """Create SearchRequest with invalid BOOLEAN value for typesOnly"""
        message_id = BEREncoder.encode_integer(1)

        # Build SearchRequest manually to inject bad BOOLEAN
        base_dn = BEREncoder.encode_octet_string(b"")
        scope = BEREncoder.encode_enumerated(0)
        deref = BEREncoder.encode_enumerated(0)
        size_limit = BEREncoder.encode_integer(0)
        time_limit = BEREncoder.encode_integer(0)

        # Invalid BOOLEAN with value 0x42
        types_only_tag = bytes([0x01])  # BOOLEAN tag
        types_only_length = bytes([0x01])
        types_only_value = bytes([0x42])  # Invalid! Should be 0x00 or 0xFF
        types_only = types_only_tag + types_only_length + types_only_value

        # Simple present filter
        filter_bytes = BEREncoder.encode_context(7, b"objectClass", primitive=True)

        # Empty attribute list
        attributes = BEREncoder.encode_sequence([])

        search_content = (base_dn + scope + deref + size_limit +
                         time_limit + types_only + filter_bytes + attributes)

        search_request = BEREncoder.encode_application(3, search_content)

        return LDAPMessage.create(1, search_request)

    @staticmethod
    def _integer_leading_zeros() -> bytes:
        """Create BindRequest with INTEGER containing leading zeros"""
        # Manually construct messageID with leading zeros
        message_id_tag = bytes([0x02])  # INTEGER tag
        message_id_length = bytes([0x04])
        message_id_value = bytes([0x00, 0x00, 0x00, 0x01])  # Leading zeros
        message_id = message_id_tag + message_id_length + message_id_value

        # Normal BindRequest
        bind_request = BindRequest.create()

        # Manual SEQUENCE
        content = message_id + bind_request
        return BEREncoder.encode_sequence([message_id, bind_request[:0]]) [:-1] + bind_request

    @staticmethod
    def _empty_integer() -> bytes:
        """Create message with zero-length INTEGER"""
        # Empty messageID (invalid)
        message_id_tag = bytes([0x02])
        message_id_length = bytes([0x00])
        message_id = message_id_tag + message_id_length

        bind_request = BindRequest.create()

        sequence_content = message_id + bind_request
        sequence_tag = bytes([0x30])
        sequence_length = BERLength.encode_length(len(sequence_content))

        return sequence_tag + sequence_length + sequence_content

    @staticmethod
    def _out_of_range_enumerated() -> bytes:
        """Create SearchRequest with invalid scope value"""
        message_id = BEREncoder.encode_integer(1)

        base_dn = BEREncoder.encode_octet_string(b"")

        # Invalid scope value (valid are 0, 1, 2)
        scope = BEREncoder.encode_enumerated(99, out_of_range=True)

        deref = BEREncoder.encode_enumerated(0)
        size_limit = BEREncoder.encode_integer(0)
        time_limit = BEREncoder.encode_integer(0)
        types_only = BEREncoder.encode_boolean(False)
        filter_bytes = BEREncoder.encode_context(7, b"objectClass", primitive=True)
        attributes = BEREncoder.encode_sequence([])

        search_content = (base_dn + scope + deref + size_limit +
                         time_limit + types_only + filter_bytes + attributes)

        search_request = BEREncoder.encode_application(3, search_content)

        return LDAPMessage.create(1, search_request)

    @staticmethod
    def _oversized_integer() -> bytes:
        """Create message with oversized messageID"""
        # messageID with way too many bytes
        message_id_tag = bytes([0x02])
        message_id_length = bytes([0x10])  # 16 bytes for messageID=1
        message_id_value = bytes([0x00] * 15 + [0x01])
        message_id = message_id_tag + message_id_length + message_id_value

        bind_request = BindRequest.create()

        sequence_content = message_id + bind_request
        sequence_tag = bytes([0x30])
        sequence_length = BERLength.encode_length(len(sequence_content))

        return sequence_tag + sequence_length + sequence_content


# Convenience function to get all test cases
def get_all_test_cases() -> Dict[str, List[Dict]]:
    """
    Get all test cases organized by test suite

    Returns:
        Dictionary mapping test suite ID to list of test cases
    """
    return {
        '1.1.1': TestCase_1_1_1_LengthEncodingAttacks.generate_all_tests(),
        '1.1.2': TestCase_1_1_2_TypeEncodingViolations.generate_all_tests(),
        '1.1.3': TestCase_1_1_3_ValueEncodingIssues.generate_all_tests()
    }
