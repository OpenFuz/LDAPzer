"""
BER (Basic Encoding Rules) Encoder with Fuzzing Capabilities

This module provides low-level BER encoding functions with support for
generating both valid and malformed encodings for security testing.

Reference: ITU-T X.690 (BER/DER encoding rules)
"""

import struct
from typing import Union, List, Optional


class BERTag:
    """BER Tag class and constants"""

    # Universal tags
    BOOLEAN = 0x01
    INTEGER = 0x02
    OCTET_STRING = 0x04
    NULL = 0x05
    ENUMERATED = 0x0A
    SEQUENCE = 0x30
    SET = 0x31

    # Tag classes
    CLASS_UNIVERSAL = 0x00
    CLASS_APPLICATION = 0x40
    CLASS_CONTEXT = 0x80
    CLASS_PRIVATE = 0xC0

    # Constructed flag
    CONSTRUCTED = 0x20
    PRIMITIVE = 0x00

    @staticmethod
    def encode_tag(tag_class: int, constructed: bool, tag_number: int) -> bytes:
        """
        Encode a BER tag

        Args:
            tag_class: CLASS_UNIVERSAL, CLASS_APPLICATION, CLASS_CONTEXT, or CLASS_PRIVATE
            constructed: True for constructed types, False for primitive
            tag_number: The tag number

        Returns:
            Encoded tag bytes
        """
        if tag_number < 31:
            # Short form
            tag = tag_class | (0x20 if constructed else 0x00) | tag_number
            return bytes([tag])
        else:
            # Long form (for tag numbers >= 31)
            first_byte = tag_class | (0x20 if constructed else 0x00) | 0x1F
            result = bytes([first_byte])

            # Encode tag number in base 128
            octets = []
            while tag_number > 0:
                octets.insert(0, (tag_number & 0x7F))
                tag_number >>= 7

            # Set high bit on all but last octet
            for i in range(len(octets) - 1):
                octets[i] |= 0x80

            result += bytes(octets)
            return result


class BERLength:
    """BER Length encoding"""

    @staticmethod
    def encode_length(length: int, indefinite: bool = False) -> bytes:
        """
        Encode a BER length field

        Args:
            length: The length value to encode
            indefinite: If True, use indefinite length encoding (not allowed in LDAP)

        Returns:
            Encoded length bytes
        """
        if indefinite:
            # Indefinite form (0x80) - NOT allowed per RFC 4511
            return bytes([0x80])

        if length < 0:
            raise ValueError("Length cannot be negative")

        if length <= 127:
            # Short form
            return bytes([length])
        else:
            # Long form
            length_bytes = []
            temp = length
            while temp > 0:
                length_bytes.insert(0, temp & 0xFF)
                temp >>= 8

            # First byte: high bit set + number of length octets
            first_byte = 0x80 | len(length_bytes)
            return bytes([first_byte]) + bytes(length_bytes)

    @staticmethod
    def encode_length_malformed(length: int, fuzz_type: str) -> bytes:
        """
        Generate malformed length encodings for fuzzing

        Args:
            length: Base length value
            fuzz_type: Type of malformation
                - 'indefinite': Indefinite length (0x80)
                - 'too_short': Length shorter than actual data
                - 'too_long': Length longer than actual data
                - 'max_int': Maximum 32-bit integer
                - 'overflow': Integer overflow attempt
                - 'beyond_packet': Length beyond reasonable packet size

        Returns:
            Malformed length bytes
        """
        if fuzz_type == 'indefinite':
            return bytes([0x80])

        elif fuzz_type == 'too_short':
            # Encode length that's too short (half the actual length)
            return BERLength.encode_length(max(0, length // 2))

        elif fuzz_type == 'too_long':
            # Encode length that's too long
            return BERLength.encode_length(length * 2 + 1000)

        elif fuzz_type == 'max_int':
            # Maximum 32-bit signed integer
            return bytes([0x84]) + struct.pack('>I', 0x7FFFFFFF)

        elif fuzz_type == 'overflow':
            # Attempt 32-bit overflow
            return bytes([0x84]) + struct.pack('>I', 0xFFFFFFFF)

        elif fuzz_type == 'beyond_packet':
            # Huge length value
            return bytes([0x88]) + struct.pack('>Q', 0xFFFFFFFFFFFFFFFF)

        else:
            raise ValueError(f"Unknown fuzz_type: {fuzz_type}")


class BEREncoder:
    """Main BER encoder class with fuzzing support"""

    @staticmethod
    def encode_boolean(value: bool, malformed: bool = False) -> bytes:
        """
        Encode a BOOLEAN value

        Args:
            value: Boolean value to encode
            malformed: If True, use non-standard encoding

        Returns:
            BER-encoded BOOLEAN
        """
        tag = bytes([BERTag.BOOLEAN])
        length = bytes([0x01])

        if malformed:
            # Invalid BOOLEAN values (should be 0x00 or 0xFF)
            invalid_values = [0x01, 0x7F, 0x80, 0xFE, 0x42]
            value_byte = bytes([invalid_values[hash(str(value)) % len(invalid_values)]])
        else:
            value_byte = bytes([0xFF if value else 0x00])

        return tag + length + value_byte

    @staticmethod
    def encode_integer(value: int, malformed: bool = False) -> bytes:
        """
        Encode an INTEGER value

        Args:
            value: Integer value to encode
            malformed: If True, create malformed encoding

        Returns:
            BER-encoded INTEGER
        """
        tag = bytes([BERTag.INTEGER])

        if malformed:
            # Various malformed integer encodings
            import random
            fuzz_choice = random.choice([
                'leading_zeros',
                'wrong_length',
                'empty',
                'too_many_bytes'
            ])

            if fuzz_choice == 'leading_zeros':
                # Unnecessary leading zeros
                value_bytes = bytes([0x00, 0x00]) + value.to_bytes(4, byteorder='big', signed=True)
            elif fuzz_choice == 'wrong_length':
                # Length doesn't match value bytes
                value_bytes = value.to_bytes(4, byteorder='big', signed=True)
                length = bytes([len(value_bytes) + 1])  # Wrong length
                return tag + length + value_bytes
            elif fuzz_choice == 'empty':
                # Empty integer (invalid)
                return tag + bytes([0x00])
            else:  # too_many_bytes
                # Unnecessarily long encoding
                value_bytes = bytes([0x00] * 10) + value.to_bytes(4, byteorder='big', signed=True)
        else:
            # Proper encoding
            if value == 0:
                value_bytes = bytes([0x00])
            else:
                # Determine minimum bytes needed
                if value > 0:
                    bit_length = value.bit_length()
                    byte_length = (bit_length + 8) // 8
                    value_bytes = value.to_bytes(byte_length, byteorder='big', signed=False)
                    # Add leading zero if high bit is set
                    if value_bytes[0] & 0x80:
                        value_bytes = bytes([0x00]) + value_bytes
                else:
                    bit_length = value.bit_length()
                    byte_length = (bit_length + 8) // 8
                    value_bytes = value.to_bytes(byte_length, byteorder='big', signed=True)

        length = BERLength.encode_length(len(value_bytes))
        return tag + length + value_bytes

    @staticmethod
    def encode_octet_string(value: bytes, constructed: bool = False) -> bytes:
        """
        Encode an OCTET STRING

        Args:
            value: Bytes to encode
            constructed: If True, use constructed encoding (invalid for OCTET STRING)

        Returns:
            BER-encoded OCTET STRING
        """
        if constructed:
            # Malformed: constructed encoding for primitive type
            tag = bytes([BERTag.OCTET_STRING | BERTag.CONSTRUCTED])
        else:
            tag = bytes([BERTag.OCTET_STRING])

        length = BERLength.encode_length(len(value))
        return tag + length + value

    @staticmethod
    def encode_enumerated(value: int, out_of_range: bool = False) -> bytes:
        """
        Encode an ENUMERATED value

        Args:
            value: Enumerated value
            out_of_range: If True, use out-of-range value

        Returns:
            BER-encoded ENUMERATED
        """
        tag = bytes([BERTag.ENUMERATED])

        if out_of_range:
            # Use absurdly large value
            value = 999999

        # Encode like INTEGER
        if value == 0:
            value_bytes = bytes([0x00])
        else:
            bit_length = value.bit_length()
            byte_length = (bit_length + 8) // 8
            value_bytes = value.to_bytes(byte_length, byteorder='big', signed=False)
            if value_bytes[0] & 0x80:
                value_bytes = bytes([0x00]) + value_bytes

        length = BERLength.encode_length(len(value_bytes))
        return tag + length + value_bytes

    @staticmethod
    def encode_sequence(elements: List[bytes], primitive: bool = False) -> bytes:
        """
        Encode a SEQUENCE

        Args:
            elements: List of encoded elements
            primitive: If True, use primitive encoding (invalid for SEQUENCE)

        Returns:
            BER-encoded SEQUENCE
        """
        if primitive:
            # Malformed: primitive encoding for constructed type
            tag = bytes([BERTag.SEQUENCE & ~BERTag.CONSTRUCTED])
        else:
            tag = bytes([BERTag.SEQUENCE])

        content = b''.join(elements)
        length = BERLength.encode_length(len(content))
        return tag + length + content

    @staticmethod
    def encode_null() -> bytes:
        """Encode a NULL value"""
        return bytes([BERTag.NULL, 0x00])

    @staticmethod
    def encode_context(tag_number: int, content: bytes, primitive: bool = False) -> bytes:
        """
        Encode a context-specific tag

        Args:
            tag_number: Context tag number
            content: Encoded content
            primitive: If True, use primitive encoding

        Returns:
            BER-encoded context tag
        """
        tag = BERTag.encode_tag(
            BERTag.CLASS_CONTEXT,
            not primitive,
            tag_number
        )
        length = BERLength.encode_length(len(content))
        return tag + length + content

    @staticmethod
    def encode_application(tag_number: int, content: bytes, primitive: bool = False) -> bytes:
        """
        Encode an application-specific tag

        Args:
            tag_number: Application tag number
            content: Encoded content
            primitive: If True, use primitive encoding

        Returns:
            BER-encoded application tag
        """
        tag = BERTag.encode_tag(
            BERTag.CLASS_APPLICATION,
            not primitive,
            tag_number
        )
        length = BERLength.encode_length(len(content))
        return tag + length + content


# Utility functions for fuzzing
def fuzz_tag(base_tag: int, fuzz_type: str) -> bytes:
    """
    Generate malformed tags

    Args:
        base_tag: Base tag value
        fuzz_type: Type of malformation
            - 'invalid_number': Use invalid tag number
            - 'wrong_constructed': Flip constructed bit
            - 'unknown_application': Use unrecognized application tag

    Returns:
        Malformed tag bytes
    """
    if fuzz_type == 'invalid_number':
        # Use reserved or invalid tag number
        return bytes([0xFF])

    elif fuzz_type == 'wrong_constructed':
        # Flip the constructed bit
        return bytes([base_tag ^ BERTag.CONSTRUCTED])

    elif fuzz_type == 'unknown_application':
        # Use unrecognized application tag (e.g., 99)
        return BERTag.encode_tag(BERTag.CLASS_APPLICATION, True, 99)

    else:
        return bytes([base_tag])
