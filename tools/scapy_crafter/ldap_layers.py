"""
Scapy Protocol Layers for LDAP

Defines Scapy packet layers for LDAP protocol based on RFC 4511.
Allows for manual packet crafting with full control over all fields.
"""

try:
    from scapy.all import *
    from scapy.packet import Packet
    from scapy.fields import (
        Field, ByteField, ShortField, IntField, StrLenField,
        StrFixedLenField, FieldLenField, PacketListField, ConditionalField,
        ByteEnumField, FieldListField, XStrField, XStrLenField
    )
    from scapy.layers.inet import TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not installed. Install with: pip install scapy")


# BER/ASN.1 Field Types for Scapy

class BERLengthField(Field):
    """
    BER-encoded length field
    Supports both short form (1 byte) and long form (multiple bytes)
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default, fmt="B")

    def addfield(self, pkt, s, val):
        """Add field to packet"""
        if val is None:
            val = 0

        if val <= 127:
            # Short form
            return s + struct.pack("B", val)
        else:
            # Long form
            length_bytes = []
            temp = val
            while temp > 0:
                length_bytes.insert(0, temp & 0xFF)
                temp >>= 8

            first_byte = 0x80 | len(length_bytes)
            return s + struct.pack("B", first_byte) + bytes(length_bytes)

    def getfield(self, pkt, s):
        """Extract field from packet"""
        if len(s) < 1:
            return s, 0

        first_byte = s[0]

        if first_byte & 0x80 == 0:
            # Short form
            return s[1:], first_byte
        elif first_byte == 0x80:
            # Indefinite form (not allowed in LDAP)
            return s[1:], -1
        else:
            # Long form
            num_octets = first_byte & 0x7F
            if len(s) < 1 + num_octets:
                return s, 0

            length = 0
            for i in range(num_octets):
                length = (length << 8) | s[1 + i]

            return s[1 + num_octets:], length


class BERTagField(ByteField):
    """BER tag field"""
    pass


class RawBERField(Field):
    """
    Raw BER-encoded data field
    Used for custom/malformed BER encodings
    """

    def __init__(self, name, default):
        Field.__init__(self, name, default)

    def addfield(self, pkt, s, val):
        if val is None:
            return s
        return s + bytes(val)

    def getfield(self, pkt, s):
        return b"", s


# LDAP Protocol Layers

if SCAPY_AVAILABLE:

    class LDAP(Packet):
        """
        Base LDAP packet layer

        LDAPMessage ::= SEQUENCE {
            messageID       MessageID,
            protocolOp      CHOICE { ... },
            controls       [0] Controls OPTIONAL }
        """

        name = "LDAP"

        fields_desc = [
            BERTagField("sequence_tag", 0x30),  # SEQUENCE tag
            BERLengthField("sequence_length", None),
            RawBERField("ldap_message", b"")
        ]

        def post_build(self, pkt, pay):
            """Calculate length if not set"""
            if self.sequence_length is None:
                # Calculate length of ldap_message
                msg_len = len(self.ldap_message) if self.ldap_message else 0

                # Rebuild with correct length
                if msg_len <= 127:
                    length_bytes = struct.pack("B", msg_len)
                else:
                    length_bytes_list = []
                    temp = msg_len
                    while temp > 0:
                        length_bytes_list.insert(0, temp & 0xFF)
                        temp >>= 8
                    first_byte = 0x80 | len(length_bytes_list)
                    length_bytes = struct.pack("B", first_byte) + bytes(length_bytes_list)

                pkt = struct.pack("B", self.sequence_tag) + length_bytes + (self.ldap_message if self.ldap_message else b"")

            return pkt + pay


    class LDAPRaw(Packet):
        """
        Raw LDAP layer for complete manual control
        Allows sending arbitrary bytes as LDAP message
        """

        name = "LDAPRaw"

        fields_desc = [
            XStrField("raw_ldap", b"")
        ]


    class LDAPMessageID(Packet):
        """LDAP Message ID (INTEGER)"""

        name = "LDAPMessageID"

        fields_desc = [
            BERTagField("tag", 0x02),  # INTEGER tag
            BERLengthField("length", None),
            IntField("message_id", 1)
        ]

        def post_build(self, pkt, pay):
            if self.length is None:
                # Encode message_id as BER INTEGER
                msg_id = self.message_id

                if msg_id == 0:
                    value_bytes = bytes([0x00])
                else:
                    # Calculate minimum bytes needed
                    bit_length = msg_id.bit_length()
                    byte_length = (bit_length + 8) // 8
                    value_bytes = msg_id.to_bytes(byte_length, byteorder='big', signed=False)
                    if value_bytes[0] & 0x80:
                        value_bytes = bytes([0x00]) + value_bytes

                length = len(value_bytes)
                pkt = struct.pack("B", self.tag) + struct.pack("B", length) + value_bytes

            return pkt + pay


    class LDAPBindRequest(Packet):
        """
        LDAP Bind Request

        BindRequest ::= [APPLICATION 0] SEQUENCE {
            version                 INTEGER (1 ..  127),
            name                    LDAPDN,
            authentication          AuthenticationChoice }
        """

        name = "LDAPBindRequest"

        fields_desc = [
            BERTagField("app_tag", 0x60),  # APPLICATION 0, constructed
            BERLengthField("app_length", None),
            RawBERField("bind_content", b"")
        ]


    class LDAPSearchRequest(Packet):
        """
        LDAP Search Request

        SearchRequest ::= [APPLICATION 3] SEQUENCE { ... }
        """

        name = "LDAPSearchRequest"

        fields_desc = [
            BERTagField("app_tag", 0x63),  # APPLICATION 3, constructed
            BERLengthField("app_length", None),
            RawBERField("search_content", b"")
        ]


    class LDAPUnbindRequest(Packet):
        """LDAP Unbind Request (APPLICATION 2, NULL)"""

        name = "LDAPUnbindRequest"

        fields_desc = [
            BERTagField("app_tag", 0x42),  # APPLICATION 2, primitive
            BERLengthField("app_length", 0)
        ]


    # Bind LDAP to TCP port 389
    bind_layers(TCP, LDAP, dport=389)
    bind_layers(TCP, LDAP, sport=389)


# Helper functions for building LDAP packets with Scapy

def create_ldap_packet_raw(destination_ip: str,
                           destination_port: int,
                           ldap_raw_bytes: bytes,
                           source_ip: str = None,
                           source_port: int = None) -> 'Packet':
    """
    Create a raw LDAP packet with Scapy

    Args:
        destination_ip: Target IP address
        destination_port: Target port (typically 389)
        ldap_raw_bytes: Raw LDAP message bytes
        source_ip: Source IP (optional, will be auto)
        source_port: Source port (optional, will be random)

    Returns:
        Scapy packet ready to send
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy is required for this function")

    # Build packet layers
    ip_layer = IP(dst=destination_ip)
    if source_ip:
        ip_layer.src = source_ip

    tcp_layer = TCP(dport=destination_port, flags='PA')  # PSH+ACK
    if source_port:
        tcp_layer.sport = source_port

    ldap_layer = LDAPRaw(raw_ldap=ldap_raw_bytes)

    packet = ip_layer / tcp_layer / ldap_layer

    return packet


def send_ldap_packet(destination_ip: str,
                    destination_port: int,
                    ldap_raw_bytes: bytes,
                    verbose: bool = True) -> None:
    """
    Send an LDAP packet using Scapy

    Args:
        destination_ip: Target IP
        destination_port: Target port
        ldap_raw_bytes: Raw LDAP message bytes
        verbose: Print packet info
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy is required. Install with: pip install scapy")

    packet = create_ldap_packet_raw(destination_ip, destination_port, ldap_raw_bytes)

    if verbose:
        print(f"Sending LDAP packet to {destination_ip}:{destination_port}")
        print(f"Packet size: {len(ldap_raw_bytes)} bytes")
        packet.show()

    # Send packet (layer 3)
    send(packet, verbose=verbose)


def sniff_ldap_responses(interface: str = None,
                        filter_str: str = "tcp port 389",
                        count: int = 10,
                        timeout: int = 10) -> List:
    """
    Sniff LDAP responses using Scapy

    Args:
        interface: Network interface to sniff on
        filter_str: BPF filter string
        count: Number of packets to capture
        timeout: Capture timeout in seconds

    Returns:
        List of captured packets
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy is required")

    print(f"Sniffing LDAP traffic on {interface or 'default interface'}...")
    print(f"Filter: {filter_str}")

    packets = sniff(iface=interface, filter=filter_str, count=count, timeout=timeout)

    print(f"Captured {len(packets)} packets")
    return packets


# Utility: Extract LDAP layer from packet
def extract_ldap_from_packet(packet) -> Optional[bytes]:
    """
    Extract raw LDAP data from a Scapy packet

    Args:
        packet: Scapy packet

    Returns:
        Raw LDAP bytes or None
    """
    if not SCAPY_AVAILABLE:
        return None

    if packet.haslayer(Raw):
        return bytes(packet[Raw].load)
    elif packet.haslayer(LDAP):
        return bytes(packet[LDAP])
    else:
        return None


# Example usage and testing
if __name__ == "__main__":
    if SCAPY_AVAILABLE:
        print("LDAP Scapy layers loaded successfully")
        print("\nAvailable layers:")
        print("  - LDAP (base layer)")
        print("  - LDAPRaw (raw bytes)")
        print("  - LDAPBindRequest")
        print("  - LDAPSearchRequest")
        print("  - LDAPUnbindRequest")
        print("\nExample:")
        print("  packet = IP(dst='192.168.1.100')/TCP(dport=389)/LDAPRaw(raw_ldap=b'...')")
    else:
        print("Scapy not available. Install with: pip install scapy")
