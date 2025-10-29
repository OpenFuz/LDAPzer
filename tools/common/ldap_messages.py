"""
LDAP Message Construction

Builds LDAP protocol messages according to RFC 4511 specifications.
Supports both valid message construction and injection of malformed elements.

LDAP Message Structure (from RFC 4511):
LDAPMessage ::= SEQUENCE {
    messageID       MessageID,
    protocolOp      CHOICE {
        bindRequest           BindRequest,
        bindResponse          BindResponse,
        unbindRequest         UnbindRequest,
        searchRequest         SearchRequest,
        searchResEntry        SearchResultEntry,
        searchResDone         SearchResultDone,
        searchResRef          SearchResultReference,
        modifyRequest         ModifyRequest,
        modifyResponse        ModifyResponse,
        addRequest            AddRequest,
        addResponse           AddResponse,
        delRequest            DelRequest,
        delResponse           DelResponse,
        modDNRequest          ModifyDNRequest,
        modDNResponse         ModifyDNResponse,
        compareRequest        CompareRequest,
        compareResponse       CompareResponse,
        abandonRequest        AbandonRequest,
        extendedReq           ExtendedRequest,
        extendedResp          ExtendedResponse,
        ...,
        intermediateResponse  IntermediateResponse },
    controls       [0] Controls OPTIONAL }
"""

from typing import Optional, List
from .ber_encoder import BEREncoder, BERLength, BERTag


class LDAPMessageID:
    """LDAP Message ID constants and utilities"""

    @staticmethod
    def encode(message_id: int) -> bytes:
        """Encode a message ID (INTEGER 0..maxInt)"""
        return BEREncoder.encode_integer(message_id)


class LDAPProtocolOp:
    """LDAP Protocol Operation Tags (APPLICATION class)"""

    # Request operations
    BIND_REQUEST = 0
    UNBIND_REQUEST = 2
    SEARCH_REQUEST = 3
    MODIFY_REQUEST = 6
    ADD_REQUEST = 8
    DEL_REQUEST = 10
    MOD_DN_REQUEST = 12
    COMPARE_REQUEST = 14
    ABANDON_REQUEST = 16
    EXTENDED_REQUEST = 23

    # Response operations
    BIND_RESPONSE = 1
    SEARCH_RES_ENTRY = 4
    SEARCH_RES_DONE = 5
    SEARCH_RES_REF = 19
    MODIFY_RESPONSE = 7
    ADD_RESPONSE = 9
    DEL_RESPONSE = 11
    MOD_DN_RESPONSE = 13
    COMPARE_RESPONSE = 15
    EXTENDED_RESPONSE = 24
    INTERMEDIATE_RESPONSE = 25


class LDAPResultCode:
    """LDAP Result Codes (ENUMERATED)"""

    SUCCESS = 0
    OPERATIONS_ERROR = 1
    PROTOCOL_ERROR = 2
    TIME_LIMIT_EXCEEDED = 3
    SIZE_LIMIT_EXCEEDED = 4
    COMPARE_FALSE = 5
    COMPARE_TRUE = 6
    AUTH_METHOD_NOT_SUPPORTED = 7
    STRONGER_AUTH_REQUIRED = 8
    REFERRAL = 10
    ADMIN_LIMIT_EXCEEDED = 11
    UNAVAILABLE_CRITICAL_EXTENSION = 12
    CONFIDENTIALITY_REQUIRED = 13
    SASL_BIND_IN_PROGRESS = 14


class BindRequest:
    """
    BindRequest ::= [APPLICATION 0] SEQUENCE {
        version                 INTEGER (1 ..  127),
        name                    LDAPDN,
        authentication          AuthenticationChoice }

    AuthenticationChoice ::= CHOICE {
        simple                  [0] OCTET STRING,
        sasl                    [3] SaslCredentials,
        ...  }
    """

    @staticmethod
    def create(version: int = 3,
               name: str = "",
               password: str = "",
               sasl_mechanism: Optional[str] = None,
               sasl_credentials: Optional[bytes] = None) -> bytes:
        """
        Create a BindRequest

        Args:
            version: LDAP version (typically 3)
            name: DN to bind as (empty for anonymous)
            password: Simple bind password
            sasl_mechanism: SASL mechanism name (if using SASL)
            sasl_credentials: SASL credentials (if using SASL)

        Returns:
            Encoded BindRequest
        """
        # Encode version
        version_encoded = BEREncoder.encode_integer(version)

        # Encode name (LDAPDN is OCTET STRING)
        name_encoded = BEREncoder.encode_octet_string(name.encode('utf-8'))

        # Encode authentication
        if sasl_mechanism:
            # SASL authentication [3]
            mech = BEREncoder.encode_octet_string(sasl_mechanism.encode('utf-8'))
            if sasl_credentials:
                creds = BEREncoder.encode_octet_string(sasl_credentials)
                sasl_seq = BEREncoder.encode_sequence([mech, creds])
            else:
                sasl_seq = BEREncoder.encode_sequence([mech])
            auth_encoded = BEREncoder.encode_context(3, sasl_seq)
        else:
            # Simple authentication [0]
            auth_encoded = BEREncoder.encode_context(0, password.encode('utf-8'), primitive=True)

        # Build the SEQUENCE
        sequence_content = version_encoded + name_encoded + auth_encoded

        # Wrap in APPLICATION 0
        return BEREncoder.encode_application(
            LDAPProtocolOp.BIND_REQUEST,
            sequence_content
        )


class SearchRequest:
    """
    SearchRequest ::= [APPLICATION 3] SEQUENCE {
        baseObject      LDAPDN,
        scope           ENUMERATED {
            baseObject              (0),
            singleLevel             (1),
            wholeSubtree            (2),
            ...  },
        derefAliases    ENUMERATED {
            neverDerefAliases       (0),
            derefInSearching        (1),
            derefFindingBaseObj     (2),
            derefAlways             (3) },
        sizeLimit       INTEGER (0 ..  maxInt),
        timeLimit       INTEGER (0 ..  maxInt),
        typesOnly       BOOLEAN,
        filter          Filter,
        attributes      AttributeSelection }
    """

    # Scope values
    SCOPE_BASE = 0
    SCOPE_ONE = 1
    SCOPE_SUB = 2

    # Deref aliases values
    DEREF_NEVER = 0
    DEREF_IN_SEARCHING = 1
    DEREF_FINDING_BASE = 2
    DEREF_ALWAYS = 3

    @staticmethod
    def create(base_dn: str = "",
               scope: int = SCOPE_BASE,
               deref: int = DEREF_NEVER,
               size_limit: int = 0,
               time_limit: int = 0,
               types_only: bool = False,
               filter_str: str = "(objectClass=*)",
               attributes: List[str] = None) -> bytes:
        """
        Create a SearchRequest

        Args:
            base_dn: Base DN for search
            scope: Search scope (0=base, 1=one, 2=sub)
            deref: Alias dereferencing behavior
            size_limit: Maximum entries to return
            time_limit: Maximum time in seconds
            types_only: Return attribute types only
            filter_str: Search filter string
            attributes: List of attributes to return

        Returns:
            Encoded SearchRequest
        """
        if attributes is None:
            attributes = []

        # Encode components
        base_dn_encoded = BEREncoder.encode_octet_string(base_dn.encode('utf-8'))
        scope_encoded = BEREncoder.encode_enumerated(scope)
        deref_encoded = BEREncoder.encode_enumerated(deref)
        size_limit_encoded = BEREncoder.encode_integer(size_limit)
        time_limit_encoded = BEREncoder.encode_integer(time_limit)
        types_only_encoded = BEREncoder.encode_boolean(types_only)

        # Encode filter (simplified - just present filter for now)
        filter_encoded = SearchRequest._encode_filter(filter_str)

        # Encode attributes
        attr_list = [BEREncoder.encode_octet_string(attr.encode('utf-8'))
                     for attr in attributes]
        attributes_encoded = BEREncoder.encode_sequence(attr_list)

        # Build SEQUENCE
        sequence_content = (base_dn_encoded + scope_encoded + deref_encoded +
                           size_limit_encoded + time_limit_encoded +
                           types_only_encoded + filter_encoded + attributes_encoded)

        # Wrap in APPLICATION 3
        return BEREncoder.encode_application(
            LDAPProtocolOp.SEARCH_REQUEST,
            sequence_content
        )

    @staticmethod
    def _encode_filter(filter_str: str) -> bytes:
        """
        Encode a simple search filter
        For now, just creates a 'present' filter for objectClass
        More complex filter parsing can be added later

        Filter ::= CHOICE {
            and             [0] SET SIZE (1..MAX) OF filter Filter,
            or              [1] SET SIZE (1..MAX) OF filter Filter,
            not             [2] Filter,
            equalityMatch   [3] AttributeValueAssertion,
            substrings      [4] SubstringFilter,
            greaterOrEqual  [5] AttributeValueAssertion,
            lessOrEqual     [6] AttributeValueAssertion,
            present         [7] AttributeDescription,
            approxMatch     [8] AttributeValueAssertion,
            extensibleMatch [9] MatchingRuleAssertion,
            ...  }
        """
        # Simple present filter: [7] "objectClass"
        # Present filter is just [7] AttributeDescription (OCTET STRING)
        if filter_str == "(objectClass=*)":
            attr_desc = "objectClass".encode('utf-8')
            return BEREncoder.encode_context(7, attr_desc, primitive=True)
        else:
            # For simplicity, default to present filter
            # Full filter parser would be more complex
            attr_desc = "objectClass".encode('utf-8')
            return BEREncoder.encode_context(7, attr_desc, primitive=True)


class UnbindRequest:
    """
    UnbindRequest ::= [APPLICATION 2] NULL
    """

    @staticmethod
    def create() -> bytes:
        """Create an UnbindRequest"""
        return BEREncoder.encode_application(
            LDAPProtocolOp.UNBIND_REQUEST,
            b'',  # NULL content
            primitive=True
        )


class AbandonRequest:
    """
    AbandonRequest ::= [APPLICATION 16] MessageID
    """

    @staticmethod
    def create(message_id_to_abandon: int) -> bytes:
        """Create an AbandonRequest"""
        message_id = BEREncoder.encode_integer(message_id_to_abandon)
        return BEREncoder.encode_application(
            LDAPProtocolOp.ABANDON_REQUEST,
            message_id,
            primitive=False
        )


class ExtendedRequest:
    """
    ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
        requestName      [0] LDAPOID,
        requestValue     [1] OCTET STRING OPTIONAL }
    """

    # Common extended operations
    OID_START_TLS = "1.3.6.1.4.1.1466.20037"
    OID_MODIFY_PASSWORD = "1.3.6.1.4.1.4203.1.11.1"
    OID_WHO_AM_I = "1.3.6.1.4.1.4203.1.11.3"

    @staticmethod
    def create(request_name: str,
               request_value: Optional[bytes] = None) -> bytes:
        """
        Create an ExtendedRequest

        Args:
            request_name: OID of the extended operation
            request_value: Optional request value

        Returns:
            Encoded ExtendedRequest
        """
        # Encode requestName [0]
        name_content = request_name.encode('utf-8')
        name_encoded = BEREncoder.encode_context(0, name_content, primitive=True)

        # Encode requestValue [1] if present
        sequence_parts = [name_encoded]
        if request_value is not None:
            value_encoded = BEREncoder.encode_context(1, request_value, primitive=True)
            sequence_parts.append(value_encoded)

        # Build SEQUENCE
        sequence_content = b''.join(sequence_parts)

        # Wrap in APPLICATION 23
        return BEREncoder.encode_application(
            LDAPProtocolOp.EXTENDED_REQUEST,
            sequence_content
        )


class LDAPMessage:
    """
    Complete LDAP Message wrapper

    LDAPMessage ::= SEQUENCE {
        messageID       MessageID,
        protocolOp      CHOICE { ... },
        controls       [0] Controls OPTIONAL }
    """

    @staticmethod
    def create(message_id: int,
               protocol_op: bytes,
               controls: Optional[List[bytes]] = None) -> bytes:
        """
        Create a complete LDAP message

        Args:
            message_id: Message ID (INTEGER)
            protocol_op: Encoded protocol operation
            controls: Optional list of encoded controls

        Returns:
            Complete LDAP message
        """
        # Encode messageID
        message_id_encoded = LDAPMessageID.encode(message_id)

        # Build sequence
        sequence_parts = [message_id_encoded, protocol_op]

        # Add controls if present
        if controls:
            controls_seq = BEREncoder.encode_sequence(controls)
            controls_encoded = BEREncoder.encode_context(0, controls_seq)
            sequence_parts.append(controls_encoded)

        # Create final SEQUENCE
        return BEREncoder.encode_sequence(sequence_parts)


class LDAPControl:
    """
    Control ::= SEQUENCE {
        controlType             LDAPOID,
        criticality             BOOLEAN DEFAULT FALSE,
        controlValue            OCTET STRING OPTIONAL }
    """

    @staticmethod
    def create(control_type: str,
               criticality: bool = False,
               control_value: Optional[bytes] = None) -> bytes:
        """
        Create an LDAP control

        Args:
            control_type: OID of the control
            criticality: Whether the control is critical
            control_value: Optional control value

        Returns:
            Encoded control
        """
        # Encode controlType (OCTET STRING for OID)
        control_type_encoded = BEREncoder.encode_octet_string(
            control_type.encode('utf-8')
        )

        sequence_parts = [control_type_encoded]

        # Encode criticality if not default (FALSE)
        if criticality:
            criticality_encoded = BEREncoder.encode_boolean(True)
            sequence_parts.append(criticality_encoded)

        # Encode controlValue if present
        if control_value is not None:
            control_value_encoded = BEREncoder.encode_octet_string(control_value)
            sequence_parts.append(control_value_encoded)

        return BEREncoder.encode_sequence(sequence_parts)
