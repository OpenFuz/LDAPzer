"""
Section 1: Protocol Encoding & Parsing Tests

This module implements RFC 4511 Section 1 test cases:
- 1.1.1: Length Encoding Attacks (6 tests)
- 1.1.2: Type Encoding Violations (5 tests)
- 1.1.3: Value Encoding Issues (5 tests)

Total: 16 test cases
"""

from .fuzzer import LDAPFuzzer, FuzzResult, ServerStatus
from .fuzz_generators import (
    TestCase_1_1_1_LengthEncodingAttacks,
    TestCase_1_1_2_TypeEncodingViolations,
    TestCase_1_1_3_ValueEncodingIssues,
    FuzzMode,
    MutationGenerator,
    get_all_test_cases
)

__all__ = [
    'LDAPFuzzer',
    'FuzzResult',
    'ServerStatus',
    'TestCase_1_1_1_LengthEncodingAttacks',
    'TestCase_1_1_2_TypeEncodingViolations',
    'TestCase_1_1_3_ValueEncodingIssues',
    'FuzzMode',
    'MutationGenerator',
    'get_all_test_cases'
]
