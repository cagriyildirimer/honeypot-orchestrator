from __future__ import annotations

import unittest
from honeypot_orchestrator.services.llmnr import _parse_llmnr_name, _build_llmnr_response
from honeypot_orchestrator.services.nbtnns import (
    _decode_netbios_ns_name,
    _parse_netbios_ns_name,
    _build_netbios_ns_response,
    _build_netbios_ns_node_status_response,
)


class LLMNRTests(unittest.TestCase):
    def test_parse_llmnr_name_valid(self) -> None:
        # LLMNR header (12 bytes) + srv01 (length 5 + srv01 + null byte) + Type (2 bytes) + Class (2 bytes)
        query_data = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05srv01\x00\x00\x01\x00\x01"
        name = _parse_llmnr_name(query_data)
        self.assertEqual(name, "srv01")

    def test_parse_llmnr_name_too_short(self) -> None:
        query_data = b"\x12\x34\x00\x00\x00\x01"
        name = _parse_llmnr_name(query_data)
        self.assertEqual(name, "")

    def test_build_llmnr_response(self) -> None:
        query_data = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05srv01\x00\x00\x01\x00\x01"
        response = _build_llmnr_response(query_data, "192.168.1.100")
        
        # Verify transaction ID matches
        self.assertEqual(response[0:2], b"\x12\x34")
        # Verify LLMNR response flags: 0x8000
        self.assertEqual(response[2:4], b"\x80\x00")
        # Verify question section is copied: b"\x05srv01\x00\x00\x01\x00\x01"
        self.assertIn(b"\x05srv01\x00\x00\x01\x00\x01", response)
        # Verify the spoofed IP bytes are appended
        self.assertTrue(response.endswith(b"\xc0\xa8\x01\x64"))


class NBTNSTests(unittest.TestCase):
    def _encode_netbios_name(self, name: str, service_type: int = 0x20) -> bytes:
        # Pad name to 15 chars
        padded = name.ljust(15).upper().encode("ascii")
        padded += bytes([service_type])
        encoded = bytearray()
        for char in padded:
            high = (char >> 4) + 0x41
            low = (char & 0x0F) + 0x41
            encoded.append(high)
            encoded.append(low)
        return bytes(encoded)

    def test_decode_netbios_ns_name(self) -> None:
        encoded = self._encode_netbios_name("WIN-SRV")
        self.assertEqual(len(encoded), 32)
        decoded = _decode_netbios_ns_name(encoded)
        # Verify decoded string is padded or stripped nicely
        self.assertEqual(decoded, "WIN-SRV")

    def test_parse_netbios_ns_name_valid(self) -> None:
        # Header (12 bytes) + Length 32 (0x20) + Encoded name (32 bytes) + Label end (0x00) + Type (2 bytes) + Class (2 bytes)
        encoded_name = self._encode_netbios_name("MY-LAPTOP")
        query_data = b"\xaa\xbb\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + encoded_name + b"\x00\x00\x20\x00\x01"
        parsed = _parse_netbios_ns_name(query_data)
        self.assertEqual(parsed, "MY-LAPTOP")

    def test_build_netbios_ns_response(self) -> None:
        encoded_name = self._encode_netbios_name("MY-LAPTOP")
        query_data = b"\xaa\xbb\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + encoded_name + b"\x00\x00\x20\x00\x01"
        
        response = _build_netbios_ns_response(query_data, "10.0.0.50")
        
        # Verify transaction ID is copied
        self.assertEqual(response[0:2], b"\xaa\xbb")
        # Verify response code flags
        self.assertEqual(response[2:4], b"\x85\x00")
        # Verify IP is appended correctly
        self.assertTrue(response.endswith(b"\x0a\x00\x00\x32"))

    def test_build_netbios_ns_node_status_response(self) -> None:
        encoded_name = self._encode_netbios_name("*")
        query_data = b"\xaa\xbb\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20" + encoded_name + b"\x00\x00\x21\x00\x01"
        
        response = _build_netbios_ns_node_status_response(query_data)
        
        # Verify transaction ID is copied
        self.assertEqual(response[0:2], b"\xaa\xbb")
        # Verify response code flags for Node Status response: 0x8400
        self.assertEqual(response[2:4], b"\x84\x00")
        # Verify NBSTAT answer type: 0x0021
        self.assertEqual(response[46:48], b"\x00\x21")
        # Verify names presence
        self.assertIn(b"WIN-SRV2019", response)
        self.assertIn(b"CORP", response)
        # Verify MAC Address
        self.assertIn(b"\x00\x15\x5d\xa1\xb2\xc3", response)
