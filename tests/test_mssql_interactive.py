from __future__ import annotations

import unittest
from honeypot_orchestrator.services.mssql import (
    _is_decoy_credential,
    _extract_login7_password,
    _extract_login7_string,
    _build_login_success_response,
    _build_sql_text_response,
    _build_sql_list_response,
    _skip_all_headers,
    _build_prelogin_response,
    _uses_tds72_plus,
    _build_login_error_response,
    _build_sql_empty_response,
)


class MSSQLInteractiveTests(unittest.TestCase):
    def test_decoy_credentials(self) -> None:
        # Check standard defaults match
        self.assertTrue(_is_decoy_credential("sa", "Password123"))
        self.assertTrue(_is_decoy_credential("sa", "password"))
        self.assertTrue(_is_decoy_credential("admin", "password"))
        self.assertTrue(_is_decoy_credential("sql_service", "password123"))
        self.assertTrue(_is_decoy_credential("administrator", "Password123"))
        
        # Check case insensitivity for username
        self.assertTrue(_is_decoy_credential("SA", "Password123"))
        self.assertTrue(_is_decoy_credential(" Admin ", "password"))
        
        # Check any credentials are now accepted
        self.assertTrue(_is_decoy_credential("sa", "WrongPassword!"))
        self.assertTrue(_is_decoy_credential("random_user", "password"))

    def test_password_deobfuscation(self) -> None:
        # 1. Encode "Secret123" to UTF-16LE
        original_pass = "Secret123"
        utf16_bytes = original_pass.encode("utf-16le")
        
        # 2. Obfuscate using TDS algorithm (swap nibbles, then XOR 0xA5)
        # E = Swap(B) ^ 0xA5 -> Swap(E ^ 0xA5) = B
        obfuscated_bytes = bytearray()
        for b in utf16_bytes:
            # High/low nibble swap
            swapped = ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)
            # XOR with 0xA5
            obfuscated_bytes.append(swapped ^ 0xA5)
            
        # 3. Build a mock LOGIN7 payload
        # Offset 44: password offset (2 bytes)
        # Offset 46: password length (2 bytes, count of characters = 9)
        # Let's place password at offset 80
        payload = bytearray(120)
        password_offset = 80
        password_length = len(original_pass)
        
        payload[44:46] = password_offset.to_bytes(2, "little")
        payload[46:48] = password_length.to_bytes(2, "little")
        payload[password_offset : password_offset + len(obfuscated_bytes)] = obfuscated_bytes
        
        # 4. Decrypt and check
        decrypted = _extract_login7_password(bytes(payload))
        self.assertEqual(decrypted, original_pass)

    def test_string_extraction(self) -> None:
        # Test generic unicode string extraction from LOGIN7 offsets
        original_str = "MY-LAPTOP"
        utf16_bytes = original_str.encode("utf-16le")
        
        payload = bytearray(100)
        offset = 64
        length = len(original_str)
        
        # Let's say we read client_hostname (offset at 36, length at 38)
        payload[36:38] = offset.to_bytes(2, "little")
        payload[38:40] = length.to_bytes(2, "little")
        payload[offset : offset + len(utf16_bytes)] = utf16_bytes
        
        extracted = _extract_login7_string(bytes(payload), 36, 38)
        self.assertEqual(extracted, original_str)

    def test_build_success_response(self) -> None:
        # Case 1: uses_tds72 = True
        response_72 = _build_login_success_response(uses_tds72=True)
        self.assertEqual(response_72[0], 0xE3)
        self.assertIn(b"\xad", response_72)
        # 13 bytes done token ends with 8 zero bytes
        self.assertTrue(response_72.endswith(b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
        
        # Case 2: uses_tds72 = False
        response_71 = _build_login_success_response(uses_tds72=False)
        self.assertEqual(response_71[0], 0xE3)
        self.assertIn(b"\xad", response_71)
        # 9 bytes done token ends with 4 zero bytes
        self.assertTrue(response_71.endswith(b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00"))

    def test_build_sql_text_response(self) -> None:
        col_name = "test_col"
        row_text = "test_val"
        
        # Case 1: uses_tds72 = True
        response_72 = _build_sql_text_response(col_name, row_text, uses_tds72=True)
        self.assertEqual(response_72[0], 0x81)
        self.assertEqual(response_72[1:3], b"\x01\x00")
        # UserType (4 bytes)
        self.assertEqual(response_72[3:7], b"\x00\x00\x00\x00")
        self.assertIn(col_name.encode("utf-16le"), response_72)
        self.assertIn(b"\xd1", response_72)
        self.assertIn(row_text.encode("utf-16le"), response_72)
        # DONE Row count is 8 bytes
        self.assertTrue(response_72.endswith(b"\x01\x00\x00\x00\x00\x00\x00\x00"))
        
        # Case 2: uses_tds72 = False
        response_71 = _build_sql_text_response(col_name, row_text, uses_tds72=False)
        self.assertEqual(response_71[0], 0x81)
        self.assertEqual(response_71[1:3], b"\x01\x00")
        # UserType (2 bytes)
        self.assertEqual(response_71[3:5], b"\x00\x00")
        self.assertIn(col_name.encode("utf-16le"), response_71)
        self.assertIn(b"\xd1", response_71)
        self.assertIn(row_text.encode("utf-16le"), response_71)
        # DONE Row count is 4 bytes
        self.assertTrue(response_71.endswith(b"\x01\x00\x00\x00"))

    def test_build_sql_list_response(self) -> None:
        col_name = "db_names"
        dbs = ["master", "tempdb", "prod_db"]
        
        # Case 1: uses_tds72 = True
        response_72 = _build_sql_list_response(col_name, dbs, uses_tds72=True)
        self.assertEqual(response_72[0], 0x81)
        for db in dbs:
            self.assertIn(db.encode("utf-16le"), response_72)
        # DONE Row count is 8 bytes
        self.assertTrue(response_72.endswith(len(dbs).to_bytes(8, "little")))
        
        # Case 2: uses_tds72 = False
        response_71 = _build_sql_list_response(col_name, dbs, uses_tds72=False)
        self.assertEqual(response_71[0], 0x81)
        for db in dbs:
            self.assertIn(db.encode("utf-16le"), response_71)
        # DONE Row count is 4 bytes
        self.assertTrue(response_71.endswith(len(dbs).to_bytes(4, "little")))

    def test_skip_all_headers(self) -> None:
        # Case 1: No All Headers block (normal query)
        query = "SELECT @@version".encode("utf-16le")
        self.assertEqual(_skip_all_headers(query), query)
        
        # Case 2: All Headers block present (length 22)
        all_headers_block = (22).to_bytes(4, "little") + b"\x00" * 18
        payload = all_headers_block + query
        self.assertEqual(_skip_all_headers(payload), query)
        
        # Case 3: Empty/Too short payload
        self.assertEqual(_skip_all_headers(b"\x01"), b"\x01")

    def test_login7_parsing_with_padding(self) -> None:
        # Create a realistic LOGIN7 payload with padding at the end
        username_str = "sa"
        username_bytes = username_str.encode("utf-16le")
        
        # Total payload will be 130 bytes, but LOGIN7 length field is 120
        payload = bytearray(130)
        payload[0:4] = (120).to_bytes(4, "little")
        
        # Set username offset and length at offsets 40 and 42
        offset = 80
        length = len(username_str)
        payload[40:42] = offset.to_bytes(2, "little")
        payload[42:44] = length.to_bytes(2, "little")
        payload[offset : offset + len(username_bytes)] = username_bytes
        
        # Verify that even with padding (len(payload) > 120), we can extract username correctly
        extracted = _extract_login7_string(bytes(payload), 40, 42)
        self.assertEqual(extracted, username_str)
        
        # Show that _skip_all_headers would corrupt/slice this payload because
        # it mistakes the LOGIN7 length field (120) for an All Headers block length.
        # This is why we must not call it on the LOGIN7 payload.
        corrupted_payload = _skip_all_headers(bytes(payload))
        self.assertNotEqual(corrupted_payload, bytes(payload))
        self.assertEqual(len(corrupted_payload), 10)  # It incorrectly slices to payload[120:]

    def test_build_prelogin_response(self) -> None:
        response = _build_prelogin_response()
        # Header table size (21 bytes) + data: Version (6), Encryption (1), Instance (1), ThreadID (4) = 33 bytes
        self.assertEqual(len(response), 33)
        
        # Verify Token IDs in header table
        self.assertEqual(response[0], 0x00)  # Version Token
        self.assertEqual(response[5], 0x01)  # Encryption Token
        self.assertEqual(response[10], 0x02) # Instance Token
        self.assertEqual(response[15], 0x03) # ThreadID Token
        self.assertEqual(response[20], 0xFF) # Terminator (EndToken)
        
        # Verify offsets
        version_offset = int.from_bytes(response[1:3], "big")
        encryption_offset = int.from_bytes(response[6:8], "big")
        instance_offset = int.from_bytes(response[11:13], "big")
        threadid_offset = int.from_bytes(response[16:18], "big")
        
        self.assertEqual(version_offset, 21)
        self.assertEqual(encryption_offset, 27)
        self.assertEqual(instance_offset, 28)
        self.assertEqual(threadid_offset, 29)
        
        # Verify lengths
        version_len = int.from_bytes(response[3:5], "big")
        encryption_len = int.from_bytes(response[8:10], "big")
        instance_len = int.from_bytes(response[13:15], "big")
        threadid_len = int.from_bytes(response[18:20], "big")
        
        self.assertEqual(version_len, 6)
        self.assertEqual(encryption_len, 1)
        self.assertEqual(instance_len, 1)
        self.assertEqual(threadid_len, 4)
        
        # Verify data values using offsets and lengths
        self.assertEqual(response[version_offset : version_offset + version_len], b"\x0f\x00\x07\xd0\x00\x00")
        self.assertEqual(response[encryption_offset], 0x02) # ENCRYPT_NOT_SUP
        self.assertEqual(response[instance_offset], 0x00)   # Empty instance name
        self.assertEqual(response[threadid_offset : threadid_offset + threadid_len], b"\x00\x00\x00\x00")

    def test_uses_tds72_plus(self) -> None:
        self.assertFalse(_uses_tds72_plus(b""))
        # TDS 7.1
        self.assertFalse(_uses_tds72_plus(b"\x71\x00\x00\x01"))
        self.assertFalse(_uses_tds72_plus(b"\x70\x00\x00\x00"))
        # TDS 7.2+
        self.assertTrue(_uses_tds72_plus(b"\x72\x09\x00\x02"))
        self.assertTrue(_uses_tds72_plus(b"\x73\x00\x00\x00"))
        self.assertTrue(_uses_tds72_plus(b"\x74\x00\x00\x04"))

    def test_build_login_error_response(self) -> None:
        # Case 1: uses_tds72 = True
        resp_72 = _build_login_error_response("sa", uses_tds72=True)
        self.assertEqual(resp_72[0], 0xAA)
        self.assertTrue(resp_72.endswith(b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
        
        # Case 2: uses_tds72 = False
        resp_71 = _build_login_error_response("sa", uses_tds72=False)
        self.assertEqual(resp_71[0], 0xAA)
        self.assertTrue(resp_71.endswith(b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00"))

    def test_build_sql_empty_response(self) -> None:
        # Case 1: uses_tds72 = True
        resp_72 = _build_sql_empty_response(uses_tds72=True)
        self.assertEqual(resp_72, b"\xfd\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        
        # Case 2: uses_tds72 = False
        resp_71 = _build_sql_empty_response(uses_tds72=False)
        self.assertEqual(resp_71, b"\xfd\x10\x00\x00\x00\x00\x00\x00\x00")
