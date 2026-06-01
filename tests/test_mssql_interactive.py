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
        response = _build_login_success_response()
        # Verify ENVCHANGE token (0xE3) is present at the beginning
        self.assertEqual(response[0], 0xE3)
        # Verify LOGINACK token (0xAD) is present in the stream
        self.assertIn(b"\xad", response)
        # Verify DONE token (0xFD) is appended
        self.assertIn(b"\xfd\x00\x00\x00", response)

    def test_build_sql_text_response(self) -> None:
        col_name = "test_col"
        row_text = "test_val"
        response = _build_sql_text_response(col_name, row_text)
        
        # Verify COLMETADATA token (0x81)
        self.assertEqual(response[0], 0x81)
        # Verify column count is 1
        self.assertEqual(response[1:3], b"\x01\x00")
        # Verify column name is present in UTF-16LE
        self.assertIn(col_name.encode("utf-16le"), response)
        # Verify ROW token (0xD1)
        self.assertIn(b"\xd1", response)
        # Verify row text is present in UTF-16LE
        self.assertIn(row_text.encode("utf-16le"), response)
        # Verify DONE token (0xFD) is appended
        self.assertTrue(response.endswith(b"\x01\x00\x00\x00\x00\x00\x00\x00"))

    def test_build_sql_list_response(self) -> None:
        col_name = "db_names"
        dbs = ["master", "tempdb", "prod_db"]
        response = _build_sql_list_response(col_name, dbs)
        
        # Verify COLMETADATA token (0x81)
        self.assertEqual(response[0], 0x81)
        # Verify row values exist
        for db in dbs:
            self.assertIn(db.encode("utf-16le"), response)
        # Verify DONE token (0xFD)
        self.assertIn(b"\xfd", response)

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
