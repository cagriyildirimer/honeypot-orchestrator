from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, MagicMock
from honeypot_orchestrator.services.http import HTTPHoneypot
from honeypot_orchestrator.profiles import HoneypotProfile, HTTPProfile, SMBProfile
from honeypot_orchestrator.event_logger import JSONLEventLogger


class HTTPInteractiveTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.http_prof = HTTPProfile(
            template_name="http_windows",
            server_header="Microsoft-IIS/10.0",
            default_status="200 OK",
            title="IIS Windows Server",
            body_html="<h1>Generic IIS</h1>"
        )
        self.smb_prof = SMBProfile(
            template_name="smb_windows",
            hostname="TEST-SRV",
            domain="TESTCORP",
            dns_domain="testcorp.local",
            native_os="Windows",
            native_lanman="Windows",
            server_guid="0",
            signing_policy=0,
            ntlm_challenge="0"
        )
        self.profile = HoneypotProfile(
            name="windows_server",
            display_name="Windows Profile",
            services=("http_windows",),
            http=self.http_prof,
            ssh=MagicMock(),
            ftp=MagicMock(),
            telnet=MagicMock(),
            smb=self.smb_prof
        )
        self.logger = AsyncMock(spec=JSONLEventLogger)
        self.service = HTTPHoneypot("http_windows", "127.0.0.1", 80, self.logger, self.profile)

    async def test_get_request_renders_gateway(self) -> None:
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("192.168.1.50", 54321)
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        # Mock GET headers request
        mock_reader.readline.side_effect = [
            b"GET / HTTP/1.1\r\n",
            b"Host: 127.0.0.1\r\n",
            b"User-Agent: test-agent\r\n",
            b"\r\n"
        ]

        written_data = []
        def mock_write(data):
            written_data.append(data)
        mock_writer.write.side_effect = mock_write

        await self.service.handle_client(mock_reader, mock_writer)

        # Verify dynamic template is injected correctly
        response_text = b"".join(written_data).decode("utf-8")
        self.assertIn("TEST-SRV Administrative Gateway", response_text)
        self.assertIn("TESTCORP (Active Directory Domain)", response_text)
        self.assertNotIn("Authentication failed", response_text)

        # Verify event logging was called
        self.logger.log.assert_any_call({
            "service": "http_windows",
            "event_type": "http_request",
            "src_ip": "192.168.1.50",
            "src_port": 54321,
            "method": "GET",
            "path": "/",
            "profile": "windows_server",
            "template": "http_windows",
            "user_agent": "test-agent",
            "summary": "GET /"
        })

    async def test_post_request_captures_credentials(self) -> None:
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("192.168.1.50", 54321)
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        # Mock POST with Content-Length header
        mock_reader.readline.side_effect = [
            b"POST / HTTP/1.1\r\n",
            b"Host: 127.0.0.1\r\n",
            b"Content-Length: 46\r\n",
            b"Content-Type: application/x-www-form-urlencoded\r\n",
            b"\r\n"
        ]
        
        # Post request payload
        mock_reader.readexactly.return_value = b"domain=TESTCORP&username=cagri&password=secret"

        written_data = []
        def mock_write(data):
            written_data.append(data)
        mock_writer.write.side_effect = mock_write

        await self.service.handle_client(mock_reader, mock_writer)

        # Verify logger.log captured credential attempt
        self.logger.log.assert_any_call({
            "service": "http_windows",
            "event_type": "credential_attempt",
            "src_ip": "192.168.1.50",
            "src_port": 54321,
            "username": "cagri",
            "password": "secret",
            "domain": "TESTCORP",
            "summary": "Captured HTTP login attempt: TESTCORP\\cagri"
        })

        # Verify dynamic template includes the authentication failure notification
        response_text = b"".join(written_data).decode("utf-8")
        self.assertIn("Authentication failed. The user name or password you entered is incorrect. Access is denied.", response_text)
