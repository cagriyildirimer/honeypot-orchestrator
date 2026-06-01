from __future__ import annotations

import asyncio

from honeypot_orchestrator.event_logger import JSONLEventLogger
from honeypot_orchestrator.profiles import HoneypotProfile
from honeypot_orchestrator.services.base import BaseHoneypotService


class HTTPHoneypot(BaseHoneypotService):
    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        logger: JSONLEventLogger,
        profile: HoneypotProfile,
    ) -> None:
        super().__init__(name=name, host=host, port=port, logger=logger)
        self.profile = profile

    def set_profile(self, profile: HoneypotProfile) -> None:
        self.profile = profile

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        try:
            # HTTP isteginin ilk satiri genelde "GET /path HTTP/1.1" bicimindedir.
            request_line = await self.read_line(reader, timeout=10.0)
            headers: dict[str, str] = {}
            while True:
                # Bos satira kadar HTTP header satirlari okunur.
                line = await self.read_line(reader, timeout=5.0)
                if not line:
                    break
                key, _, value = line.partition(":")
                if key and value:
                    headers[key.strip().lower()] = value.strip()

            method, path, _ = _parse_request_line(request_line)

            # POST isteklerinin payload icerigini oku
            content_length = 0
            try:
                content_length = int(headers.get("content-length", "0"))
            except ValueError:
                pass

            body_payload = b""
            if content_length > 0:
                if content_length < 8192:
                    body_payload = await asyncio.wait_for(reader.readexactly(content_length), timeout=5.0)
                else:
                    body_payload = await asyncio.wait_for(reader.read(8192), timeout=5.0)

            username = ""
            password = ""
            domain = ""
            login_error = False

            if method == "POST":
                from urllib.parse import parse_qs
                parsed = parse_qs(body_payload.decode("utf-8", errors="replace"))
                username = parsed.get("username", [""])[0].strip()
                password = parsed.get("password", [""])[0].strip()
                domain = parsed.get("domain", [""])[0].strip()

                if username or password:
                    login_error = True
                    # Giriş denemelerini credential_attempt olayı olarak logluyoruz
                    await self.log_event(
                        "credential_attempt",
                        src_ip=src_ip,
                        src_port=src_port,
                        service=self.name,
                        username=username,
                        password=password,
                        domain=domain or self.profile.smb.domain,
                        summary=f"Captured HTTP login attempt: {domain or self.profile.smb.domain}\\{username}",
                    )

            http_profile = self.profile.http
            # Istek metodu, yol ve User-Agent gibi temel izler loglanir.
            await self.log_event(
                "http_request",
                src_ip=src_ip,
                src_port=src_port,
                method=method,
                path=path,
                profile=self.profile.name,
                template=http_profile.template_name,
                user_agent=headers.get("user-agent", ""),
                summary=f"{method} {path}",
            )

            # Windows profili için dinamik kurumsal login sayfası üretiliyor
            if http_profile.template_name == "http_windows":
                hostname = self.profile.smb.hostname
                domain_val = self.profile.smb.domain
                body = _get_windows_admin_html(hostname, domain_val, login_error)
            else:
                body = http_profile.body_html

            response = (
                f"HTTP/1.1 {http_profile.default_status}\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Server: {http_profile.server_header}\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{body}"
            )
            await self.write(writer, response)
        except Exception as exc:
            # Bozuk veya beklenmeyen isteklerde baglanti hatasi olarak iz birakilir.
            await self.log_event(
                "connection_error",
                src_ip=src_ip,
                src_port=src_port,
                error=type(exc).__name__,
            )
        finally:
            await self.close_writer(writer)


def _parse_request_line(request_line: str) -> tuple[str, str, str]:
    # Eksik veya bozuk request line geldiginde guvenli varsayilanlar kullanilir.
    parts = request_line.split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return "UNKNOWN", "/", ""


def _get_windows_admin_html(hostname: str, domain: str, login_error: bool) -> str:
    error_placeholder = ""
    if login_error:
        error_placeholder = """
            <div class="error-alert">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 20px; height: 20px; flex-shrink: 0;">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
                <span>Authentication failed. The user name or password you entered is incorrect. Access is denied.</span>
            </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Server Administration Gateway</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', sans-serif;
        }}
        body {{
            background: linear-gradient(135deg, #0b0f19 0%, #111827 50%, #1e1b4b 100%);
            color: #f3f4f6;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            width: 100%;
            max-width: 440px;
            perspective: 1000px;
        }}
        .card {{
            background: rgba(17, 24, 39, 0.7);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 40px 32px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
            animation: slideIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }}
        @keyframes slideIn {{
            from {{
                opacity: 0;
                transform: translateY(30px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
        .logo-area {{
            text-align: center;
            margin-bottom: 32px;
        }}
        .logo-icon {{
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
            border-radius: 12px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
            box-shadow: 0 8px 16px rgba(37, 99, 235, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .logo-icon svg {{
            width: 32px;
            height: 32px;
            color: white;
        }}
        .title {{
            font-size: 20px;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 6px;
            letter-spacing: -0.5px;
        }}
        .subtitle {{
            font-size: 13px;
            color: #9ca3af;
        }}
        .error-alert {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-left: 4px solid #ef4444;
            border-radius: 8px;
            padding: 14px 16px;
            margin-bottom: 24px;
            font-size: 13px;
            color: #fca5a5;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            animation: shake 0.4s ease-in-out;
        }}
        @keyframes shake {{
            0%, 100% {{ transform: translateX(0); }}
            20%, 60% {{ transform: translateX(-6px); }}
            40%, 80% {{ transform: translateX(6px); }}
        }}
        .form-group {{
            margin-bottom: 20px;
            position: relative;
        }}
        .form-label {{
            display: block;
            font-size: 11px;
            font-weight: 600;
            color: #9ca3af;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .input-wrapper {{
            position: relative;
        }}
        .input-wrapper svg {{
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            width: 18px;
            height: 18px;
            color: #6b7280;
            transition: color 0.3s;
        }}
        .form-input {{
            width: 100%;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 12px 16px 12px 42px;
            color: #ffffff;
            font-size: 14px;
            outline: none;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .form-input:focus {{
            background: rgba(255, 255, 255, 0.07);
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }}
        .form-input:focus + svg {{
            color: #3b82f6;
        }}
        .form-select {{
            appearance: none;
            -webkit-appearance: none;
            cursor: pointer;
        }}
        .select-arrow {{
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            pointer-events: none;
            color: #6b7280;
            width: 16px;
            height: 16px;
        }}
        .btn-submit {{
            width: 100%;
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 14px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.2);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            margin-top: 10px;
        }}
        .btn-submit:hover {{
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(37, 99, 235, 0.4);
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
        }}
        .btn-submit:active {{
            transform: translateY(1px);
        }}
        .footer {{
            margin-top: 24px;
            text-align: center;
            font-size: 11px;
            color: #4b5563;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="logo-area">
                <div class="logo-icon">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                    </svg>
                </div>
                <h1 class="title">{hostname} Administrative Gateway</h1>
                <p class="subtitle">Windows Server Administration Center</p>
            </div>
            
            {error_placeholder}
            
            <form action="/" method="POST">
                <div class="form-group">
                    <label class="form-label">Domain</label>
                    <div class="input-wrapper">
                        <select class="form-input form-select" name="domain">
                            <option value="{domain}" selected>{domain} (Active Directory Domain)</option>
                            <option value="LOCAL">LOCAL (Local Machine)</option>
                        </select>
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="left: 14px;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path>
                        </svg>
                        <svg class="select-arrow" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                        </svg>
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label">Username</label>
                    <div class="input-wrapper">
                        <input class="form-input" type="text" name="username" placeholder="{domain}\\Administrator" required autofocus>
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                        </svg>
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label">Password</label>
                    <div class="input-wrapper">
                        <input class="form-input" type="password" name="password" placeholder="••••••••" required>
                        <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                        </svg>
                    </div>
                </div>

                <button class="btn-submit" type="submit">Sign In</button>
            </form>
            
            <div class="footer">
                &copy; Microsoft Corporation. All rights reserved.
            </div>
        </div>
    </div>
</body>
</html>"""

