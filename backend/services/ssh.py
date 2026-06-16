from __future__ import annotations

import asyncio
import asyncssh

from core.event_logger import JSONLEventLogger
from system.profiles import HoneypotProfile
from services.base import BaseHoneypotService


def _resolve_windows_path(current: str, target: str) -> str:
    target = target.replace("/", "\\")
    if target.startswith("C:\\") or target.startswith("c:\\"):
        parts = target.split("\\")
    elif target.startswith("\\"):
        parts = ["C:"] + target.lstrip("\\").split("\\")
    else:
        parts = current.split("\\") + target.split("\\")
    
    resolved_parts = []
    for p in parts:
        p = p.strip()
        if p == "." or not p:
            continue
        elif p == "..":
            if len(resolved_parts) > 1:
                resolved_parts.pop()
        else:
            resolved_parts.append(p)
            
    if resolved_parts:
        if not resolved_parts[0].endswith(":"):
            resolved_parts[0] = resolved_parts[0] + ":"
    return "\\".join(resolved_parts)


def _resolve_linux_path(current: str, target: str) -> str:
    if target.startswith("/"):
        parts = target.split("/")
    else:
        parts = current.split("/") + target.split("/")
        
    resolved_parts = []
    for p in parts:
        p = p.strip()
        if p == "." or not p:
            continue
        elif p == "..":
            if resolved_parts:
                resolved_parts.pop()
        else:
            resolved_parts.append(p)
    return "/" + "/".join(resolved_parts)


def _get_mock_file_content(path: str) -> str:
    path_lower = path.lower().replace("/", "\\")
    if path_lower.endswith("notes.txt"):
        return "Tüm servis entegrasyonlarını tamamlayıp güvenlik duvarı kurallarını gözden geçirin.\r\n"
    elif path_lower.endswith("todo.txt"):
        return (
            "1. Web paneli şifrelerini değiştir\r\n"
            "2. SQL Server yedeklerini al\r\n"
            "3. Gereksiz portları kapat\r\n"
        )
    elif path_lower.endswith("install_log.txt"):
        return (
            "2026-06-01 10:11:05 [INFO] Installer started.\r\n"
            "2026-06-01 10:12:10 [INFO] Files copied successfully.\r\n"
            "2026-06-01 10:12:15 [INFO] Installation completed.\r\n"
        )
    elif path_lower.endswith("passwd"):
        return (
            "root:x:0:0:root:/root:/bin/bash\r\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n"
        )
    elif path_lower.endswith("hosts"):
        return "127.0.0.1 localhost\r\n192.168.1.240 ubuntu-srv\r\n"
    elif path_lower.endswith("resolv.conf"):
        return "nameserver 1.1.1.1\r\nnameserver 8.8.8.8\r\n"
    elif path_lower.endswith("syslog"):
        return (
            "Jun  3 10:14:22 ubuntu-srv systemd[1]: Started Periodic Command Scheduler.\r\n"
            "Jun  3 10:15:01 ubuntu-srv CRON[2015]: (root) CMD (sysstat)\r\n"
        )
    elif path_lower.endswith("auth.log"):
        return (
            "Jun  3 10:14:22 ubuntu-srv sshd[2012]: Accepted password for root from 192.168.1.105 port 54321 ssh2\r\n"
        )
    else:
        return "Erişim reddedildi veya dosya okunamıyor.\r\n"


class MySSHServer(asyncssh.SSHServer):
    def __init__(self, service: FakeSSHHoneypot):
        self.service = service
        self.attempts = 0
        self.peername = None

    def connection_made(self, conn: asyncssh.SSHConnection):
        self.peername = conn.get_extra_info('peername')
        src_ip = self.peername[0] if self.peername else "unknown"
        src_port = self.peername[1] if self.peername else 0
        asyncio.create_task(
            self.service.log_event("connection", src_ip=src_ip, src_port=src_port)
        )

    def connection_lost(self, exc: Exception | None):
        src_ip = self.peername[0] if self.peername else "unknown"
        src_port = self.peername[1] if self.peername else 0
        asyncio.create_task(
            self.service.log_event("client_disconnected", src_ip=src_ip, src_port=src_port)
        )

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        self.attempts += 1
        src_ip = self.peername[0] if self.peername else "unknown"
        src_port = self.peername[1] if self.peername else 0
        
        await self.service.log_event(
            "login_attempt",
            src_ip=src_ip,
            src_port=src_port,
            profile=self.service.profile.name,
            username=username,
            password=password,
            summary=f"SSH Login attempted for username='{username}' password='{password}' (Access Denied)",
        )
        
        # İkinci denemede herhangi bir boş olmayan girişi kabul et
        if self.attempts >= 2 and len(username.strip()) > 0 and len(password.strip()) > 0:
            return True
            
        return False


class FakeSSHHoneypot(BaseHoneypotService):
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
        self._server = None

    def set_profile(self, profile: HoneypotProfile) -> None:
        self.profile = profile

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        pass

    @property
    def running(self) -> bool:
        return self._server is not None

    async def start(self) -> None:
        if self.running:
            return
            
        # Dinamik olarak RSA özel anahtarı üret
        key = asyncssh.generate_private_key('ssh-rsa')
        
        # Sürüm/banner bilgisini ayarla
        banner_str = self.profile.ssh.banner
        if banner_str.startswith("SSH-2.0-"):
            version = banner_str[8:].strip()
        else:
            version = banner_str.strip()
            
        self._server = await asyncssh.create_server(
            lambda: MySSHServer(self),
            host=self.host,
            port=self.port,
            server_host_keys=[key],
            line_editor=True,
            server_version=version,
            process_factory=self.handle_ssh_session
        )
        await self.log_event("service_started", summary=f"{self.name} listening (SSH).")

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None
        await self.log_event("service_stopped", summary=f"{self.name} stopped.")

    async def handle_ssh_session(self, process: asyncssh.SSHServerProcess) -> None:
        username = process.get_extra_info("username")
        peername = process.get_extra_info("peername")
        src_ip = peername[0] if peername else "unknown"
        src_port = peername[1] if peername else 0
        
        await self.log_event(
            "login_success",
            src_ip=src_ip,
            src_port=src_port,
            profile=self.profile.name,
            username=username,
            summary=f"SSH Authentication succeeded for user '{username}'",
        )
        
        is_windows = "windows" in self.profile.name
        
        # Dizin yapısı tanımları
        if is_windows:
            win_tree = {
                "C:": [("Users", True, 0), ("Windows", True, 0), ("Program Files", True, 0)],
                "C:\\Users": [("Administrator", True, 0), (username, True, 0)] if username != "Administrator" else [("Administrator", True, 0)],
                f"C:\\Users\\{username}": [("Desktop", True, 0), ("Documents", True, 0), ("Downloads", True, 0), ("notes.txt", False, 120)],
                f"C:\\Users\\{username}\\Desktop": [("Chrome.lnk", False, 1024), ("shortcut.lnk", False, 512)],
                f"C:\\Users\\{username}\\Documents": [("finance.xlsx", False, 12045), ("todo.txt", False, 150)],
                f"C:\\Users\\{username}\\Downloads": [("installer.exe", False, 4520310), ("install_log.txt", False, 843)],
                "C:\\Windows": [("System32", True, 0), ("explorer.exe", False, 3510000)],
                "C:\\Windows\\System32": [("cmd.exe", False, 280000), ("ping.exe", False, 85000)],
            }
            current_dir = f"C:\\Users\\{username}"
            welcome = (
                "\r\nMicrosoft Windows [Version 10.0.17763.379]\r\n"
                "(c) 2018 Microsoft Corporation. Tüm hakları saklıdır.\r\n\r\n"
            )
        else:
            linux_tree = {
                "/": [("bin", True, 0), ("boot", True, 0), ("dev", True, 0), ("etc", True, 0), ("home", True, 0), ("lib", True, 0), ("lib64", True, 0), ("media", True, 0), ("mnt", True, 0), ("opt", True, 0), ("proc", True, 0), ("root", True, 0), ("run", True, 0), ("sbin", True, 0), ("srv", True, 0), ("sys", True, 0), ("tmp", True, 0), ("usr", True, 0), ("var", True, 0)],
                "/root": [("Desktop", True, 0), ("Documents", True, 0), ("Downloads", True, 0), ("notes.txt", False, 120)],
                "/home": [(username, True, 0)],
                f"/home/{username}": [("Desktop", True, 0), ("Documents", True, 0), ("Downloads", True, 0), ("notes.txt", False, 120)],
                "/root/Desktop": [("chrome.desktop", False, 128)],
                "/root/Documents": [("report.pdf", False, 10245), ("todo.txt", False, 150)],
                "/root/Downloads": [("backup.tar.gz", False, 84210)],
                f"/home/{username}/Desktop": [("chrome.desktop", False, 128)],
                f"/home/{username}/Documents": [("report.pdf", False, 10245), ("todo.txt", False, 150)],
                f"/home/{username}/Downloads": [("backup.tar.gz", False, 84210)],
                "/etc": [("passwd", False, 1205), ("group", False, 850), ("hosts", False, 150), ("resolv.conf", False, 85)],
                "/tmp": [("ssh-auth.sock", False, 0)],
                "/var": [("log", True, 0)],
                "/var/log": [("syslog", False, 2048), ("auth.log", False, 1024)],
            }
            current_dir = "/root" if username == "root" else f"/home/{username}"
            welcome = (
                f"\r\nWelcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n"
                f" * Documentation:  https://help.ubuntu.com\r\n"
                f" * Management:     https://landscape.canonical.com\r\n"
                f" * Support:        https://ubuntu.com/advantage\r\n\r\n"
                f"Last login: Wed Jun  3 10:14:22 2026 from {src_ip}\r\n"
            )

        process.stdout.write(welcome)
        
        while True:
            if is_windows:
                prompt = f"{current_dir}>"
            else:
                suffix = "# " if username == "root" else "$ "
                prompt = f"{username}@ubuntu-srv:{current_dir}{suffix}"
                
            process.stdout.write(prompt)
            
            try:
                cmd_line = await process.stdin.readline()
            except (asyncio.CancelledError, Exception):
                break
                
            if not cmd_line:
                break
                
            cmd = cmd_line.strip()
            if not cmd:
                continue
                
            await self.log_event(
                "ssh_command",
                src_ip=src_ip,
                src_port=src_port,
                profile=self.profile.name,
                username=username,
                command=cmd,
                summary=f"SSH command executed by '{username}': {cmd}",
            )
            
            # Split command and arguments
            parts = cmd.split(maxsplit=1)
            base_cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""
            
            if base_cmd in {"exit", "quit"}:
                process.stdout.write("logout\r\n")
                break
                
            response = ""
            if is_windows:
                if base_cmd == "whoami":
                    response = f"win-srv2019\\{username}\r\n"
                elif base_cmd == "cd":
                    if not arg:
                        response = f"{current_dir}\r\n"
                    else:
                        if arg.lower() in {"c:", "c:\\", "c:/"}:
                            current_dir = "C:"
                            response = ""
                        else:
                            target_dir = _resolve_windows_path(current_dir, arg)
                            if target_dir in win_tree:
                                current_dir = target_dir
                                response = ""
                            else:
                                # Check if it is a file
                                parent = "\\".join(target_dir.split("\\")[:-1])
                                file_name = target_dir.split("\\")[-1]
                                if parent in win_tree and any(name.lower() == file_name.lower() and not is_dir for name, is_dir, _ in win_tree[parent]):
                                    response = "The directory name is invalid.\r\n"
                                else:
                                    response = "The system cannot find the path specified.\r\n"
                elif base_cmd in {"dir", "ls"}:
                    target_dir = current_dir
                    if arg:
                        target_dir = _resolve_windows_path(current_dir, arg)
                        
                    if target_dir in win_tree:
                        items = win_tree[target_dir]
                        response = f" Directory of {target_dir}\r\n\r\n"
                        dirs_count = 0
                        files_count = 0
                        files_size = 0
                        for name, is_dir, size in items:
                            if is_dir:
                                response += f"2026-06-03  10:15    <DIR>          {name}\r\n"
                                dirs_count += 1
                            else:
                                response += f"2026-06-03  10:15             {size:<8} {name}\r\n"
                                files_count += 1
                                files_size += size
                        response += f"               {files_count} File(s)            {files_size} bytes\r\n"
                        response += f"               {dirs_count} Dir(s)  42,919,203,840 bytes free\r\n"
                    else:
                        response = "File Not Found\r\n"
                elif base_cmd in {"type", "cat"}:
                    if not arg:
                        response = "The syntax of the command is incorrect.\r\n"
                    else:
                        target_file = _resolve_windows_path(current_dir, arg)
                        parent = "\\".join(target_file.split("\\")[:-1])
                        file_name = target_file.split("\\")[-1]
                        if parent in win_tree and any(name.lower() == file_name.lower() and not is_dir for name, is_dir, _ in win_tree[parent]):
                            response = _get_mock_file_content(target_file)
                        else:
                            response = "The system cannot find the file specified.\r\n"
                elif base_cmd == "ipconfig":
                    response = (
                        "\r\nWindows IP Configuration\r\n\r\n"
                        "Ethernet adapter Ethernet0:\r\n\r\n"
                        "   Connection-specific DNS Suffix  . : corp.local\r\n"
                        "   IPv4 Address. . . . . . . . . . . : 192.168.1.240\r\n"
                        "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n"
                        "   Default Gateway . . . . . . . . . : 192.168.1.1\r\n"
                    )
                elif base_cmd == "systeminfo":
                    response = (
                        "Host Name:                 WIN-SRV2019\r\n"
                        "OS Name:                   Microsoft Windows Server 2019 Standard\r\n"
                        "OS Version:                10.0.17763 N/A Build 17763\r\n"
                        "OS Manufacturer:           Microsoft Corporation\r\n"
                        "OS Configuration:          Member Server\r\n"
                        "OS Build Type:             Multiprocessor Free\r\n"
                        "System Manufacturer:       VMware, Inc.\r\n"
                        "System Model:              VMware Virtual Platform\r\n"
                        "System Type:               x64-based PC\r\n"
                        "Processor(s):              1 Processor(s) Installed.\r\n"
                        "                           [01]: Intel64 Family 6 Model 186 Stepping 2 GenuineIntel ~2496 Mhz\r\n"
                        "BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019\r\n"
                        "Windows Directory:         C:\\Windows\r\n"
                        "System Directory:          C:\\Windows\\system32\r\n"
                        "Boot Device:               \\Device\\HarddiskVolume1\r\n"
                        "System Locale:             en-us;English (United States)\r\n"
                        "Input Locale:              en-us;English (United States)\r\n"
                    )
                elif base_cmd == "net" and arg.lower() == "user":
                    response = (
                        f"\r\nUser accounts for \\\\WIN-SRV2019\r\n\r\n"
                        "-------------------------------------------------------------------------------\r\n"
                        "Administrator            Guest                    DefaultAccount           \r\n"
                        f"WDAGUtilityAccount       {username}               \r\n"
                        "The command completed successfully.\r\n"
                    )
                elif base_cmd in {"netstat", "net stat"}:
                    response = (
                        "\r\nActive Connections\r\n\r\n"
                        "  Proto  Local Address          Foreign Address        State\r\n"
                        f"  TCP    192.168.1.240:22       {src_ip}:{src_port}     ESTABLISHED\r\n"
                        "  TCP    192.168.1.240:3389     0.0.0.0:0              LISTENING\r\n"
                        "  TCP    192.168.1.240:445      0.0.0.0:0              LISTENING\r\n"
                    )
                elif base_cmd == "help":
                    response = "Supported commands: whoami, cd, dir, ls, type, cat, ipconfig, systeminfo, net user, netstat, help, exit\r\n"
                else:
                    response = f"'{cmd}' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
            else:
                # Linux
                if base_cmd == "whoami":
                    response = f"{username}\r\n"
                elif base_cmd == "id":
                    response = "uid=0(root) gid=0(root) groups=0(root)\r\n" if username == "root" else f"uid=1000({username}) gid=1000({username}) groups=1000({username})\r\n"
                elif base_cmd == "pwd":
                    response = f"{current_dir}\r\n"
                elif base_cmd == "cd":
                    if not arg or arg == "~":
                        current_dir = "/root" if username == "root" else f"/home/{username}"
                        response = ""
                    else:
                        target_dir = _resolve_linux_path(current_dir, arg)
                        if target_dir in linux_tree:
                            current_dir = target_dir
                            response = ""
                        else:
                            parent = "/" + "/".join(target_dir.split("/")[1:-1])
                            file_name = target_dir.split("/")[-1]
                            if parent in linux_tree and any(name.lower() == file_name.lower() and not is_dir for name, is_dir, _ in linux_tree[parent]):
                                    response = f"bash: cd: {arg}: Not a directory\r\n"
                            else:
                                    response = f"bash: cd: {arg}: No such file or directory\r\n"
                elif base_cmd in {"ls", "dir"}:
                    target_dir = current_dir
                    if arg:
                        target_dir = _resolve_linux_path(current_dir, arg)
                        
                    if target_dir in linux_tree:
                        items = linux_tree[target_dir]
                        names = [name for name, _, _ in items]
                        response = "  ".join(names) + "\r\n" if names else ""
                    else:
                        response = f"ls: cannot access '{arg}': No such file or directory\r\n"
                elif base_cmd == "cat":
                    if not arg:
                        response = ""
                    else:
                        target_file = _resolve_linux_path(current_dir, arg)
                        parent = "/" + "/".join(target_file.split("/")[1:-1])
                        file_name = target_file.split("/")[-1]
                        if parent in linux_tree and any(name.lower() == file_name.lower() and not is_dir for name, is_dir, _ in linux_tree[parent]):
                            response = _get_mock_file_content(target_file)
                        else:
                            response = f"cat: {arg}: No such file or directory\r\n"
                elif base_cmd in {"ifconfig", "ip"}:
                    response = (
                        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                        "        inet 192.168.1.240  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
                        "        ether 00:15:5d:00:1a:2b  txqueuelen 1000  (Ethernet)\r\n"
                    )
                elif base_cmd == "uname" and arg.lower() == "-a":
                    response = "Linux ubuntu-srv 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"
                elif base_cmd == "help":
                    response = "Supported commands: whoami, id, pwd, cd, ls, cat, ifconfig, ip, uname -a, help, exit\r\n"
                else:
                    response = f"bash: {cmd}: command not found\r\n"
            
            process.stdout.write(response)
            
        process.exit(0)
