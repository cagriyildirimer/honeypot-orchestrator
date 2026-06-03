from __future__ import annotations

import asyncio

from honeypot_orchestrator.event_logger import JSONLEventLogger
from honeypot_orchestrator.profiles import HoneypotProfile
from honeypot_orchestrator.services.base import BaseHoneypotService


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

    def set_profile(self, profile: HoneypotProfile) -> None:
        self.profile = profile

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            ssh_profile = self.profile.ssh
            await self.write(writer, ssh_profile.banner)
            
            username = ""
            authenticated = False
            
            for attempt in range(1, 4):
                if not username:
                    await self.write(writer, ssh_profile.login_prompt)
                    username = await self.read_line(reader)
                    if not username:
                        return
                
                await self.write(
                    writer,
                    ssh_profile.password_prompt_template.format(username=username or "unknown"),
                )
                password = await self.read_line(reader)
                
                # Log login attempt
                await self.log_event(
                    "login_attempt",
                    src_ip=src_ip,
                    src_port=src_port,
                    profile=self.profile.name,
                    username=username,
                    password=password,
                    summary=f"SSH Login attempted for username='{username}' password='{password}' (Access Denied)",
                )
                
                # İkinci denemede herhangi bir boş olmayan girişi kabul et
                if attempt >= 2 and len(username.strip()) > 0 and len(password.strip()) > 0:
                    authenticated = True
                    break
                else:
                    await self.write(writer, ssh_profile.denied_message)
                    # Reset username for next attempt to prompt again
                    username = ""
            
            if authenticated:
                await self.log_event(
                    "login_success",
                    src_ip=src_ip,
                    src_port=src_port,
                    profile=self.profile.name,
                    username=username,
                    summary=f"SSH Authentication succeeded for user '{username}'",
                )
                
                if "windows" in self.profile.name:
                    welcome = (
                        "\r\nMicrosoft Windows [Version 10.0.17763.379]\r\n"
                        "(c) 2018 Microsoft Corporation. Tüm hakları saklıdır.\r\n\r\n"
                    )
                    prompt_template = "C:\\Users\\{username}>"
                else:
                    welcome = (
                        f"\r\nWelcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-88-generic x86_64)\r\n\r\n"
                        f" * Documentation:  https://help.ubuntu.com\r\n"
                        f" * Management:     https://landscape.canonical.com\r\n"
                        f" * Support:        https://ubuntu.com/advantage\r\n\r\n"
                        f"Last login: Wed Jun  3 10:14:22 2026 from {src_ip}\r\n"
                    )
                    prompt_template = "{username}@ubuntu-srv:~# " if username == "root" else "{username}@ubuntu-srv:~$ "
                
                await self.write(writer, welcome)
                
                while True:
                    prompt = prompt_template.format(username=username)
                    await self.write(writer, prompt)
                    cmd_line = await self.read_line(reader, timeout=120.0)
                    
                    if not cmd_line:
                        if reader.at_eof():
                            break
                        continue
                    
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
                    
                    cmd_lower = cmd.lower()
                    if cmd_lower in {"exit", "quit"}:
                        await self.write(writer, "logout\r\n")
                        break
                    
                    response = ""
                    if "windows" in self.profile.name:
                        if cmd_lower == "whoami":
                            response = f"win-srv2019\\{username}\r\n"
                        elif cmd_lower in {"dir", "ls"}:
                            response = (
                                " Volume in drive C has no label.\r\n"
                                " Volume Serial Number is 4C28-9F0D\r\n\r\n"
                                f" Directory of C:\\Users\\{username}\r\n\r\n"
                                "2026-06-03  10:15    <DIR>          .\r\n"
                                "2026-06-03  10:15    <DIR>          ..\r\n"
                                "2026-06-03  10:15    <DIR>          Desktop\r\n"
                                "2026-06-03  10:15    <DIR>          Documents\r\n"
                                "2026-06-03  10:15    <DIR>          Downloads\r\n"
                                "2026-06-03  10:15               142 flag.txt\r\n"
                                "               1 File(s)            142 bytes\r\n"
                                "               5 Dir(s)  42,919,203,840 bytes free\r\n"
                            )
                        elif cmd_lower in {"cat flag.txt", "type flag.txt"}:
                            response = "CTF{w1nd0w5_55h_d3c0y_5ucc355}\r\n"
                        elif cmd_lower == "ipconfig":
                            response = (
                                "\r\nWindows IP Configuration\r\n\r\n"
                                "Ethernet adapter Ethernet0:\r\n\r\n"
                                "   Connection-specific DNS Suffix  . : corp.local\r\n"
                                "   IPv4 Address. . . . . . . . . . . : 192.168.1.240\r\n"
                                "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n"
                                "   Default Gateway . . . . . . . . . : 192.168.1.1\r\n"
                            )
                        elif cmd_lower == "systeminfo":
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
                        elif cmd_lower == "net user":
                            response = (
                                f"\r\nUser accounts for \\\\WIN-SRV2019\r\n\r\n"
                                "-------------------------------------------------------------------------------\r\n"
                                "Administrator            Guest                    DefaultAccount           \r\n"
                                f"WDAGUtilityAccount       {username}               \r\n"
                                "The command completed successfully.\r\n"
                            )
                        elif cmd_lower in {"netstat", "net stat"}:
                            response = (
                                "\r\nActive Connections\r\n\r\n"
                                "  Proto  Local Address          Foreign Address        State\r\n"
                                f"  TCP    192.168.1.240:22       {src_ip}:{src_port}     ESTABLISHED\r\n"
                                "  TCP    192.168.1.240:3389     0.0.0.0:0              LISTENING\r\n"
                                "  TCP    192.168.1.240:445      0.0.0.0:0              LISTENING\r\n"
                            )
                        elif cmd_lower == "help":
                            response = "Supported commands: whoami, dir, ls, type, cat, ipconfig, systeminfo, net user, netstat, help, exit\r\n"
                        else:
                            response = f"'{cmd}' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
                    else:
                        # Linux
                        if cmd_lower == "whoami":
                            response = f"{username}\r\n"
                        elif cmd_lower == "id":
                            response = "uid=0(root) gid=0(root) groups=0(root)\r\n" if username == "root" else f"uid=1000({username}) gid=1000({username}) groups=1000({username})\r\n"
                        elif cmd_lower == "pwd":
                            response = "/root\r\n" if username == "root" else f"/home/{username}\r\n"
                        elif cmd_lower in {"ls", "dir"}:
                            response = "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var  flag.txt\r\n"
                        elif cmd_lower == "cat flag.txt":
                            response = "CTF{l1nux_55h_d3c0y_5ucc355}\r\n"
                        elif cmd_lower == "cat /etc/passwd":
                            response = (
                                "root:x:0:0:root:/root:/bin/bash\r\n"
                                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
                                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
                                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n"
                            )
                        elif cmd_lower in {"ifconfig", "ip a", "ip addr"}:
                            response = (
                                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                                "        inet 192.168.1.240  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
                                "        ether 00:15:5d:00:1a:2b  txqueuelen 1000  (Ethernet)\r\n"
                            )
                        elif cmd_lower == "uname -a":
                            response = "Linux ubuntu-srv 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"
                        elif cmd_lower == "help":
                            response = "Supported commands: whoami, id, pwd, ls, cat, ifconfig, ip, uname, help, exit\r\n"
                        else:
                            response = f"bash: {cmd}: command not found\r\n"
                    
                    await self.write(writer, response)
        except (BrokenPipeError, ConnectionResetError):
            await self.log_event("client_disconnected", src_ip=src_ip, src_port=src_port)
        except Exception as exc:
            await self.log_event(
                "connection_error",
                src_ip=src_ip,
                src_port=src_port,
                error=type(exc).__name__,
            )
        finally:
            await self.close_writer(writer)
