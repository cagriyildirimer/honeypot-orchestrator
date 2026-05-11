from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HTTPProfile:
    template_name: str
    server_header: str
    default_status: str
    title: str
    body_html: str


@dataclass(frozen=True)
class SSHProfile:
    template_name: str
    banner: str
    login_prompt: str
    password_prompt_template: str
    denied_message: str


@dataclass(frozen=True)
class FTPProfile:
    template_name: str
    banner: str
    user_prompt_response: str
    login_failed_response: str
    quit_response: str
    fallback_response: str


@dataclass(frozen=True)
class TelnetProfile:
    template_name: str
    banner: str
    password_prompt: str
    login_failed_response: str


@dataclass(frozen=True)
class HoneypotProfile:
    name: str
    display_name: str
    services: tuple[str, ...]
    http: HTTPProfile
    ssh: SSHProfile
    ftp: FTPProfile
    telnet: TelnetProfile


PROFILES: dict[str, HoneypotProfile] = {
    "empty": HoneypotProfile(
        name="empty",
        display_name="Empty Profile",
        services=(),
        http=HTTPProfile(
            template_name="http_empty",
            server_header="Honeypot-Orchestrator",
            default_status="200 OK",
            title="No Active Profile",
            body_html=(
                "<html><head><title>No Active Profile</title></head>"
                "<body>"
                "<h1>No Active Profile</h1>"
                "<p>Select and apply a host profile from the dashboard to start decoy services.</p>"
                "</body></html>\n"
            ),
        ),
        ssh=SSHProfile(
            template_name="ssh_empty",
            banner="",
            login_prompt="",
            password_prompt_template="{username}",
            denied_message="",
        ),
        ftp=FTPProfile(
            template_name="ftp_empty",
            banner="",
            user_prompt_response="",
            login_failed_response="",
            quit_response="",
            fallback_response="",
        ),
        telnet=TelnetProfile(
            template_name="telnet_empty",
            banner="",
            password_prompt="",
            login_failed_response="",
        ),
    ),
    "linux_server": HoneypotProfile(
        name="linux_server",
        display_name="Linux Server Profile",
        services=("http", "ssh", "ftp", "telnet"),
        http=HTTPProfile(
            template_name="http_linux",
            server_header="nginx/1.18.0",
            default_status="200 OK",
            title="Welcome to nginx!",
            body_html=(
                "<html><head><title>Welcome to nginx!</title></head>"
                "<body>"
                "<h1>Welcome to nginx!</h1>"
                "<p>If you see this page, the nginx web server is successfully installed "
                "and working.</p>"
                "<p>Further configuration is required.</p>"
                "</body></html>\n"
            ),
        ),
        ssh=SSHProfile(
            template_name="ssh_linux",
            banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
            login_prompt="login as: ",
            password_prompt_template="{username}@localhost's password: ",
            denied_message="Permission denied, please try again.\r\n",
        ),
        ftp=FTPProfile(
            template_name="ftp_linux",
            banner="220 ProFTPD Server (Ubuntu) [127.0.0.1]\r\n",
            user_prompt_response="331 Password required\r\n",
            login_failed_response="530 Login incorrect\r\n",
            quit_response="221 Goodbye\r\n",
            fallback_response="502 Command not implemented\r\n",
        ),
        telnet=TelnetProfile(
            template_name="telnet_linux",
            banner="Ubuntu 22.04 LTS localhost tty1\r\n\r\nlogin: ",
            password_prompt="Password: ",
            login_failed_response="\r\nLogin incorrect\r\n",
        ),
    ),
    "windows_server": HoneypotProfile(
        name="windows_server",
        display_name="Windows Server Profile",
        services=("http",),
        http=HTTPProfile(
            template_name="http_windows",
            server_header="Microsoft-IIS/10.0",
            default_status="200 OK",
            title="IIS Windows Server",
            body_html=(
                "<html><head><title>IIS Windows Server</title></head>"
                "<body>"
                "<h1>Internet Information Services</h1>"
                "<p>Windows Server role services are installed and ready to be configured.</p>"
                "<p>Review server bindings and application pools from Server Manager.</p>"
                "</body></html>\n"
            ),
        ),
        ssh=SSHProfile(
            template_name="ssh_windows",
            banner="SSH-2.0-OpenSSH_for_Windows_9.5\r\n",
            login_prompt="login as: ",
            password_prompt_template="{username}@WIN-SRV2019 password: ",
            denied_message="Permission denied, please try again.\r\n",
        ),
        ftp=FTPProfile(
            template_name="ftp_windows",
            banner="220 Microsoft FTP Service\r\n",
            user_prompt_response="331 Password required\r\n",
            login_failed_response="530 User cannot log in.\r\n",
            quit_response="221 Goodbye.\r\n",
            fallback_response="500 Syntax error, command unrecognized.\r\n",
        ),
        telnet=TelnetProfile(
            template_name="telnet_windows",
            banner="Microsoft Telnet Service\r\nlogin: ",
            password_prompt="Password: ",
            login_failed_response="\r\nLogon failure: unknown user name or bad password.\r\n",
        ),
    ),
}


def load_profile(name: str) -> HoneypotProfile:
    normalized = name.strip().lower().replace("-", "_")
    return PROFILES.get(normalized, PROFILES["empty"])


def get_profile(name: str) -> HoneypotProfile | None:
    normalized = name.strip().lower().replace("-", "_")
    return PROFILES.get(normalized)


def list_profiles() -> list[dict[str, object]]:
    return [
        {
            "name": profile.name,
            "display_name": profile.display_name,
            "services": list(profile.services),
        }
        for profile in PROFILES.values()
    ]
