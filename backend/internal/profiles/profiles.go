package profiles

type TelnetProfile struct {
	TemplateName        string
	Banner              string
	PasswordPrompt      string
	LoginFailedResponse string
}

type HTTPProfile struct {
	TemplateName  string
	ServerHeader  string
	DefaultStatus string
	Title         string
	BodyHTML      string
}

type FTPProfile struct {
	TemplateName        string
	Banner              string
	UserPromptResponse  string
	LoginFailedResponse string
	QuitResponse        string
	FallbackResponse    string
}

type SSHProfile struct {
	TemplateName           string
	Banner                 string
	LoginPrompt            string
	PasswordPromptTemplate string
	DeniedMessage          string
}

type SMBProfile struct {
	TemplateName  string
	Hostname      string
	Domain        string
	DNSDomain     string
	NativeOS      string
	NativeLanman  string
	ServerGUID    string
	SigningPolicy int
	NtlmChallenge string
}

type HoneypotProfile struct {
	Name        string
	DisplayName string
	Services    []string
	Telnet      TelnetProfile
	HTTP        HTTPProfile
	FTP         FTPProfile
	SSH         SSHProfile
	SMB         SMBProfile
}

var Profiles = map[string]*HoneypotProfile{
	"empty": {
		Name:        "empty",
		DisplayName: "Empty Profile",
		Services:    []string{},
		Telnet: TelnetProfile{
			TemplateName:        "telnet_empty",
			Banner:              "",
			PasswordPrompt:      "",
			LoginFailedResponse: "",
		},
		HTTP: HTTPProfile{
			TemplateName:  "http_empty",
			ServerHeader:  "Honeypot-Orchestrator",
			DefaultStatus: "200 OK",
			Title:         "No Active Profile",
			BodyHTML:      "<html><head><title>No Active Profile</title></head><body><h1>No Active Profile</h1></body></html>\n",
		},
		FTP: FTPProfile{
			TemplateName:        "ftp_empty",
			Banner:              "",
			UserPromptResponse:  "",
			LoginFailedResponse: "",
			QuitResponse:        "",
			FallbackResponse:    "",
		},
		SSH: SSHProfile{
			TemplateName:           "ssh_empty",
			Banner:                 "",
			LoginPrompt:            "",
			PasswordPromptTemplate: "{username}",
			DeniedMessage:          "",
		},
		SMB: SMBProfile{
			TemplateName:  "smb_empty",
			Hostname:      "WORKGROUP",
			Domain:        "WORKGROUP",
			DNSDomain:     "localdomain",
			NativeOS:      "Windows 10 Pro 19042",
			NativeLanman:  "Windows 10 6.3",
			ServerGUID:    "00000000000000000000000000000000",
			SigningPolicy: 0,
			NtlmChallenge: "0000000000000000",
		},
	},
	"linux_server": {
		Name:        "linux_server",
		DisplayName: "Linux Server Profile",
		Services:    []string{"http_linux", "ssh_linux", "ftp_linux", "telnet_linux"},
		Telnet: TelnetProfile{
			TemplateName:        "telnet_linux",
			Banner:              "Ubuntu 22.04 LTS localhost tty1\r\n\r\nlogin: ",
			PasswordPrompt:      "Password: ",
			LoginFailedResponse: "\r\nLogin incorrect\r\n",
		},
		HTTP: HTTPProfile{
			TemplateName:  "http_linux",
			ServerHeader:  "nginx/1.18.0",
			DefaultStatus: "200 OK",
			Title:         "Welcome to nginx!",
			BodyHTML:      "<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working.</p></body></html>\n",
		},
		FTP: FTPProfile{
			TemplateName:        "ftp_linux",
			Banner:              "220 ProFTPD Server (Ubuntu) [127.0.0.1]\r\n",
			UserPromptResponse:  "331 Password required\r\n",
			LoginFailedResponse: "530 Login incorrect\r\n",
			QuitResponse:        "221 Goodbye\r\n",
			FallbackResponse:    "502 Command not implemented\r\n",
		},
		SSH: SSHProfile{
			TemplateName:           "ssh_linux",
			Banner:                 "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n",
			LoginPrompt:            "login as: ",
			PasswordPromptTemplate: "{username}@localhost's password: ",
			DeniedMessage:          "Permission denied, please try again.\r\n",
		},
		SMB: SMBProfile{
			TemplateName:  "smb_linux",
			Hostname:      "ubuntu-srv",
			Domain:        "WORKGROUP",
			DNSDomain:     "localdomain",
			NativeOS:      "Samba 4.15.13-Ubuntu",
			NativeLanman:  "Samba 4.15.13-Ubuntu",
			ServerGUID:    "11223344556677889900aabbccddeeff",
			SigningPolicy: 1,
			NtlmChallenge: "1122334455667788",
		},
	},
	"windows_server": {
		Name:        "windows_server",
		DisplayName: "Windows Server Profile",
		Services:    []string{"http_windows", "dns_windows", "netbios_windows", "ldap_windows", "ldaps_windows", "mssql_windows", "rdp_windows", "smb_windows", "llmnr_windows", "nbtnns_windows", "ssh_windows", "rpc_windows"},
		Telnet: TelnetProfile{
			TemplateName:        "telnet_windows",
			Banner:              "Microsoft Telnet Service\r\nlogin: ",
			PasswordPrompt:      "Password: ",
			LoginFailedResponse: "\r\nLogon failure: unknown user name or bad password.\r\n",
		},
		HTTP: HTTPProfile{
			TemplateName:  "http_windows",
			ServerHeader:  "Microsoft-IIS/10.0",
			DefaultStatus: "200 OK",
			Title:         "IIS Windows Server",
			BodyHTML:      "<html><head><title>IIS Windows Server</title></head><body><h1>Internet Information Services</h1><p>Windows Server role services are installed and ready to be configured.</p></body></html>\n",
		},
		FTP: FTPProfile{
			TemplateName:        "ftp_windows",
			Banner:              "220 Microsoft FTP Service\r\n",
			UserPromptResponse:  "331 Password required\r\n",
			LoginFailedResponse: "530 User cannot log in.\r\n",
			QuitResponse:        "221 Goodbye.\r\n",
			FallbackResponse:    "500 Syntax error, command unrecognized.\r\n",
		},
		SSH: SSHProfile{
			TemplateName:           "ssh_windows",
			Banner:                 "SSH-2.0-OpenSSH_for_Windows_9.5\r\n",
			LoginPrompt:            "login as: ",
			PasswordPromptTemplate: "{username}@WIN-SRV2019 password: ",
			DeniedMessage:          "Permission denied, please try again.\r\n",
		},
		SMB: SMBProfile{
			TemplateName:  "smb_windows",
			Hostname:      "WIN-SRV2019",
			Domain:        "CORP",
			DNSDomain:     "corp.local",
			NativeOS:      "Windows Server 2019 Standard 17763",
			NativeLanman:  "Windows Server 2019 6.3",
			ServerGUID:    "7da29f0dd5324af6a9b7227bb3140f9c",
			SigningPolicy: 1,
			NtlmChallenge: "0123456789abcdef",
		},
	},
}

func GetProfile(name string) *HoneypotProfile {
	p, ok := Profiles[name]
	if !ok {
		return Profiles["empty"]
	}
	return p
}
