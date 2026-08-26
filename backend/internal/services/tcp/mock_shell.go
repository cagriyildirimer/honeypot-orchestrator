package tcp

import (
	"strings"
)

func ResolveWindowsPath(current, target string) string {
	target = strings.ReplaceAll(target, "/", "\\")
	var parts []string
	if strings.HasPrefix(strings.ToLower(target), "c:\\") {
		parts = strings.Split(target, "\\")
	} else if strings.HasPrefix(target, "\\") {
		parts = append([]string{"C:"}, strings.Split(strings.TrimPrefix(target, "\\"), "\\")...)
	} else {
		parts = append(strings.Split(current, "\\"), strings.Split(target, "\\")...)
	}

	var resolved []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "." || p == "" {
			continue
		}
		if p == ".." {
			if len(resolved) > 1 {
				resolved = resolved[:len(resolved)-1]
			}
		} else {
			resolved = append(resolved, p)
		}
	}

	if len(resolved) > 0 && !strings.HasSuffix(resolved[0], ":") {
		resolved[0] = resolved[0] + ":"
	}
	return strings.Join(resolved, "\\")
}

func ResolveLinuxPath(current, target string) string {
	var parts []string
	if strings.HasPrefix(target, "/") {
		parts = strings.Split(target, "/")
	} else {
		parts = append(strings.Split(current, "/"), strings.Split(target, "/")...)
	}

	var resolved []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "." || p == "" {
			continue
		}
		if p == ".." {
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
		} else {
			resolved = append(resolved, p)
		}
	}
	return "/" + strings.Join(resolved, "/")
}

func GetMockFileContent(path string) string {
	pathLower := strings.ToLower(path)
	if strings.HasSuffix(pathLower, "notes.txt") {
		return "Tüm servis entegrasyonlarını tamamlayıp güvenlik duvarı kurallarını gözden geçirin.\r\n"
	}
	if strings.HasSuffix(pathLower, "todo.txt") {
		return "1. Web paneli şifrelerini değiştir\r\n2. SQL Server yedeklerini al\r\n3. Gereksiz portları kapat\r\n"
	}
	if strings.HasSuffix(pathLower, "install_log.txt") {
		return "2026-06-01 10:11:05 [INFO] Installer started.\r\n2026-06-01 10:12:10 [INFO] Files copied successfully.\r\n2026-06-01 10:12:15 [INFO] Installation completed.\r\n"
	}
	if strings.HasSuffix(pathLower, "passwd") {
		return "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\r\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\r\n"
	}
	if strings.HasSuffix(pathLower, "hosts") {
		return "127.0.0.1 localhost\r\n192.168.1.240 ubuntu-srv\r\n"
	}
	if strings.HasSuffix(pathLower, "resolv.conf") {
		return "nameserver 1.1.1.1\r\nnameserver 8.8.8.8\r\n"
	}
	return "Erişim reddedildi veya dosya okunamıyor.\r\n"
}
