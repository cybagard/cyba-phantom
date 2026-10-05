package config

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

func checkAddr(raw string) (string, error) {
	_, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("invalid address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("port must be between 1 and 65535")
	}

	return raw, nil
}

func checkOpsAddr(raw string) (string, error) {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("invalid address: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("port must be between 1 and 65535")
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("ops.listen must be an IP literal")
	}

	if ip.IsUnspecified() {
		return "", fmt.Errorf("ops.listen cannot be unspecified address")
	}

	// RFC 1918, RFC 4193 or loopback
	if !ip.IsLoopback() && !isPrivateIP(ip) {
		return "", fmt.Errorf("ops.listen must be loopback or private IP")
	}

	return raw, nil
}

func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// RFC 1918
		if ip4[0] == 10 || (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || (ip4[0] == 192 && ip4[1] == 168) {
			return true
		}
	} else {
		// RFC 4193 (Unique Local Address)
		if len(ip) == 16 && ip[0] == 0xfd && (ip[1]&0xfe) == 0xfe {
			return true
		}
	}
	return false
}

func checkHtpasswd(raw string) (string, error) {
	if err := validatePath(raw, true); err != nil {
		return "", err
	}

	info, err := os.Stat(raw)
	if err != nil {
		return "", fmt.Errorf("htpasswd file error: %w", err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("htpasswd must be a regular file")
	}

	// M14: no other-read bit (0640 root:canary)
	if info.Mode()&0004 != 0 {
		return "", fmt.Errorf("htpasswd must not be world-readable")
	}

	return raw, nil
}

func checkEmail(raw string) (string, error) {
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return "", fmt.Errorf("invalid email: %w", err)
	}

	if addr.Address != raw {
		return "", fmt.Errorf("email must be exactly the parsed address")
	}

	if strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("email must not contain CR or LF")
	}

	return raw, nil
}

func checkCA(raw string) (string, error) {
	if raw == "letsencrypt" || raw == "letsencrypt-staging" {
		return raw, nil
	}

	if !isHTTPSURL(raw) {
		return "", fmt.Errorf("ca must be letsencrypt, letsencrypt-staging, or an https URL")
	}

	return raw, nil
}

func checkStateDir(raw string, root string) (string, error) {
	if err := validatePath(raw, false); err != nil {
		return "", err
	}

	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// M15: Resolve nearest existing parent and check if under root
	parent := filepath.Dir(abs)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("failed to resolve state root symlinks: %w", err)
	}

	if !strings.HasPrefix(resolvedParent, resolvedRoot) {
		return "", fmt.Errorf("path must be under state directory %s", resolvedRoot)
	}

	return abs, nil
}

func validatePath(p string, strictMode bool) error {
	if p == "" {
		return fmt.Errorf("path cannot be empty")
	}

	if !filepath.IsAbs(p) {
		return fmt.Errorf("path must be absolute")
	}

	if filepath.Clean(p) != p {
		return fmt.Errorf("path must be cleaned")
	}

	if strings.Contains(p, "\x00") {
		return fmt.Errorf("path must not contain NUL bytes")
	}

	// M14: file mode check (owner uid 0 or euid)
	info, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("path error: %w", err)
	}

	// If it's a directory, we don't check IsRegular.
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("path must be a regular file or directory")
	}

	// Mode: no group/other write bit (0640)
	if info.Mode()&0022 != 0 {
		return fmt.Errorf("path must not be group or world writable")
	}

	return nil
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}

	if u.Scheme != "https" && u.Scheme != "udp" && u.Scheme != "tcp" && u.Scheme != "tls" {
		return false
	}

	if u.Host == "" {
		return false
	}

	if u.User != nil {
		return false
	}

	if u.Fragment != "" {
		return false
	}

	if u.Opaque != "" {
		return false
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	ip := net.ParseIP(host)
	if ip != nil {
		// M19: not link-local, not unspecified
		if ip.IsLoopback() || ip.IsUnspecified() {
			return false
		}
		if len(ip) == 16 && (ip[0] == 0xfe && ip[1] == 0x80) {
			return false
		}
		if ip4 := ip.To4(); ip4 != nil {
			if ip4[0] == 169 && ip4[1] == 254 {
				return false
			}
		}
	}

	return true
}

func redact(raw string) string {
	if raw == "" {
		return ""
	}

	var b strings.Builder
	for _, r := range raw {
		if !unicode.IsPrint(r) {
			b.WriteRune(' ')
		} else {
			b.WriteRune(r)
		}
	}

	res := b.String()
	if len(res) > 64 {
		res = res[:64]
	}

	return res
}
