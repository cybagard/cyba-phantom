package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestLoad_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	// Create dummy state root and files/dirs
	stateRoot := filepath.Join(tmpDir, "state")
	os.MkdirAll(stateRoot, 0755)
	htpasswd := filepath.Join(stateRoot, "htpasswd")
	os.WriteFile(htpasswd, []byte("user:hash"), 0640)
	cacheDir := filepath.Join(stateRoot, "certs")
	os.MkdirAll(cacheDir, 0755)

	content := fmt.Sprintf("acme:\n  email: admin@example.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	os.WriteFile(path, []byte(content), 0644)

	opts := Options{
		StateRoot: stateRoot,
		Env:       func() []string { return nil },
	}

	_, err := Load(path, opts)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestLoad_InvalidKey(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	stateRoot := filepath.Join(tmpDir, "state")
	os.MkdirAll(stateRoot, 0755)
	htpasswd := filepath.Join(stateRoot, "htpasswd")
	os.WriteFile(htpasswd, []byte("user:hash"), 0640)
	cacheDir := filepath.Join(stateRoot, "certs")
	os.MkdirAll(cacheDir, 0755)

	content := fmt.Sprintf("acme:\n  email: admin@example.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n  unknown: value\n", htpasswd, cacheDir)
	os.WriteFile(path, []byte(content), 0644)

	opts := Options{
		StateRoot: stateRoot,
	}

	_, err := Load(path, opts)
	if err == nil {
		t.Error("expected error for unknown key, got nil")
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	stateRoot := filepath.Join(tmpDir, "state")
	os.MkdirAll(stateRoot, 0755)
	htpasswd := filepath.Join(stateRoot, "htpasswd")
	os.WriteFile(htpasswd, []byte("user:hash"), 0640)
	cacheDir := filepath.Join(stateRoot, "certs")
	os.MkdirAll(cacheDir, 0755)

	content := fmt.Sprintf("listen:\n  http: :80\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	os.WriteFile(path, []byte(content), 0644)

	opts := Options{
		StateRoot: stateRoot,
	}

	_, err := Load(path, opts)
	if err == nil {
		t.Error("expected error for missing acme.email, got nil")
	}
}

func TestTU10_EnvOverridePrecedence(t *testing.T) {
	// T-U-10: precedence default < file < env
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	stateRoot := filepath.Join(tmpDir, "state")
	os.MkdirAll(stateRoot, 0755)
	htpasswd := filepath.Join(stateRoot, "htpasswd")
	os.WriteFile(htpasswd, []byte("user:hash"), 0640)
	cacheDir := filepath.Join(stateRoot, "certs")
	os.MkdirAll(cacheDir, 0755)

	content := fmt.Sprintf("listen:\n  http: :8080\nacme:\n  email: a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Env value: :9090
	env := []string{"CANARY_LISTEN_HTTP=:9090", "CANARY_ACME_EMAIL=env@example.com"}
	opts := Options{
		StateRoot: stateRoot,
		Env:       func() []string { return env },
	}

	cfg, err := Load(path, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen.HTTP != ":9090" {
		t.Errorf("expected :9090, got %s", cfg.Listen.HTTP)
	}
}

func setupEnv(t *testing.T) (string, string, string, Options) {
	t.Helper()
	tmpDir := t.TempDir()
	stateRoot := filepath.Join(tmpDir, "state")
	os.MkdirAll(stateRoot, 0755)
	htpasswd := filepath.Join(stateRoot, "htpasswd")
	os.WriteFile(htpasswd, []byte("user:hash"), 0640)
	cacheDir := filepath.Join(stateRoot, "certs")
	os.MkdirAll(cacheDir, 0755)

	return tmpDir, htpasswd, cacheDir, Options{
		StateRoot: stateRoot,
		Env:       func() []string { return nil },
	}
}

func TestTS10_AliasRejected(t *testing.T) {
	// T-S-10: reject aliases
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("anchors: &a 1\nref: *a\nacme:\n  email: a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for alias, got nil")
	} else if !strings.Contains(err.Error(), "contains an alias") && !strings.Contains(err.Error(), "contains an anchor") {
		t.Errorf("expected error to mention 'contains an alias' or 'contains an anchor', got %v", err)
	}
}

func TestTS10_DuplicateKeyRejected(t *testing.T) {
	// T-S-10: reject duplicate keys
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: a@b.com\n  email: c@d.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for duplicate key, got nil")
	} else if !strings.Contains(err.Error(), "contains duplicate key") {
		t.Errorf("expected error to mention 'contains duplicate key', got %v", err)
	}
}

func TestTS10_NestingLimit(t *testing.T) {
	// T-S-10: reject nesting > 8
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := "a: b"
	for i := 0; i < 10; i++ {
		var indented strings.Builder
		for _, line := range strings.Split(content, "\n") {
			indented.WriteString("  " + line + "\n")
		}
		content = fmt.Sprintf("l%d:\n%s", i, indented.String())
	}
	content = fmt.Sprintf("acme:\n  email: a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n%s", htpasswd, cacheDir, content)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for deep nesting, got nil")
	} else if !strings.Contains(err.Error(), "nesting exceeds limit of 8") {
		t.Errorf("expected error to mention 'nesting exceeds limit of 8', got %v", err)
	}
}

func TestTS10_BOMRejected(t *testing.T) {
	// T-S-10: reject BOM
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	err := os.WriteFile(path, append([]byte("\xef\xbb\xbf"), []byte(content)...), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for BOM, got nil")
	} else if !strings.Contains(err.Error(), "must not contain a BOM") {
		t.Errorf("expected error to mention 'must not contain a BOM', got %v", err)
	}
}

func TestTS10_NulRejected(t *testing.T) {
	// T-S-10: reject NUL bytes
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: \x00a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for NUL byte, got nil")
	} else if !strings.Contains(err.Error(), "must not contain NUL bytes") {
		t.Errorf("expected error to mention 'must not contain NUL bytes', got %v", err)
	}
}

func TestTS10_FileTooLargeRejected(t *testing.T) {
	// T-S-10: reject files > 64 KiB
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	padding := strings.Repeat("a", 64*1024+1)
	content += "padding: " + padding + "\n"
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for file too large, got nil")
	} else if !strings.Contains(err.Error(), "exceeds 64 KiB limit") {
		t.Logf("File size: %d", len(content))
		t.Errorf("expected error to mention 'exceeds 64 KiB limit', got %v", err)
	}
}

func TestTS10_MultiDocRejected(t *testing.T) {
	// T-S-10: reject multi-document YAML
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n---\nacme:\n  email: b@c.com\n", htpasswd, cacheDir)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for multi-document YAML, got nil")
	} else if !strings.Contains(err.Error(), "must contain only one document") {
		t.Errorf("expected error to mention 'must contain only one document', got %v", err)
	}
}

func TestTS10_CustomTagRejected(t *testing.T) {
	// T-S-10: reject custom tags
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: !!python/object a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for custom tag, got nil")
	} else if !strings.Contains(err.Error(), "contains custom tag") {
		t.Errorf("expected error to mention 'contains custom tag', got %v", err)
	}
}

func TestTS10_MergeKeyRejected(t *testing.T) {
	// T-S-10: reject merge keys (<<)
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  <<: 123\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for merge key, got nil")
	} else if !strings.Contains(err.Error(), "contains merge key") {
		t.Errorf("expected error to mention 'contains merge key', got %v", err)
	}
}

func TestTS10_BoolShorthandRejected(t *testing.T) {
	// T-S-10: reject YAML 1.1 bool shorthands (on, yes)
	k := key{path: "test", kind: kindBool}
	if err := checkScalar(k, "yes", leaf{}); err == nil {
		t.Error("expected error for 'yes' as bool, got nil")
	}
	if err := checkScalar(k, "on", leaf{}); err == nil {
		t.Error("expected error for 'on' as bool, got nil")
	}
}

func TestTS10_OctalIntRejected(t *testing.T) {
	// T-S-10: reject octal integers (leading zero)
	k := key{path: "test", kind: kindInt}
	if err := checkScalar(k, "0755", leaf{}); err == nil {
		t.Error("expected error for octal integer, got nil")
	} else if !strings.Contains(err.Error(), "leading zeros not allowed") {
		t.Errorf("expected error to mention 'leading zeros not allowed', got %v", err)
	}
}

func TestTS10_QuotedIntRejected(t *testing.T) {
	// T-S-10: reject quoted numbers on int check
	k := key{path: "test", kind: kindInt}
	l := leaf{value: "123", style: yaml.SingleQuotedStyle}
	if err := checkScalar(k, l.value, l); err == nil {
		t.Error("expected error for quoted integer, got nil")
	} else if !strings.Contains(err.Error(), "quoted numbers not allowed") {
		t.Errorf("expected error to mention 'quoted numbers not allowed', got %v", err)
	}
}

func TestTS10_LiteralExpansionRejected(t *testing.T) {
	// T-S-10: ${HOME} stays literal (no expansion)
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: ${HOME}@example.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Acme.Email != "${HOME}@example.com" {
		t.Errorf("expected literal ${HOME}@example.com, got %s", cfg.Acme.Email)
	}
}

func TestTS10_SecretNotLeaked(t *testing.T) {
	// T-S-10: secret values not leaked in errors
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	// Create a config that will fail validation on a secret key
	content := "acme:\n  email: invalid-email\n" // email is not secret, let's make it secret for this test
	os.WriteFile(path, []byte(content), 0644)

	// Manually mark acme.email as secret
	secretByPath["acme.email"] = true
	defer delete(secretByPath, "acme.email")

	opts := Options{}
	_, err := Load(path, opts)
	if err == nil {
		t.Error("expected error for invalid email, got nil")
	} else if strings.Contains(err.Error(), "invalid-email") {
		t.Errorf("secret value leaked in error: %v", err)
	}
}

func TestTS10_NoDialChecked(t *testing.T) {
	// T-S-10: no network calls during --check
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	os.WriteFile(path, []byte(content), 0644)

	// Inject dialer/resolver that fail on use
	opts.Check = true
	opts.Dialer = &failDialer{}
	opts.Resolver = &failResolver{}

	_, err := Load(path, opts)
	if err != nil {
		t.Errorf("unexpected error during no-dial check: %v", err)
	}
}

type failDialer struct{}

func (d *failDialer) Dial(network, address string) (net.Conn, error) {
	panic("dialer used")
}

type failResolver struct{}

func (r *failResolver) LookupHost(host string) ([]string, error) {
	panic("resolver used")
}

func TestTS10_ConfigPermsRejected(t *testing.T) {
	// T-S-10 (M14): reject world-writable config files
	tmpDir, htpasswd, cacheDir, opts := setupEnv(t)
	path := filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf("acme:\n  email: a@b.com\nops:\n  basic_auth_htpasswd: %s\nacme.cache_dir: %s\n", htpasswd, cacheDir)
	os.WriteFile(path, []byte(content), 0666)
	os.Chmod(path, 0666)

	_, err := Load(path, opts)
	if err == nil {
		t.Error("expected error for world-writable config, got nil")
	} else if !strings.Contains(err.Error(), "must not be group or world writable") {
		t.Errorf("expected error to mention 'must not be group or world writable', got %v", err)
	}
}

func FuzzLoad(f *testing.F) {
	// Seed with known bad cases from T-S-10
	f.Add([]byte("anchors: &a 1\nref: *a\n"))
	f.Add([]byte("acme:\n  email: a@b.com\n  email: c@d.com\n"))
	f.Add([]byte("\xef\xbb\xbfacme:\n  email: a@b.com\n"))
	f.Add([]byte("acme:\n  email: \x00a@b.com\n"))
	f.Add([]byte("acme:\n  email: a@b.com\n---\nacme:\n  email: b@c.com\n"))
	f.Add([]byte("acme:\n  email: !!python/object a@b.com\n"))
	f.Add([]byte("defaults: &d\n  email: a@b.com\nacme:\n  <<: *d\n"))
	f.Add([]byte("acme:\n  email: a@b.com\n" + strings.Repeat("a", 64*1024+1)))

	f.Fuzz(func(t *testing.T, b []byte) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "fuzz.yaml")
		os.WriteFile(path, b, 0644)

		Load(path, Options{})
	})
}
