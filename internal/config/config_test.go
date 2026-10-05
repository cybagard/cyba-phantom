package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
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

func TestTS10_AliasRejected(t *testing.T) {
	// T-S-10: reject aliases
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(path, []byte("anchors: &a 1\nref: *a\nacme:\n  email: a@b.com\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{}
	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for alias, got nil")
	}
}

func TestTS10_DuplicateKeyRejected(t *testing.T) {
	// T-S-10: reject duplicate keys
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(path, []byte("acme:\n  email: a@b.com\n  email: c@d.com\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{}
	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for duplicate key, got nil")
	}
}

func TestTS10_NestingLimit(t *testing.T) {
	// T-S-10: reject nesting > 8
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	content := "a: b\n"
	for i := 0; i < 10; i++ {
		content = fmt.Sprintf("l%d:\n  %s", i, content)
	}
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{}
	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for deep nesting, got nil")
	}
}

func TestTS10_BOMRejected(t *testing.T) {
	// T-S-10: reject BOM
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(path, append([]byte("\xef\xbb\xbf"), []byte("acme:\n  email: a@b.com\n")...), 0644)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{}
	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for BOM, got nil")
	}
}

func TestTS10_NulRejected(t *testing.T) {
	// T-S-10: reject NUL bytes
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(path, []byte("acme:\n  email: \x00a@b.com\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{}
	_, err = Load(path, opts)
	if err == nil {
		t.Error("expected error for NUL byte, got nil")
	}
}

func FuzzLoad(f *testing.F) {
	// Seed with known bad cases from T-S-10
	f.Add([]byte("anchors: &a 1\nref: *a\n"))
	f.Add([]byte("acme:\n  email: a@b.com\n  email: c@d.com\n"))
	f.Add([]byte("\xef\xbb\xbfacme:\n  email: a@b.com\n"))
	f.Add([]byte("acme:\n  email: \x00a@b.com\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "config.yaml")
		os.WriteFile(path, data, 0644)

		opts := Options{
			StateRoot: tmpDir,
		}
		_, _ = Load(path, opts)
	})
}
