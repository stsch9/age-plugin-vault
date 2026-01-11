package vaultclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadVaultTokenSuccess(t *testing.T) {
	tmp := t.TempDir()
	tokenPath := filepath.Join(tmp, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("mytoken\n"), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	oldHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tmp); err != nil {
		t.Fatalf("failed to set HOME: %v", err)
	}
	defer os.Setenv("HOME", oldHome)

	tok, err := loadVaultToken()
	if err != nil {
		t.Fatalf("loadVaultToken failed: %v", err)
	}
	if tok != "mytoken" {
		t.Fatalf("unexpected token value: want %q got %q", "mytoken", tok)
	}
}

func TestLoadVaultTokenMissingFile(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tmp); err != nil {
		t.Fatalf("failed to set HOME: %v", err)
	}
	defer os.Setenv("HOME", oldHome)

	if _, err := loadVaultToken(); err == nil {
		t.Fatalf("expected error when .vault-token is missing")
	} else if !strings.Contains(err.Error(), ".vault-token") {
		t.Fatalf("error message should reference .vault-token: %v", err)
	}
}

func TestVaultClientMissingToken(t *testing.T) {
	tmp := t.TempDir()
	oldHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tmp); err != nil {
		t.Fatalf("failed to set HOME: %v", err)
	}
	defer os.Setenv("HOME", oldHome)

	if _, err := VaultClient(); err == nil {
		t.Fatalf("expected VaultClient to error when token missing")
	} else if !(strings.Contains(err.Error(), "unable to load vault token") || strings.Contains(err.Error(), ".vault-token")) {
		t.Fatalf("unexpected error from VaultClient: %v", err)
	}
}
