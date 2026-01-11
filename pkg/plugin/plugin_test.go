package plugin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/stsch9/age-plugin-vault/internal/bech32"
)

func TestParseVaultIdentity_Success(t *testing.T) {
	data := []byte("my-identity-key")
	s, err := bech32.Encode(IDENTITY_HRP, data)
	if err != nil {
		t.Fatalf("bech32.Encode failed: %v", err)
	}

	id, err := ParseVaultIdentity(s)
	if err != nil {
		t.Fatalf("ParseVaultIdentity failed: %v", err)
	}
	if id.key != string(data) {
		t.Fatalf("unexpected identity key: want %q got %q", string(data), id.key)
	}
}

func TestParseVaultIdentity_WrongHRP(t *testing.T) {
	// Encode with a different HRP
	enc, err := bech32.Encode("age-plugin-other-", []byte("x"))
	if err != nil {
		t.Fatalf("bech32.Encode failed: %v", err)
	}
	if _, err := ParseVaultIdentity(enc); err == nil {
		t.Fatalf("expected error for wrong HRP")
	} else if !strings.Contains(err.Error(), "invalid type") {
		t.Fatalf("unexpected error for wrong HRP: %v", err)
	}
}

func TestWrapUnwrap_Success(t *testing.T) {
	key := "test-key"
	fileKey := []byte{1, 2, 3, 4, 5}

	// Create temp HOME and write a .vault-token for VaultClient to read
	tmp := t.TempDir()
	tokenPath := filepath.Join(tmp, ".vault-token")
	if err := os.WriteFile(tokenPath, []byte("token"), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	oldHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tmp); err != nil {
		t.Fatalf("failed to set HOME: %v", err)
	}
	defer os.Setenv("HOME", oldHome)

	// Start a test HTTP server to mock Vault API
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/transit/encrypt/" + key:
			var req map[string]string
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Ensure plaintext is present (base64 encoded by our Wrap)
			if _, ok := req["plaintext"]; !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			resp := map[string]map[string]string{"data": {"ciphertext": "mock-ciphertext"}}
			_ = json.NewEncoder(w).Encode(resp)
		case "/v1/transit/decrypt/" + key:
			var req map[string]string
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if _, ok := req["ciphertext"]; !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// Return the plaintext as base64 so Unwrap can decode it
			resp := map[string]map[string]string{"data": {"plaintext": base64.StdEncoding.EncodeToString(fileKey)}}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	oldVault := os.Getenv("VAULT_ADDR")
	if err := os.Setenv("VAULT_ADDR", srv.URL); err != nil {
		t.Fatalf("failed to set VAULT_ADDR: %v", err)
	}
	defer os.Setenv("VAULT_ADDR", oldVault)

	id := &Identity{key: key}

	stanzas, err := id.Wrap(fileKey)
	if err != nil {
		t.Fatalf("Wrap failed: %v", err)
	}
	if len(stanzas) != 1 {
		t.Fatalf("expected 1 stanza, got %d", len(stanzas))
	}
	st := stanzas[0]
	if st.Type != label {
		t.Fatalf("unexpected stanza type: want %q got %q", label, st.Type)
	}
	if len(st.Args) != 1 || st.Args[0] != "vault-recipient" {
		t.Fatalf("unexpected stanza args: %v", st.Args)
	}
	if !bytes.Equal(st.Body, []byte("mock-ciphertext")) {
		t.Fatalf("unexpected stanza body: %q", string(st.Body))
	}

	// Now test Unwrap using the stanza returned by Wrap
	out, err := id.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("Unwrap failed: %v", err)
	}
	if !bytes.Equal(out, fileKey) {
		t.Fatalf("unwrap result mismatch: want %v got %v", fileKey, out)
	}
}

func TestUnwrap_NoMatchingStanza(t *testing.T) {
	id := &Identity{key: "k"}
	_, err := id.Unwrap([]*age.Stanza{{Type: "other"}})
	if err != age.ErrIncorrectIdentity {
		t.Fatalf("expected ErrIncorrectIdentity, got: %v", err)
	}
}

func TestUnwrap_InvalidStanzaArgs(t *testing.T) {
	id := &Identity{key: "k"}
	_, err := id.Unwrap([]*age.Stanza{{Type: label, Args: []string{}}})
	if err == nil || !strings.Contains(err.Error(), "invalid stanza") {
		t.Fatalf("expected invalid stanza error, got: %v", err)
	}
}
