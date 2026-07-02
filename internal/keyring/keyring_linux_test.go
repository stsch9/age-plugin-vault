//go:build linux
// +build linux

package keyring

import (
    "fmt"
    "strings"
    "testing"
    "time"

    "golang.org/x/sys/unix"
)

func TestKeyringScopeID(t *testing.T) {
    tests := []struct {
        scope   string
        want    int
        wantErr bool
    }{
        {scope: "process", want: unix.KEY_SPEC_PROCESS_KEYRING},
        {scope: "session", want: unix.KEY_SPEC_SESSION_KEYRING},
        {scope: "user", want: unix.KEY_SPEC_USER_KEYRING},
        {scope: "invalid", wantErr: true},
    }

    for _, tt := range tests {
        got, err := keyringScopeID(tt.scope)
        if tt.wantErr {
            if err == nil {
                t.Fatalf("expected error for scope %q", tt.scope)
            }
            continue
        }
        if err != nil {
            t.Fatalf("keyringScopeID(%q) returned unexpected error: %v", tt.scope, err)
        }
        if got != tt.want {
            t.Fatalf("keyringScopeID(%q) = %d, want %d", tt.scope, got, tt.want)
        }
    }
}

func TestReadKeyringValue_ProcessScope(t *testing.T) {
    description := fmt.Sprintf("age-plugin-vault-test-%d", time.Now().UnixNano())
    payload := []byte("0123456789abcdef0123456789abcdef")

    keyID, err := unix.AddKey("user", description, payload, unix.KEY_SPEC_PROCESS_KEYRING)
    if err != nil {
        t.Fatalf("failed to add key to process keyring: %v", err)
    }
    defer func() {
        _, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, keyID, unix.KEY_SPEC_PROCESS_KEYRING, 0, 0)
    }()

    got, err := ReadKeyringValue("process", description)
    if err != nil {
        t.Fatalf("ReadKeyringValue failed: %v", err)
    }
    if got != string(payload) {
        t.Fatalf("unexpected key value: want %q got %q", string(payload), got)
    }
}

func TestReadKeyringValue_MissingKey(t *testing.T) {
    description := fmt.Sprintf("age-plugin-vault-missing-test-%d", time.Now().UnixNano())

    _, err := ReadKeyringValue("process", description)
    if err == nil {
        t.Fatalf("expected error when reading missing key")
    }
    if !strings.Contains(err.Error(), "Cannot find key") {
        t.Fatalf("unexpected error for missing key: %v", err)
    }
}
