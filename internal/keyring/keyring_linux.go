//go:build linux

package keyring

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// https://blog.cloudflare.com/de-de/the-linux-kernel-key-retention-service-and-why-you-should-use-it-in-your-next-application/

// keyringScopeID converts a human-readable scope name into the corresponding special keyring ID used by the kernel.
//
//	process -> KEY_SPEC_PROCESS_KEYRING (@p) - only for the current process (tree)
//	session -> KEY_SPEC_SESSION_KEYRING (@s) - only for the current Login-/Shell-Session
//	user    -> KEY_SPEC_USER_KEYRING    (@u) - across all Sessions of the User
func keyringScopeID(scope string) (int, error) {
	switch scope {
	case "process":
		return unix.KEY_SPEC_PROCESS_KEYRING, nil
	case "session":
		return unix.KEY_SPEC_SESSION_KEYRING, nil
	case "user":
		return unix.KEY_SPEC_USER_KEYRING, nil
	default:
		return 0, fmt.Errorf("unknown keyring scope %q (expected: process, session or user)", scope)
	}
}

// readKeyringValue searches for a "user" key based on its description in the
// specified keyring scope and returns its content as a string.
//
// The stored value is interpreted by the caller as a hex string
// (16 bytes -> 32 characters), so that the same format as the file variant
// can be used.
func ReadKeyringValue(scope, description string) (string, error) {
	keyringID, err := keyringScopeID(scope)
	if err != nil {
		return "", err
	}

	// Search for the key (type "user") based on its description in the keyring.
	keyID, err := unix.KeyctlSearch(keyringID, "user", description, 0)
	if err != nil {
		return "", fmt.Errorf("Cannot find key %q in %s keyring: %v", description, scope, err)
	}

	// Read the content of the key from the kernel memory.
	//
	// According to its documentation, KeyctlString is intended
	// for KEYCTL_DESCRIBE/KEYCTL_GET_SECURITY, whose return
	// values are NUL-terminated; it therefore always truncates
	// the last byte (buffer[:length-1]).
	// However, the KEYCTL_READ payload of a "user" key is
	// NOT NUL-terminated, which would otherwise cause the last
	// character to be lost (e.g., 32 → 31 hex characters, "odd-length hex string").
	//
	// First, we use a zero-filled buffer to determine the required length,
	// and then we read exactly that number of bytes.
	length, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, nil, 0)
	if err != nil {
		return "", fmt.Errorf("Cannot determine size of key %q in %s keyring: %v", description, scope, err)
	}

	buffer := make([]byte, length)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, keyID, buffer, 0)
	if err != nil {
		return "", fmt.Errorf("Cannot read key %q from %s keyring: %v", description, scope, err)
	}
	if n > len(buffer) {
		n = len(buffer)
	}

	return string(buffer[:n]), nil
}
