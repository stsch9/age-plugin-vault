//go:build !linux

package keyring

import (
	"fmt"
	"runtime"
)

// ReadKeyringValue is only available on Linux. On all other platforms
// (e.g., macOS during development), there is no kernel keyring,
// so this version returns a meaningful error.
func ReadKeyringValue(scope, description string) (string, error) {
	return "", fmt.Errorf("reading keys from the kernel keyring is only supported on Linux (current OS: %s)", runtime.GOOS)
}
