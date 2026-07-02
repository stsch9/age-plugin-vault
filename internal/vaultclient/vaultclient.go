package vaultclient

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/stsch9/age-plugin-vault/internal/keyring"

	vault "github.com/hashicorp/vault/api"
)

const keyringPrefix = "keyring:"

func loadVaultToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	tokenPath := home + "/.vault-token"
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("unable to read vault token from %s: %v", tokenPath, err)
	}

	if after, ok := strings.CutPrefix(string(token), keyringPrefix); ok {
		return readKeyFromKeyring(after)
	}

	return strings.TrimSpace(string(token)), nil
}

func VaultClient() (*vault.Client, error) {
	config := vault.DefaultConfig() // modify for more granular configuration

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, errors.New("unable to initialize Vault client: " + err.Error())
	}

	token, err := loadVaultToken()
	if err != nil {
		return nil, errors.New("unable to load vault token: " + err.Error())
	}
	client.SetToken(token)

	return client, nil
}

func readKeyFromKeyring(spec string) (string, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid keyring spec %q (expected: keyring:<scope>:<description>)", spec)
	}

	scope, description := parts[0], strings.TrimSpace(parts[1])

	value, err := keyring.ReadKeyringValue(scope, description)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(value), nil
}
