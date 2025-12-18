package vaultclient

import (
	"errors"
	"fmt"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

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
