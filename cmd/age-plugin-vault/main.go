package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"example/age-plugin-vault/internal/bech32"

	"filippo.io/age"
	"filippo.io/age/plugin"
	vault "github.com/hashicorp/vault/api"
)

const (
	PLUGIN_NAME   = "vault"
	RECIPIENT_HRP = "age1" + PLUGIN_NAME
	IDENTITY_HRP  = "age-plugin-" + PLUGIN_NAME + "-"
)

const label = "age-encryption.org/vault"

func main() {
	// root token in identity
	//fmt.Println(plugin.EncodeIdentity("vault", []byte("key1")))

	p, err := plugin.New("vault")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	generate := flag.String("generate", "", "Generate a new credential for the given Keyname.")

	p.RegisterFlags(nil)
	flag.Parse()

	if *generate != "" {
		fmt.Println(plugin.EncodeIdentity("vault", []byte(*generate)))
		return
	}

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		i, err := ParseVaultIdentity(plugin.EncodeIdentity("vault", data))
		if err != nil {
			return nil, err
		}

		return i, nil
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		i, err := ParseVaultIdentity(plugin.EncodeIdentity("vault", data))
		if err != nil {
			return nil, err
		}

		return i, nil
	})
	os.Exit(p.Main())
}

type Identity struct {
	key string
}

func ParseVaultIdentity(identity string) (*Identity, error) {
	hrp, data, err := bech32.Decode(strings.ToLower(identity))
	if err != nil {
		return nil, err
	}

	if hrp != IDENTITY_HRP {
		return nil, fmt.Errorf("malformed identity %s: invalid type %s", identity, hrp)
	}

	return &Identity{string(data)}, nil
}

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

func (i *Identity) Unwrap(s []*age.Stanza) ([]byte, error) {
	for _, stanza := range s {
		if stanza.Type != label {
			continue
		}
		if len(stanza.Args) != 1 {
			return nil, errors.New("vault: invalid stanza: expected 1 argument")
		}

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

		dataKeyResponse, err := client.Logical().Write("transit/decrypt/"+i.key, map[string]any{"ciphertext": string(stanza.Body)})
		if err != nil {
			return nil, errors.New("unable to generate data key: " + err.Error())
		}

		// Extract the plaintext data key from the response
		plaintextKey, ok := dataKeyResponse.Data["plaintext"].(string)

		if !ok {
			return nil, errors.New("plaintext key type assertion failed")
		}

		fileKey, err := base64.StdEncoding.DecodeString(plaintextKey)
		if err != nil {
			return nil, errors.New("failed to decode base64 plaintext key: " + err.Error())
		}

		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func (i *Identity) Wrap(fileKey []byte) ([]*age.Stanza, error) {

	plaintextKey := base64.StdEncoding.EncodeToString(fileKey)

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

	dataKeyResponse, err := client.Logical().Write("transit/encrypt/"+i.key, map[string]any{"plaintext": plaintextKey})
	if err != nil {
		return nil, errors.New("unable to generate data key: " + err.Error())
	}

	ciphertext, ok := dataKeyResponse.Data["ciphertext"].(string)
	if !ok {
		return nil, errors.New("plaintext key type assertion failed.")
	}

	return []*age.Stanza{{
		Type: label,
		Args: []string{"vault-recipient"},
		Body: []byte(ciphertext),
	}}, nil
}
