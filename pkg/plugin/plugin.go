package plugin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/stsch9/age-plugin-vault/internal/bech32"
	"github.com/stsch9/age-plugin-vault/internal/vaultclient"

	"filippo.io/age"
)

const (
	PLUGIN_NAME   = "vault"
	RECIPIENT_HRP = "age1" + PLUGIN_NAME
	IDENTITY_HRP  = "age-plugin-" + PLUGIN_NAME + "-"
)

const label = "age-encryption.org/vault"

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

func (i *Identity) Unwrap(s []*age.Stanza) ([]byte, error) {
	for _, stanza := range s {
		if stanza.Type != label {
			continue
		}
		if len(stanza.Args) != 1 {
			return nil, errors.New("vault: invalid stanza: expected 1 argument")
		}

		client, err := vaultclient.VaultClient()
		if err != nil {
			return nil, errors.New("unable to initialize Vault client: " + err.Error())
		}

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

	client, err := vaultclient.VaultClient()
	if err != nil {
		return nil, errors.New("unable to initialize Vault client: " + err.Error())
	}

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
