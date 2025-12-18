package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/stsch9/age-plugin-vault/pkg/plugin"

	"filippo.io/age"
	page "filippo.io/age/plugin"
)

func main() {
	// root token in identity

	p, err := page.New("vault")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	generate := flag.String("generate", "", "Generate a new credential for the given Keyname.")

	p.RegisterFlags(nil)
	flag.Parse()

	if *generate != "" {
		fmt.Println(page.EncodeIdentity("vault", []byte(*generate)))
		return
	}

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		i, err := plugin.ParseVaultIdentity(page.EncodeIdentity("vault", data))
		if err != nil {
			return nil, err
		}

		return i, nil
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		i, err := plugin.ParseVaultIdentity(page.EncodeIdentity("vault", data))
		if err != nil {
			return nil, err
		}

		return i, nil
	})
	os.Exit(p.Main())
}
