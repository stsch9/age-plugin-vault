# age-plugin-vault 🔒

> [!WARNING]
> This is currently an experimental plugin.

**age-plugin-vault** is a plugin for the `age` encryption tool that uses HashiCorp Vault's Transit secrets engine to encrypt and decrypt file keys.

---

## 🔧 Prerequisites

- Go (1.20+ recommended)
- A running HashiCorp Vault server with the `transit` engine enabled
- A Vault token available in `~/.vault-token` or configured via standard Vault environment variables (e.g., `VAULT_ADDR`, `VAULT_TOKEN`)

> Note: The Vault client uses `vault.DefaultConfig()`. If Vault is not at `http://127.0.0.1:8200`, set `VAULT_ADDR` accordingly.

---

## 🚀 Quickstart — Build

From the project root:

```bash
# Build everything
go build ./...

# Or build only the plugin binary
go build -o age-plugin-vault ./cmd/age-plugin-vault
```

---

## 🧾 Generate an Identity / Recipient

Generate an identity string (key name) that can be used with `age` for encryption/decryption:

```bash
# Generates an identity string for 'my-keyname'
./age-plugin-vault -generate my-keyname
```

The output is an `age` identity (bech32-encoded) for this plugin, e.g. `age-plugin-vault-...`.

---

## 🔐 Configure Vault

1. Enable the Transit engine (if not already enabled):

```bash
vault secrets enable transit
```

2. Create a transit key:

```bash
vault write -f transit/keys/my-keyname
```

3. Ensure the Vault token you use has permissions to call `transit/encrypt/*` and `transit/decrypt/*`.

---

## ✉️ Encrypt & Decrypt with `age`

- Encrypt (use the `vault` recipient):

```bash
age -e -i identity-file-or-string> -o secret.txt.age secret.txt
```

- Decrypt (provide the identity string or file):

```bash
age -d -i <identity-file-or-string> -o secret.txt secret.txt.age
```

---

## 🧪 Tests

```bash
go test ./...
```

---

## Contributing 🤝

Contributions, issues and feature requests are welcome. Please open an issue or a pull request.

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

If you need help setting up Vault or integrating the plugin with `age`, please open an issue. 💬
