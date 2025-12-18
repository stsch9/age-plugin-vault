# age-plugin-vault 🔒

> [!WARNING]
> This is currently an experimental plugin.

**age-plugin-vault** is a plugin for the [age](https://github.com/FiloSottile/age) encryption tool that uses HashiCorp Vault's Transit secrets engine to encrypt and decrypt the age [file key](https://github.com/C2SP/C2SP/blob/main/age.md#file-key).

---

## 🔧 Prerequisites

- Go (1.20+ recommended)
- A running HashiCorp Vault server with the `transit` engine enabled
- A Vault token available in `~/.vault-token`

> Note: The Vault client uses `vault.DefaultConfig()`. If Vault is not at `http://127.0.0.1:8200`, set Vault environment variable `VAULT_ADDR` accordingly.

---

## 🚀 Quickstart — Build

From the project root:

```bash
# Clone repo
git clone git@github.com:stsch9/age-plugin-vault.git
cd age-plugin-vault

# Build the plugin binary
go build -o age-plugin-vault ./cmd/age-plugin-vault/main.go
```

Ensure that `age-plugin-vault` is stored in a directory that is included in the PATH variable.

---

## 🔐 Configure Vault

1. Enable the Transit engine (if not already enabled):

```bash
vault secrets enable transit
```

2. Create a transit key:

```bash
vault write -f transit/keys/my-keyname type=<KEY_TYP>
```
Only use key types that support encryption.


3. Ensure the Vault token you use has permissions to call `transit/encrypt/my-keyname` and `transit/decrypt/my-keyname`.

---

## 🔐 Generate an Identity / Recipient
The name of the vault key is used as the age identity.
Generate an identity string (key name) that can be used with `age` for encryption/decryption:

```bash
# Generates an identity string for 'my-keyname'
./age-plugin-vault -generate my-keyname
```

The output is an `age` identity (bech32-encoded) for this plugin, e.g. `age-plugin-vault-...`.

---


## ✉️ Encrypt & Decrypt with `age`

- Encrypt (use the identity):

```bash
age -e -i <identity-file-or-string> -o secret.txt.age secret.txt
```

- Decrypt (provide the identity string or file):

```bash
age -d -i <identity-file-or-string> -o secret.txt secret.txt.age
```

---

## 🧪 Tests

Tbd

```bash
go test ./...
```

---

## Questions
The vault key name is used as the identity, and the recipient stanza always contains 
```bash
-> age-encryption.org/vault vault-recipient
```
Would it make more sense to use the vault key name in the recipient stanza?

---

## Contributing 🤝

Contributions, issues and feature requests are welcome. Please open an issue or a pull request.

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

If you need help setting up Vault or integrating the plugin with `age`, please open an issue. 💬
