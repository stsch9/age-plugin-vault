#!/usr/bin/env bash

# Secure Vault AppRole authentication using Kernel Keyring
# 
# This script:
# 1. Unwraps a Vault wrapping token to retrieve a secret ID
# 2. Stores the secret ID in the Linux kernel keyring
# 3. Authenticates to Vault using AppRole (role_id + secret_id)
# 4. Stores the Vault authentication token in the kernel keyring
#
# Prerequisites: vault, jq, keyctl installed

set -euo pipefail

# Usage:
#   ./machine_encryption.sh <role-id> <wrapping-token>
#
# Example:
#   ./machine_encryption.sh 2aa0d2bf-196c-f03f-9d8b-e42d448762a4 s.1234567890abcdef

# AppRole role ID - identifies the application role in Vault
# Passed as the first positional parameter
ROLE_ID="${1:-}"

# Wrapping token passed as the second positional parameter - contains the secret ID
# This is a single-use token that unwraps to the secret ID
WRAP_TOKEN="${2:-}"

# Validate that both required parameters were provided
if [[ -z "${ROLE_ID}" || -z "${WRAP_TOKEN}" ]]; then
  echo "Usage: $0 <role-id> <wrapping-token>"
  echo ""
  echo "The wrapping-token is a single-use Vault token that contains the secret ID."
  echo "Obtain it from your Vault administrator."
  exit 1
fi

# Ensure Vault address is configured
if [[ -z "${VAULT_ADDR:-}" ]]; then
  echo "VAULT_ADDR is not set. Please export VAULT_ADDR before running this script."
  exit 1
fi

# Step 1: Unwrap the Vault response to extract the secret ID
# - vault unwrap: decrypts the wrapping token to get the original secret data
# - jq: parses JSON output and extracts the 'secret_id' field
# - tr: removes newline characters
# - keyctl padd: stores the secret ID in the Linux kernel keyring under the 'user' namespace
KEY_ID=$(vault unwrap -format=json "$WRAP_TOKEN" | jq -r '.data.secret_id' | tr -d '\n' | keyctl padd user secret_id @s)

if [[ -z "${KEY_ID:-}" ]]; then
  echo "Failed to retrieve a secret ID from the wrapping token."
  exit 1
fi

# Step 2: Authenticate to Vault using AppRole authentication method
# - keyctl print: retrieves the secret ID from the kernel keyring
# - vault write: sends role_id and secret_id to Vault's AppRole login endpoint
# - -field=token: extracts only the auth token from the response
# - tr: removes newlines
# - keyctl padd: stores the resulting Vault token in the kernel keyring
keyctl print "$KEY_ID" | vault write -field=token auth/approle/login role_id="$ROLE_ID" secret_id=- | keyctl padd user vault_token @s

echo "keyring:session:vault_token" > ~/.vault-token

echo "Vault authentication successful. Token stored in kernel keyring."
echo "Generating identity.txt file ..."
age-plugin-vault -generate my-transit-key > identity.txt

age -e -i identity.txt -o go.sum.age go.sum
echo "Encrypted go.sum file created: go.sum.age"

echo "Decrypting go.sum.age file ..."
age -d -i identity.txt go.sum.age
