#!/bin/bash

# Download Vault
wget https://releases.hashicorp.com/vault/1.15.4/vault_1.15.4_linux_amd64.zip -O vault.zip
sudo unzip -o vault.zip -d /usr/bin
rm vault.zip

# Run Vault
# kill $(lsof -t -i:8200)
vault server -dev -dev-root-token-id="root" &
sleep 5

# Set Vault address and token

VAULT_ADDR='http://127.0.0.1:8200'
VAULT_TOKEN="root"

# Vault Configs
vault auth enable approle
vault write auth/approle/role/my-role secret_id_ttl=10m token_ttl=20m token_max_ttl=30m secret_id_num_uses=40 token_num_uses=50 policies="my-policy"
vault secrets enable transit
vault write -f transit/keys/test-key

vault policy write my-policy -<<EOF
path "transit/encrypt/test-key" {
  capabilities = ["update"]
}
EOF

# Get AppRole ID and Secret ID

APPROLE_ROLE_ID=$(vault read auth/approle/role/my-role/role-id | grep role_id | awk '{print $2}')
APPROLE_W_SECRET=$(vault write -wrap-ttl=120s -f -format=json auth/approle/role/my-role/secret-id | jq -r '.wrap_info.token')