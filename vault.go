package vaultonic

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type VaultParams struct {
	Address              string
	ApproleRoleID        string
	ApproleWrappedSecret string
	KeyName              string
}

type AppRoleWriteCustomSecretIdResponse struct {
	SecretId         string `json:"secret_id,omitempty"`
	SecretIdAccessor string `json:"secret_id_accessor,omitempty"`
	SecretIdNumUses  int32  `json:"secret_id_num_uses,omitempty"`
	SecretIdTtl      int32  `json:"secret_id_ttl,omitempty"`
}

type Vault struct {
	client     *vault.Client
	parameters VaultParams
}

// func NewVaultClient(ctx context.Context, parameters VaultParams) (*Vault, *vault.Secret, error) {
// 	log.Printf("connecting to vault @ %s", parameters.Address)

// 	config := vault.DefaultConfig()
// 	config.Address = parameters.Address

// 	client, err := vault.NewClient(config)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("unable to initialize vault client: %w", err)
// 	}

// 	v := &Vault{
// 		client:     client,
// 		parameters: parameters,
// 	}

// 	token, err := v.login(ctx)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("vault login error: %w", err)
// 	}

// 	log.Println("connecting to vault: success!")

// 	return v, token, nil
// }

func VaultClient(params VaultParams) (*Vault, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := vault.New(
		vault.WithAddress(params.Address),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	v := &Vault{
		client:     client,
		parameters: params,
	}

	unwrap, err := vault.Unwrap[AppRoleWriteCustomSecretIdResponse](ctx, client, params.ApproleWrappedSecret)
	if err != nil {
		return nil, "", fmt.Errorf("error unwrapping token: %s", err)
	}

	resp, err := v.login(ctx, unwrap.Data.SecretId)
	if err != nil {
		return nil, "", fmt.Errorf("error when logging into Vault %s", err)
	}
	if err := v.client.SetToken(resp); err != nil {
		return nil, "", fmt.Errorf("error setting token: %s", err)
	}

	return v, resp, nil
}

func (v *Vault) login(ctx context.Context, secret_id string) (string, error) {
	log.Printf("logging in to vault with approle auth; role id: %s", v.parameters.ApproleRoleID)

	// approleSecretID := &approle.SecretID{
	// 	FromFile: v.parameters.ApproleSecretIDFile,
	// }

	// approleAuth, err := approle.NewAppRoleAuth(
	// 	v.parameters.ApproleRoleID,
	// 	approleSecretID,
	// 	approle.WithWrappingToken(),
	// )
	// if err != nil {
	// 	return nil, fmt.Errorf(" unable to initialize approle authentication method: %w", err)
	// }

	// log.Print(approleAuth)

	// authInfo, err := v.client.Auth().Login(ctx, approleAuth)
	// if err != nil {
	// 	return nil, fmt.Errorf("unable to login using approle method: %w", err)
	// }

	// if authInfo == nil {
	// 	return nil, fmt.Errorf("no approle info was returned after the login")
	// }

	// log.Println("logging in to vault with approle auth: success!")
	// return authInfo, nil

	resp, err := v.client.Auth.AppRoleLogin(
		ctx,
		schema.AppRoleLoginRequest{
			RoleId:   v.parameters.ApproleRoleID,
			SecretId: secret_id,
		},
	)
	if err != nil {
		return "", fmt.Errorf("login Error: %s", err)
	}
	fmt.Printf("logged Into Vault: %s\n", resp.Auth.ClientToken)
	return resp.Auth.ClientToken, nil
}

func (v *Vault) Encrypt(ctx context.Context, data []byte) (map[string]interface{}, error) {
	log.Printf("encrypting data...")
	pt := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(data),
	}

	tep := "transit/encrypt/" + v.parameters.KeyName

	cipher, err := v.client.Write(ctx, tep, pt)
	// cipher, err := v.client.Logical().WriteWithContext(ctx, v.parameters.TransitEncrypt, pt)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	return cipher.Data, nil
}

func VaultMiddleware(parameters VaultParams) gin.HandlerFunc {
	vault, _, err := VaultClient(parameters)
	if err != nil {
		log.Fatal("error init vault: %w", err)
	}
	return func(ctx *gin.Context) {
		ctx.Set("vault", vault)
		ctx.Next()
	}
}
