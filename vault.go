package vaultonic

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

type VaultParams struct {
	Address              string
	ApproleRoleID        string
	ApproleWrappedSecret string
	KeyName              string
	KvPath               string
	SecretPath           string
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

func VaultClient(params VaultParams) (*Vault, *vault.Secret, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := vault.DefaultConfig()
	config.Address = params.Address

	client, err := vault.NewClient(config)

	if err != nil {
		log.Fatal(err)
	}

	v := &Vault{
		client:     client,
		parameters: params,
	}

	token, err := v.login(ctx)
	if err != nil {
		log.Fatalf("error logging in to vault: %s", err)
	}

	log.Println("connecting to vault: success!")
	return v, token, nil

}

func (v *Vault) login(ctx context.Context) (*vault.Secret, error) {
	log.Printf("logging in to vault with approle auth; role id: %s", v.parameters.ApproleRoleID)

	approleSecretId := &approle.SecretID{
		FromString: v.parameters.ApproleWrappedSecret,
	}

	approleAuth, err := approle.NewAppRoleAuth(
		v.parameters.ApproleRoleID,
		approleSecretId,
		// approle.WithWrappingToken(),
	)

	if err != nil {
		return nil, fmt.Errorf("login Error: %s", err)
	}

	authInfo, err := v.client.Auth().Login(ctx, approleAuth)

	if err != nil {
		return nil, fmt.Errorf("unable to login using approle: %s", err)
	}

	if authInfo == nil {
		return nil, fmt.Errorf("no approle info")
	}

	fmt.Printf("logged Into Vault with approle\n")

	return authInfo, nil
}

func (v *Vault) Encrypt(ctx context.Context, data []byte) (map[string]interface{}, error) {
	log.Printf("encrypting data...")
	pt := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(data),
	}

	tep := "transit/encrypt/" + v.parameters.KeyName

	cipher, err := v.client.Logical().WriteWithContext(ctx, tep, pt)

	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %w", err)
	}

	return cipher.Data, nil
}

func (v *Vault) Kvput(ctx context.Context, secret string, k string, vl string) (*vault.KVSecret, error) {
	log.Printf("writing secret to vault...")
	secretPath := v.parameters.SecretPath + "/" + secret
	kvPath := v.parameters.KvPath
	data := map[string]interface{}{
		k: vl, 
	}
	r, err := v.client.KVv2(kvPath).Put(ctx, secretPath, data)
	if err != nil {
		return nil, fmt.Errorf("error writing secret to vault: %w", err)
	}

	return r, nil
}

func (v *Vault) Kvget(ctx context.Context, secret string) (map[string]interface{}, error) {
	log.Printf("reading secret from vault...")
	secretPath := v.parameters.SecretPath + "/" + secret
	kvPath := v.parameters.KvPath
	// data := map[string]interface{}{
	// 	"data": map[string]interface{}{
	// 		k: vl,
	// 	},
	// }
	// r, err := v.client.KVv2(kvPath).Put(ctx, secretPath, data)
	// if err != nil {
	// 	return nil, fmt.Errorf("error writing secret to vault: %w", err)
	// }

	// return r, nil
	data, err := v.client.KVv2(kvPath).Get(ctx, secretPath)
	if err != nil {
		return nil, fmt.Errorf("error reading secret from vault: %w", err)
	}
	r := data.Data

	return r, nil
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
