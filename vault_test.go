package vaultonic

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	_ "github.com/joho/godotenv/autoload"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupGin() *gin.Engine {
	r := gin.Default()

	parameters := VaultParams{
		Address:              "http://127.0.0.1:8200",
		ApproleRoleID:        os.Getenv("APPROLE_ROLE_ID"),
		ApproleWrappedSecret: os.Getenv("APPROLE_W_SECRET"),
		KeyName:              "test-key",
		KvPath:               "secret",
		SecretPath:           "/go-test",
	}

	r.Use(VaultMiddleware(parameters))

	r.GET("/vaultonic/:encrypt", func(c *gin.Context) {
		param := c.Param("encrypt")
		vault := c.MustGet("vault").(*Vault)
		data := []byte(param)
		cipher, err := vault.Encrypt(c, data)
		if err != nil {
			c.JSON(500, gin.H{
				"message": err.Error(),
			})
			return
		}
		log.Print(cipher["ciphertext"])
		c.JSON(200, gin.H{
			"message": cipher["ciphertext"],
		})
	})

	r.GET("/vaultonic/secret/write/:secret/:key/:value", func(c *gin.Context) {
		param := c.Param("secret")
		k := c.Param("key")
		vl := c.Param("value")
		vault := c.MustGet("vault").(*Vault)
		res, err := vault.Kvput(c, param, k, vl)
		if err != nil {
			log.Print(err)
			c.JSON(500, gin.H{
				"message": err.Error(),
			})
			return
		}
		log.Print(res)
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	r.GET("/vaultonic/secret/read/:secret", func(c *gin.Context) {
		param := c.Param("secret")
		vault := c.MustGet("vault").(*Vault)
		secret, err := vault.Kvget(c, param)
		if err != nil {
			log.Print(err)
			c.JSON(500, gin.H{
				"message": err.Error(),
			})
			return
		}
		log.Println(secret)
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	return r
}

func TestVaultonicEncrypt(t *testing.T) {
	r := setupGin()
	req, _ := http.NewRequest("GET", "/vaultonic/this-is-a-test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestVaultonicWriteSecret(t *testing.T) {
	r := setupGin()
	req, _ := http.NewRequest("GET", "/vaultonic/secret/write/mysecret/password/122345234523434", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestVaultonicReadSEcret(t *testing.T) {
	r := setupGin()
	req, _ := http.NewRequest("GET", "/vaultonic/secret/read/mysecret", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}
