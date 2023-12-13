package vaultonic

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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
		c.JSON(200, gin.H{
			"message": cipher["ciphertext"],
		})
	})

	return r
}

func TestVaultonic(t *testing.T) {
	r := setupGin()
	req, _ := http.NewRequest("GET", "/vaultonic/this-is-a-test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}
