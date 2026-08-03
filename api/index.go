package handler

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// DTO Request & Response
type PasswordCheckRequest struct {
	Password string `json:"password"`
}

type PasswordCheckResponse struct {
	Password      string `json:"password"`
	FullHash      string `json:"full_hash"`
	Prefix        string `json:"prefix"`
	Suffix        string `json:"suffix"`
	MatchedSuffix string `json:"matched_suffix"`
	IsPwned       bool   `json:"is_pwned"`
	PwnedCount    int    `json:"pwned_count"`
	Message       string `json:"message"`
}

type GeneratePasswordResponse struct {
	Password string `json:"generated_password"`
}

// LOGIKA 1: CHECK PASSWORD HIBP (Sama Persis)
func checkPasswordHIBP(password string) (PasswordCheckResponse, error) {
	hasher := sha1.New()
	hasher.Write([]byte(password))
	fullHash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

	prefix := fullHash[:5]
	userSuffix := fullHash[5:]

	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	resp, err := http.Get(url)
	if err != nil {
		return PasswordCheckResponse{}, fmt.Errorf("gagal terhubung ke API HIBP: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PasswordCheckResponse{}, fmt.Errorf("API HIBP merespon status HTTP: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return PasswordCheckResponse{}, fmt.Errorf("gagal membaca data respon: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(body)), "\r\n")

	matchedSuffix := ""
	pwnedCount := 0
	isPwned := false

	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			apiSuffix := strings.TrimSpace(parts[0])
			count, parseErr := strconv.Atoi(strings.TrimSpace(parts[1]))

			if parseErr == nil && apiSuffix == userSuffix {
				isPwned = true
				pwnedCount = count
				matchedSuffix = apiSuffix
				break
			}
		}
	}

	msg := "✅ AMAN! Password belum pernah bocor di internet."
	if isPwned {
		msg = fmt.Sprintf("⚠️ BAHAYA! Password ini ditemukan di kebocoran data sebanyak %d kali!", pwnedCount)
	}

	return PasswordCheckResponse{
		Password:      password,
		FullHash:      fullHash,
		Prefix:        prefix,
		Suffix:        userSuffix,
		MatchedSuffix: matchedSuffix,
		IsPwned:       isPwned,
		PwnedCount:    pwnedCount,
		Message:       msg,
	}, nil
}

// LOGIKA 2: GENERATE RANDOM SECURE PASSWORD (Sama Persis)
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	result := make([]byte, length)

	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}

	return string(result), nil
}

// Global Router Gin
var app *gin.Engine

func init() {
	gin.SetMode(gin.ReleaseMode)
	app = gin.New()
	app.Use(gin.Recovery())

	// Endpoint 1: Check Password
	app.POST("/api/check-password", func(c *gin.Context) {
		var req PasswordCheckRequest

		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Password) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password tidak boleh kosong!"})
			return
		}

		res, err := checkPasswordHIBP(strings.TrimSpace(req.Password))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, res)
	})

	// Endpoint 2: Generate Password
	app.GET("/api/generate-password", func(c *gin.Context) {
		pass, err := generateRandomPassword(16)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat password acak"})
			return
		}

		c.JSON(http.StatusOK, GeneratePasswordResponse{Password: pass})
	})
}

// Handler Entrypoint untuk Vercel Serverless Function
func Handler(w http.ResponseWriter, r *http.Request) {
	app.ServeHTTP(w, r)
}