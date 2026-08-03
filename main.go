package main

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

// DTO (Data Transfer Object) Request & Response
type PasswordCheckRequest struct {
	Password string `json:"password"`
}

type PasswordCheckResponse struct {
	Password      string `json:"password"`
	FullHash      string `json:"full_hash"`
	Prefix        string `json:"prefix"`
	Suffix        string `json:"suffix"`
	MatchedSuffix string `json:"matched_suffix"` // Suffix yang cocok 100% dari API HIBP
	IsPwned       bool   `json:"is_pwned"`
	PwnedCount    int    `json:"pwned_count"`
	Message       string `json:"message"`
}

type GeneratePasswordResponse struct {
	Password string `json:"generated_password"`
}

// ---------------------------------------------------------
// LOGIKA 1: CHECK PASSWORD HIBP (k-Anonymity)
// ---------------------------------------------------------
func checkPasswordHIBP(password string) (PasswordCheckResponse, error) {
	// 1. Generate SHA-1 Hash dari Password
	hasher := sha1.New()
	hasher.Write([]byte(password))
	fullHash := strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

	// 2. Potong Hash menjadi Prefix (5) & Suffix (35)
	prefix := fullHash[:5]
	userSuffix := fullHash[5:]

	// 3. Tembak API HIBP hanya dengan Prefix 5 karakter
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

	// 4. Split Respon Per Baris (Format HIBP: SUFFIX:COUNT)
	lines := strings.Split(strings.TrimSpace(string(body)), "\r\n")

	matchedSuffix := ""
	pwnedCount := 0
	isPwned := false

	// 5. Cari Suffix yang 100% Cocok Presisi
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			apiSuffix := strings.TrimSpace(parts[0])
			count, parseErr := strconv.Atoi(strings.TrimSpace(parts[1]))

			// Pencocokan 100% sama dengan milik user
			if parseErr == nil && apiSuffix == userSuffix {
				isPwned = true
				pwnedCount = count
				matchedSuffix = apiSuffix // Berhasil dicocokkan presisi
				break
			}
		}
	}

	// 6. Buat Pesan Status
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

// ---------------------------------------------------------
// LOGIKA 2: GENERATE RANDOM SECURE PASSWORD
// ---------------------------------------------------------
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	result := make([]byte, length)

	for i := range result {
		// Menggunakan crypto/rand agar secara kriptografi aman & acak
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}

	return string(result), nil
}

// ---------------------------------------------------------
// MAIN FUNCTION & ROUTER
// ---------------------------------------------------------
func main() {
	r := gin.Default()

	// Layani File HTML
	r.StaticFile("/", "./index.html")

	// Endpoint 1: Cek Keamanan Password
	r.POST("/api/check-password", func(c *gin.Context) {
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

	// Endpoint 2: Generate Password Acak Kuat
	r.GET("/api/generate-password", func(c *gin.Context) {
		// Default panjang 16 karakter
		pass, err := generateRandomPassword(16)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat password acak"})
			return
		}

		c.JSON(http.StatusOK, GeneratePasswordResponse{Password: pass})
	})

	fmt.Println("🚀 Server HIBP berjalan di http://localhost:8080")
	r.Run(":8080")
}