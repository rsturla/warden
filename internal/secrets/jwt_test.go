package secrets

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestSignRS256JWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwt, err := signRS256JWT(key, map[string]any{
		"iss": "test@example.com",
		"aud": "https://example.com/token",
		"iat": 1000000,
		"exp": 1003600,
	})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}

	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]string
	json.Unmarshal(headerBytes, &header)
	if header["alg"] != "RS256" {
		t.Errorf("alg = %q, want RS256", header["alg"])
	}

	claimsBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(claimsBytes, &claims)
	if claims["iss"] != "test@example.com" {
		t.Errorf("iss = %v", claims["iss"])
	}

	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestParseRSAPrivateKeyPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	parsed, err := parseRSAPrivateKey(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Error("key mismatch")
	}
}

func TestParseRSAPrivateKeyPKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	parsed, err := parseRSAPrivateKey(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Error("key mismatch")
	}
}

func TestParseRSAPrivateKeyInvalid(t *testing.T) {
	_, err := parseRSAPrivateKey([]byte("not pem"))
	if err == nil {
		t.Fatal("expected error")
	}
}
