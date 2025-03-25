package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
	SaltLength    = 16
	NonceSize     = chacha20poly1305.NonceSizeX
)

// GenerateKeyPair generates a new X25519 key pair for E2EE
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate public key: %v", err)
	}

	return privateKey, publicKey, nil
}

// HashPassword creates a secure hash using Argon2id with a random salt
func HashPassword(password string) (string, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLen,
	)

	// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		Argon2Memory, Argon2Time, Argon2Threads, b64Salt, b64Hash)

	return encoded, nil
}

// VerifyPassword checks if a password matches its hash
func VerifyPassword(password, encodedHash string) (bool, error) {
	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %v", err)
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.threads,
		params.keyLen,
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// EncryptMessage encrypts a message using ChaCha20-Poly1305
func EncryptMessage(message []byte, recipientPubKey, senderPrivKey []byte) ([]byte, []byte, []byte, error) {
	fmt.Printf("[Crypto] EncryptMessage called with message length: %d, recipient key length: %d, sender key length: %d\n", 
		len(message), len(recipientPubKey), len(senderPrivKey))
	
	// Generate ephemeral key pair
	fmt.Printf("[Crypto] Generating ephemeral key pair\n")
	ephemeralPrivKey, ephemeralPubKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Printf("[Crypto] Error generating ephemeral key pair: %v\n", err)
		return nil, nil, nil, fmt.Errorf("failed to generate ephemeral key pair: %v", err)
	}
	fmt.Printf("[Crypto] Ephemeral key pair generated successfully\n")

	// Compute shared secret using both key pairs
	fmt.Printf("[Crypto] Computing first shared secret\n")
	sharedSecret1, err := curve25519.X25519(senderPrivKey, recipientPubKey)
	if err != nil {
		fmt.Printf("[Crypto] Error computing first shared secret: %v\n", err)
		return nil, nil, nil, fmt.Errorf("failed to compute first shared secret: %v", err)
	}
	fmt.Printf("[Crypto] First shared secret computed successfully\n")

	fmt.Printf("[Crypto] Computing second shared secret\n")
	sharedSecret2, err := curve25519.X25519(ephemeralPrivKey, recipientPubKey)
	if err != nil {
		fmt.Printf("[Crypto] Error computing second shared secret: %v\n", err)
		return nil, nil, nil, fmt.Errorf("failed to compute second shared secret: %v", err)
	}
	fmt.Printf("[Crypto] Second shared secret computed successfully\n")

	// Combine shared secrets and hash them to get a 32-byte key
	fmt.Printf("[Crypto] Combining shared secrets\n")
	sharedKey := make([]byte, 0, len(sharedSecret1)+len(sharedSecret2))
	sharedKey = append(sharedKey, sharedSecret1...)
	sharedKey = append(sharedKey, sharedSecret2...)
	fmt.Printf("[Crypto] Combined shared key length before hashing: %d\n", len(sharedKey))
	
	// Hash the combined key to get a 32-byte key suitable for chacha20poly1305
	hashKey := argon2.IDKey(
		sharedKey,
		[]byte("cryptic-salt"), // Using a constant salt for deterministic hashing
		1, // Minimal time cost for performance
		64 * 1024, // Memory cost
		4, // Parallelism
		32, // Output a 32-byte key
	)
	fmt.Printf("[Crypto] Hashed key length: %d\n", len(hashKey))
	sharedKey = hashKey

	// Create AEAD cipher
	fmt.Printf("[Crypto] Creating AEAD cipher\n")
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		fmt.Printf("[Crypto] Error creating AEAD: %v\n", err)
		return nil, nil, nil, fmt.Errorf("failed to create AEAD: %v", err)
	}
	fmt.Printf("[Crypto] AEAD cipher created successfully\n")

	// Generate nonce
	fmt.Printf("[Crypto] Generating nonce\n")
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Printf("[Crypto] Error generating nonce: %v\n", err)
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	fmt.Printf("[Crypto] Nonce generated successfully, length: %d\n", len(nonce))

	// Encrypt message
	fmt.Printf("[Crypto] Encrypting message\n")
	ciphertext := aead.Seal(nil, nonce, message, nil)
	fmt.Printf("[Crypto] Message encrypted successfully, ciphertext length: %d\n", len(ciphertext))

	return ciphertext, nonce, ephemeralPubKey, nil
}

// DecryptMessage decrypts a message using ChaCha20-Poly1305
func DecryptMessage(ciphertext, nonce, ephemeralPubKey []byte, recipientPrivKey []byte, senderPubKey []byte) ([]byte, error) {
	// Compute shared secrets
	sharedSecret1, err := curve25519.X25519(recipientPrivKey, senderPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute first shared secret: %v", err)
	}

	sharedSecret2, err := curve25519.X25519(recipientPrivKey, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute second shared secret: %v", err)
	}

	// Combine shared secrets
	sharedKey := make([]byte, 0, len(sharedSecret1)+len(sharedSecret2))
	sharedKey = append(sharedKey, sharedSecret1...)
	sharedKey = append(sharedKey, sharedSecret2...)

	// Hash the combined key to get a 32-byte key suitable for chacha20poly1305
	hashKey := argon2.IDKey(
		sharedKey,
		[]byte("cryptic-salt"), // Using a constant salt for deterministic hashing
		1, // Minimal time cost for performance
		64 * 1024, // Memory cost
		4, // Parallelism
		32, // Output a 32-byte key
	)
	sharedKey = hashKey

	// Create AEAD cipher
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	// Decrypt message
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %v", err)
	}

	return plaintext, nil
}

type params struct {
	memory  uint32
	time    uint32
	threads uint8
	keyLen  uint32
}

func decodeHash(encodedHash string) (p *params, salt, hash []byte, err error) {
	var version int
	_, err = fmt.Sscanf(encodedHash, "$argon2id$v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != 19 {
		return nil, nil, nil, fmt.Errorf("incompatible version: %d", version)
	}

	p = &params{}
	_, err = fmt.Sscanf(encodedHash, "$argon2id$v=19$m=%d,t=%d,p=%d",
		&p.memory, &p.time, &p.threads)
	if err != nil {
		return nil, nil, nil, err
	}

	splits := strings.Split(encodedHash, "$")
	if len(splits) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	salt, err = base64.RawStdEncoding.DecodeString(splits[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLen = Argon2KeyLen

	hash, err = base64.RawStdEncoding.DecodeString(splits[5])
	if err != nil {
		return nil, nil, nil, err
	}

	return p, salt, hash, nil
}