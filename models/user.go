package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"      // Argon2id hash with salt`
	PublicKey    string `gorm:"type:text"     // X25519 public key for E2EE`
	PrivateInfo  string `gorm:"type:text"     // Encrypted private information`
	Balance      float64 `gorm:"default:0.0" // Account balance`
	Messages     []Message `gorm:"foreignKey:SenderID"`
	Transactions []Transaction
}

// Message represents an encrypted message between users
type Message struct {
	gorm.Model
	SenderID    uint   `gorm:"not null"`
	ReceiverID  uint   `gorm:"not null"`
	Ciphertext  string `gorm:"type:text"  // ChaCha20-Poly1305 encrypted message`
	Nonce       string `gorm:"type:text"  // Encryption nonce`
	EphemeralPK string `gorm:"type:text"  // Sender's ephemeral public key`
}

// Transaction represents a financial transaction
type Transaction struct {
	gorm.Model
	UserID      uint    `gorm:"not null"`
	Amount      float64 `gorm:"not null"`
	Description string
	Timestamp   time.Time `gorm:"not null"`
}