package controllers

import (
	"encoding/base64"
	"net/http"

	"x/cryptic/models"
	"x/cryptic/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type MessageController struct {
	db *gorm.DB
}

func NewMessageController(db *gorm.DB) *MessageController {
	return &MessageController{db: db}
}

type SendMessageRequest struct {
	ReceiverUsername string `json:"receiver_username" binding:"required"`
	Message         string `json:"message" binding:"required"`
}

type MessageResponse struct {
	ID        uint   `json:"id"`
	SenderID  uint   `json:"sender_id"`
	Timestamp string `json:"timestamp"`
}

// SendMessage handles sending encrypted messages between users
func (mc *MessageController) SendMessage(c *gin.Context) {
	// Get sender ID from JWT token
	senderID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Find receiver
	var receiver models.User
	if err := mc.db.Where("username = ?", req.ReceiverUsername).First(&receiver).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Receiver not found"})
		return
	}

	// Get sender's private key and receiver's public key
	var sender models.User
	if err := mc.db.First(&sender, senderID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sender info"})
		return
	}

	// Decode keys
	receiverPubKey, err := base64.StdEncoding.DecodeString(receiver.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid receiver public key"})
		return
	}

	// Encrypt message
	ciphertext, nonce, ephemeralPubKey, err := utils.EncryptMessage(
		[]byte(req.Message),
		receiverPubKey,
		[]byte(sender.PrivateInfo), // Sender's private key should be securely stored
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt message"})
		return
	}

	// Store encrypted message
	message := &models.Message{
		SenderID:    uint(senderID.(uint)),
		ReceiverID:  receiver.ID,
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		EphemeralPK: base64.StdEncoding.EncodeToString(ephemeralPubKey),
	}

	if err := mc.db.Create(message).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save message"})
		return
	}

	c.JSON(http.StatusCreated, MessageResponse{
		ID:        message.ID,
		SenderID:  message.SenderID,
		Timestamp: message.CreatedAt.Format("2006-01-02 15:04:05"),
	})
}

// GetMessages retrieves all messages for the current user
func (mc *MessageController) GetMessages(c *gin.Context) {
	// Get user ID from JWT token
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get user's messages
	var messages []models.Message
	if err := mc.db.Where("receiver_id = ?", userID).Find(&messages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get messages"})
		return
	}

	// Get user's private key for decryption
	var user models.User
	if err := mc.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}

	// Process messages
	response := make([]gin.H, 0)
	for _, msg := range messages {
		// Get sender's public key
		var sender models.User
		if err := mc.db.First(&sender, msg.SenderID).Error; err != nil {
			continue
		}

		// Decode message components
		ciphertext, err := base64.StdEncoding.DecodeString(msg.Ciphertext)
		if err != nil {
			continue
		}

		nonce, err := base64.StdEncoding.DecodeString(msg.Nonce)
		if err != nil {
			continue
		}

		ephemeralPubKey, err := base64.StdEncoding.DecodeString(msg.EphemeralPK)
		if err != nil {
			continue
		}

		senderPubKey, err := base64.StdEncoding.DecodeString(sender.PublicKey)
		if err != nil {
			continue
		}

		// Decrypt message
		plaintext, err := utils.DecryptMessage(
			ciphertext,
			nonce,
			ephemeralPubKey,
			[]byte(user.PrivateInfo), // User's private key should be securely stored
			senderPubKey,
		)
		if err != nil {
			continue
		}

		response = append(response, gin.H{
			"id":        msg.ID,
			"sender":    sender.Username,
			"message":   string(plaintext),
			"timestamp": msg.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	c.JSON(http.StatusOK, response)
}