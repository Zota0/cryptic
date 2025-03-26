package controllers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	// Log raw request body
	rawData, _ := c.GetRawData()
	fmt.Printf("[SendMessage] Raw request body: %s\n", string(rawData))
	c.Request.Body = io.NopCloser(bytes.NewBuffer(rawData))

	var req SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Log validation error
		fmt.Printf("[SendMessage] Validation error: %v\n", err)
		fmt.Printf("[SendMessage] Request data attempted to parse: %+v\n", req)
		validationErrors := make(map[string]string)
		if err.Error() == "EOF" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Request body is empty"})
			return
		}
		if strings.Contains(err.Error(), "receiver_username") {
			validationErrors["receiver_username"] = "Receiver username is required"
		}
		if strings.Contains(err.Error(), "message") {
			validationErrors["message"] = "Message is required"
		}
		if len(validationErrors) == 0 {
			validationErrors["error"] = "Invalid request format"
		}
		validationErrors["error"] = err.Error() + " - " + validationErrors["error"]
		c.JSON(http.StatusBadRequest, validationErrors)
		return
	}

	fmt.Printf("[SendMessage] Successfully parsed request: receiver_username=%s, message_length=%d\n", req.ReceiverUsername, len(req.Message))

	// Get sender ID from JWT token
	senderID, exists := c.Get("user_id")
	if !exists {
		fmt.Printf("[SendMessage] Error: user_id not found in context\n")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	fmt.Printf("[SendMessage] Sender ID: %v\n", senderID)

	// Find receiver
	var receiver models.User
	if err := mc.db.Where("username = ?", req.ReceiverUsername).First(&receiver).Error; err != nil {
		// Check if receiver exists but is soft-deleted
		var count int64
		if err := mc.db.Unscoped().Model(&models.User{}).Where("username = ? AND deleted_at IS NOT NULL", req.ReceiverUsername).Count(&count).Error; err == nil && count > 0 {
			fmt.Printf("[SendMessage] Receiver username %s is soft-deleted\n", req.ReceiverUsername)
		} else {
			fmt.Printf("[SendMessage] Receiver username %s not found\n", req.ReceiverUsername)
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "Receiver not found"})
		return
	}
	fmt.Printf("[SendMessage] Receiver found: ID %d\n", receiver.ID)

	// Get sender's private key and receiver's public key
	var sender models.User
	if err := mc.db.First(&sender, senderID).Error; err != nil {
		fmt.Printf("[SendMessage] Failed to get sender info for ID %d: %v\n", senderID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sender info"})
		return
	}
	fmt.Printf("[SendMessage] Sender info retrieved: username=%s\n", sender.Username)

	// Decode keys
	receiverPubKey, err := base64.StdEncoding.DecodeString(receiver.PublicKey)
	if err != nil {
		fmt.Printf("[SendMessage] Failed to decode receiver's public key: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid receiver public key"})
		return
	}
	fmt.Printf("[SendMessage] Receiver public key decoded successfully\n")

	// Encrypt message
	fmt.Printf("[SendMessage] Encrypting message (length=%d)\n", len(req.Message))
	ciphertext, nonce, ephemeralPubKey, err := utils.EncryptMessage(
		[]byte(req.Message),
		receiverPubKey,
		[]byte(sender.PrivateInfo),
	)
	if err != nil {
		fmt.Printf("[SendMessage] Encryption failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt message"})
		return
	}
	fmt.Printf("[SendMessage] Message encrypted successfully\n")

	// Store encrypted message
	message := &models.Message{
		SenderID:    uint(senderID.(uint)),
		ReceiverID:  receiver.ID,
		Ciphertext:  base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		EphemeralPK: base64.StdEncoding.EncodeToString(ephemeralPubKey),
	}

	fmt.Printf("[SendMessage] Storing encrypted message in database\n")
	if err := mc.db.Create(message).Error; err != nil {
		fmt.Printf("[SendMessage] Failed to save message: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save message"})
		return
	}
	fmt.Printf("[SendMessage] Message stored successfully with ID: %d\n", message.ID)

	c.JSON(http.StatusCreated, MessageResponse{
		ID:        message.ID,
		SenderID:  message.SenderID,
		Timestamp: message.CreatedAt.Format("2006-01-02 15:04:05"),
	})
	fmt.Printf("[SendMessage] Message sent successfully from %d to %d\n", senderID, receiver.ID)
}

// GetMessages retrieves all messages for the current user
func (mc *MessageController) GetMessages(c *gin.Context) {
	// Get user ID from JWT token
	userID, exists := c.Get("user_id")
	if !exists {
		fmt.Printf("[GetMessages] Error: user_id not found in context\n")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	fmt.Printf("[GetMessages] User ID: %v\n", userID)

	// Get user's messages
	fmt.Printf("[GetMessages] Retrieving messages for user %d\n", userID)
	var messages []models.Message
	if err := mc.db.Where("receiver_id = ?", userID).Find(&messages).Error; err != nil {
		fmt.Printf("[GetMessages] Failed to retrieve messages: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get messages"})
		return
	}
	fmt.Printf("[GetMessages] Found %d messages\n", len(messages))

	// Get user's private key for decryption
	var user models.User
	if err := mc.db.First(&user, userID).Error; err != nil {
		fmt.Printf("[GetMessages] Failed to get user info: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}
	fmt.Printf("[GetMessages] User info retrieved: username=%s\n", user.Username)

	// Process messages
	response := make([]gin.H, 0)
	for _, msg := range messages {
		fmt.Printf("[GetMessages] Processing message ID %d\n", msg.ID)

		// Get sender's public key
		var sender models.User
		if err := mc.db.First(&sender, msg.SenderID).Error; err != nil {
			fmt.Printf("[GetMessages] Failed to find sender %d for message %d: %v\n", msg.SenderID, msg.ID, err)
			continue
		}

		// Decode message components
		ciphertext, err := base64.StdEncoding.DecodeString(msg.Ciphertext)
		if err != nil {
			fmt.Printf("[GetMessages] Failed to decode ciphertext for message %d: %v\n", msg.ID, err)
			continue
		}

		nonce, err := base64.StdEncoding.DecodeString(msg.Nonce)
		if err != nil {
			fmt.Printf("[GetMessages] Failed to decode nonce for message %d: %v\n", msg.ID, err)
			continue
		}

		ephemeralPubKey, err := base64.StdEncoding.DecodeString(msg.EphemeralPK)
		if err != nil {
			fmt.Printf("[GetMessages] Failed to decode ephemeral public key for message %d: %v\n", msg.ID, err)
			continue
		}

		senderPubKey, err := base64.StdEncoding.DecodeString(sender.PublicKey)
		if err != nil {
			fmt.Printf("[GetMessages] Failed to decode sender's public key for message %d: %v\n", msg.ID, err)
			continue
		}

		// Decrypt message
		fmt.Printf("[GetMessages] Decrypting message %d\n", msg.ID)
		plaintext, err := utils.DecryptMessage(
			ciphertext,
			nonce,
			ephemeralPubKey,
			[]byte(user.PrivateInfo),
			senderPubKey,
		)
		if err != nil {
			fmt.Printf("[GetMessages] Decryption failed for message %d: %v\n", msg.ID, err)
			continue
		}
		fmt.Printf("[GetMessages] Successfully decrypted message %d\n", msg.ID)

		response = append(response, gin.H{
			"id":        msg.ID,
			"sender":    sender.Username,
			"message":   string(plaintext),
			"timestamp": msg.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	fmt.Printf("[GetMessages] Returning %d decrypted messages to user %d\n", len(response), userID)
	c.JSON(http.StatusOK, response)
}