package controllers

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"x/cryptic/models"
	"x/cryptic/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthController struct {
	db *gorm.DB
}

func NewAuthController(db *gorm.DB) *AuthController {
	return &AuthController{db: db}
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,alphanum,min=3,max=30"`
	Password string `json:"password" binding:"required,min=8,max=72"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

type StatusResponse struct {
	Authenticated bool   `json:"authenticated"`
	Username     string `json:"username,omitempty"`
}

// Status returns the current authentication status
func (ac *AuthController) Status(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusOK, StatusResponse{Authenticated: false})
		return
	}

	var user models.User
	if err := ac.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusOK, StatusResponse{Authenticated: false})
		return
	}

	c.JSON(http.StatusOK, StatusResponse{
		Authenticated: true,
		Username:     user.Username,
	})
}

// Register handles user registration
func (ac *AuthController) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please ensure all fields are filled correctly. Username must be 3-30 characters long and contain only letters and numbers. Password must be at least 8 characters long."})
		return
	}

	// Check if username already exists
	var existingUser models.User
	if err := ac.db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// Generate password hash
	passwordHash, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Generate key pair for E2EE
	privateKey, publicKey, err := utils.GenerateKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key pair"})
		return
	}

	// Encrypt private key with user's password hash as the key
	encryptedPrivKey, nonce, ephemPubKey, err := utils.EncryptMessage(privateKey, publicKey, privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt private key"})
		return
	}

	// Store encrypted private key info
	privateInfo := fmt.Sprintf("%s:%s:%s",
		base64.StdEncoding.EncodeToString(encryptedPrivKey),
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(ephemPubKey))

	// Create user
	user := &models.User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		PublicKey:    base64.StdEncoding.EncodeToString(publicKey),
		PrivateInfo:  privateInfo,
		Balance:      0,
	}

	if err := ac.db.Create(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Generate JWT token
	token, err := utils.GenerateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusCreated, AuthResponse{Token: token})
}

// Login handles user authentication
func (ac *AuthController) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Find user
	var user models.User
	if err := ac.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	valid, err := utils.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token, err := utils.GenerateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{Token: token})
}