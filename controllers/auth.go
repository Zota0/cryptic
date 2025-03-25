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

type AuthController struct {
	db *gorm.DB
}

func NewAuthController(db *gorm.DB) *AuthController {
	return &AuthController{db: db}
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,alphanum,min=3,max=30"`
	Email    string `json:"email" binding:"required,email"`
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
	userID, exists := c.Get("user_id")
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
    // Log raw request body
    rawData, _ := c.GetRawData()
    fmt.Printf("[Register] Raw request body: %s\n", string(rawData))
    
    // Since we consumed the body, we need to restore it
    c.Request.Body = io.NopCloser(bytes.NewBuffer(rawData))

    var req RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        // Log validation error
        fmt.Printf("[Register] Validation error: %v\n", err)
        fmt.Printf("[Register] Request data attempted to parse: %+v\n", req)
        validationErrors := map[string]string{}
		if err.Error() == "EOF" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Request body is empty"})
			return
		}
		if strings.Contains(err.Error(), "username") {
			validationErrors["username"] = "Username must be 3-30 characters long and contain only letters and numbers"
		}
		if strings.Contains(err.Error(), "email") {
			validationErrors["email"] = "Please provide a valid email address"
		}
		if strings.Contains(err.Error(), "password") {
			validationErrors["password"] = "Password must be at least 8 characters long"
		}
		if len(validationErrors) == 0 {
			validationErrors["error"] = "Invalid request format"
		}

		validationErrors["error"] = "" + err.Error() + validationErrors["error"]
		c.JSON(http.StatusBadRequest, validationErrors)
		return
	}
	
	// Log successful parsing
	fmt.Printf("[Register] Successfully parsed request: username=%s, email=%s\n", req.Username, req.Email)

	// Check if username already exists (including soft-deleted users)
	var count int64
	if err := ac.db.Unscoped().Model(&models.User{}).Where("username = ?", req.Username).Count(&count).Error; err != nil {
		// This is an actual database error
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check username availability"})
		return
	}
	
	if count > 0 {
		// Check if it's a soft-deleted user
		var deletedUser models.User
		if err := ac.db.Unscoped().Where("username = ? AND deleted_at IS NOT NULL", req.Username).First(&deletedUser).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username is reserved"})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		}
		return
	}
	
	// Username is available, proceed with registration

	// Generate password hash
	fmt.Printf("[Register] Generating password hash for user %s\n", req.Username)
	passwordHash, err := utils.HashPassword(req.Password)
	if err != nil {
		fmt.Printf("[Register] Error hashing password: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	fmt.Printf("[Register] Password hash generated successfully\n")

	// Generate key pair for E2EE
	fmt.Printf("[Register] Generating key pair for E2EE\n")
	privateKey, publicKey, err := utils.GenerateKeyPair()
	if err != nil {
		fmt.Printf("[Register] Error generating key pair: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key pair"})
		return
	}
	fmt.Printf("[Register] Key pair generated successfully, public key length: %d\n", len(publicKey))

	// Encrypt private key with user's password hash as the key
	fmt.Printf("[Register] Encrypting private key\n")
	encryptedPrivKey, nonce, ephemPubKey, err := utils.EncryptMessage(privateKey, publicKey, privateKey)
	if err != nil {
		fmt.Printf("[Register] Error encrypting private key: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt private key"})
		return
	}
	fmt.Printf("[Register] Private key encrypted successfully\n")

	// Store encrypted private key info
	privateInfo := fmt.Sprintf("%s:%s:%s",
		base64.StdEncoding.EncodeToString(encryptedPrivKey),
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(ephemPubKey))

	// Create user
	fmt.Printf("[Register] Creating user in database: %s\n", req.Username)
	user := &models.User{
		Username:     req.Username,
		PasswordHash: passwordHash,
		PublicKey:    base64.StdEncoding.EncodeToString(publicKey),
		PrivateInfo:  privateInfo,
		Balance:      0,
	}

	if err := ac.db.Create(user).Error; err != nil {
		fmt.Printf("[Register] Error creating user in database: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	fmt.Printf("[Register] User created successfully with ID: %d\n", user.ID)

	// Generate JWT token
	fmt.Printf("[Register] Generating JWT token\n")
	token, err := utils.GenerateToken(user.ID)
	if err != nil {
		fmt.Printf("[Register] Error generating token: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	fmt.Printf("[Register] Token generated successfully\n")

	c.JSON(http.StatusCreated, AuthResponse{Token: token})
	fmt.Printf("[Register] Registration completed successfully for user: %s\n", req.Username)
}

// Login handles user authentication
func (ac *AuthController) Login(c *gin.Context) {
    // Log raw request body
    rawData, _ := c.GetRawData()
    fmt.Printf("[Login] Raw request body: %s\n", string(rawData))
    
    // Since we consumed the body, we need to restore it
    c.Request.Body = io.NopCloser(bytes.NewBuffer(rawData))

    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        // Log validation error
        fmt.Printf("[Login] Validation error: %v\n", err)
        fmt.Printf("[Login] Request data attempted to parse: %+v\n", req)
        validationErrors := map[string]string{}
		if err.Error() == "EOF" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Request body is empty"})
			return
		}
		if strings.Contains(err.Error(), "username") {
			validationErrors["username"] = "Username is required"
		}
		if strings.Contains(err.Error(), "password") {
			validationErrors["password"] = "Password is required"
		}
		if len(validationErrors) == 0 {
			validationErrors["error"] = "Invalid request format"
		}

		validationErrors["error"] = "" + err.Error() + validationErrors["error"]
		c.JSON(http.StatusBadRequest, validationErrors)
		return
	}
	
	// Log successful parsing
	fmt.Printf("[Login] Successfully parsed request: username=%s\n", req.Username)

	// Find user (excluding soft-deleted users)
	var user models.User
	if err := ac.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		// Check if user exists but is soft-deleted
		var deletedUser models.User
		if err := ac.db.Unscoped().Where("username = ? AND deleted_at IS NOT NULL", req.Username).First(&deletedUser).Error; err == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Account has been deactivated"})
			return
		}
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