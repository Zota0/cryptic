package controllers

import (
	"net/http"
	"time"

	"x/cryptic/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type TransactionController struct {
	db *gorm.DB
}

func NewTransactionController(db *gorm.DB) *TransactionController {
	return &TransactionController{db: db}
}

type CreateTransactionRequest struct {
	Amount      float64 `json:"amount" binding:"required"`
	Description string  `json:"description"`
}

type TransactionResponse struct {
	ID          uint      `json:"id"`
	Amount      float64   `json:"amount"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

type BalanceResponse struct {
	Balance float64 `json:"balance"`
}

// CreateTransaction handles creating a new transaction
func (tc *TransactionController) CreateTransaction(c *gin.Context) {
	// Get user ID from JWT token
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req CreateTransactionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Start transaction
	tx := tc.db.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
		return
	}

	// Create transaction record
	transaction := &models.Transaction{
		UserID:      uint(userID.(uint)),
		Amount:      req.Amount,
		Description: req.Description,
		Timestamp:   time.Now(),
	}

	if err := tx.Create(transaction).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create transaction"})
		return
	}

	// Update user balance
	if err := tx.Model(&models.User{}).Where("id = ?", userID).Update("balance", gorm.Expr("balance + ?", req.Amount)).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update balance"})
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	c.JSON(http.StatusCreated, TransactionResponse{
		ID:          transaction.ID,
		Amount:      transaction.Amount,
		Description: transaction.Description,
		Timestamp:   transaction.Timestamp,
	})
}

// GetTransactions retrieves all transactions for the current user
func (tc *TransactionController) GetTransactions(c *gin.Context) {
	// Get user ID from JWT token
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get user's transactions
	var transactions []models.Transaction
	if err := tc.db.Where("user_id = ?", userID).Order("timestamp desc").Find(&transactions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get transactions"})
		return
	}

	// Format response
	response := make([]TransactionResponse, len(transactions))
	for i, t := range transactions {
		response[i] = TransactionResponse{
			ID:          t.ID,
			Amount:      t.Amount,
			Description: t.Description,
			Timestamp:   t.Timestamp,
		}
	}

	c.JSON(http.StatusOK, response)
}

// GetBalance retrieves the current balance for the user
func (tc *TransactionController) GetBalance(c *gin.Context) {
	// Get user ID from JWT token
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get user's balance
	var user models.User
	if err := tc.db.Select("balance").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get balance"})
		return
	}

	c.JSON(http.StatusOK, BalanceResponse{Balance: user.Balance})
}