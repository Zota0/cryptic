package routes

import (
	"x/cryptic/controllers"
	"x/cryptic/middleware"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// SetupRoutes configures all API routes
func SetupRoutes(r *gin.Engine, db *gorm.DB) {
	// Initialize controllers
	authController := controllers.NewAuthController(db)
	messageController := controllers.NewMessageController(db)
	transactionController := controllers.NewTransactionController(db)

	// Public routes
	public := r.Group("/api")
	{
		// Authentication routes
		public.POST("/register", authController.Register)
		public.POST("/login", authController.Login)
		public.GET("/auth/status", authController.Status)
	}

	// Protected routes
	protected := r.Group("/api")
	protected.Use(middleware.AuthMiddleware())
	{
		// Message routes
		protected.POST("/messages", messageController.SendMessage)
		protected.GET("/messages", messageController.GetMessages)

		// Transaction routes
		protected.POST("/transactions", transactionController.CreateTransaction)
		protected.GET("/transactions", transactionController.GetTransactions)
		protected.GET("/balance", transactionController.GetBalance)
	}
}