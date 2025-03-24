package main

import (
	"log"
	"net/http"
	"os"
	_ "path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"x/cryptic/database"
	"x/cryptic/middleware"
	"x/cryptic/routes"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using system environment variables")
	}

	// Set up database connection
	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		dsn = "root:password@tcp(127.0.0.1:3306)/cryptic?charset=utf8mb4&parseTime=True&loc=Local"
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize database
	database.InitDB(db)

	// Set up Gin router
	r := gin.Default()

	// Set up middleware
	r.Use(middleware.CORSMiddleware())

	// Set up API routes first
	routes.SetupRoutes(r, db)

	// Serve static files from frontend directory
	r.Static("/static", "./frontend/static")

	// Serve frontend HTML files
	r.LoadHTMLGlob("frontend/*.html")

	// Frontend routes
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})
	r.GET("/messages", func(c *gin.Context) {
		c.HTML(http.StatusOK, "messages.html", nil)
	})
	r.GET("/transactions", func(c *gin.Context) {
		c.HTML(http.StatusOK, "transactions.html", nil)
	})

	// Handle 404 for frontend routes
	r.NoRoute(func(c *gin.Context) {
		if c.Request.Header.Get("Accept") == "application/json" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
			return
		}
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}