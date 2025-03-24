package database

import (
	"log"
	"x/cryptic/models"

	"gorm.io/gorm"
)

// InitDB initializes the database connection and performs migrations
func InitDB(db *gorm.DB) {
	// Auto-migrate the schema
	log.Println("Running database migrations...")
	err2 := db.AutoMigrate(
		&models.User{},
		&models.Message{},
		&models.Transaction{},
	)
	if err2 != nil {
		log.Fatalf("Failed to migrate database: %v", err2)
	}
	log.Println("Database migrations completed successfully")
}