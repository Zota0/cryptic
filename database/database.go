package database

import (
	"log"
	"x/cryptic/models"

	"gorm.io/gorm"
)

// InitDB initializes the database connection and performs migrations
func InitDB(db *gorm.DB) {
	// Disable foreign key constraint checks temporarily
	db.Exec("SET FOREIGN_KEY_CHECKS = 0")

	// Auto-migrate the schema
	log.Println("Running database migrations...")
	err2 := db.AutoMigrate(
		&models.User{},
		&models.Message{},
		&models.Transaction{},
	)
	if err2 != nil {
		log.Printf("Migration warning: %v", err2)
	}

	// Re-enable foreign key constraint checks
	db.Exec("SET FOREIGN_KEY_CHECKS = 1")

	// Verify foreign key constraints
	if err := db.SetupJoinTable(&models.User{}, "Messages", &models.Message{}); err != nil {
		log.Printf("Foreign key setup warning: %v", err)
	}
	if err := db.SetupJoinTable(&models.User{}, "Transactions", &models.Transaction{}); err != nil {
		log.Printf("Foreign key setup warning: %v", err)
	}

	log.Println("Database migrations completed successfully")
}