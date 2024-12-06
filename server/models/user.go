package models

// User represents a user in the OAuth system.
type User struct {
	BaseModel
	Username     string `gorm:"unique;not null"`
	PasswordHash string `gorm:"not null"`
	Email        string `gorm:"unique;not null"`
}
