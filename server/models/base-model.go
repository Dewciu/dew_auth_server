package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type BaseModel struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"` // UUID generation
	CreatedAt time.Time      `gorm:"not null;default:current_timestamp"`             // Default creation time
	UpdatedAt time.Time      `gorm:"not null;default:current_timestamp"`             // Updated via triggers or GORM hooks
	DeletedAt gorm.DeletedAt `gorm:"index"`                                          // Soft delete support
}
