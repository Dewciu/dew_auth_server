package models

import (
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Client struct {
	BaseModel
	ID            uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	Secret        string    `gorm:"type:varchar(255);unique"`
	RedirectURI   string    `gorm:"type:text;not null"`
	GrantTypes    string    `gorm:"type:text"`
	ResponseTypes string    `gorm:"type:text"`
	Scopes        string    `gorm:"type:text"`
	ContactEmail  string    `gorm:"type:varchar(255);not null;unique"`
	Name          string    `gorm:"type:varchar(255);not null;unique"`
	Public        bool      `gorm:"type:boolean;not null;default:false"`
}

func (c *Client) BeforeSave(tx *gorm.DB) (err error) {
	if !c.Public && c.Secret == "" {
		return errors.New("secret is required when public is true")
	}
	return nil
}
