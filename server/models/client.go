package models

type Client struct {
	BaseModel
	Secret        string `gorm:"type:varchar(255);not null"` // Client secret (hashed)
	RedirectURIs  string `gorm:"type:text;not null"`         // Comma-separated redirect URIs
	GrantTypes    string `gorm:"type:text;not null"`         // Comma-separated grant types
	ResponseTypes string `gorm:"type:text;not null"`         // Comma-separated response types
	Scopes        string `gorm:"type:text;not null"`         // Comma-separated scopes
	ContactEmail  string `gorm:"type:varchar(255);not null"` // Contact email
	Name          string `gorm:"type:varchar(255);not null"` // Client name
}
