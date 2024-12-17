package models

type Client struct {
	BaseModel
	Secret        string `gorm:"type:varchar(255);not null;unique"` // Client secret (hashed)
	RedirectURI   string `gorm:"type:text;not null"`
	GrantTypes    string `gorm:"type:text"`                         // Comma-separated grant types
	ResponseTypes string `gorm:"type:text"`                         // Comma-separated response types
	Scopes        string `gorm:"type:text"`                         // Comma-separated scopes
	ContactEmail  string `gorm:"type:varchar(255);not null;unique"` // Contact email
	Name          string `gorm:"type:varchar(255);not null;unique"` // Client name
}
