package repositories

import (
	"context"

	"github.com/dewciu/dew_auth_server/server/models"
	"gorm.io/gorm"
)

var _ IClientRepository = new(ClientRepository)

type IClientRepository interface {
	GetWithID(ctx context.Context, id string) (*models.Client, error)
	Create(ctx context.Context, client *models.Client) error
	DeleteWithID(ctx context.Context, id string) error
	Update(ctx context.Context, client *models.Client) error
}

type ClientRepository struct {
	database *gorm.DB
}

func NewClientRepository(database *gorm.DB) IClientRepository {
	return &ClientRepository{
		database: database,
	}
}

func (r *ClientRepository) GetWithID(ctx context.Context, id string) (*models.Client, error) {
	var client models.Client
	result := r.database.Where("id = ?", id).First(&client)
	if result.Error != nil {
		return nil, result.Error
	}

	return &client, nil
}

func (r *ClientRepository) Create(ctx context.Context, client *models.Client) error {
	result := r.database.WithContext(ctx).Create(client)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *ClientRepository) DeleteWithID(ctx context.Context, id string) error {
	result := r.database.WithContext(ctx).Where("id = ?", id).Delete(&models.Client{})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (r *ClientRepository) Update(ctx context.Context, client *models.Client) error {
	result := r.database.WithContext(ctx).Save(client)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
