package core

import (
	"time"
)

// Password тип сущности пароля
type Password struct {
	// название сервиса или сайта
	Name string `json:"name"`

	// значение пароля
	Value string `json:"value"`

	// категория для группировки
	Category string `json:"category"`

	// дата создания записи
	CreatedAt time.Time `json:"created_at"`

	// дата последнего изменения
	LastModified time.Time `json:"last_modified"`
}

// NewPassword создать экземпляр типа Password
func NewPassword(name, value, category string) Password {
	now := time.Now()
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    now,
		LastModified: now,
	}
}
