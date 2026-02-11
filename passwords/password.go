package passwords

import (
	"errors"
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
func NewPassword(name, value, category string) (Password, error) {
	if len(name) == 0 {
		return Password{},
			errors.New("название сервиса или сайта не может быть пустым")
	}
	if len(value) == 0 {
		return Password{},
			errors.New("значение пароля не может быть пустым")
	}
	if len(category) == 0 {
		return Password{},
			errors.New("значение категории не может быть пустым")
	}

	now := time.Now()
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    now,
		LastModified: now,
	}, nil
}
