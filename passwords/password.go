package passwords

import (
	"errors"
	"time"
)

// Password тип сущности пароля
type Password struct {
	// название сервиса или сайта
	Name string

	// значение пароля
	Value string

	// категория для группировки
	Category string

	// дата создания записи
	CreatedAt time.Time

	// дата последнего изменения
	LastModified time.Time
}

// NewPassword создать экземпляр типа Password
func NewPassword(name, value, category string) (Password, error) {
	if len(name) == 0 {
		return Password{},
			errors.New("Название сервиса или сайта не может быть пустым")
	}
	if len(value) == 0 {
		return Password{},
			errors.New("Значение пароля не может быть пустым")
	}
	if len(category) == 0 {
		return Password{},
			errors.New("Значение категории не может быть пустым")
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
