package passwords

import (
	"testing"
)

func TestPassword(t *testing.T) {
	name := "github.com"
	value := "superSecretPassword123"
	category := "development"
	// now := time.Now()
	// want := Password{
	// 	Name:         name,
	// 	Value:        value,
	// 	Category:     category,
	// 	CreatedAt:    now,
	// 	LastModified: now,
	// }

	t.Run("Успешное создание экземпляра Password", func(t *testing.T) {
		got, err := NewPassword(name, value, category)
		if err != nil {
			t.Errorf("Не удалось создать Password: %s", err)
		}
		if got.Name != name {
			t.Errorf("Неверное название сервиса или сайта want %s, got %s", name, got.Name)
		}
		if got.Value != value {
			t.Errorf("Неверное значение пароля want %s, got %s", value, got.Value)
		}
		if got.Value != value {
			t.Errorf("Неверное значение категории want %s, got %s", category, got.Category)
		}
	})

}
