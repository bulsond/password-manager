package core_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/bulsond/password-manager/core"
)

// TestNewPassword проверяет корректность работы фабричной функции
func TestNewPassword(t *testing.T) {
	t.Run("создаёт пароль с корректными полями", func(t *testing.T) {
		name := "github.com"
		value := "superSecretPassword123"
		category := "development"

		password := core.NewPassword(name, value, category)

		if password.Name != name {
			t.Errorf("ожидали Name = %q, получили %q", name, password.Name)
		}
		if password.Value != value {
			t.Errorf("ожидали Value = %q, получили %q", value, password.Value)
		}
		if password.Category != category {
			t.Errorf("ожидали Category = %q, получили %q", category, password.Category)
		}
	})

	t.Run("устанавливает временные метки корректно", func(t *testing.T) {
		before := time.Now()
		password := core.NewPassword("test", "pass", "cat")
		after := time.Now()

		// CreatedAt и LastModified должны быть равны
		if !password.CreatedAt.Equal(password.LastModified) {
			t.Errorf("ожидали, что CreatedAt == LastModified, но %v != %v",
				password.CreatedAt, password.LastModified)
		}

		// Временная метка должна быть в разумных пределах времени выполнения теста
		if password.CreatedAt.Before(before) || password.CreatedAt.After(after) {
			t.Errorf("ожидали, что время создания между %v и %v, получили %v",
				before, after, password.CreatedAt)
		}
	})

	t.Run("маршалируется в JSON с ожидаемой структурой", func(t *testing.T) {
		password := core.NewPassword("github.com", "superSecretPassword123", "development")

		data, err := json.Marshal(password)
		if err != nil {
			t.Fatalf("ошибка маршалинга: %v", err)
		}

		// Распарсим в map для проверки отдельных полей
		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("ошибка анмаршалинга: %v", err)
		}

		// Проверка строковых полей
		tests := []struct {
			key      string
			expected string
		}{
			{"name", "github.com"},
			{"value", "superSecretPassword123"},
			{"category", "development"},
		}
		for _, tt := range tests {
			if result[tt.key] != tt.expected {
				t.Errorf("ожидали %s = %q, получили %q", tt.key, tt.expected, result[tt.key])
			}
		}

		// Проверка временных полей: должны быть валидным RFC3339
		for _, field := range []string{"created_at", "last_modified"} {
			tStr, ok := result[field].(string)
			if !ok {
				t.Errorf("ожидали, что %q будет string, получили %T", field, result[field])
				continue
			}
			if _, err := time.Parse(time.RFC3339, tStr); err != nil {
				t.Errorf("ожидали, что %q будет валидным RFC3339, ошибка: %v", field, err)
			}
		}

		// Дополнительно: проверим, что created_at и last_modified равны в JSON
		if result["created_at"] != result["last_modified"] {
			t.Errorf("ожидали, что created_at == last_modified в JSON, но %q != %q",
				result["created_at"], result["last_modified"])
		}
	})
}
