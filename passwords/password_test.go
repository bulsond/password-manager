package passwords

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Тестирование фабричной функции NewPassword
func TestNewPassword(t *testing.T) {
	t.Run("успешное создание", func(t *testing.T) {
		name := "example.com"
		value := "mySecretPassword"
		category := "social"

		password, err := NewPassword(name, value, category)

		if err != nil {
			t.Fatalf("ожидается отсутствие ошибки, получено: %v", err)
		}

		if password.Name != name {
			t.Errorf("Name = %q; ожидается %q", password.Name, name)
		}
		if password.Value != value {
			t.Errorf("Value = %q; ожидается %q", password.Value, value)
		}
		if password.Category != category {
			t.Errorf("Category = %q; ожидается %q", password.Category, category)
		}

		// Проверим, что время заполнено
		now := time.Now()
		if password.CreatedAt.IsZero() || password.LastModified.IsZero() {
			t.Error("CreatedAt или LastModified не были установлены")
		}

		// Проверим, что даты близки к текущему времени (допуск на выполнение)
		if password.CreatedAt.Sub(now).Abs().Seconds() > 5 {
			t.Error("CreatedAt выходит за пределы допустимого времени")
		}
	})

	t.Run("ошибка: пустое имя", func(t *testing.T) {
		_, err := NewPassword("", "pass", "cat")
		if err == nil {
			t.Fatal("ожидается ошибка при пустом имени")
		}
		expectedErr := errors.New("название сервиса или сайта не может быть пустым")
		if err.Error() != expectedErr.Error() {
			t.Errorf("ожидается ошибка %v, получено %v", expectedErr, err)
		}
	})

	t.Run("ошибка: пустое значение", func(t *testing.T) {
		_, err := NewPassword("site", "", "cat")
		if err == nil {
			t.Fatal("ожидается ошибка при пустом значении")
		}
		expectedErr := errors.New("значение пароля не может быть пустым")
		if err.Error() != expectedErr.Error() {
			t.Errorf("ожидается ошибка %v, получено %v", expectedErr, err)
		}
	})

	t.Run("ошибка: пустая категория", func(t *testing.T) {
		_, err := NewPassword("site", "pass", "")
		if err == nil {
			t.Fatal("ожидается ошибка при пустой категории")
		}
		expectedErr := errors.New("значение категории не может быть пустым")
		if err.Error() != expectedErr.Error() {
			t.Errorf("ожидается ошибка %v, получено %v", expectedErr, err)
		}
	})
}

// Тестирование JSON сериализации и десериализации
func TestPasswordJSONSerialization(t *testing.T) {
	name := "test.com"
	value := "secret123"
	category := "work"

	password, err := NewPassword(name, value, category)
	if err != nil {
		t.Fatalf("не удалось создать Password: %v", err)
	}

	// Сериализация в JSON
	jsonData, err := json.Marshal(password)
	if err != nil {
		t.Fatalf("ошибка при маршалинге в JSON: %v", err)
	}

	var decodedPassword Password
	err = json.Unmarshal(jsonData, &decodedPassword)
	if err != nil {
		t.Fatalf("ошибка при анмаршалинге из JSON: %v", err)
	}

	if decodedPassword.Name != password.Name {
		t.Errorf("Name после десериализации: %q, ожидалось: %q", decodedPassword.Name, password.Name)
	}
	if decodedPassword.Value != password.Value {
		t.Errorf("Value после десериализации: %q, ожидалось: %q", decodedPassword.Value, password.Value)
	}
	if decodedPassword.Category != password.Category {
		t.Errorf("Category после десериализации: %q, ожидалось: %q", decodedPassword.Category, password.Category)
	}
	if !decodedPassword.CreatedAt.Equal(password.CreatedAt) {
		t.Errorf("CreatedAt после десериализации не совпадает")
	}
	if !decodedPassword.LastModified.Equal(password.LastModified) {
		t.Errorf("LastModified после десериализации не совпадает")
	}
}
