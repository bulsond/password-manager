package core_test

import (
	"strings"
	"testing"

	"github.com/bulsond/password-manager/core"
)

// TestNewPasswordManager проверяет корректность создания менеджера паролей
func TestNewPasswordManager(t *testing.T) {
	t.Run("создаёт менеджер с пустым состоянием", func(t *testing.T) {
		filePath := "passwords.dat"
		pm := core.NewPasswordManager(filePath)

		// Проверка полей структуры
		if pm == nil {
			t.Fatal("ожидали непустой указатель на PasswordManager")
		}
		if pm.Passwords == nil {
			t.Error("ожидали, что Passwords будет инициализирован как пустая карта")
		}
		if len(pm.Passwords) != 0 {
			t.Errorf("ожидали пустую карту Passwords, получили длину %d", len(pm.Passwords))
		}
	})

	t.Run("String() возвращает ожидаемый формат вывода", func(t *testing.T) {
		filePath := "passwords.dat"
		pm := core.NewPasswordManager(filePath)

		expected := `Initialized: false
File path: passwords.dat
Passwords count: 0`

		actual := pm.String()

		if actual != expected {
			t.Errorf("несоответствие вывода String():\nожидали:\n%q\nполучили:\n%q", expected, actual)
		}
	})

	t.Run("String() не раскрывает чувствительные данные", func(t *testing.T) {
		pm := core.NewPasswordManager("secret.dat")

		output := pm.String()

		// Проверяем, что в выводе нет мастер-ключа или значений паролей
		sensitive := []string{"masterKey", "superSecret", "value", "Password{"}
		for _, s := range sensitive {
			if strings.Contains(output, s) {
				t.Errorf("вывод String() содержит чувствительную информацию: %q", s)
			}
		}
	})

	t.Run("String() отражает количество паролей", func(t *testing.T) {
		pm := core.NewPasswordManager("test.dat")

		// Добавляем тестовые пароли напрямую (в реальном коде — через методы)
		pm.Passwords["github.com"] = core.NewPassword("github.com", "pass1", "dev")
		pm.Passwords["gitlab.com"] = core.NewPassword("gitlab.com", "pass2", "dev")

		output := pm.String()

		// Проверяем, что в выводе указано правильное количество
		expectedCount := "Passwords count: 2"
		if !strings.Contains(output, expectedCount) {
			t.Errorf("ожидали, что вывод будет содержать %q, получили:\n%s", expectedCount, output)
		}
	})

	t.Run("String() с другим путём к файлу", func(t *testing.T) {
		testPaths := []string{
			"/var/secure/vault.db",
			"~/my-passwords.json",
			"C:\\Users\\vault\\data.enc",
		}

		for _, path := range testPaths {
			t.Run(path, func(t *testing.T) {
				pm := core.NewPasswordManager(path)
				output := pm.String()

				expectedLine := "File path: " + path
				if !strings.Contains(output, expectedLine) {
					t.Errorf("ожидали строку %q в выводе, получили:\n%s", expectedLine, output)
				}
			})
		}
	})
}
