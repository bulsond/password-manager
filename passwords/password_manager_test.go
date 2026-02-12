package passwords

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestNewPasswordManager(t *testing.T) {
	t.Run("должен возвращать ошибку при пустом пути к файлу", func(t *testing.T) {
		_, err := NewPasswordManager("")
		if err == nil {
			t.Fatal("ожидалась ошибка при пустом пути к файлу, получено nil")
		}
		if err.Error() != "путь к файлу хранения не может быть пустым" {
			t.Errorf("ожидалось сообщение об ошибке 'путь к файлу хранения не может быть пустым', получено '%s'", err.Error())
		}
	})

	t.Run("должен инициализироваться с пустым словарём паролей и пустым мастер-ключом", func(t *testing.T) {
		filePath := "/tmp/passwords.json"
		pm, err := NewPasswordManager(filePath)
		if err != nil {
			t.Fatalf("неожиданная ошибка при инициализации: %v", err)
		}
		if pm.FilePath != filePath {
			t.Errorf("ожидалось, что FilePath будет '%s', получено '%s'", filePath, pm.FilePath)
		}
		if len(pm.Passwords) != 0 {
			t.Errorf("ожидалось, что Passwords будет пустым словарём, получено %d элементов", len(pm.Passwords))
		}
		if len(pm.MasterKey) != 0 {
			t.Errorf("ожидалось, что MasterKey будет пустым, получено %d байт", len(pm.MasterKey))
		}
		if pm.IsInitialized {
			t.Errorf("ожидалось, что IsInitialized будет false, получено true")
		}
	})
}

func TestPasswordManager_JSON_Serialization(t *testing.T) {
	t.Run("должен корректно сериализоваться в JSON, исключая чувствительные поля", func(t *testing.T) {
		now := time.Now()
		pm := PasswordManager{
			Passwords: map[string]Password{
				"gmail": {
					Name:         "Gmail",
					Value:        "secret123",
					Category:     "email",
					CreatedAt:    now,
					LastModified: now.Add(time.Hour),
				},
				"github": {
					Name:         "GitHub",
					Value:        "token456",
					Category:     "code",
					CreatedAt:    now.Add(-24 * time.Hour),
					LastModified: now.Add(-12 * time.Hour),
				},
			},
			MasterKey:     []byte("supersecretkey123"),
			FilePath:      "/home/user/passwords.json",
			IsInitialized: true,
		}

		data, err := json.Marshal(pm)
		if err != nil {
			t.Fatalf("не удалось сериализовать PasswordManager в JSON: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("не удалось десериализовать JSON обратно: %v", err)
		}

		// Проверяем, что чувствительные поля отсутствуют в JSON
		if _, ok := result["MasterKey"]; ok {
			t.Error("поле MasterKey не должно присутствовать в JSON, но оно было включено")
		}
		if _, ok := result["FilePath"]; ok {
			t.Error("поле FilePath не должно присутствовать в JSON, но оно было включено")
		}
		if _, ok := result["IsInitialized"]; ok {
			t.Error("поле IsInitialized не должно присутствовать в JSON, но оно было включено")
		}

		// Проверяем, что поле Passwords присутствует и содержит корректные данные
		passwords, ok := result["passwords"]
		if !ok {
			t.Error("поле passwords отсутствует в выходном JSON")
		}
		passwordsMap, ok := passwords.(map[string]interface{})
		if !ok {
			t.Error("поле passwords должно быть объектом (map), но оно имеет другой тип")
		}
		if len(passwordsMap) != 2 {
			t.Errorf("ожидалось 2 пароля, получено %d", len(passwordsMap))
		}

		// Проверяем первый пароль (gmail)
		gmail, ok := passwordsMap["gmail"].(map[string]interface{})
		if !ok {
			t.Error("пароль 'gmail' должен быть объектом")
		}
		if name, ok := gmail["name"]; !ok || name != "Gmail" {
			t.Errorf("ожидалось имя 'Gmail', получено '%v'", name)
		}
		if value, ok := gmail["value"]; !ok || value != "secret123" {
			t.Errorf("ожидался пароль 'secret123', получено '%v'", value)
		}
		if category, ok := gmail["category"]; !ok || category != "email" {
			t.Errorf("ожидалась категория 'email', получена '%v'", category)
		}
		if _, ok := gmail["created_at"]; !ok {
			t.Error("поле created_at отсутствует для gmail")
		}
		if _, ok := gmail["last_modified"]; !ok {
			t.Error("поле last_modified отсутствует для gmail")
		}

		// Проверяем второй пароль (github)
		github, ok := passwordsMap["github"].(map[string]interface{})
		if !ok {
			t.Error("пароль 'github' должен быть объектом")
		}
		if name, ok := github["name"]; !ok || name != "GitHub" {
			t.Errorf("ожидалось имя 'GitHub', получено '%v'", name)
		}
		if value, ok := github["value"]; !ok || value != "token456" {
			t.Errorf("ожидался пароль 'token456', получено '%v'", value)
		}
		if category, ok := github["category"]; !ok || category != "code" {
			t.Errorf("ожидалась категория 'code', получена '%v'", category)
		}
		if _, ok := github["created_at"]; !ok {
			t.Error("поле created_at отсутствует для github")
		}
		if _, ok := github["last_modified"]; !ok {
			t.Error("поле last_modified отсутствует для github")
		}
	})

	t.Run("должен корректно десериализоваться из JSON с полными данными паролей", func(t *testing.T) {
		jsonData := `{
			"passwords": {
				"google": {
					"name": "Google",
					"value": "pass123",
					"category": "email",
					"created_at": "2026-01-15T10:00:00Z",
					"last_modified": "2026-02-10T14:30:00Z"
				},
				"twitter": {
					"name": "Twitter",
					"value": "pass456",
					"category": "social",
					"created_at": "2026-01-20T09:00:00Z",
					"last_modified": "2026-02-05T16:20:00Z"
				}
			}
		}`

		var pm PasswordManager
		if err := json.Unmarshal([]byte(jsonData), &pm); err != nil {
			t.Fatalf("не удалось десериализовать JSON: %v", err)
		}

		// Проверяем, что пароли загружены
		if len(pm.Passwords) != 2 {
			t.Errorf("ожидалось 2 пароля, получено %d", len(pm.Passwords))
		}

		google := pm.Passwords["google"]
		if google.Name != "Google" {
			t.Errorf("ожидалось имя 'Google', получено '%s'", google.Name)
		}
		if google.Value != "pass123" {
			t.Errorf("ожидался пароль 'pass123', получено '%s'", google.Value)
		}
		if google.Category != "email" {
			t.Errorf("ожидалась категория 'email', получена '%s'", google.Category)
		}
		if google.CreatedAt.IsZero() {
			t.Error("поле CreatedAt не должно быть нулевым")
		}
		if google.LastModified.IsZero() {
			t.Error("поле LastModified не должно быть нулевым")
		}

		twitter := pm.Passwords["twitter"]
		if twitter.Name != "Twitter" {
			t.Errorf("ожидалось имя 'Twitter', получено '%s'", twitter.Name)
		}
		if twitter.Value != "pass456" {
			t.Errorf("ожидался пароль 'pass456', получено '%s'", twitter.Value)
		}
		if twitter.Category != "social" {
			t.Errorf("ожидалась категория 'social', получена '%s'", twitter.Category)
		}
		if twitter.CreatedAt.IsZero() {
			t.Error("поле CreatedAt не должно быть нулевым")
		}
		if twitter.LastModified.IsZero() {
			t.Error("поле LastModified не должно быть нулевым")
		}

		// Проверяем, что чувствительные поля остались по умолчанию
		if len(pm.MasterKey) != 0 {
			t.Errorf("ожидалось, что MasterKey будет пустым, получено %d байт", len(pm.MasterKey))
		}
		if pm.FilePath != "" {
			t.Errorf("ожидалось, что FilePath будет пустым, получено '%s'", pm.FilePath)
		}
		if pm.IsInitialized {
			t.Errorf("ожидалось, что IsInitialized будет false, получено true")
		}
	})

	t.Run("должен корректно обрабатывать пустой JSON-объект", func(t *testing.T) {
		jsonData := `{}`

		var pm PasswordManager
		if err := json.Unmarshal([]byte(jsonData), &pm); err != nil {
			t.Fatalf("не удалось десериализовать пустой JSON: %v", err)
		}

		if len(pm.Passwords) != 0 {
			t.Errorf("ожидалось, что Passwords будет пустым словарём, получено %d элементов", len(pm.Passwords))
		}
		if len(pm.MasterKey) != 0 {
			t.Errorf("ожидалось, что MasterKey будет пустым, получено %d байт", len(pm.MasterKey))
		}
		if pm.FilePath != "" {
			t.Errorf("ожидалось, что FilePath будет пустым, получено '%s'", pm.FilePath)
		}
		if pm.IsInitialized {
			t.Errorf("ожидалось, что IsInitialized будет false, получено true")
		}
	})
}

func TestPasswordManager_FilePersistence(t *testing.T) {
	t.Run("должен корректно записывать и загружать данные из файла", func(t *testing.T) {
		// Создаём временный файл
		tempFile, err := os.CreateTemp("", "passwords_*.json")
		if err != nil {
			t.Fatalf("не удалось создать временный файл: %v", err)
		}
		defer os.Remove(tempFile.Name()) // очистка

		now := time.Now()
		pm := PasswordManager{
			Passwords: map[string]Password{
				"example": {
					Name:         "Пример",
					Value:        "mypassword",
					Category:     "тест",
					CreatedAt:    now,
					LastModified: now.Add(5 * time.Minute),
				},
			},
			MasterKey:     []byte("key"),
			FilePath:      tempFile.Name(),
			IsInitialized: true,
		}

		data, err := json.Marshal(pm)
		if err != nil {
			t.Fatalf("не удалось сериализовать PasswordManager: %v", err)
		}

		if err := os.WriteFile(tempFile.Name(), data, 0644); err != nil {
			t.Fatalf("не удалось записать данные в файл: %v", err)
		}

		// Читаем данные обратно из файла
		content, err := os.ReadFile(tempFile.Name())
		if err != nil {
			t.Fatalf("не удалось прочитать файл: %v", err)
		}

		var loaded PasswordManager
		if err := json.Unmarshal(content, &loaded); err != nil {
			t.Fatalf("не удалось десериализовать данные из файла: %v", err)
		}

		// Проверяем, что только Passwords были загружены
		if len(loaded.Passwords) != 1 {
			t.Errorf("ожидалось 1 пароль, получено %d", len(loaded.Passwords))
		}

		example := loaded.Passwords["example"]
		if example.Name != "Пример" {
			t.Errorf("ожидалось имя 'Пример', получено '%s'", example.Name)
		}
		if example.Value != "mypassword" {
			t.Errorf("ожидался пароль 'mypassword', получено '%s'", example.Value)
		}
		if example.Category != "тест" {
			t.Errorf("ожидалась категория 'тест', получена '%s'", example.Category)
		}
		if example.CreatedAt.IsZero() {
			t.Error("поле CreatedAt не должно быть нулевым")
		}
		if example.LastModified.IsZero() {
			t.Error("поле LastModified не должно быть нулевым")
		}

		// Проверяем, что чувствительные поля не загрузились
		if len(loaded.MasterKey) != 0 {
			t.Errorf("ожидалось, что MasterKey будет пустым, получено %d байт", len(loaded.MasterKey))
		}
		if loaded.FilePath != "" {
			t.Errorf("ожидалось, что FilePath будет пустым, получено '%s'", loaded.FilePath)
		}
		if loaded.IsInitialized {
			t.Errorf("ожидалось, что IsInitialized будет false, получено true")
		}
	})
}

func TestGeneratePassword(t *testing.T) {
	pm, _ := NewPasswordManager("test.dat")

	t.Run("успешное создание пароля с длинной в 12 символов", func(t *testing.T) {
		pswd, err := pm.GeneratePassword(12)
		if err != nil {
			t.Errorf("пароль в 12 символов не создан, получена ошибка: %s", err)
		}
		if len(pswd) != 12 {
			t.Errorf("ожидался пароль в 12 символов, а получен длиной в: %d", len(pswd))
		}
	})
	t.Run("безуспешная попытка создания пароля с длинной в 4 символа", func(t *testing.T) {
		_, err := pm.GeneratePassword(4)
		if err == nil {
			t.Fatal("ожидалась ошибка при коротком пароле, получено nil")
		}
		if err.Error() != "длина пароля не может быть меньше 8 символов" {
			t.Errorf("ожидалось сообщение об ошибке 'длина пароля не может быть меньше 8 символов', получено '%s'", err.Error())
		}
	})
}

func TestSavePassword(t *testing.T) {
	pm, _ := NewPasswordManager("test.dat")
	pm.IsInitialized = true

	t.Run("успешно сохранен пароль", func(t *testing.T) {
		err := pm.SavePassword("github.com", "MyPassword123", "dev")
		if err != nil {
			t.Errorf("ожидалось успешное сохранение пароля, а получена ошибка: %s", err)
		}
		if _, ok := pm.Passwords["github.com"]; !ok {
			t.Error("не найден пароль среди сохраненных паролей")
		}
	})
	t.Run("ошибка: менеджер должен быть инициализирован", func(t *testing.T) {
		pm, _ := NewPasswordManager("test.dat")
		err := pm.SavePassword("github.com", "MyPassword123", "dev")
		if err == nil {
			t.Fatal("ожидалась ошибка об инициализации, а получено nil")
		}
		if err.Error() != "менеджер паролей не инициализирован" {
			t.Errorf("ожидалось сообщение об ошибке 'менеджер паролей не инициализирован', получено '%s'", err.Error())
		}
	})
	t.Run("ошибка: пустое имя", func(t *testing.T) {
		err := pm.SavePassword("", "pass", "cat")
		if err == nil {
			t.Fatal("ожидается ошибка при пустом имени")
		}
		expectedErr := errors.New("название сервиса или сайта не может быть пустым")
		if err.Error() != expectedErr.Error() {
			t.Errorf("ожидается ошибка %v, получено %v", expectedErr, err)
		}
	})
	t.Run("ошибка: пустое значение", func(t *testing.T) {
		err := pm.SavePassword("site", "", "cat")
		if err == nil {
			t.Fatal("ожидается ошибка при пустом значении")
		}
		expectedErr := errors.New("значение пароля не может быть пустым")
		if err.Error() != expectedErr.Error() {
			t.Errorf("ожидается ошибка %v, получено %v", expectedErr, err)
		}
	})
	t.Run("ошибка: пустая категория", func(t *testing.T) {
		err := pm.SavePassword("site", "pass", "")
		if err == nil {
			t.Fatal("ожидается ошибка при пустой категории")
		}
		expectedErr := errors.New("значение категории не может быть пустым")
		if err.Error() != expectedErr.Error() {
			t.Errorf("ожидается ошибка %v, получено %v", expectedErr, err)
		}
	})
	t.Run("ошибка: пароль должен иметь оригинальное название", func(t *testing.T) {
		pm, _ := NewPasswordManager("test.dat")
		pm.IsInitialized = true
		err1 := pm.SavePassword("github.com", "MyPassword123", "dev")
		if err1 != nil {
			t.Fatal("предварительное сохранение пароля вызвало неожиданную ошибку")
		}

		err2 := pm.SavePassword("github.com", "MyPassword123", "dev")
		if err2 == nil {
			t.Fatal("ожидалась ошибка о дублировании пароля, а получено nil")
		}
		if err2.Error() != "такой пароль уже существует" {
			t.Errorf("ожидалось сообщение об ошибке 'такой пароль уже существует', получено '%s'", err2.Error())
		}
	})
}

func TestGetPassword(t *testing.T) {
	t.Run("успешно получен пароль", func(t *testing.T) {
		pm, _ := NewPasswordManager("test.dat")
		pm.IsInitialized = true
		err := pm.SavePassword("github.com", "MyPassword123", "dev")
		if err != nil {
			t.Fatal("ожидалось успешное сохранение пароля перед попыткой получения пароля")
		}
		pwd, err := pm.GetPassword("github.com")
		if err != nil {
			t.Fatalf("ожидалось получение пароля, а получена ошибка: %s", err)
		}
		if pwd.Name != "github.com" {
			t.Error("не найден пароль среди сохраненных паролей")
		}
		if pwd.Value != "MyPassword123" {
			t.Error("не найден пароль среди сохраненных паролей")
		}
		if pwd.Category != "dev" {
			t.Error("не найден пароль среди сохраненных паролей")
		}
	})
	t.Run("ошибка: менеджер должен быть инициализирован", func(t *testing.T) {
		pm, _ := NewPasswordManager("test.dat")
		_, err := pm.GetPassword("github.com")
		if err == nil {
			t.Fatal("ожидалась ошибка об инициализации, а получено nil")
		}
		if err.Error() != "менеджер паролей не инициализирован" {
			t.Errorf("ожидалось сообщение об ошибке 'менеджер паролей не инициализирован', получено '%s'", err.Error())
		}
	})

	t.Run("ошибка: пароль не найден", func(t *testing.T) {
		pm, _ := NewPasswordManager("test.dat")
		pm.IsInitialized = true
		_, err := pm.GetPassword("github.com")
		if err == nil {
			t.Fatal("ожидалось получение ошибки 'пароль не найден' а получено nil")
		}
		if err.Error() != "пароль не найден" {
			t.Errorf("ожидалось сообщение об ошибке 'пароль не найден', получено '%s'", err.Error())
		}
	})
}

func TestListPasswords(t *testing.T) {
	t.Run("ошибка: менеджер должен быть инициализирован", func(t *testing.T) {
		pm, _ := NewPasswordManager("test.dat")
		_, err := pm.ListPasswords()
		if err == nil {
			t.Fatal("ожидалась ошибка об инициализации, а получено nil")
		}
		if err.Error() != "менеджер паролей не инициализирован" {
			t.Errorf("ожидалось сообщение об ошибке 'менеджер паролей не инициализирован', получено '%s'", err.Error())
		}
	})

	t.Run("успешно получен список паролей", func(t *testing.T) {
		pm, _ := NewPasswordManager("test.dat")
		pm.IsInitialized = true
		pm.SavePassword("github.com", "GitPass123", "dev")
		pm.SavePassword("gmail.com", "MailPass456", "email")
		pm.SavePassword("netflix.com", "NetflixPass789", "entertainment")

		pwds, err := pm.ListPasswords()
		if err != nil {
			t.Errorf("получение списка паролей вызвало ошибку: %s", err)
		}
		if len(pwds) != 3 {
			t.Error("количество полученных паролей не соответствует количеству сохраненных")
		}

	})

	t.Run("успешно получен пустой список паролей", func(t *testing.T) {
		pm, _ := NewPasswordManager("test.dat")
		pm.IsInitialized = true

		pwds, err := pm.ListPasswords()
		if err != nil {
			t.Errorf("получение списка паролей вызвало ошибку: %s", err)
		}
		if len(pwds) != 0 {
			t.Error("ожидалость получение пустого списка паролей, а получен непустой список")
		}

	})
}
