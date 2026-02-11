package passwords

import "errors"

// PasswordManager работа с паролями
type PasswordManager struct {
	// Passwords хранилище паролей, где ключ - название сервиса
	Passwords map[string]Password `json:"passwords"`

	// MasterKey главный ключ шифрования, используется для защиты всех паролей
	MasterKey []byte `json:"-"`

	// FilePath путь к файлу для хранения зашифрованных данных
	FilePath string `json:"-"`

	// IsInitialized флаг, показывающий установлен ли мастер-пароль
	IsInitialized bool `json:"-"`
}

// NewPasswordManager создание экземпляра PasswordManager
func NewPasswordManager(filePath string) (PasswordManager, error) {
	if len(filePath) == 0 {
		return PasswordManager{},
			errors.New("путь к файлу хранения не может быть пустым")
	}

	return PasswordManager{
		Passwords:     map[string]Password{},
		MasterKey:     []byte{},
		FilePath:      filePath,
		IsInitialized: false,
	}, nil
}
