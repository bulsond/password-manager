package core

import "fmt"

// PasswordManager работа с паролями
type PasswordManager struct {
	// passwords хранилище паролей, где ключ - название сервиса
	Passwords map[string]Password `json:"passwords"`

	// masterKey главный ключ шифрования, используется для защиты всех паролей
	masterKey []byte `json:"-"`

	// filePath путь к файлу для хранения зашифрованных данных
	filePath string `json:"-"`

	// isInitialized флаг, показывающий установлен ли мастер-пароль
	isInitialized bool `json:"-"`
}

// String реализует интерфейс fmt.Stringer для безопасного отображения менеджера паролей
// Вывод не содержит чувствительных данных (мастер-ключ, значения паролей)
func (pm *PasswordManager) String() string {
	return fmt.Sprintf("Initialized: %v\nFile path: %s\nPasswords count: %d",
		pm.isInitialized,
		pm.filePath,
		len(pm.Passwords),
	)
}

// NewPasswordManager создание экземпляра PasswordManager
func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		Passwords:     make(map[string]Password),
		masterKey:     []byte{},
		filePath:      filePath,
		isInitialized: false,
	}
}
