package passwords

import (
	"crypto/rand"
	"errors"
	"math/big"
)

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

// GeneratePassword генерация пароля с длинной не менее 8 символов
func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "",
			errors.New("длина пароля не может быть меньше 8 символов")
	}
	result := make([]byte, length)
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789" +
		"!@#$%^&*()-_=+[]{}|;:,.<>?"
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", err
		}
		result[i] = charset[idx.Int64()]
	}

	//
	return string(result), nil
}

// SavePassword создание и внесение в список паролей у менеджера паролей
func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.IsInitialized {
		return errors.New("менеджер паролей не инициализирован")
	}
	pwd, err := NewPassword(name, value, category)
	if err != nil {
		return err
	}
	if _, ok := pm.Passwords[name]; ok {
		return errors.New("такой пароль уже существует")
	}

	pm.Passwords[pwd.Name] = pwd

	return nil
}
