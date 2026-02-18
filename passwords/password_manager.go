package passwords

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/bulsond/password-manager/encryptors"
)

// Encryptor операции по (де)шифрованию паролей
type Encryptor interface {
	// Зашифровать данные
	Encrypt(key, data []byte) (encryptors.EncryptedData, error)
	// Дешифровать данные
	Decrypt(key []byte, data encryptors.EncryptedData) (string, error)
}

// Storaging операции по хранению данных паролей
type Storaging interface {
	// Save сохранение в файл зашифрованных паролей
	Save(filePath string, data encryptors.EncryptedData) error

	// Read вычитка из файла зашифрованных паролей
	Read(filePath string) (encryptors.EncryptedData, error)
}

var (
	ErrWeakPassword        = errors.New("длина пароля не может быть меньше 8 символов")
	ErrNotInitialized      = errors.New("менеджер паролей не инициализирован")
	ErrEmptyFilePath       = errors.New("путь к файлу хранения не может быть пустым")
	ErrPasswordDuplication = errors.New("такой пароль уже существует")
	ErrPasswordNotFound    = errors.New("пароль не найден")
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
			ErrEmptyFilePath
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
			ErrWeakPassword
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

// SavePassword создание и внесение в список паролей
func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.IsInitialized {
		return ErrNotInitialized
	}
	pwd, err := NewPassword(name, value, category)
	if err != nil {
		return err
	}
	if _, ok := pm.Passwords[name]; ok {
		return ErrPasswordDuplication
	}

	pm.Passwords[pwd.Name] = pwd

	return nil
}

// GetPassword извлечение пароля по его имени из списка паролей
func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.IsInitialized {
		return Password{},
			ErrNotInitialized
	}
	if pwd, ok := pm.Passwords[name]; !ok {
		return Password{},
			ErrPasswordNotFound
	} else {
		return pwd, nil
	}
}

// ListPasswords получение списка всех паролей
func (pm *PasswordManager) ListPasswords() ([]Password, error) {
	if !pm.IsInitialized {
		return []Password{},
			ErrNotInitialized
	}

	cap := len(pm.Passwords)
	if cap == 0 {
		return []Password{}, nil
	}

	result := make([]Password, 0, cap)
	for _, p := range pm.Passwords {
		result = append(result, p)
	}

	return result, nil
}

// SetMasterPassword установка мастер-пароля
func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	masterKey := make([]byte, 32)
	copied := copy(masterKey, masterPassword)
	if copied < 8 {
		return ErrWeakPassword
	}

	pm.MasterKey = masterKey
	pm.IsInitialized = true
	return nil
}

// SaveToFile сохранение в файл состояния менеджера паролей
func (pm *PasswordManager) SaveToFile(encryptor Encryptor, storage Storaging) error {
	// Проверить, что менеджер инициализирован
	if !pm.IsInitialized {
		return ErrNotInitialized
	}

	// Сериализовать map паролей в JSON
	data, err := json.Marshal(pm.Passwords)
	if err != nil {
		return err
	}

	// Зашифруем
	encryptedData, err := encryptor.Encrypt(pm.MasterKey, data)
	if err != nil {
		return err
	}

	// Сохранить IV и зашифрованные данные в файл
	err = storage.Save(pm.FilePath, encryptedData)
	if err != nil {
		return err
	}

	return nil
}
