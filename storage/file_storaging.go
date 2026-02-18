package storage

import (
	"os"

	"github.com/bulsond/password-manager/encryptors"
)

// FileStoraging хранение в файле
type FileStoraging struct{}

func (fs *FileStoraging) Save(filePath string, data encryptors.EncryptedData) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Сначала записываем IV
	if _, err := file.Write(data.IV); err != nil {
		return err
	}
	// Затем зашифрованные данные
	if _, err := file.Write(data.Data); err != nil {
		return err
	}
	return nil
}

func (fs *FileStoraging) Read(filePath string) (encryptors.EncryptedData, error) {
	panic("unimplemented")
}
