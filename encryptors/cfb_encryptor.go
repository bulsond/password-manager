package encryptors

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// CFBencryptor использование CFB
type CFBencryptor struct{}

func (e *CFBencryptor) Encrypt(key, data []byte) (EncryptedData, error) {
	// Создать новый блок шифрования AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedData{}, err
	}
	// Сгенерировать случайный вектор инициализации
	iv := make([]byte, aes.BlockSize) // BlockSize = 16 для AES
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return EncryptedData{}, err
	}
	// Создать шифровальщик и зашифровать данные
	stream := cipher.NewCFBEncrypter(block, iv)
	encryptedData := make([]byte, len(data))
	stream.XORKeyStream(encryptedData, data)

	return EncryptedData{
		Data: encryptedData,
		IV:   iv,
	}, nil
}

func (e *CFBencryptor) Decrypt(key []byte, data EncryptedData) (string, error) {
	panic("unimplemented")
}
