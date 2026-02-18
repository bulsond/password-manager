package encryptors

// EncryptedData зашифрованные данные паролей
type EncryptedData struct {
	// Вектор
	IV []byte
	// Данные
	Data []byte
}
