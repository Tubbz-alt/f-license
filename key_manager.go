package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/furkansenharputlu/f-license/config"
	"github.com/furkansenharputlu/f-license/lcs"
	"github.com/furkansenharputlu/f-license/storage"
	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"
)

type KeyManager struct {
}

func (m *KeyManager) GetOrAddHMACSecret(k *config.Key) error {

	if k.KeyID != "" {
		log.Debugf("HMAC key will be used with the given ID %s", k.KeyID)
		err := storage.GlobalKeyHandler.GetByID(k.KeyID, k)
		if err != nil {
			logrus.WithError(err).Errorf("HMAC key with the given ID couldn't be retrieved: %s", k.KeyID)
			return err
		}

		val, err := Decrypt([]byte(config.Global.Secret), k.Encrypted)
		if err != nil {
			return err
		}

		k.Raw=string(val)
	}

	log.Debug("Raw HMAC secret will be used")

	var err error
	rawKeyInBytes := []byte(k.Raw)

	k.Encrypted, err = Encrypt([]byte(config.Global.Secret), rawKeyInBytes)
	if err != nil {
		log.Error("Raw key couldn't be encrypted")
		return err
	}

	k.KeyID = lcs.HexSHA256(rawKeyInBytes)

	err = storage.GlobalKeyHandler.AddIfNotExisting(k)
	if err != nil {
		logrus.WithError(err).Error("Key couldn't be stored")
		return err
	}

	return nil
}

func (m *KeyManager) AddRSAPair(pair *config.RSAPair) error {

	// TODO check for private and public keys match, otherwise raise error

	var err error

	// Private key
	privateRawKeyInBytes := []byte(pair.Private.Raw)

	pair.Private.Encrypted, err = Encrypt([]byte(config.Global.Secret), privateRawKeyInBytes)
	if err != nil {
		log.Error("Raw private key couldn't be encrypted")
		return err
	}

	pair.Private.KeyID = lcs.HexSHA256(privateRawKeyInBytes)

	err = storage.GlobalKeyHandler.AddIfNotExisting(&pair.Private)
	if err != nil {
		logrus.WithError(err).Error("Private key couldn't be stored")
		return err
	}

	// Public key
	publicRawKeyInBytes := []byte(pair.Private.Raw)

	pair.Public.Encrypted, err = Encrypt([]byte(config.Global.Secret), publicRawKeyInBytes)
	if err != nil {
		log.Error("Raw public key couldn't be encrypted")
		return err
	}

	pair.Public.KeyID = lcs.HexSHA256(publicRawKeyInBytes)

	err = storage.GlobalKeyHandler.AddIfNotExisting(&pair.Public)
	if err != nil {
		logrus.WithError(err).Error("Public key couldn't be stored")
		return err
	}

	return nil
}

// https://itnext.io/encrypt-data-with-a-password-in-go-b5366384e291
func Encrypt(key, data []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// https://itnext.io/encrypt-data-with-a-password-in-go-b5366384e291
func Decrypt(key, data []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
