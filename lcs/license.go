package lcs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"reflect"
	"strings"

	"github.com/furkansenharputlu/f-license/config"

	"github.com/dgrijalva/jwt-go"

)

type License struct {
	ID           string                 `bson:"id" json:"id"`
	Headers      map[string]interface{} `bson:"headers" json:"headers"`
	Token        string                 `bson:"token" json:"token"`
	Claims       jwt.MapClaims          `bson:"claims" json:"claims"`
	Active       bool                   `bson:"active" json:"active"`
	Keys         config.Keys            `bson:"keys" json:"keys"`
	SignKey      interface{}
	SignKeyRaw   []byte
	VerifyKey    interface{}
	VerifyKeyRaw []byte
}

func (l *License) MarshalJSON() ([]byte, error) {

	res := map[string]interface{}{
		"id":      l.ID,
		"headers": l.Headers,
		"token":   l.Token,
		"claims":  l.Claims,
		"active":  l.Active,
	}

	if strings.HasPrefix(l.GetAlg(), "HS") {
		res["key_id"] = l.Keys.HMACSecret.KeyID
	} else if strings.HasPrefix(l.GetAlg(), "RS") {
		res["key_id"] = map[string]string{
			"public_key_id":  l.Keys.RSAPublicKey.KeyID,
			"private_key_id": l.Keys.RSAPrivateKey.KeyID,
		}
	}

	return json.Marshal(res)
}

func (l *License) GetAppName() (appName string) {
	app, ok := l.Headers["app"]
	if ok {
		appName = app.(string)
		return
	}

	return
}

func (l *License) SetAppName(appName string) {
	l.Headers["app"] = appName
}

// GetAlg returns alg defined in the license header.
func (l *License) GetAlg() (alg string) {
	algInt, ok := l.Headers["alg"]
	if ok {
		alg = algInt.(string)
		return
	}

	return alg
}

func (l *License) GetApp(appName string) (*config.App, error) {
	app, ok := config.Global.Apps[appName]
	if !ok {
		return nil, errors.New("app not found with given name")
	}

	return app, nil
}

func (l *License) ApplyApp() error {
	var alg string
	var keys config.Keys
	emptyKeys := config.Keys{}

	appName := l.GetAppName()
	if appName == "" {
		alg = l.GetAlg()
		keys = l.Keys
	} else {
		app, err := l.GetApp(appName)
		if err != nil {
			return err
		}

		alg = app.Alg
		keys = app.Keys
	}

	if alg == "" {
		alg = "HS256"
	}

	l.Headers["alg"] = alg

	if reflect.DeepEqual(keys, emptyKeys) {
		keys = config.Global.DefaultKeys
	}

	l.Keys = keys

	return nil
}

func (l *License) Generate() error {

	if len(l.Headers) == 0 {
		l.Headers = make(map[string]interface{})
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(l.GetAlg()), l.Claims)
	token.Header = l.Headers

	signedString, err := token.SignedString(l.SignKey)
	if err != nil {
		return err
	}

	l.Token = signedString

	l.ID = HexSHA256([]byte(signedString))

	return nil
}

func HexSHA256(key []byte) string {
	certSHA := sha256.Sum256(key)
	return hex.EncodeToString(certSHA[:])
}


func (l *License) EncryptKeys() error {

	/*switch l.signKey.(type) {
	case *rsa.PrivateKey:
		ciphertext, err := Encrypt([]byte(config.Global.AdminSecret), l.signKeyRaw)
		if err != nil {
			return err
		}

		l.Keys. = string(ciphertext)
	}
	if l.signKey == l.Keys.HMACSecret {
		ciphertext, err := Encrypt([]byte(config.Global.AdminSecret), []byte(l.Keys.HMACSecret))
		if err != nil {
			return err
		}

		l.Keys.HMACSecret = string(ciphertext)
	} else {

	}*/
	return nil

}

func (l *License) IsLicenseValid(tokenString string) (bool, error) {
	if !l.Active {
		return false, nil
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return l.VerifyKey, nil
		case *jwt.SigningMethodRSA:

			return l.VerifyKey, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	return token.Valid, err
}
