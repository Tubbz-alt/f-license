package lcs

import (
	"errors"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"strings"

	"github.com/furkansenharputlu/f-license/config"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func fatalf(format string, err error) {
	if err != nil {
		logrus.Fatalf(format, err)
	}
}

type License struct {
	ID        primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	Headers   map[string]interface{} `bson:"headers" json:"headers"`
	Hash      string                 `bson:"hash" json:"-"`
	Token     string                 `bson:"token" json:"token"`
	Claims    jwt.MapClaims          `bson:"claims" json:"claims"`
	Active    bool                   `bson:"active" json:"active"`
	Keys      config.Keys           `bson:"keys" json:"keys"`
	signKey   interface{}
	verifyKey interface{}
}

func (l *License) GetAppName() (appName string) {
	app, ok := l.Headers["app"]
	if ok {
		appName = app.(string)
		return
	}

	return
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

func (l *License) ApplyApp(appName string) error {
	var alg string
	var keys config.Keys
	emptyKeys := config.Keys{}

	if appName == "" {
		alg = l.GetAlg()
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

	if keys == emptyKeys {
		keys = config.Global.DefaultKeys
	}

	l.Keys = keys

	return nil
}

func (l *License) Generate() error {

	if len(l.Headers) == 0 {
		l.Headers = make(map[string]interface{})
	}

	err := l.ApplyApp(l.GetAppName())
	if err != nil {
		return err
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(l.GetAlg()), l.Claims)
	token.Header = l.Headers

	l.LoadSignKey()
	l.LoadVerifyKey()

	signedString, err := token.SignedString(l.signKey)
	if err != nil {
		return err
	}

	l.Token = signedString

	h := fnv.New64a()
	h.Write([]byte(signedString))
	l.Hash = fmt.Sprintf("%v", h.Sum64())

	return nil
}

func (l *License) LoadSignKey() {

	if strings.HasPrefix(l.GetAlg(), "HS") {
		l.signKey = []byte(l.Keys.HMACSecret)
	} else {
		var signKeyInBytes []byte
		var err error
		if l.Keys.RSAPublicKey.ID == "" {
			signKeyInBytes, err = ioutil.ReadFile(l.Keys.RSAPrivateKey.FilePath)
			fatalf("Couldn't read rsa private key file: %s", err)
		} else {
			// TODO
			logrus.Info("Find cert by Id: not implemented yet")
		}

		l.signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKeyInBytes)
		fatalf("Couldn't parse private key: %s", err)
	}
}

func (l *License) LoadVerifyKey() {

	if strings.HasPrefix(l.GetAlg(), "HS") {
		l.verifyKey = []byte(l.Keys.HMACSecret)
	} else {
		var verifyKeyInBytes []byte
		var err error
		if l.Keys.RSAPublicKey.ID == "" {
			verifyKeyInBytes, err = ioutil.ReadFile(l.Keys.RSAPublicKey.FilePath)
			fatalf("Couldn't read public key: %s", err)
		} else {
			// TODO
			logrus.Info("Find cert by Id: not implemented yet")
		}

		l.verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyKeyInBytes)
		fatalf("Couldn't parse public key: %s", err)
	}
}

func (l *License) IsLicenseValid(tokenString string) (bool, error) {
	if !l.Active {
		return false, nil
	}

	if l.verifyKey == nil {
		err := l.ApplyApp(l.GetAppName())
		if err != nil {
			return false, nil
		}
		l.LoadVerifyKey()
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return l.verifyKey, nil
		case *jwt.SigningMethodRSA:

			return l.verifyKey, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	return token.Valid, err
}
