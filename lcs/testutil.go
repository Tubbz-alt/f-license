package lcs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/furkansenharputlu/f-license/config"
)

const (
	TestHMACSecret        = "test-hmac-secret"
	TestAppHMACSecret     = "test-app-hmac-secret"
	TestDefaultHMACSecret = "test-default-hmac-secret"

	TestAppName = "test-app"
)

func ResetTestConfig() {
	app := config.Global.Apps["test-app"]
	app.Alg = "RS512"
	config.Global.Apps["test-app"] = app
}

func SampleLicense(lGen ...func(l *License)) (l *License) {
	publicKeyFile, privateKeyFile := SampleKeys()
	defer func() {
		_ = privateKeyFile.Close()
		_ = publicKeyFile.Close()
	}()

	l = &License{
		Active: true,
		Headers: map[string]interface{}{
			"typ": "Trial",
			"alg": "HS256",
		},
		Claims: jwt.MapClaims{
			"name":    "Furkan",
			"address": "Istanbul, Turkey",
		},
		Keys: config.Keys{
			HMACSecret: config.Key{
				Raw: TestHMACSecret,
			},
			RSAPrivateKey: config.Key{
				FilePath: privateKeyFile.Name(),
			},
			RSAPublicKey: config.Key{
				FilePath: publicKeyFile.Name(),
			},
		},
	}

	if len(lGen) > 0 {
		lGen[0](l)
	}
	return
}

func SampleApp() {
	publicKeyFile, privateKeyFile := SampleKeys()
	defer func() {
		_ = privateKeyFile.Close()
		_ = publicKeyFile.Close()
	}()
	app := config.Global.Apps["test-app"]
	app.Keys.HMACSecret = config.Key{
		Raw: TestAppHMACSecret,
	}
	app.Keys.RSAPrivateKey.FilePath = privateKeyFile.Name()
	app.Keys.RSAPublicKey.FilePath = publicKeyFile.Name()
	app.Alg = "RS512"
	config.Global.Apps["test-app"] = app
}

func SampleKeys() (publicKeyFile *os.File, privateKeyFile *os.File) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := &x509.Certificate{}
	template.SerialNumber = serialNumber
	template.BasicConstraintsValid = true
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(time.Hour)

	derBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	var certPem bytes.Buffer
	pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	publicKeyFile, _ = ioutil.TempFile("", "key.pem")
	_, _ = publicKeyFile.Write(certPem.Bytes())

	var keyPem bytes.Buffer
	_ = pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	privateKeyFile, _ = ioutil.TempFile("", "key.pem")
	_, _ = privateKeyFile.Write(keyPem.Bytes())

	return publicKeyFile, privateKeyFile
}
