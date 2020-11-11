package config

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"

	"github.com/sirupsen/logrus"
)

var Global = &Config{}

type Config struct {
	Port             int             `json:"port"`
	ControlAPISecret string          `json:"control_api_secret"`
	Secret           string          `json:"secret"`
	Apps             map[string]*App `json:"apps"`
	DefaultKeys      Keys            `json:"default_keys"`
	MongoURL         string          `json:"mongo_url"`
	DBName           string          `json:"db_name"`
	ServerOptions    ServerOptions   `json:"server_options"`
}

type Keys struct {
	HMACSecret    Key `bson:"hmac_secret" json:"hmac_secret"`
	RSAPrivateKey Key `bson:"rsa_private_key" json:"rsa_private_key"`
	RSAPublicKey  Key `bson:"rsa_public_key" json:"rsa_public_key"`
}

type RSAPair struct {
	Private Key `json:"private"`
	Public  Key `json:"public"`
}

type Key struct {
	Name      string `bson:"name" json:"name"`
	Type      string `bson:"type" json:"type"`
	FilePath  string `bson:"-" json:"file_path"`
	Raw       string `bson:"-" json:"raw"`
	KeyID     string `bson:"key_id" json:"key_id"`
	Encrypted []byte `bson:"encrypted" json:"-"`
}

func (k *Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Name  string `json:"name"`
		KeyID string `json:"key_id"`
		Raw   string `json:"raw"`
	}{
		Name:  k.Name,
		KeyID: k.KeyID,
		Raw:   k.Raw,
	})
}

func (c *Config) Load(filePath string) {
	configuration, err := ioutil.ReadFile(filePath)
	if err != nil {
		logrus.WithError(err).Error("Couldn't read config file")
	}

	err = json.Unmarshal(configuration, &c)
	if err != nil {
		logrus.WithError(err).Error("Couldn't unmarshal configuration")
	}
}

type ServerOptions struct {
	EnableTLS bool       `json:"enable_tls"`
	CertFile  string     `json:"cert_file"`
	KeyFile   string     `json:"key_file"`
	TLSConfig tls.Config `json:"tls_config"`
}

type App struct {
	Name string `json:"name"`
	Alg  string `json:"alg"`
	Keys Keys   `json:"keys"`
}
