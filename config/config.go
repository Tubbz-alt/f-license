package config

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"

	"github.com/sirupsen/logrus"
)

var Global = &Config{}

type Config struct {
	Port          int             `json:"port"`
	AdminSecret   string          `json:"admin_secret"`
	Apps          map[string]*App `json:"apps"`
	DefaultKeys   Keys            `json:"default_keys"`
	MongoURL      string          `json:"mongo_url"`
	DBName        string          `json:"db_name"`
	ServerOptions ServerOptions   `json:"server_options"`
}

type Keys struct {
	HMACSecret    string `bson:"hmac_secret" json:"hmac_secret"`
	RSAPrivateKey Key    `bson:"rsa_private_key" json:"rsa_private_key"`
	RSAPublicKey  Key    `bson:"rsa_public_key" json:"rsa_public_key"`
}

type Key struct {
	ID       string `bson:"id" json:"id"`
	FilePath string `bson:"file_path" json:"file_path"`
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
