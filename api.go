package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/furkansenharputlu/f-license/config"
	"github.com/furkansenharputlu/f-license/lcs"
	"github.com/furkansenharputlu/f-license/storage"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func isSHA256(value string) bool {
	// check if hex encoded
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}

	return true
}

func UploadKey(w http.ResponseWriter, r *http.Request) {

	typ := mux.Vars(r)["type"]

	bytes, _ := ioutil.ReadAll(r.Body)

	var err error
	var km KeyManager

	if typ == "hmac" {
		var hmac *config.Key
		err = json.Unmarshal(bytes, &hmac)
		if err != nil {
			ReturnError(w, http.StatusBadRequest, "Key couldn't be unmarshalled")
			return
		}

		if hmac.Raw == "" {
			if hmac.FilePath == "" {
				ReturnError(w, http.StatusBadRequest, "Neither raw key or key file path provided")
				return
			}

			rawKeyInBytes, err := ioutil.ReadFile(hmac.FilePath)
			if err != nil {
				ReturnError(w, http.StatusNotFound, err.Error())
				return
			}

			hmac.Raw = string(rawKeyInBytes)
		}

		err = km.GetOrAddHMACSecret(hmac)
		if err != nil {
			ReturnError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else if typ == "rsa" {
		var rsaPair *config.RSAPair
		err = json.Unmarshal(bytes, &rsaPair)
		if err != nil {
			ReturnError(w, http.StatusBadRequest, "Key couldn't be unmarshalled")
			return
		}

		// RSA Private Key
		if rsaPair.Private.Raw == "" {
			if rsaPair.Private.FilePath == "" {
				ReturnError(w, http.StatusBadRequest, "Neither raw key or key file path provided for private key")
				return
			}

			rawKeyInBytes, err := ioutil.ReadFile(rsaPair.Private.FilePath)
			if err != nil {
				ReturnError(w, http.StatusNotFound, err.Error())
				return
			}

			rsaPair.Private.Raw = string(rawKeyInBytes)
		}

		// RSA Public Key
		if rsaPair.Public.Raw == "" {
			if rsaPair.Public.FilePath == "" {
				ReturnError(w, http.StatusBadRequest, "Neither raw key or key file path provided for public key")
				return
			}

			rawKeyInBytes, err := ioutil.ReadFile(rsaPair.Public.FilePath)
			if err != nil {
				ReturnError(w, http.StatusNotFound, err.Error())
				return
			}

			rsaPair.Private.Raw = string(rawKeyInBytes)
		}

		err = km.AddRSAPair(rsaPair)
		if err != nil {
			ReturnError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

}

func GetAllKeys(w http.ResponseWriter, r *http.Request) {

}

func GetKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var k config.Key
	err := storage.GlobalKeyHandler.GetByID(id, &k)
	if err != nil {
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	val, err := Decrypt([]byte(config.Global.Secret), k.Encrypted)
	if err != nil {
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	k.Raw = string(val)

	ReturnResponse(w, 200, &k)
}

func DeleteKey(w http.ResponseWriter, r *http.Request) {

}

// Load should work as follows:
//  1. If key doesn't exist, encrypt and save it to database
//  2. If key already exists, just use it and give log in debug mode.
//  3. If id is set, try to get from database,
//  4. if it can't find the id in the database, error
func LoadSignKey(l *lcs.License) {
	km := KeyManager{}

	if strings.HasPrefix(l.GetAlg(), "HS") {
		_ = km.GetOrAddHMACSecret(&l.Keys.HMACSecret) // TODO: Handle error
		l.SignKey = []byte(l.Keys.HMACSecret.Raw)
	} else {
		var signKeyInBytes []byte
		var err error
		if l.Keys.RSAPrivateKey.KeyID == "" {
			signKeyInBytes, err = ioutil.ReadFile(l.Keys.RSAPrivateKey.FilePath)
			l.Keys.RSAPrivateKey.KeyID = lcs.HexSHA256(signKeyInBytes)
			fatalf("Couldn't read rsa private key file: %s", err)
		} else {
			// TODO
			logrus.Info("Find cert by Id: not implemented yet")
		}

		l.SignKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKeyInBytes)
		fatalf("Couldn't parse private key: %s", err)
		l.SignKeyRaw = signKeyInBytes
	}
}

func LoadVerifyKey(l *lcs.License) {
	km := KeyManager{}
	if strings.HasPrefix(l.GetAlg(), "HS") {
		_ = km.GetOrAddHMACSecret(&l.Keys.HMACSecret) // TODO: Handle error
		l.VerifyKey = []byte(l.Keys.HMACSecret.Raw)
	} else {
		var verifyKeyInBytes []byte
		var err error
		if l.Keys.RSAPublicKey.KeyID == "" {
			verifyKeyInBytes, err = ioutil.ReadFile(l.Keys.RSAPublicKey.FilePath)
			l.Keys.RSAPublicKey.KeyID = lcs.HexSHA256(verifyKeyInBytes)
			fatalf("Couldn't read public key: %s", err)
		} else {
			// TODO
			logrus.Info("Find cert by Id: not implemented yet")
		}

		l.VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyKeyInBytes)
		fatalf("Couldn't parse public key: %s", err)
		l.VerifyKeyRaw = verifyKeyInBytes
	}
}

func fatalf(format string, err error) {
	if err != nil {
		logrus.Fatalf(format, err)
	}
}

func GenerateLicense(w http.ResponseWriter, r *http.Request) {
	bytes, _ := ioutil.ReadAll(r.Body)

	var l lcs.License
	err := json.Unmarshal(bytes, &l)
	if err != nil {
		logrus.WithError(err).Error("Request body couldn't be marshalled")
		ReturnError(w, http.StatusBadRequest, err.Error())
		return
	}

	_ = l.ApplyApp() //TODO: Handle error

	LoadSignKey(&l)
	LoadVerifyKey(&l)

	err = l.Generate()
	if err != nil {
		logrus.WithError(err).Error("License couldn't be generated")
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err, errCode := storage.LicenseHandler.AddIfNotExisting(&l)
	if err != nil {
		logrus.WithError(err).Error("License couldn't be stored")

		responseCode := http.StatusInternalServerError

		if errCode == storage.ItemDuplicationError {
			responseCode = http.StatusConflict
		}

		ReturnError(w, responseCode, err.Error())
		return
	}

	ReturnResponse(w, http.StatusOK, map[string]interface{}{
		"id":    l.ID,
		"token": l.Token,
	})
}

func GetApp(w http.ResponseWriter, r *http.Request) {
	//appName := mux.Vars(r)["name"]

	var app = config.App{
		Name: "test-app",
		Alg:  "HS512",
		Keys: config.Keys{
			HMACSecret: config.Key{
				Raw: "test-secret",
			},
		},
	}

	ReturnResponse(w, 200, app)
}

func GetAllApps(w http.ResponseWriter, r *http.Request) {

	ReturnResponse(w, http.StatusOK, config.Global.Apps)
}

func GetLicense(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var l lcs.License
	err := storage.LicenseHandler.GetByID(id, &l)
	if err != nil {
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ReturnResponse(w, 200, &l)
}

func GetAllLicenses(w http.ResponseWriter, r *http.Request) {
	licenses := make([]*lcs.License, 0)
	err := storage.LicenseHandler.GetAll(&licenses)
	if err != nil {
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ReturnResponse(w, 200, licenses)
}

func ChangeLicenseActiveness(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	inactivate := strings.Contains(r.URL.Path, "/inactivate")

	err := storage.LicenseHandler.Activate(id, inactivate)
	if err != nil {
		logrus.WithError(err).Error("Error while activeness change")
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var message string

	if inactivate {
		message = "Inactivated"
	} else {
		message = "Activated"
	}

	ReturnResponse(w, 200, map[string]interface{}{
		"message": message,
	})
}

func VerifyLicense(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("token")

	var l lcs.License
	err := storage.LicenseHandler.GetByToken(token, &l)
	if err != nil {
		logrus.WithError(err).Error("Error while getting license")
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = l.ApplyApp()
	if err != nil {
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	LoadVerifyKey(&l)

	ok, err := l.IsLicenseValid(token)
	if err != nil {
		ReturnResponse(w, http.StatusUnauthorized, map[string]interface{}{
			"valid":   false,
			"message": err.Error(),
		})

		return
	}

	ReturnResponse(w, 200, map[string]interface{}{
		"valid": ok,
	})
}

func DeleteLicense(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	err := storage.LicenseHandler.DeleteByID(id)
	if err != nil {
		logrus.WithError(err).Error("Error while deleting license")
		ReturnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ReturnResponse(w, 200, map[string]interface{}{
		"message": "License successfully deleted",
	})
}

func Ping(w http.ResponseWriter, r *http.Request) {

}

func ReturnResponse(w http.ResponseWriter, statusCode int, resp interface{}) {
	bytes, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, string(bytes))
}

func ReturnError(w http.ResponseWriter, statusCode int, errMsg string) {
	resp := map[string]interface{}{
		"error": errMsg,
	}
	bytes, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, string(bytes))
}

func AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != config.Global.ControlAPISecret {
			ReturnResponse(w, http.StatusUnauthorized, map[string]interface{}{
				"message": "Authorization failed",
			})
			return
		}

		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}
