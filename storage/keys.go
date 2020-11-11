package storage

import (
	"context"
	"errors"
	"fmt"
	"github.com/furkansenharputlu/f-license/config"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type KeyHandler interface {
	AddIfNotExisting(k *config.Key) error
	//Activate(id string, inactivate bool) error
	GetByID(id string, k *config.Key) error
	//GetAll(licenses *[]*lcs.License) error
	//GetByToken(token string, l *lcs.License) error
	//DeleteByID(id string) error
	//DropDatabase() error
}

var GlobalKeyHandler KeyHandler

type mongoKeyHandler struct {
	col *mongo.Collection
}

func (h mongoKeyHandler) AddIfNotExisting(k *config.Key) error {

	filter := bson.M{"key_id": k.KeyID}
	res := h.col.FindOne(context.Background(), filter)
	err := res.Err()
	if err != nil {
		if err != mongo.ErrNoDocuments {
			return err
		}
	} else {
		var existingKey config.Key
		_ = res.Decode(&existingKey)
		return errors.New(fmt.Sprintf("there is already such key with ID: %s", existingKey.KeyID))
	}

	update := bson.M{"$set": k}
	_, err = h.col.UpdateOne(context.Background(), filter, update, options.Update().SetUpsert(true))
	if err != nil {
		return errors.New(fmt.Sprintf("error while inserting key: %s", err))
	}

	return nil
}

func (h mongoKeyHandler) GetByID(keyID string, k *config.Key) error {

	filter := bson.M{"key_id": keyID}
	res := h.col.FindOne(context.Background(), filter)
	err := res.Err()
	if err != nil {
		return err
	}

	_ = res.Decode(k)

	return nil
}
