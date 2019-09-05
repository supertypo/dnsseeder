package controllers

import (
	"fmt"
	"github.com/daglabs/btcd/apiserver/database"
	"github.com/daglabs/btcd/apiserver/models"
	"github.com/daglabs/btcd/apiserver/utils"
	"github.com/daglabs/btcd/util/daghash"
	"github.com/jinzhu/gorm"
	"net/http"
)

// GetTransactionByIDHandler returns a transaction by a given transaction ID.
func GetTransactionByIDHandler(txID string) (interface{}, *utils.HandlerError) {
	if len(txID) != daghash.TxIDSize*2 {
		return nil, utils.NewHandlerError(http.StatusUnprocessableEntity, fmt.Sprintf("The given txid is not a hex-encoded %d-byte hash.", daghash.TxIDSize))
	}
	tx := &models.Transaction{}
	db := database.DB.Where("transaction_id = ?", txID)
	addTxPreloadedFields(db).First(&tx)
	if tx.ID == 0 {
		return nil, utils.NewHandlerError(http.StatusNotFound, "No transaction with the given txid was found.")
	}
	return convertTxModelToTxResponse(tx), nil
}

// GetTransactionByHashHandler returns a transaction by a given transaction hash.
func GetTransactionByHashHandler(txHash string) (interface{}, *utils.HandlerError) {
	if len(txHash) != daghash.HashSize*2 {
		return nil, utils.NewHandlerError(http.StatusUnprocessableEntity, fmt.Sprintf("The given txhash is not a hex-encoded %d-byte hash.", daghash.HashSize))
	}
	tx := &models.Transaction{}
	db := database.DB.Where("transaction_hash = ?", txHash)
	addTxPreloadedFields(db).First(&tx)
	if tx.ID == 0 {
		return nil, utils.NewHandlerError(http.StatusNotFound, "No transaction with the given txhash was found.")
	}
	return convertTxModelToTxResponse(tx), nil
}

func addTxPreloadedFields(db *gorm.DB) *gorm.DB {
	return db.Preload("AcceptingBlock").
		Preload("Subnetwork").
		Preload("TransactionOutputs").
		Preload("TransactionInputs.TransactionOutput.Transaction")
}