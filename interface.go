package lambda_sdk

import (
	"github.com/LambdaIM/lambda-sdk/key"
	"github.com/tendermint/tendermint/crypto"
)

var(
	_ Key = &key.KeyAPI{}
)

type Key interface {
	CreateMnemonic() (string, error)
	Create(bip39passwd string) (string, crypto.PrivKey, error)
	Recover(mnemonic string, bip39passwd string) (crypto.PrivKey, error)

	GetBechAddress(prefix string, pubKey []byte) (string, error)
	GetPubkeyFromBech(bechPubAddr string) (string, crypto.PubKey, error)

	EncryptPrivKey(priv crypto.PrivKey, passwd string) string
	DecryptPrivKey(privArmor string, passwd string) (crypto.PrivKey, error)
}


type FullNode interface {
	Key
}