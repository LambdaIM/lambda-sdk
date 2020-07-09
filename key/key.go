package key

import (
	"github.com/cosmos/cosmos-sdk/crypto/keys/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mintkey"
	"github.com/cosmos/go-bip39"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

const (
	mnemonicEntropySize = 256
	hdPath              = "44'/364'/0'/0/0"
)

type KeyAPI struct {}

func (k *KeyAPI) CreateMnemonic() (string, error) {
	var mnemonic string

	// read entropy seed straight from crypto.Rand and convert to mnemonic
	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		return "", err
	}

	mnemonic, err = bip39.NewMnemonic(entropySeed[:])
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

func (k *KeyAPI) derive(mnemonic string, bip39passwd string) (crypto.PrivKey, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39passwd)
	if err != nil {
		return nil, err
	}

	masterPriv, ch := hd.ComputeMastersFromSeed(seed)
	derivedPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, hdPath)
	if err != nil {
		return nil, err
	}

	return secp256k1.PrivKeySecp256k1(derivedPriv), nil
}

func (k *KeyAPI) Create(bip39passwd string) (string, crypto.PrivKey, error) {
	mnemonic, err := k.CreateMnemonic()
	if err != nil {
		return "", nil, err
	}

	info, err := k.derive(mnemonic, bip39passwd)
	return mnemonic, info, err
}

func (k *KeyAPI) Recover(mnemonic string, bip39passwd string) (crypto.PrivKey, error) {
	 return k.derive(mnemonic, bip39passwd)
}

func (k *KeyAPI) EncryptPrivKey(priv crypto.PrivKey, passwd string) string {
	return mintkey.EncryptArmorPrivKey(priv, passwd)
}

func (k *KeyAPI) DecryptPrivKey(privArmor string, passwd string) (crypto.PrivKey, error) {
	return mintkey.UnarmorDecryptPrivKey(privArmor, passwd)
}
