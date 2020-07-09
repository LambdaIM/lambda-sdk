package key

import (
	"fmt"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/encoding/amino"
	"github.com/tendermint/tendermint/libs/bech32"
)

const (
	CoinType = 364

	Bech32MainPrefix = "lambda"

	// PrefixValidator is the prefix for validator keys
	PrefixValidator = "val"
	// PrefixValidator is the prefix for market keys
	PrefixMarket = "market"
	// PrefixValidator is the prefix for miner keys
	PrefixMiner = "miner"
	// PrefixConsensus is the prefix for consensus keys
	PrefixConsensus = "cons"
	// PrefixPublic is the prefix for public keys
	PrefixPublic = "pub"
	// PrefixOperator is the prefix for operator keys
	PrefixOperator = "oper"

	// Bech32PrefixAccAddr defines the Bech32 prefix of an account's address
	Bech32PrefixAccAddr = Bech32MainPrefix
	// Bech32PrefixAccPub defines the Bech32 prefix of an account's public key
	Bech32PrefixAccPub = Bech32MainPrefix + PrefixPublic
	// Bech32PrefixValAddr defines the Bech32 prefix of a validator's operator address
	Bech32PrefixValAddr = Bech32MainPrefix + PrefixValidator + PrefixOperator
	// Bech32PrefixValPub defines the Bech32 prefix of a validator's operator public key
	Bech32PrefixValPub = Bech32MainPrefix + PrefixValidator + PrefixOperator + PrefixPublic
	// Bech32PrefixConsAddr defines the Bech32 prefix of a consensus node address
	Bech32PrefixConsAddr = Bech32MainPrefix + PrefixValidator + PrefixConsensus
	// Bech32PrefixConsPub defines the Bech32 prefix of a consensus node public key
	Bech32PrefixConsPub = Bech32MainPrefix + PrefixValidator + PrefixConsensus + PrefixPublic
	// Bech32PrefixValAddr defines the Bech32 prefix of a miner's operator address
	Bech32PrefixMinerAddr = Bech32MainPrefix + PrefixMiner + PrefixOperator
	// Bech32PrefixValPub defines the Bech32 prefix of a miner's operator public key
	Bech32PrefixMinerPub = Bech32MainPrefix + PrefixMiner + PrefixOperator + PrefixPublic
	// Bech32PrefixValAddr defines the Bech32 prefix of a market's operator address
	Bech32PrefixMarketAddr = Bech32MainPrefix + PrefixMarket + PrefixOperator
	// Bech32PrefixValPub defines the Bech32 prefix of a market's operator public key
	Bech32PrefixMarketPub = Bech32MainPrefix + PrefixMarket + PrefixOperator + PrefixPublic
)

var (
	bechMap = map[string]string{
		"acc":        Bech32PrefixAccAddr,
		"acc/pub":    Bech32PrefixAccPub,
		"val":        Bech32PrefixValAddr,
		"val/pub":    Bech32PrefixValPub,
		"cons":       Bech32PrefixConsAddr,
		"cons/pub":   Bech32PrefixConsPub,
		"miner":      Bech32PrefixMinerAddr,
		"miner/pub":  Bech32PrefixMinerPub,
		"market":     Bech32PrefixMarketAddr,
		"market/pub": Bech32PrefixMarketPub,
	}
)

func (k *KeyAPI) GetBechAddress(prefix string, pubKey []byte) (string, error) {
	if _, ok := bechMap[prefix]; !ok {
		return "", fmt.Errorf("%v was not support", prefix)
	}

	bech32Addr, err := bech32.ConvertAndEncode(bechMap[prefix], pubKey)
	if err != nil {
		return "", err
	}

	return bech32Addr, nil
}

func (k *KeyAPI) GetPubkeyFromBech(bechAddr string) (string, crypto.PubKey, error) {
	hrp, bz, err := bech32.DecodeAndConvert(bechAddr)
	if err != nil {
		return hrp, nil, err
	}

	pk, err := cryptoAmino.PubKeyFromBytes(bz)
	if err != nil {
		return hrp, nil,  err
	}

	return hrp, pk, nil
}
