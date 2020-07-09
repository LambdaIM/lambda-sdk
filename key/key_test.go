package key

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSign(t *testing.T) {
	k := KeyAPI{}
	mnemonic, priv, err := k.Create( "passwd")
	assert.NoError(t, err)

	priv1, err:= k.Recover( mnemonic, "passwd")
	assert.NoError(t, err)
	assert.True(t, priv.Equals(priv1))

	pub := priv.PubKey()
	assert.NoError(t, err)

	msg := []byte("test bz")
	rz, err := priv.Sign(msg)
	assert.NoError(t, err)

	assert.True(t, pub.VerifyBytes(msg, rz))
}

func TestEncryption(t *testing.T)  {
	k := KeyAPI{}
	_, priv, err := k.Create("passwd")
	assert.NoError(t, err)

	privArmor := k.EncryptPrivKey(priv, "passwd")
	priv1, err := k.DecryptPrivKey(privArmor, "passwd")
	assert.NoError(t, err)

	assert.True(t, priv.Equals(priv1))

	_, err2 := k.DecryptPrivKey(privArmor, "p1")
	assert.Error(t, err2)
}
