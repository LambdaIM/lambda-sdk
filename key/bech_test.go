package key

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBech(t *testing.T) {
	key := KeyAPI{}
	_, err := key.GetBechAddress("w1", []byte{})
	assert.Error(t, err)

	mn, priv, err := key.Create( "")
	assert.NoError(t, err)
	t.Log(mn)

	pkBz := priv.PubKey().Address().Bytes()
	bechAddr, err := key.GetBechAddress("acc", pkBz)
	assert.NoError(t, err)
	t.Log(bechAddr)
}
