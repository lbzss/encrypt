package encrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	key  = "1qaz2wsx3edc4rfv"
	data = "P@ssw0rd"
	text = "NEv50FWtf9LfPMEiBpx7Xg=="
)

func TestEncryptByAes(t *testing.T) {
	should := assert.New(t)

	text, err := EncryptByAes([]byte(data), []byte(key))
	// if should.NoError(err) {
	// 	t.Log(text)
	// }
	if !should.Equal(text, data) {
		t.Fatalf("err: %s", err)
	}
}

func TestDecryptByAes(t *testing.T) {
	should := assert.New(t)

	data, err := DecryptByAes(text, []byte(key))
	// if should.NoError(err) {
	// 	t.Log(string(data))
	// }
	if !should.Equal(text, data) {
		t.Fatalf("err: %s", err)
	}
}
