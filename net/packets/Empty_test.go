package packets

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

var ValidEmptyPayload = &EmptyPayload{}

func TestEmptyWriteRead(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := ValidEmptyPayload
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), n)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	assert.Equal(t, uint(0), payload.Size())
	rPayload := &EmptyPayload{}
	n, err = rPayload.WriteTo(buff)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), n)
}
