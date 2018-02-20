package canister_test

import (
	"testing"

	"github.com/stormentt/zpass-lib/canister"
	"github.com/stormentt/zpass-lib/random"
	"github.com/stretchr/testify/assert"
)

func TestCanister(t *testing.T) {
	c := canister.New()
	c.Set("testString", "hello world")
	c.Set("testInt", 5)
	c.Set("testFloat", 5.5)

	json, err := c.Release()
	assert.NoError(t, err)
	t.Logf("canister: %s\n", json)

	gotString, ok, err := c.GetString("testString")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, gotString, "hello world")

	gotInt, ok, err := c.GetInt64("testInt")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, gotInt, int64(5))

	gotFloat, ok, err := c.GetFloat64("testFloat")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, gotFloat, float64(5.5))
}

func TestOverwriting(t *testing.T) {
	c := canister.New()
	c.Set("testing", 1)
	c.Set("testing", 2)

	json, err := c.Release()
	assert.NoError(t, err)
	t.Logf("canister: %s\n", json)

	got, ok, err := c.GetInt64("testing")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, got, int64(2))
}

func TestNesting(t *testing.T) {
	c := canister.New()
	c.Set("test.in.a.giant.nested.map.this.is.a.lot.of.insides", "hello")

	json, err := c.Release()
	assert.NoError(t, err)
	t.Logf("canister: %s\n", json)

	got, ok, err := c.GetString("test.in.a.giant.nested.map.this.is.a.lot.of.insides")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, got, "hello")
}

func TestFilling(t *testing.T) {
	c, err := canister.Fill(`{"this": 5, "is":{"a":"test"}}`)
	assert.NoError(t, err)

	json, err := c.Release()
	assert.NoError(t, err)
	t.Logf("canister: %s\n", json)

	gotThis, ok, err := c.GetInt64("this")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, gotThis, int64(5))

	gotTest, ok, err := c.GetString("is.a")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, gotTest, "test")
}

func TestBytes(t *testing.T) {
	c := canister.New()
	bytes := random.Bytes(64)
	t.Logf("bytes: %x\n", bytes)

	c.Set("bytes", bytes)

	json, err := c.Release()
	assert.NoError(t, err)
	t.Logf("canister: %s\n", json)

	retrieved, ok, err := c.GetBytes("bytes")
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, bytes, retrieved)
}
