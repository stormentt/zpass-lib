package slices_test

import (
	"bytes"
	"testing"
	"zpass-lib/util/slices"
)

func TestCombine(t *testing.T) {
	slice1 := []byte("Hello")
	slice2 := []byte("World")
	expected := []byte("HelloWorld")
	combined := slices.Combine(slice1, slice2)
	if !bytes.Equal(combined, expected) {
		t.Error("Combined slice did not equal expected slice")
	}
}

func BenchmarkCombine(b *testing.B) {
	slice1 := []byte("Hello")
	slice2 := []byte("World")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		slices.Combine(slice1, slice2)
	}
}
