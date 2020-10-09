package tredd

import (
	"bytes"
	"log"
	"testing"
)

func TestCrypt(t *testing.T) {
	index := uint64(0)
	key := [32]byte{}
	chunk := []byte{'A', 'B', 'C'}
	expected := []byte{170, 86, 104}
	log.Println("Before:", chunk)
	Crypt(key, chunk, index)
	log.Println("AFter:", chunk)
	if bytes.Compare(expected, chunk) != 0 {
		t.Fatalf("Expected %+v, Was %+v", expected, chunk)
	}

}
