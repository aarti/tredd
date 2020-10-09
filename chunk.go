package tredd

import (
	"crypto/sha256"

	"github.com/chain/txvm/errors"
	"github.com/ethereum/go-ethereum/rlp"
)

// ChunkSize is the size of a chunk of Tredd data.
const ChunkSize = 8192

// ChunkStore stores and retrieves data in chunks.
// The chunk size need not be ChunkSize.
type ChunkStore interface {
	// Add adds a chunk to the end of the ChunkStore.
	Add([]byte) error

	// Get gets the chunk with the given index (0-based).
	Get(uint64) ([]byte, error)

	// Len tells the number of chunks in the store.
	Len() (int64, error)
}

var errMissingChunk = errors.New("missing chunk")

// The crypt function is super simple. Given a 32-byte seed (or “key”), a chunk of data,
// and a sequence number (or “index”) for that chunk (from 0 to numchunks-1),
// it computes a sequence of 32-byte subkeys, enough to cover the bytes of the chunk 1-for-1 (edited)
// Each subkey is computed by hashing the concatenation key||index||i (where i ranges from 0 to
// whatever’s needed to cover the length of the chunk) (edited)
// and then encrypting/decrypting the chunk is simply xor-ing each byte with
// the corresponding byte of the corresponding subkey
// This may not be the best cipher, but it was the best that TxVM was able to support.
// Maybe Solidity has something better built-in?

/**
* 32-byte seed (or “key”)
* a chunk of data
*
 */
func Crypt(key [32]byte, chunk []byte, index uint64) {
	var (
		hasher = sha256.New()
		subkey [32]byte
	)

	for i := 0; 32*i < len(chunk); i++ {
		// compute subchunk key
		hasher.Reset()
		hasher.Write(key[:])
		x, err := rlp.EncodeToBytes(index)
		if err != nil {
			panic(err)
		}
		hasher.Write(x)
		y, err := rlp.EncodeToBytes(uint64(i))
		if err != nil {
			panic(err)
		}
		hasher.Write(y)
		// hasher.Write(txvm.Encode(txvm.Int(index)))
		// hasher.Write(txvm.Encode(txvm.Int(i)))
		hasher.Sum(subkey[:0])

		pos := 32 * i
		end := pos + 32
		if end > len(chunk) {
			end = len(chunk)
		}

		for j := 0; pos+j < end; j++ {
			chunk[pos+j] ^= subkey[j]
		}
	}
}
