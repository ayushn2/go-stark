package merkle

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"golang.org/x/crypto/sha3"
)

var (
	leafPrefix      = []byte{0x00}
	interiorPrefix  = []byte{0x01}
	emptyStringHash = sha3.Sum256([]byte{})
)

// AuditHash stores the hash value and denotes which side of the concatenation
// operation it should be on.
// For example, if we have a hashed item A and an audit hash {Val: B, RightOperator: false},
// the validation is: H(B + A).
type AuditHash struct {
	Val           []byte
	RightOperator bool // FALSE indicates the hash should be on the LEFT side of concatenation, TRUE for right side.
}

// Proof returns the proofs required to validate an item at index i, not including the original item i.
// This errors when the requested index is out of bounds.
func Proof(items [][]byte, i int) ([]AuditHash, error) {
	if i < 0 || i >= len(items) {
		return nil, errors.New("index %v is out of bounds")
	}
	if len(items) == 1 {
		return []AuditHash{}, nil
	}

	k := prevPowerOfTwo(len(items))
	recurse := items[:k]
	aggregate := items[k:]
	rightOperator := true
	if i >= k {
		i = i - k
		recurse, aggregate = aggregate, recurse
		rightOperator = false
	}
	res, err := Proof(recurse, i)
	if err != nil {
		return nil, err
	}
	res = append(res, AuditHash{Root(aggregate), rightOperator})
	return res, nil
}

// Root creates a merkle tree from a slice of byte slices
// and returns the root hash of the tree.
func Root(items [][]byte) []byte {
	switch len(items) {
	case 0:
		return emptyStringHash[:]

	case 1:
		h := sha3.New256()

		h.Write(leafPrefix)
		h.Write(items[0])
		root := h.Sum(nil)
		return root

	default:
		k := prevPowerOfTwo(len(items))
		left := Root(items[:k])
		right := Root(items[k:])

		h := sha3.New256()
		h.Write(interiorPrefix)
		h.Write(left[:])
		h.Write(right[:])

		root := h.Sum(nil)
		return root
	}
}

// prevPowerOfTwo returns the largest power of two that is smaller than a given number.
// In other words, for some input n, the prevPowerOfTwo k is a power of two such that
// k < n <= 2k. This is a helper function used during the calculation of a merkle tree.
func prevPowerOfTwo(n int) int {
	// If the number is a power of two, divide it by 2 and return.
	if n&(n-1) == 0 {
		return n / 2
	}

	// Otherwise, find the previous PoT.
	exponent := uint(math.Log2(float64(n)))
	return 1 << exponent // 2^exponent
}

func concat(a []byte, b []byte) []byte {
	return append(a, b...)
}
func hash(a []byte) [32]byte {
	h := sha3.Sum256(a)
	return h
}
func hexify(a []byte) string {
	return hex.EncodeToString(a)
}

func unhexify(s string) []byte {
	d, _ := hex.DecodeString(s)
	return d
}

/*

   The binary Merkle Tree with 7 leaves:

               hash
              /    \
             /      \
            /        \
           /          \
          /            \
         k              l
        / \            / \
       /   \          /   \
      /     \        /     \
     g       h      i      j
    / \     / \    / \     |
    a b     c d    e f     d6
    | |     | |    | |
   d0 d1   d2 d3  d4 d5

   The audit path for d0 is [b, h, l].

   The audit path for d3 is [c, g, l].

   The audit path for d4 is [f, j, k].

   The audit path for d6 is [i, k].
*/

// Verify takes the hash of an item and an audit path
// and verifies whether a proof is correct.
func Verify(items [][]byte, index int, auditpath []AuditHash) bool {

	h := hash(concat(leafPrefix, items[index]))
	for _, proofs := range auditpath {

		proof := proofs.Val
		isRight := proofs.RightOperator

		if isRight {
			concatRight := concat(h[:], proof)
			h = hash(concat(interiorPrefix, concatRight))
		} else {
			concatLeft := concat(proof, h[:])
			h = hash(concat(interiorPrefix, concatLeft))
		}

	}

	return bytes.Equal(Root(items), h[:])
}