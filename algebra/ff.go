// Package ff implements finite field elements over an integer usually the integer
// is a prime number.
package algebra

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

const (
	primeCheckPasses = 16 // This gives us a probability of 0.9999999997671694
)

var (
	errNonPrimeModulus = errors.New("finite fields are defined over prime modulus only")
)

// FiniteField represents a field over modulus q.
type FiniteField struct {
	q *Integer
}

// NewFiniteField creates a new field
func NewFiniteField(q *Integer) (FiniteField, error) {
	return FiniteField{q}, nil
}

// Zero returns the 0 on Fq
func (ff FiniteField) Zero() FieldElement {
	return FieldElement{Zero, ff}
}

// One returns the 1 on Fq
func (ff FiniteField) One() FieldElement {
	return FieldElement{One, ff}
}

// Modulus returns the Finite Field modulus
func (ff FiniteField) Modulus() *Integer {
	return ff.q
}

// Char returns the characteristic of the finite field
func (ff FiniteField) Char() *Integer {
	return ff.q
}

// Rand returns a random field element
func (ff FiniteField) Rand() (FieldElement, error) {

	var fe FieldElement

	maxbits := ff.q.BitLen()
	buf := make([]byte, (maxbits / 8))
	_, err := rand.Read(buf)
	if err != nil {
		return fe, err
	}
	r := new(big.Int).SetBytes(buf)

	// r over q, nil
	return FieldElement{r, ff}, nil
}

// Add sums two FintieField elements
func (ff FiniteField) Add(x, y FieldElement) FieldElement {
	return ff.NewFieldElement(ModAdd(x.n, y.n, ff.q))
}

// Sub subs two FiniteField elements
func (ff FiniteField) Sub(x, y FieldElement) FieldElement {
	return ff.NewFieldElement(ModSub(x.n, y.n, ff.q))
}

// Mul multiplies two FiniteField elements
func (ff FiniteField) Mul(x, y FieldElement) FieldElement {
	return ff.NewFieldElement(ModMul(x.n, y.n, ff.q))
}

// Div divides two FiniteField elements
func (ff FiniteField) Div(x, y FieldElement) FieldElement {
	return ff.NewFieldElement(ModDiv(x.n, y.n, ff.q))
}

// FieldElement is defined over a finite field of order p
// this isn't an efficient way to represent them a better way
// involves encoding FieldElements as polynomials.
type FieldElement struct {
	n *Integer
	p FiniteField
}

// String implements stringer
func (fe *FieldElement) String() string {

	return fmt.Sprintf("%d(F/%d)", fe.n, fe.p.q)
}

// New takes a number and the field's order
func New(n, p *Integer) (FieldElement, error) {
	var z = FieldElement{
		n: n, p: FiniteField{p},
	}
	// an element of Fp can't be bigger than p nor less than zero
	if Cmp(n, p) == 1 || Cmp(n, Zero) == -1 {
		return z, errors.New("n not in the F")
	}

	return z, nil
}

// NewFieldElement returns a new field eleemnt
func (ff FiniteField) NewFieldElement(x *Integer) FieldElement {

	return FieldElement{Mod(x, ff.q), ff}
}

// NewFieldElementFromInt64 takes int64 params
func (ff FiniteField) NewFieldElementFromInt64(x int64) FieldElement {
	return ff.NewFieldElement(FromInt64(x))
}

// Double compues 2*fe
func (fe FieldElement) Double() FieldElement {
	var r = fe.p.Add(fe, fe)
	return r
}

// Neg returns -1*fe
func (fe FieldElement) Neg() FieldElement {
	r := new(big.Int).Neg(fe.n)
	r = Mod(r, fe.p.q)
	return FieldElement{r, fe.p}
}

// Square returns fe^2
func (fe FieldElement) Square() FieldElement {
	return fe.p.Mul(fe, fe)
}

// Exp computes fe^e
func (fe FieldElement) Exp(e *Integer) FieldElement {
	var r = ModExp(fe.n, e, fe.p.q)
	return FieldElement{r, fe.p}
}

// Inv computes fe-1
func (fe FieldElement) Inv() FieldElement {
	var r = ModInv(fe.n, fe.p.q)
	return FieldElement{r, fe.p}
}

// IsZero returns if the fieldelement is zero
func (fe FieldElement) IsZero() bool {
	return fe.n.Cmp(Zero) == 0
}

// Field returns the FiniteField where are in
func (fe FieldElement) Field() FiniteField {
	return fe.p
}

// Big casts a field element to an Integer
func (fe FieldElement) Big() *Integer {
	return new(big.Int).Set(fe.n)
}

// Equal checks for equality between field elements
func (fe FieldElement) Equal(other FieldElement) bool {

	if fe.p.Modulus().Cmp(other.p.Modulus()) != 0 || fe.n.Cmp(other.n) != 0 {
		return false
	}

	return true
}

// Cmp compares field elements
func (ff FiniteField) Cmp(x FieldElement, y FieldElement) int {

	if x.p.q.Cmp(y.p.q) != 0 {
		return -1
	}
	return x.n.Cmp(y.n)
}