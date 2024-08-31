package snowblind

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"sync"

	r255 "github.com/gtank/ristretto255"
)

// generatorH memoizes the point H=sha512(G) which is used as our
// secondary generator for Pedersen commitments.
var generatorH = sync.OnceValue(func() *r255.Element {
	h := sha512.New()
	_, err := h.Write(r255.NewIdentityElement().Bytes())
	if err != nil {
		panic(err)
	}

	digest := make([]byte, sha512.Size)
	h.Sum(digest)

	return r255.NewElement().FromUniformBytes(digest)
})

// PublicKey is used for obtaining and verifying Snowblind signatures.
type PublicKey struct {
	point *r255.Element
}

var _ crypto.PublicKey = &PublicKey{}

// NewPublicKey returns the Snowblind public key corresponding to the 32-byte key
// given as an argument.
func NewPublicKey(key []byte) (*PublicKey, error) {
	point, err := r255.NewIdentityElement().SetCanonicalBytes(key)
	return &PublicKey{point: point}, err
}

// Bytes returns the 32-byte representation of pk
func (pk *PublicKey) Bytes() []byte {
	if pk.point != nil {
		return pk.point.Bytes()
	}

	return nil
}

// Equal returns true if op is a Snowblind public key and is equal to pk.
func (pk *PublicKey) Equal(op crypto.PublicKey) bool {
	otherPK, ok := op.(*PublicKey)
	if !ok {
		return false
	}

	return otherPK.point.Equal(pk.point) == 1
}

// PrivateKey is used for signing Snowblind signatures.
type PrivateKey struct {
	multiplier *r255.Scalar
}

var _ crypto.PrivateKey = &PrivateKey{}

// NewPrivateKey returns the Snowblind private key corresponding to the
// given 32-byte key.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	multiplier, err := r255.NewScalar().SetCanonicalBytes(key)
	return &PrivateKey{multiplier: multiplier}, err
}

// Public returns the public key corresponding to sk. To meet the crypto library
// PrivateKey interface, the return type is crypto.PublicKey, so users will need
// to type assert to PublicKey.
func (sk *PrivateKey) Public() crypto.PublicKey {
	pk := &PublicKey{}
	pk.point = r255.NewIdentityElement().ScalarBaseMult(sk.multiplier)
	return pk
}

// Bytes returns the 32-byte representation of sk.
func (sk *PrivateKey) Bytes() []byte {
	if sk.multiplier != nil {
		return sk.multiplier.Bytes()
	}

	return nil
}

// Equal returns true if op is a Snowblind PrivateKey and is equal to sk
func (sk *PrivateKey) Equal(op crypto.PrivateKey) bool {
	otherSK, ok := op.(*PrivateKey)
	if !ok {
		return false
	}

	return otherSK.multiplier.Equal(sk.multiplier) == 1
}

// GenerateKey returns a PrivateKey using bytes read from rand. Users should basically
// always use crypto.Rand as an argument here.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	randomBuffer := make([]byte, 64)

	_, err := rand.Read(randomBuffer)
	if err != nil {
		return nil, err
	}

	multiplier, err := r255.NewScalar().SetUniformBytes(randomBuffer)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{multiplier: multiplier}, nil
}

// SignerState keeps track of information needed to sign a Snowblind signature and can only
// be used once per signature.
type SignerState struct {
	sk       *r255.Scalar
	a, b     *r255.Scalar // elements of Zp
	y        *r255.Scalar // element of Zp*
	finished bool
}

// NewSignerState returns a signer state which can be used to sign a Snowblind signature.
func (sk *PrivateKey) NewSignerState() *SignerState {
	return &SignerState{sk: sk.multiplier}
}

// NewCommitment returns a commitment which should be sent to the user as the first move of
// communication in the three move protocol.
func (ss *SignerState) NewCommitment() ([]byte, error) {
	if ss.a != nil {
		return nil, errors.New("this signer state was already used to generate a commitment")
	}

	randomBuffer := make([]byte, 192)
	_, err := rand.Read(randomBuffer)
	if err != nil {
		return nil, err
	}

	// for the non-hiding commitment
	ss.a, err = r255.NewScalar().SetUniformBytes(randomBuffer[:64])
	if err != nil {
		return nil, err
	}

	// A = aG
	A := r255.NewIdentityElement().ScalarBaseMult(ss.a)

	// for the Pedersen commitment
	ss.b, err = r255.NewScalar().SetUniformBytes(randomBuffer[64:128])
	if err != nil {
		return nil, err
	}
	ss.y, err = r255.NewScalar().SetUniformBytes(randomBuffer[128:])
	if err != nil {
		return nil, err
	}

	// B = bG + yH
	B := r255.NewIdentityElement().ScalarBaseMult(ss.b)
	B = B.Add(B, r255.NewIdentityElement().ScalarMult(ss.y, generatorH()))

	return append(A.Bytes(), B.Bytes()...), nil
}

// UserState keeps track of information needed to obtain a signature from a signer, and can only
// be used once per signature.
type UserState struct {
	pk       *PublicKey
	cmtA     *r255.Element
	cmtB     *r255.Element
	bigRBar  *r255.Element
	msg      []byte
	c        *r255.Scalar
	r        *r255.Scalar
	alpha    *r255.Scalar
	beta     *r255.Scalar
	finished bool
}

// NewUserState returns a new user state which can be used to obtain a signature from a signer.
func (pk *PublicKey) NewUserState() *UserState {
	return &UserState{pk: pk}
}

// scalarIsZero returns true if the given scalar is equal to zero
func scalarIsZero(s *r255.Scalar) bool {
	return s.Equal(r255.NewScalar().Zero()) == 1
}

// simple square-and-multiply for s^5
func scalarPowFive(s *r255.Scalar) *r255.Scalar {
	res := r255.NewScalar().Multiply(s, s) // res=s^2
	res = res.Multiply(res, res)           // res=res^2=s^4
	res = res.Multiply(res, s)             // res=res*s=s^4*s=s^5
	return res
}

// NewChallenge takes a commitment (cmt) from the signer and a message (msg) to be signed,
// and returns a challenge which should be sent back to the signer as the second move of communication
// in the three move protocol.
func (us *UserState) NewChallenge(cmt []byte, msg []byte) ([]byte, error) {
	if us.cmtA != nil {
		return nil, errors.New("user state has already been used to generate a challenge")
	}

	var err error
	us.cmtA, err = r255.NewIdentityElement().SetCanonicalBytes(cmt[:32])
	if err != nil {
		return nil, err
	}
	us.cmtB, err = r255.NewIdentityElement().SetCanonicalBytes(cmt[32:])
	if err != nil {
		return nil, err
	}

	randomBuffer := make([]byte, 64*3)
	_, err = rand.Read(randomBuffer)
	if err != nil {
		return nil, err
	}

	alpha, err := r255.NewScalar().SetUniformBytes(randomBuffer[:64])
	if err != nil {
		return nil, err
	}

	// the chance of this happening is negligible, so we do not even retry
	// this is a common pattern from the golang crypto stdlib
	if scalarIsZero(alpha) {
		return nil, errors.New("alpha is zero")
	}

	r, err := r255.NewScalar().SetUniformBytes(randomBuffer[64:128])
	if err != nil {
		return nil, err
	}

	beta, err := r255.NewScalar().SetUniformBytes(randomBuffer[128:])
	if err != nil {
		return nil, err
	}

	alphaPowFive := scalarPowFive(alpha)

	bigRBar := r255.NewIdentityElement().ScalarBaseMult(r)                                                                 // bigRBar = rG
	bigRBar.Add(bigRBar, r255.NewIdentityElement().ScalarMult(alphaPowFive, us.cmtA))                                      // bigRBar = rG + (alpha^5) A
	bigRBar.Add(bigRBar, r255.NewIdentityElement().ScalarMult(r255.NewScalar().Multiply(alphaPowFive, beta), us.pk.point)) // bigRBar = rG + (alpha^5) A + (alpha^5 beta) pk
	bigRBar.Add(bigRBar, r255.NewIdentityElement().ScalarMult(alpha, us.cmtB))                                             // bigRBar = rG + (alpha^5) A + (alpha^5 beta) pk + alpha B

	cBar, err := sigHash(us.pk.point, msg, bigRBar)
	if err != nil {
		return nil, err
	}

	c := r255.NewScalar().Multiply(cBar, r255.NewScalar().Invert(alphaPowFive)) // c = cBar * (alpha^5)^(-1)
	c.Add(c, beta)                                                              // c = cBar * (alpha^5)^(-1) + beta

	us.c = c
	us.msg = msg
	us.bigRBar = bigRBar
	us.r = r
	us.alpha = alpha
	us.beta = beta

	return c.Bytes(), nil
}

type response struct {
	z *r255.Scalar
	b *r255.Scalar
	y *r255.Scalar
}

func (rsp *response) Bytes() []byte {
	return append(append(rsp.z.Bytes(), rsp.b.Bytes()...), rsp.y.Bytes()...)
}

func (rsp *response) SetCanonicalBytes(b []byte) error {
	rsp.z = r255.NewScalar()
	rsp.b = r255.NewScalar()
	rsp.y = r255.NewScalar()

	if _, err := rsp.z.SetCanonicalBytes(b[:32]); err != nil {
		return err
	}

	if _, err := rsp.b.SetCanonicalBytes(b[32:64]); err != nil {
		return err
	}

	_, err := rsp.y.SetCanonicalBytes(b[64:])
	return err
}

// NewResponse takes a challenge (chalBytes) and returns a response which should be sent to the user
// to allow them to obtain the final signature on their message.
func (ss *SignerState) NewResponse(chalBytes []byte) ([]byte, error) {
	if ss.a == nil {
		return nil, errors.New("this signer state has not been user to generate a commitment yet")
	}

	if ss.finished {
		return nil, errors.New("this signer state has already been used to generate a response")
	}

	chal, err := r255.NewScalar().SetCanonicalBytes(chalBytes)
	if err != nil {
		return nil, err
	}

	yPowFive := scalarPowFive(ss.y)           // yPowFive = y^5
	f := r255.NewScalar().Add(chal, yPowFive) // f = c + y^5

	z := r255.NewScalar().Add(ss.a, r255.NewScalar().Multiply(f, ss.sk)) // z = a + f*sk

	ss.finished = true

	return (&response{z: z, b: ss.b, y: ss.y}).Bytes(), nil
}

type signature struct {
	bigRBar *r255.Element
	zBar    *r255.Scalar
	yBar    *r255.Scalar
}

func (s *signature) Bytes() []byte {
	return append(append(s.bigRBar.Bytes(), s.zBar.Bytes()...), s.yBar.Bytes()...)
}

func (s *signature) SetCanonicalBytes(b []byte) error {
	s.bigRBar = r255.NewIdentityElement()
	s.zBar = r255.NewScalar()
	s.yBar = r255.NewScalar()

	if _, err := s.bigRBar.SetCanonicalBytes(b[:32]); err != nil {
		return err
	}

	if _, err := s.zBar.SetCanonicalBytes(b[32:64]); err != nil {
		return err
	}

	_, err := s.yBar.SetCanonicalBytes(b[64:])
	return err
}

// NewSignature takes a response (rsp) from the signer and returns the completed signature.
func (us *UserState) NewSignature(rsp []byte) ([]byte, error) {
	if us.cmtA == nil {
		return nil, errors.New("this user state has not yet been used to generate a challenge")
	}

	if us.finished {
		return nil, errors.New("this user state has already been used to generate a signature")
	}

	var decodedRsp response
	if err := decodedRsp.SetCanonicalBytes(rsp); err != nil {
		return nil, err
	}

	checkB := r255.NewIdentityElement().ScalarBaseMult(decodedRsp.b)                     // checkB = bG
	checkB.Add(checkB, r255.NewIdentityElement().ScalarMult(decodedRsp.y, generatorH())) // checkB = bG + yH

	if checkB.Equal(us.cmtB) == 0 {
		return nil, errors.New("signer did not honestly generate the response: checkB != cmtB")
	}

	zG := r255.NewIdentityElement().ScalarBaseMult(decodedRsp.z)

	yPowFive := scalarPowFive(decodedRsp.y)

	checkzG := r255.NewIdentityElement().Add(us.cmtA, r255.NewIdentityElement().ScalarMult(r255.NewScalar().Add(us.c, yPowFive), us.pk.point)) // checkzG = A + (c + y^5) pk

	if checkzG.Equal(zG) == 0 {
		return nil, errors.New("signer did not honestly generate the response: checkzG != zG")
	}

	zBar := r255.NewScalar().Add(us.r, r255.NewScalar().Multiply(scalarPowFive(us.alpha), decodedRsp.z)) // zBar = r + alpha^5 z
	zBar.Add(zBar, r255.NewScalar().Multiply(us.alpha, decodedRsp.b))                                    // zBar = r + alpha^5 z + alpha b

	yBar := r255.NewScalar().Multiply(us.alpha, decodedRsp.y)

	us.finished = true

	sig := &signature{bigRBar: us.bigRBar, zBar: zBar, yBar: yBar}

	// I'm a little uncertain as to why this is necessary, but it's in the paper.
	if !Verify(us.pk, sig.Bytes(), us.msg) {
		return nil, errors.New("signature does not verify")
	}

	return sig.Bytes(), nil
}

// Verify checks that a signature (sig) is valid relative to the given message (msg) and public key (pk).
func Verify(pk *PublicKey, sig []byte, msg []byte) bool {
	decodedSig := &signature{}
	if err := decodedSig.SetCanonicalBytes(sig); err != nil {
		return false
	}

	cBar, err := sigHash(pk.point, msg, decodedSig.bigRBar)
	if err != nil || scalarIsZero(decodedSig.yBar) {
		return false
	}

	f := r255.NewScalar().Add(cBar, scalarPowFive(decodedSig.yBar)) // f = cBar + yBar ^5

	leftCheck := r255.NewIdentityElement().Add(decodedSig.bigRBar, r255.NewIdentityElement().ScalarMult(f, pk.point)) // leftCheck = Rbar + (cBar + yBar ^5) pk
	rightCheck := r255.NewIdentityElement().Add(r255.NewIdentityElement().ScalarBaseMult(decodedSig.zBar),
		r255.NewIdentityElement().ScalarMult(decodedSig.yBar, generatorH())) // rightCheck = zBar G + yBar H

	return leftCheck.Equal(rightCheck) == 1
}

func sigHash(pk *r255.Element, m []byte, bigRBar *r255.Element) (*r255.Scalar, error) {
	h := sha512.New()
	_, err := h.Write(pk.Bytes())
	if err != nil {
		return nil, err
	}

	_, err = h.Write(m)
	if err != nil {
		return nil, err
	}

	_, err = h.Write(bigRBar.Bytes())
	if err != nil {
		return nil, err
	}

	digest := make([]byte, sha512.Size)
	h.Sum(digest)

	result := r255.NewScalar().FromUniformBytes(digest)

	return result, nil
}
