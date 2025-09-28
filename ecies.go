package ecies

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math/big"
)

var (
	ErrImport                     = fmt.Errorf("ecies: failed to import key")
	ErrInvalidCurve               = fmt.Errorf("ecies: invalid elliptic curve")
	ErrInvalidParams              = fmt.Errorf("ecies: invalid ECIES parameters")
	ErrInvalidPublicKey           = fmt.Errorf("ecies: invalid public key")
	ErrSharedKeyIsPointAtInfinity = fmt.Errorf("ecies: shared key is point at infinity")
	ErrSharedKeyTooBig            = fmt.Errorf("ecies: shared key params are too big")
)

// PublicKey is a representation of an elliptic curve public key.
type PublicKey struct {
	X *big.Int
	Y *big.Int
	elliptic.Curve
	Params *ECIESParams
}

// Export an ECIES public key as an ECDSA public key.
func (pub *PublicKey) ExportECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: pub.Curve, X: pub.X, Y: pub.Y}
}

// Import an ECDSA public key as an ECIES public key.
func ImportECDSAPublic(pub *ecdsa.PublicKey) *PublicKey {
	return &PublicKey{
		X:      pub.X,
		Y:      pub.Y,
		Curve:  pub.Curve,
		Params: ParamsFromCurve(pub.Curve),
	}
}

// KeyProvider is an interface to access the Private Key derivatives for decryption.
// It allows to abstract use cases where the private key itself is not accessible e.g. HSM devices.
type KeyProvider interface {
	Public() *PublicKey
	GenerateShared(pub *PublicKey) ([]byte, error)
}

// PrivateKey is a representation of an elliptic curve private key.
// It implements the KeyProvider interface for the local in-memory key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// Export an ECIES private key as an ECDSA private key.
func (prv *PrivateKey) ExportECDSA() *ecdsa.PrivateKey {
	pub := &prv.PublicKey
	pubECDSA := pub.ExportECDSA()
	return &ecdsa.PrivateKey{PublicKey: *pubECDSA, D: prv.D}
}

// Import an ECDSA private key as an ECIES private key.
func ImportECDSA(prv *ecdsa.PrivateKey) *PrivateKey {
	pub := ImportECDSAPublic(&prv.PublicKey)
	return &PrivateKey{*pub, prv.D}
}

// Generate an elliptic curve public / private keypair. If params is nil,
// the recommended default paramters for the key will be chosen.
func GenerateKey(rand io.Reader, curve elliptic.Curve, params *ECIESParams) (prv *PrivateKey, err error) {
	pb, x, y, err := elliptic.GenerateKey(curve, rand)
	if err != nil {
		return
	}
	prv = new(PrivateKey)
	prv.PublicKey.X = x
	prv.PublicKey.Y = y
	prv.PublicKey.Curve = curve
	prv.D = new(big.Int).SetBytes(pb)
	if params == nil {
		params = ParamsFromCurve(curve)
	}
	prv.PublicKey.Params = params
	return
}

func (prv *PrivateKey) Public() *PublicKey {
	return &prv.PublicKey
}

// SEC 1 section 3.3.1: ECDH key agreement method used to establish secret keys for encryption.
func (prv *PrivateKey) GenerateShared(pub *PublicKey) ([]byte, error) {
	if prv.PublicKey.Curve != pub.Curve {
		return nil, ErrInvalidCurve
	}
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
	if x == nil {
		return nil, ErrSharedKeyIsPointAtInfinity
	}

	out := make([]byte, (pub.Curve.Params().BitSize+7)/8)
	return x.FillBytes(out), nil
}

var (
	ErrKeyDataTooLong = fmt.Errorf("ecies: can't supply requested key data")
	ErrSharedTooLong  = fmt.Errorf("ecies: shared secret is too long")
	ErrInvalidMessage = fmt.Errorf("ecies: invalid message")
)

var (
	big2To32   = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	big2To32M1 = new(big.Int).Sub(big2To32, big.NewInt(1))
)

func incCounter(ctr []byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	} else if ctr[2]++; ctr[2] != 0 {
		return
	} else if ctr[1]++; ctr[1] != 0 {
		return
	} else if ctr[0]++; ctr[0] != 0 {
		return
	}
}

// NIST SP 800-56c Concatenation Key Derivation Function (see section 4.1).
func concatKDF(hash hash.Hash, z, s1 []byte, kdLen int) (k []byte, err error) {
	if s1 == nil {
		s1 = make([]byte, 0)
	}

	reps := ((kdLen + 7) * 8) / (hash.BlockSize() * 8)
	if big.NewInt(int64(reps)).Cmp(big2To32M1) > 0 {
		fmt.Println(big2To32M1)
		return nil, ErrKeyDataTooLong
	}

	counter := []byte{0, 0, 0, 1}
	k = make([]byte, 0)

	for i := 0; i <= reps; i++ {
		hash.Write(counter)
		hash.Write(z)
		hash.Write(s1)
		k = append(k, hash.Sum(nil)...)
		hash.Reset()
		incCounter(counter)
	}

	k = k[:kdLen]
	return
}

// Generate an initialisation vector for CTR mode.
func generateIV(params *ECIESParams, rand io.Reader) (iv []byte, err error) {
	iv = make([]byte, params.BlockSize)
	_, err = io.ReadFull(rand, iv)
	return
}

func (prv *PrivateKey) Decrypt(rand io.Reader, c, s1, s2 []byte) (m []byte, err error) {
	return Decrypt(prv, c, s1, s2)
}

// symEncrypt carries out CTR encryption using the block cipher specified in the parameters.
func symEncrypt(rand io.Reader, params *ECIESParams, key []byte, m io.Reader, w io.Writer, sum hash.Hash) (err error) {
	c, err := params.Cipher(key)
	if err != nil {
		return
	}

	iv, err := generateIV(params, rand)
	if err != nil {
		return
	}

	w.Write(iv)
	sum.Write(iv)

	cw := &ctrHashWriter{ctr: cipher.NewCTR(c, iv), sum: sum, w: w, encode: true}
	_, err = io.Copy(cw, m)
	return
}

var _ io.Writer = (*ctrHashWriter)(nil)

type ctrHashWriter struct {
	w      io.Writer
	sum    hash.Hash
	ctr    cipher.Stream
	encode bool
}

func (g *ctrHashWriter) Write(p []byte) (n int, err error) {
	p2 := make([]byte, len(p))

	if !g.encode {
		// Decryption: write original ciphertext to MAC before decrypting
		g.sum.Write(p)
		g.ctr.XORKeyStream(p2, p)
	} else {
		// Encryption: encrypt and then write ciphertext to MAC
		g.ctr.XORKeyStream(p2, p)
		g.sum.Write(p2)
	}

	n, err = g.w.Write(p2)
	if err != nil {
		return n, fmt.Errorf("ctr writer err: %v", err)
	}

	return n, err
}

// Encrypt encrypts a message using ECIES as specified in SEC 1, 5.1. If
// the shared information parameters aren't being used, they should be nil.
func Decrypt(prv KeyProvider, c, s1, s2 []byte) (m []byte, err error) {
	rbuf := bytes.NewBuffer(c)
	wbuf := bytes.NewBuffer(nil)
	err = DecryptIO(prv, rbuf, len(c), wbuf, s1, s2)
	if err != nil {
		return nil, err
	}
	m = wbuf.Bytes()
	return
}

func DecryptIO(prv KeyProvider, c io.Reader, cSize int, w io.Writer, s1, s2 []byte) (err error) {
	if cSize == 0 {
		err = ErrInvalidMessage
		return
	}
	pub := prv.Public()
	params := pub.Params
	if params == nil {
		if params = ParamsFromCurve(pub.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}
	hash := params.Hash()

	var c_0 = make([]byte, 1)
	if _, err = c.Read(c_0); err != nil {
		return err
	}

	var kLen, hLen, mStart, mEnd int
	hLen = hash.Size()
	kLen = (pub.Curve.Params().BitSize + 7) / 8
	switch c_0[0] {
	case 2, 3:
		// https://github.com/golang/go/blob/go1.19.5/src/crypto/elliptic/elliptic.go#L147
		mStart = 1 + kLen
	case 4:
		// https://github.com/golang/go/blob/go1.19.5/src/crypto/elliptic/elliptic.go#L120
		mStart = 1 + 2*kLen
	default:
		err = ErrInvalidPublicKey
		return
	}
	if cSize < (mStart + hLen + 1) {
		err = ErrInvalidMessage
		return
	}
	mEnd = cSize - hLen // This is the start of the MAC tag.

	var cmStart = make([]byte, mStart)
	cmStart[0] = c_0[0]
	if _, err = c.Read(cmStart[1:]); err != nil {
		return err
	}

	R := new(PublicKey)
	R.Curve = pub.Curve
	R.X, R.Y = elliptic.Unmarshal(R.Curve, cmStart)
	if R.X == nil {
		err = ErrInvalidPublicKey
		return
	}
	if !R.Curve.IsOnCurve(R.X, R.Y) {
		err = ErrInvalidCurve
		return
	}

	z, err := prv.GenerateShared(R)
	if err != nil {
		return
	}

	K, err := concatKDF(hash, z, s1, params.KeyLen+params.KeyLen)
	if err != nil {
		return
	}

	Ke := K[:params.KeyLen]
	Km := K[params.KeyLen:]
	hash.Write(Km)
	Km = hash.Sum(nil)
	hash.Reset()

	cBodyLen := mEnd - mStart // This is the length of the encrypted message part (em).

	sum := hmac.New(params.Hash, Km)
	lastSum, err := symDecrypt(params, Ke, c, cBodyLen, w, sum)
	if err != nil {
		return
	}

	sum.Write(s2)

	d := sum.Sum(nil)
	if subtle.ConstantTimeCompare(lastSum, d) != 1 {
		err = ErrInvalidMessage
		return
	}

	return

}

func symDecrypt(params *ECIESParams, key []byte, r io.Reader, rLength int, w io.Writer, sum hash.Hash) (lastSum []byte, err error) {
	c, err := params.Cipher(key)
	if err != nil {
		return
	}

	var iv = make([]byte, params.BlockSize)
	if _, err = r.Read(iv); err != nil {
		return nil, err
	}
	sum.Write(iv)

	// The reader for the encrypted message, which is rLength bytes long.
	// It excludes the IV (already read) and the MAC tag (at the end).
	rLength -= len(iv)
	lr := io.LimitReader(r, int64(rLength))

	cw := &ctrHashWriter{ctr: cipher.NewCTR(c, iv), sum: sum, w: w, encode: false}
	_, err = io.Copy(cw, lr)
	if err != nil {
		return nil, err
	}

	// After reading the encrypted message, the rest of the reader is the MAC tag.
	lastSum, err = io.ReadAll(r)

	return
}

func Encrypt(rand io.Reader, pub *PublicKey, m, s1, s2 []byte) (ct []byte, err error) {
	rbuf := bytes.NewBuffer(m)
	wbuf := bytes.NewBuffer(nil)
	err = EncryptIO(rand, pub, rbuf, wbuf, s1, s2)
	if err != nil {
		return nil, err
	}
	ct = wbuf.Bytes()
	return
}

func EncryptIO(rand io.Reader, pub *PublicKey, m io.Reader, w io.Writer, s1, s2 []byte) (err error) {
	params := pub.Params
	if params == nil {
		if params = ParamsFromCurve(pub.Curve); params == nil {
			err = ErrUnsupportedECIESParameters
			return
		}
	}
	R, err := GenerateKey(rand, pub.Curve, params)
	if err != nil {
		return
	}

	hash := params.Hash()
	z, err := R.GenerateShared(pub)
	if err != nil {
		return
	}
	K, err := concatKDF(hash, z, s1, params.KeyLen+params.KeyLen)
	if err != nil {
		return
	}
	Ke := K[:params.KeyLen]
	Km := K[params.KeyLen:]
	hash.Write(Km)
	Km = hash.Sum(nil)
	hash.Reset()

	Rb := elliptic.Marshal(pub.Curve, R.PublicKey.X, R.PublicKey.Y)
	w.Write(Rb)

	sum := hmac.New(params.Hash, Km)
	err = symEncrypt(rand, params, Ke, m, w, sum)
	if err != nil {
		return
	}
	sum.Write(s2)

	d := sum.Sum(nil)
	w.Write(d)

	return
}
