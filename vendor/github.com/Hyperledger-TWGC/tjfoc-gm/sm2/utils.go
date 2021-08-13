package sm2

import (
	"encoding/asn1"
	"math/big"
)

func Decompress(input []byte) *PublicKey {
	var aa, xx, xx3 sm2P256FieldElement

	P256Sm2()
	x := &big.Int{}
	x.SetBytes(input[1:])
	xx = sm2P256FromBig(x)
	xx3 = sm2P256Square(xx)   // x3 = x ^ 2
	xx3 = sm2P256Mul(xx3, xx) // x3 = x ^ 2 * x
	aa = sm2P256Mul(a, xx)    // a = a * x
	xx3 = sm2P256Add(xx3, aa)
	xx3 = sm2P256Add(xx3, b)

	y2 := &big.Int{}
	sm2P256ToBig(xx3, y2)
	y := &big.Int{}
	y.ModSqrt(y2, P)
	if getLastBit(y)+2 != uint(input[0]) {
		y.Sub(P, y)
	}
	return &PublicKey{
		Curve: P256Sm2(),
		X:     x,
		Y:     y,
	}
}

func Compress(a *PublicKey) []byte {
	buf := []byte{}
	yp := getLastBit(a.Y)
	buf = append(buf, a.X.Bytes()...)
	if n := len(a.X.Bytes()); n < 32 {
		buf = append(zeroByteSlice[:(32-n)], buf...)
	}
	buf = append([]byte{byte(yp + 2)}, buf...)
	return buf
}

func SignDigitToSignData(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(sm2Signature{r, s})
}

func SignDataToSignDigit(sign []byte) (*big.Int, *big.Int, error) {
	var sm2Sign sm2Signature

	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return nil, nil, err
	}
	return sm2Sign.R, sm2Sign.S, nil
}
