package circuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

func ByteArrayToLimbs(api frontend.API, array []uints.U8) ([]frontend.Variable, error) {
	ret := make([]frontend.Variable, (len(array)+7)/8)
	ap := make([]uints.U8, 8*len(ret)-len(array))
	for i := range ap {
		ap[i] = uints.NewU8(0)
	}
	array = append(ap, array...)
	for i := range ret {
		ret[len(ret)-1-i] = api.Add(
			api.Mul(1<<0, array[8*i+7].Val),
			api.Mul(1<<8, array[8*i+6].Val),
			api.Mul(1<<16, array[8*i+5].Val),
			api.Mul(1<<24, array[8*i+4].Val),
			api.Mul(1<<32, array[8*i+3].Val),
			api.Mul(1<<40, array[8*i+2].Val),
			api.Mul(1<<48, array[8*i+1].Val),
			api.Mul(1<<56, array[8*i+0].Val),
		)
	}
	return ret, nil
}

func BytesToHash(api frontend.API, in []uints.U8) (*emulated.Element[emulated.Secp256k1Fr], error) {
	msghash, err := ByteArrayToLimbs(api, in)
	if err != nil {
		return nil, err
	}
	efp, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return nil, err
	}
	return efp.NewElement(msghash), nil
}

func BytesToSig(api frontend.API, in []uints.U8) (*ecdsa.Signature[emulated.Secp256k1Fr], error) {
	if len(in) != 64 {
		return nil, fmt.Errorf("invalid sig length")
	}
	r, err := ByteArrayToLimbs(api, in[:32])
	if err != nil {
		return nil, err
	}
	s, err := ByteArrayToLimbs(api, in[32:])
	if err != nil {
		return nil, err
	}
	var sig ecdsa.Signature[emulated.Secp256k1Fr]
	efp, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return nil, err
	}
	sig.R = *efp.NewElement(r)
	sig.S = *efp.NewElement(s)
	return &sig, nil
}

func BytesToPubkey(api frontend.API, in []uints.U8) (*ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr], error) {
	if len(in) != 65 {
		return nil, fmt.Errorf("invalid pubkey length")
	}
	x, err := ByteArrayToLimbs(api, in[1:33])
	if err != nil {
		return nil, err
	}
	y, err := ByteArrayToLimbs(api, in[33:])
	if err != nil {
		return nil, err
	}
	var pub ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	efp, err := emulated.NewField[emulated.Secp256k1Fp](api)
	if err != nil {
		return nil, err
	}
	pub.X = *efp.NewElement(x)
	pub.Y = *efp.NewElement(y)
	return &pub, nil
}
