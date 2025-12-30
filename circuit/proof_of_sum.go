package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/hash/sha3"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

const (
	LimitSeconds = 10 * 60
	SumMaxItems  = 2
)

type ProofOfSumCircuit struct {
	PayloadHashs [SumMaxItems][32]uints.U8
	Timestamps   [SumMaxItems]frontend.Variable
	Values       [SumMaxItems]frontend.Variable
	SigBytes     [SumMaxItems][64]uints.U8

	PubBytes  [SumMaxItems][65]uints.U8
	StartTime frontend.Variable

	Threshold  frontend.Variable `gnark:",public"`
	EthAddress frontend.Variable `gnark:",public"`
}

func (c *ProofOfSumCircuit) Define(api frontend.API) error {
	sum := frontend.Variable(0)
	timeUpper := api.Add(c.StartTime, LimitSeconds)
	timeCmp := cmp.NewBoundedComparator(api, big.NewInt(LimitSeconds*2), false)

	for i := 0; i < SumMaxItems; i++ {
		if err := c.validateSig(api, c.PayloadHashs[i][:], c.Timestamps[i],
			c.Values[i], c.SigBytes[i][:], c.PubBytes[i][:], c.EthAddress); err != nil {
			return err
		}
		// StartTime <= timestamp[i]
		timeCmp.AssertIsLessEq(c.StartTime, c.Timestamps[i])
		// timestamp[i] <= StartTime + 24h
		timeCmp.AssertIsLessEq(c.Timestamps[i], timeUpper)

		// sum += value[i]
		sum = api.Add(sum, c.Values[i])
	}

	// sum > threshold
	sumCmp := cmp.NewBoundedComparator(api, big.NewInt(1<<62), false)
	// enforce: threshold <= sum
	sumCmp.AssertIsLessEq(c.Threshold, sum)
	return nil
}

func (c *ProofOfSumCircuit) validateSig(api frontend.API, PayloadHash []uints.U8, Timestamp, Value frontend.Variable, SigBytes []uints.U8,
	PubBytes []uints.U8, ethAddr frontend.Variable) error {

	if len(PayloadHash) != 32 {
		return fmt.Errorf("invalid payload hash length")
	}

	// validate signatures
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}
	lastHash, err := hashSumInput(api, uapi, PayloadHash, Timestamp, Value)
	if err != nil {
		return err
	}
	if err := ecdsaVerification(api, lastHash, SigBytes, PubBytes); err != nil {
		return err
	}

	// validate eth address
	keccak, err := sha3.NewLegacyKeccak256(api)
	if err != nil {
		return err
	}
	keccak.Write(PubBytes[1:])
	hashBits := keccak.Sum()
	lower20Bytes := hashBits[12:]
	addrBits := api.ToBinary(ethAddr, 160)
	for i := 19; i >= 0; i-- {
		dl := api.ToBinary(lower20Bytes[19-i].Val, 8)
		for j := 0; j < 8; j++ {
			api.AssertIsEqual(dl[j], addrBits[i*8+j])
		}
	}
	return nil
}

func hashSumInput(api frontend.API, uapi *uints.BinaryField[uints.U64],
	payloadHash []uints.U8, timestamp, value frontend.Variable) ([]uints.U8, error) {
	hasher, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	hasher.Write(payloadHash[:])
	hasher.Write(uapi.UnpackLSB(uapi.ValueOf(timestamp))[:])
	hasher.Write(uapi.UnpackLSB(uapi.ValueOf(value))[:])
	return hasher.Sum(), nil
}

func ecdsaVerification(api frontend.API, ha []uints.U8, sig []uints.U8, pub []uints.U8) error {
	msg, err := BytesToHash(api, ha)
	if err != nil {
		return err
	}
	pubkey, err := BytesToPubkey(api, pub)
	if err != nil {
		return err
	}
	signature, err := BytesToSig(api, sig)
	if err != nil {
		return err
	}
	pubkey.Verify(api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp](), msg, signature)
	return nil
}
