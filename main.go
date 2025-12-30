package main

import (
	"bytes"
	"crypto/sha256"
	"log"
	"main/circuit"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// Compile the circuit
	pl := circuit.ProofOfSumCircuit{}
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &pl)
	if err != nil {
		log.Fatalf("compilation error: %v", err)
	}
	var circuitBuf bytes.Buffer
	if _, err := r1cs.WriteTo(&circuitBuf); err != nil {
		log.Fatalf("compilation error: %v", err)
	}

	// Write circuit data to file
	if err := os.WriteFile("sum.circuit", circuitBuf.Bytes(), 0644); err != nil {
		log.Fatalf("failed to write circuit data: %v", err)
	}

	// Setup: Generate proving and verification keys
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("setup error: %v", err)
	}
	var pkBuf bytes.Buffer
	if _, err := pk.WriteTo(&pkBuf); err != nil {
		log.Fatalf("pk write error: %v", err)
	}

	// Write proving key data to file
	if err := os.WriteFile("sum.pk", pkBuf.Bytes(), 0644); err != nil {
		log.Fatalf("failed to write proving key data: %v", err)
	}

	// Writes the verifying key to a Solidity contract file
	fSolidity, err := os.Create("sum.sol")
	if err != nil {
		log.Fatal(err)
	}
	defer fSolidity.Close()

	if err := vk.ExportSolidity(fSolidity, solidity.WithHashToFieldFunction(sha256.New())); err != nil {
		log.Fatal(err)
	}
}
