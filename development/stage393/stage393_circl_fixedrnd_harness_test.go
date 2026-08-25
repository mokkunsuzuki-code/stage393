package mldsa65

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestStage393DeterministicFixedRandomness(t *testing.T) {
	if SeedSize != sha256.Size {
		t.Fatalf(
			"unexpected ML-DSA-65 seed size: %d",
			SeedSize,
		)
	}

	/*
		Public, non-secret, test-only deterministic fixture.

		This is intentionally reproducible and MUST NOT
		be interpreted as production secret key material.
	*/
	seedDigest := sha256.Sum256(
		[]byte(
			"QSP Stage393 public non-secret deterministic test key v1",
		),
	)

	var seed [SeedSize]byte
	copy(seed[:], seedDigest[:])

	publicKey, privateKey :=
		NewKeyFromSeed(&seed)

	message := []byte(
		"QSP Stage393 ML-DSA-65 fixed-randomness probe",
	)

	context := []byte(
		"QSP-Stage393",
	)

	if len(context) > 255 {
		t.Fatal("context too long")
	}

	/*
		Match CIRCL public SignTo / Verify framing:

		    0x00 || ctx_len || ctx || message
	*/
	framed := make(
		[]byte,
		0,
		2+len(context)+len(message),
	)

	framed = append(
		framed,
		byte(0),
		byte(len(context)),
	)

	framed = append(
		framed,
		context...,
	)

	framed = append(
		framed,
		message...,
	)

	fixedRandomness := sha256.Sum256(
		[]byte(
			"QSP Stage393 fixed-randomness probe v1",
		),
	)

	signatureOne :=
		privateKey.unsafeSignInternal(
			framed,
			fixedRandomness,
		)

	signatureTwo :=
		privateKey.unsafeSignInternal(
			framed,
			fixedRandomness,
		)

	if !bytes.Equal(
		signatureOne,
		signatureTwo,
	) {
		t.Fatal(
			"repeat signature byte equality failed",
		)
	}

	if !Verify(
		publicKey,
		message,
		context,
		signatureOne,
	) {
		t.Fatal(
			"CIRCL public Verify rejected fixed-randomness signature",
		)
	}

	rawPublicKey, err :=
		publicKey.MarshalBinary()

	if err != nil {
		t.Fatal(err)
	}

	publicKeyHash :=
		sha256.Sum256(rawPublicKey)

	messageHash :=
		sha256.Sum256(message)

	contextHash :=
		sha256.Sum256(context)

	signatureHash :=
		sha256.Sum256(signatureOne)

	seedFingerprint :=
		sha256.Sum256(seed[:])

	fixedRandomnessFingerprint :=
		sha256.Sum256(
			fixedRandomness[:],
		)

	fmt.Println(
		"algorithm = ML-DSA-65",
	)

	fmt.Printf(
		"raw_public_key_size = %d\n",
		len(rawPublicKey),
	)

	fmt.Printf(
		"signature_size = %d\n",
		len(signatureOne),
	)

	fmt.Printf(
		"public_key_sha256 = %x\n",
		publicKeyHash,
	)

	fmt.Printf(
		"message_sha256 = %x\n",
		messageHash,
	)

	fmt.Printf(
		"context_sha256 = %x\n",
		contextHash,
	)

	fmt.Printf(
		"test_seed_sha256 = %x\n",
		seedFingerprint,
	)

	fmt.Printf(
		"fixed_randomness_sha256 = %x\n",
		fixedRandomnessFingerprint,
	)

	fmt.Printf(
		"signature_sha256 = %x\n",
		signatureHash,
	)

	fmt.Println(
		"repeat_signature_byte_equality = true",
	)

	fmt.Println(
		"circl_public_verify = true",
	)

	outputDir :=
		os.Getenv(
			"STAGE393_OUTPUT_DIR",
		)

	if outputDir == "" {
		t.Fatal(
			"STAGE393_OUTPUT_DIR missing",
		)
	}

	if err := os.MkdirAll(
		outputDir,
		0700,
	); err != nil {
		t.Fatal(err)
	}

	publicFiles := map[string][]byte{
		"public-key.raw": rawPublicKey,

		"message.bin": message,

		"context.bin": context,

		"signature.bin": signatureOne,
	}

	for name, data := range publicFiles {

		path :=
			filepath.Join(
				outputDir,
				name,
			)

		if err := os.WriteFile(
			path,
			data,
			0600,
		); err != nil {
			t.Fatal(err)
		}
	}

	fmt.Println(
		"private_key_persisted = false",
	)

	fmt.Println(
		"raw_test_seed_persisted = false",
	)

	fmt.Println(
		"raw_fixed_randomness_persisted = false",
	)

	fmt.Println(
		"PASS: Stage393 deterministic CIRCL fixed-randomness harness",
	)
}
