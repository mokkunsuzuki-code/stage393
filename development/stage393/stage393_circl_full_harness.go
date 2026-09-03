package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const (
	harnessSchema          = "qsp.stage393.circl-file-result.v1"
	harnessVersion         = "stage393-circl-full-harness-v1"
	circlCommit            = "cfa7c70defd831ffb0792ab2af560bfef43d60ca"
	circlTree              = "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139"
	wycheproofCommit       = "dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166"
	overlayGeneratorSHA256 = "cb57f79ab1059cda2fcf4471eee9f8b3cd88c31f384680ad7c21d9bffb6ed169"
)

type vectorFile struct {
	Algorithm     string      `json:"algorithm"`
	NumberOfTests int         `json:"numberOfTests"`
	Schema        string      `json:"schema"`
	TestGroups    []testGroup `json:"testGroups"`
}

type testGroup struct {
	Type        string       `json:"type"`
	PrivateSeed *string      `json:"privateSeed,omitempty"`
	PrivateKey  *string      `json:"privateKey,omitempty"`
	PublicKey   *string      `json:"publicKey,omitempty"`
	Tests       []testVector `json:"tests"`
}

type testVector struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Msg     *string  `json:"msg,omitempty"`
	Ctx     *string  `json:"ctx,omitempty"`
	Rnd     *string  `json:"rnd,omitempty"`
	Mu      *string  `json:"mu,omitempty"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
	Flags   []string `json:"flags"`
}

type implementation struct {
	algorithm      string
	seedSize       int
	publicKeySize  int
	privateKeySize int
	signatureSize  int

	newFromSeed func(seed []byte) (sk any, pk any, publicBytes []byte, err error)

	importPrivate func(encoded []byte) (sk any, pk any, publicBytes []byte, err error)
	importPublic  func(encoded []byte) (pk any, err error)

	signFixedRnd   func(sk any, msg []byte, ctx []byte, rnd [32]byte) ([]byte, error)
	signExternalMu func(sk any, mu [64]byte, rnd [32]byte) []byte

	verify           func(pk any, msg []byte, ctx []byte, sig []byte) bool
	verifyExternalMu func(pk any, mu [64]byte, sig []byte) bool
}

type groupSetup struct {
	sk                any
	pk                any
	publicBytes       []byte
	rejected          bool
	rejectionStage    string
	rejectionDetail   string
	panicDetected     bool
	panicDetail       string
	publicKeyProvided bool
	publicKeyMatch    bool
}

type testOutcome struct {
	GroupIndex              int    `json:"group_index"`
	TCID                    int    `json:"tc_id"`
	Kind                    string `json:"kind"`
	Lane                    string `json:"lane"`
	ExpectedResult          string `json:"expected_result"`
	ObservedResult          string `json:"observed_result"`
	Matched                 bool   `json:"matched"`
	OperationSucceeded      bool   `json:"operation_succeeded"`
	SignatureExact          bool   `json:"signature_exact"`
	GeneratedSignatureValid bool   `json:"generated_signature_valid"`
	PublicKeyBindingOK      bool   `json:"public_key_binding_ok"`
	RejectionStage          string `json:"rejection_stage,omitempty"`
	Reason                  string `json:"reason"`
	GeneratedSignatureSHA   string `json:"generated_signature_sha256,omitempty"`
	RuntimeError            bool   `json:"runtime_error"`
}

type fileResult struct {
	Schema                      string        `json:"schema"`
	HarnessVersion              string        `json:"harness_version"`
	Implementation              string        `json:"implementation"`
	ImplementationCommit        string        `json:"implementation_commit"`
	ImplementationTree          string        `json:"implementation_tree"`
	OverlayGeneratorSHA256      string        `json:"overlay_generator_sha256"`
	WycheproofCommit            string        `json:"wycheproof_commit"`
	VectorFileSHA256            string        `json:"vector_file_sha256"`
	Algorithm                   string        `json:"algorithm"`
	Kind                        string        `json:"kind"`
	VectorSchema                string        `json:"vector_schema"`
	DeclaredVectorCount         int           `json:"declared_vector_count"`
	ExecutedVectorCount         int           `json:"executed_vector_count"`
	ExpectedValidCount          int           `json:"expected_valid_count"`
	ExpectedInvalidCount        int           `json:"expected_invalid_count"`
	MatchedCount                int           `json:"matched_count"`
	MismatchedCount             int           `json:"mismatched_count"`
	RuntimeErrorCount           int           `json:"runtime_error_count"`
	UnsupportedVectorCount      int           `json:"unsupported_vector_count"`
	SkippedVectorCount          int           `json:"skipped_vector_count"`
	RawPrivateMaterialPersisted bool          `json:"raw_private_material_persisted"`
	Decision                    string        `json:"decision"`
	Tests                       []testOutcome `json:"tests"`
}

func implementationFor(algorithm string) (implementation, error) {
	switch algorithm {
	case "44":
		return implementation{
			algorithm:      "ML-DSA-44",
			seedSize:       mldsa44.SeedSize,
			publicKeySize:  mldsa44.PublicKeySize,
			privateKeySize: mldsa44.PrivateKeySize,
			signatureSize:  mldsa44.SignatureSize,
			newFromSeed: func(seed []byte) (any, any, []byte, error) {
				if len(seed) != mldsa44.SeedSize {
					return nil, nil, nil, fmt.Errorf("seed length %d, want %d", len(seed), mldsa44.SeedSize)
				}
				var fixed [mldsa44.SeedSize]byte
				copy(fixed[:], seed)
				pk, sk := mldsa44.NewKeyFromSeed(&fixed)
				return sk, pk, pk.Bytes(), nil
			},
			importPrivate: func(encoded []byte) (any, any, []byte, error) {
				sk := new(mldsa44.PrivateKey)
				if err := sk.UnmarshalBinary(encoded); err != nil {
					return nil, nil, nil, err
				}
				pk, ok := sk.Public().(*mldsa44.PublicKey)
				if !ok {
					return nil, nil, nil, fmt.Errorf("unexpected ML-DSA-44 public key type")
				}
				return sk, pk, pk.Bytes(), nil
			},
			importPublic: func(encoded []byte) (any, error) {
				pk := new(mldsa44.PublicKey)
				if err := pk.UnmarshalBinary(encoded); err != nil {
					return nil, err
				}
				return pk, nil
			},
			signFixedRnd: func(sk any, msg []byte, ctx []byte, rnd [32]byte) ([]byte, error) {
				typed, ok := sk.(*mldsa44.PrivateKey)
				if !ok {
					return nil, fmt.Errorf("unexpected ML-DSA-44 private key type")
				}
				return mldsa44.Stage393SignFixedRnd(typed, msg, ctx, rnd)
			},
			signExternalMu: func(sk any, mu [64]byte, rnd [32]byte) []byte {
				return mldsa44.Stage393SignExternalMu(sk.(*mldsa44.PrivateKey), mu, rnd)
			},
			verify: func(pk any, msg []byte, ctx []byte, sig []byte) bool {
				return mldsa44.Verify(pk.(*mldsa44.PublicKey), msg, ctx, sig)
			},
			verifyExternalMu: func(pk any, mu [64]byte, sig []byte) bool {
				return mldsa44.Stage393VerifyExternalMu(pk.(*mldsa44.PublicKey), mu, sig)
			},
		}, nil

	case "65":
		return implementation{
			algorithm:      "ML-DSA-65",
			seedSize:       mldsa65.SeedSize,
			publicKeySize:  mldsa65.PublicKeySize,
			privateKeySize: mldsa65.PrivateKeySize,
			signatureSize:  mldsa65.SignatureSize,
			newFromSeed: func(seed []byte) (any, any, []byte, error) {
				if len(seed) != mldsa65.SeedSize {
					return nil, nil, nil, fmt.Errorf("seed length %d, want %d", len(seed), mldsa65.SeedSize)
				}
				var fixed [mldsa65.SeedSize]byte
				copy(fixed[:], seed)
				pk, sk := mldsa65.NewKeyFromSeed(&fixed)
				return sk, pk, pk.Bytes(), nil
			},
			importPrivate: func(encoded []byte) (any, any, []byte, error) {
				sk := new(mldsa65.PrivateKey)
				if err := sk.UnmarshalBinary(encoded); err != nil {
					return nil, nil, nil, err
				}
				pk, ok := sk.Public().(*mldsa65.PublicKey)
				if !ok {
					return nil, nil, nil, fmt.Errorf("unexpected ML-DSA-65 public key type")
				}
				return sk, pk, pk.Bytes(), nil
			},
			importPublic: func(encoded []byte) (any, error) {
				pk := new(mldsa65.PublicKey)
				if err := pk.UnmarshalBinary(encoded); err != nil {
					return nil, err
				}
				return pk, nil
			},
			signFixedRnd: func(sk any, msg []byte, ctx []byte, rnd [32]byte) ([]byte, error) {
				typed, ok := sk.(*mldsa65.PrivateKey)
				if !ok {
					return nil, fmt.Errorf("unexpected ML-DSA-65 private key type")
				}
				return mldsa65.Stage393SignFixedRnd(typed, msg, ctx, rnd)
			},
			signExternalMu: func(sk any, mu [64]byte, rnd [32]byte) []byte {
				return mldsa65.Stage393SignExternalMu(sk.(*mldsa65.PrivateKey), mu, rnd)
			},
			verify: func(pk any, msg []byte, ctx []byte, sig []byte) bool {
				return mldsa65.Verify(pk.(*mldsa65.PublicKey), msg, ctx, sig)
			},
			verifyExternalMu: func(pk any, mu [64]byte, sig []byte) bool {
				return mldsa65.Stage393VerifyExternalMu(pk.(*mldsa65.PublicKey), mu, sig)
			},
		}, nil

	case "87":
		return implementation{
			algorithm:      "ML-DSA-87",
			seedSize:       mldsa87.SeedSize,
			publicKeySize:  mldsa87.PublicKeySize,
			privateKeySize: mldsa87.PrivateKeySize,
			signatureSize:  mldsa87.SignatureSize,
			newFromSeed: func(seed []byte) (any, any, []byte, error) {
				if len(seed) != mldsa87.SeedSize {
					return nil, nil, nil, fmt.Errorf("seed length %d, want %d", len(seed), mldsa87.SeedSize)
				}
				var fixed [mldsa87.SeedSize]byte
				copy(fixed[:], seed)
				pk, sk := mldsa87.NewKeyFromSeed(&fixed)
				return sk, pk, pk.Bytes(), nil
			},
			importPrivate: func(encoded []byte) (any, any, []byte, error) {
				sk := new(mldsa87.PrivateKey)
				if err := sk.UnmarshalBinary(encoded); err != nil {
					return nil, nil, nil, err
				}
				pk, ok := sk.Public().(*mldsa87.PublicKey)
				if !ok {
					return nil, nil, nil, fmt.Errorf("unexpected ML-DSA-87 public key type")
				}
				return sk, pk, pk.Bytes(), nil
			},
			importPublic: func(encoded []byte) (any, error) {
				pk := new(mldsa87.PublicKey)
				if err := pk.UnmarshalBinary(encoded); err != nil {
					return nil, err
				}
				return pk, nil
			},
			signFixedRnd: func(sk any, msg []byte, ctx []byte, rnd [32]byte) ([]byte, error) {
				typed, ok := sk.(*mldsa87.PrivateKey)
				if !ok {
					return nil, fmt.Errorf("unexpected ML-DSA-87 private key type")
				}
				return mldsa87.Stage393SignFixedRnd(typed, msg, ctx, rnd)
			},
			signExternalMu: func(sk any, mu [64]byte, rnd [32]byte) []byte {
				return mldsa87.Stage393SignExternalMu(sk.(*mldsa87.PrivateKey), mu, rnd)
			},
			verify: func(pk any, msg []byte, ctx []byte, sig []byte) bool {
				return mldsa87.Verify(pk.(*mldsa87.PublicKey), msg, ctx, sig)
			},
			verifyExternalMu: func(pk any, mu [64]byte, sig []byte) bool {
				return mldsa87.Stage393VerifyExternalMu(pk.(*mldsa87.PublicKey), mu, sig)
			},
		}, nil
	default:
		return implementation{}, fmt.Errorf("unsupported parameter set %q", algorithm)
	}
}

func decodeHexField(name string, value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid hex: %w", name, err)
	}
	return decoded, nil
}

func decodeOptionalHex(name string, value *string) ([]byte, bool, error) {
	if value == nil {
		return nil, false, nil
	}
	decoded, err := decodeHexField(name, *value)
	if err != nil {
		return nil, true, err
	}
	return decoded, true, nil
}

func hasFlag(flags []string, wanted string) bool {
	for _, value := range flags {
		if value == wanted {
			return true
		}
	}
	return false
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func safeNewFromSeed(impl implementation, seed []byte) (sk any, pk any, publicBytes []byte, err error, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = true
			err = fmt.Errorf("panic during seed key setup: %v", recovered)
		}
	}()
	sk, pk, publicBytes, err = impl.newFromSeed(seed)
	return
}

func safeImportPrivate(impl implementation, encoded []byte) (sk any, pk any, publicBytes []byte, err error, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = true
			err = fmt.Errorf("panic during private-key import: %v", recovered)
		}
	}()
	sk, pk, publicBytes, err = impl.importPrivate(encoded)
	return
}

func safeImportPublic(impl implementation, encoded []byte) (pk any, err error, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = true
			err = fmt.Errorf("panic during public-key import: %v", recovered)
		}
	}()
	pk, err = impl.importPublic(encoded)
	return
}

func safeSignFixedRnd(impl implementation, sk any, msg []byte, ctx []byte, rnd [32]byte) (sig []byte, err error, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = true
			err = fmt.Errorf("panic during message/context signing: %v", recovered)
		}
	}()
	sig, err = impl.signFixedRnd(sk, msg, ctx, rnd)
	return
}

func safeSignExternalMu(impl implementation, sk any, mu [64]byte, rnd [32]byte) (sig []byte, err error, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = true
			err = fmt.Errorf("panic during External-Mu signing: %v", recovered)
		}
	}()
	sig = impl.signExternalMu(sk, mu, rnd)
	return sig, nil, false
}

func safeVerify(impl implementation, pk any, msg []byte, ctx []byte, sig []byte) (accepted bool, err error, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = true
			err = fmt.Errorf("panic during verification: %v", recovered)
		}
	}()
	return impl.verify(pk, msg, ctx, sig), nil, false
}

func safeVerifyExternalMu(impl implementation, pk any, mu [64]byte, sig []byte) (accepted bool, err error, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicked = true
			err = fmt.Errorf("panic during External-Mu verification: %v", recovered)
		}
	}()
	return impl.verifyExternalMu(pk, mu, sig), nil, false
}

func setupSignGroup(kind string, impl implementation, group testGroup) groupSetup {
	setup := groupSetup{}

	switch kind {
	case "sign_seed":
		if group.PrivateSeed == nil {
			setup.panicDetected = true
			setup.panicDetail = "schema error: privateSeed missing"
			return setup
		}
		seed, err := decodeHexField("privateSeed", *group.PrivateSeed)
		if err != nil {
			setup.panicDetected = true
			setup.panicDetail = err.Error()
			return setup
		}
		if len(seed) != impl.seedSize {
			setup.rejected = true
			setup.rejectionStage = "seed_length_precondition"
			setup.rejectionDetail = fmt.Sprintf("seed length %d, want %d", len(seed), impl.seedSize)
			return setup
		}
		sk, pk, publicBytes, err, panicked := safeNewFromSeed(impl, seed)
		if panicked {
			setup.panicDetected = true
			setup.panicDetail = err.Error()
			return setup
		}
		if err != nil {
			setup.rejected = true
			setup.rejectionStage = "seed_key_setup"
			setup.rejectionDetail = err.Error()
			return setup
		}
		setup.sk = sk
		setup.pk = pk
		setup.publicBytes = publicBytes

	case "sign_noseed":
		if group.PrivateKey == nil {
			setup.panicDetected = true
			setup.panicDetail = "schema error: privateKey missing"
			return setup
		}
		encoded, err := decodeHexField("privateKey", *group.PrivateKey)
		if err != nil {
			setup.panicDetected = true
			setup.panicDetail = err.Error()
			return setup
		}
		sk, pk, publicBytes, err, panicked := safeImportPrivate(impl, encoded)
		if panicked {
			setup.panicDetected = true
			setup.panicDetail = err.Error()
			return setup
		}
		if err != nil {
			setup.rejected = true
			setup.rejectionStage = "private_key_import"
			setup.rejectionDetail = err.Error()
			return setup
		}
		setup.sk = sk
		setup.pk = pk
		setup.publicBytes = publicBytes

	default:
		setup.panicDetected = true
		setup.panicDetail = "unsupported sign kind " + kind
		return setup
	}

	if group.PublicKey != nil {
		setup.publicKeyProvided = true
		expected, err := decodeHexField("publicKey", *group.PublicKey)
		if err != nil {
			setup.panicDetected = true
			setup.panicDetail = err.Error()
			return setup
		}
		setup.publicKeyMatch = bytes.Equal(expected, setup.publicBytes)
	} else {
		setup.publicKeyMatch = false
	}

	return setup
}

func setupVerifyGroup(impl implementation, group testGroup) groupSetup {
	setup := groupSetup{}
	if group.PublicKey == nil {
		setup.panicDetected = true
		setup.panicDetail = "schema error: publicKey missing"
		return setup
	}
	encoded, err := decodeHexField("publicKey", *group.PublicKey)
	if err != nil {
		setup.panicDetected = true
		setup.panicDetail = err.Error()
		return setup
	}
	pk, err, panicked := safeImportPublic(impl, encoded)
	if panicked {
		setup.panicDetected = true
		setup.panicDetail = err.Error()
		return setup
	}
	if err != nil {
		setup.rejected = true
		setup.rejectionStage = "public_key_import"
		setup.rejectionDetail = err.Error()
		return setup
	}
	setup.pk = pk
	setup.publicBytes = encoded
	setup.publicKeyProvided = true
	setup.publicKeyMatch = true
	return setup
}

func expectationIsValid(result string) (bool, error) {
	switch result {
	case "valid":
		return true, nil
	case "invalid":
		return false, nil
	default:
		return false, fmt.Errorf("unsupported Wycheproof result %q", result)
	}
}

func evaluateVerify(impl implementation, groupIndex int, setup groupSetup, test testVector) testOutcome {
	outcome := testOutcome{
		GroupIndex:         groupIndex,
		TCID:               test.TCID,
		Kind:               "verify",
		Lane:               "message_context_verify",
		ExpectedResult:     test.Result,
		PublicKeyBindingOK: setup.publicKeyMatch,
	}

	expectedValid, err := expectationIsValid(test.Result)
	if err != nil {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		outcome.Reason = err.Error()
		return outcome
	}

	if setup.panicDetected {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		outcome.Reason = setup.panicDetail
		return outcome
	}

	if setup.rejected {
		outcome.ObservedResult = "reject"
		outcome.RejectionStage = setup.rejectionStage
		outcome.Reason = setup.rejectionDetail
		outcome.Matched = !expectedValid
		return outcome
	}

	msg, present, err := decodeOptionalHex("msg", test.Msg)
	if err != nil || !present {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		if err != nil {
			outcome.Reason = err.Error()
		} else {
			outcome.Reason = "schema error: verify msg missing"
		}
		return outcome
	}

	ctx, _, err := decodeOptionalHex("ctx", test.Ctx)
	if err != nil {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		outcome.Reason = err.Error()
		return outcome
	}

	sig, err := decodeHexField("sig", test.Sig)
	if err != nil {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		outcome.Reason = err.Error()
		return outcome
	}

	accepted, callErr, panicked := safeVerify(impl, setup.pk, msg, ctx, sig)
	if panicked || callErr != nil {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		outcome.Reason = callErr.Error()
		return outcome
	}

	outcome.OperationSucceeded = true
	if accepted {
		outcome.ObservedResult = "accept"
	} else {
		outcome.ObservedResult = "reject"
	}
	outcome.Matched = accepted == expectedValid
	outcome.Reason = "verification result compared with Wycheproof expectation"
	return outcome
}

func signLane(test testVector) string {
	if hasFlag(test.Flags, "Internal") {
		if test.Rnd != nil {
			return "external_mu_randomized_fixed_rnd"
		}
		return "external_mu_deterministic_zero_rnd"
	}
	if test.Rnd != nil {
		return "message_context_randomized_fixed_rnd"
	}
	return "message_context_deterministic_zero_rnd"
}

func evaluateSign(kind string, impl implementation, groupIndex int, setup groupSetup, test testVector) testOutcome {
	outcome := testOutcome{
		GroupIndex:              groupIndex,
		TCID:                    test.TCID,
		Kind:                    kind,
		Lane:                    signLane(test),
		ExpectedResult:          test.Result,
		PublicKeyBindingOK:      setup.publicKeyProvided && setup.publicKeyMatch,
		SignatureExact:          false,
		GeneratedSignatureValid: false,
	}

	expectedValid, err := expectationIsValid(test.Result)
	if err != nil {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		outcome.Reason = err.Error()
		return outcome
	}

	if setup.panicDetected {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		outcome.Reason = setup.panicDetail
		return outcome
	}

	if setup.rejected {
		outcome.ObservedResult = "reject"
		outcome.RejectionStage = setup.rejectionStage
		outcome.Reason = setup.rejectionDetail
		outcome.Matched = !expectedValid
		return outcome
	}

	var rnd [32]byte
	if test.Rnd != nil {
		rndBytes, err := decodeHexField("rnd", *test.Rnd)
		if err != nil {
			outcome.RuntimeError = true
			outcome.ObservedResult = "error"
			outcome.Reason = err.Error()
			return outcome
		}
		if len(rndBytes) != len(rnd) {
			outcome.RuntimeError = true
			outcome.ObservedResult = "error"
			outcome.Reason = fmt.Sprintf("rnd length %d, want %d", len(rndBytes), len(rnd))
			return outcome
		}
		copy(rnd[:], rndBytes)
	}

	internalLane := hasFlag(test.Flags, "Internal")
	var generated []byte
	var signErr error
	var panicked bool
	var verified bool

	if internalLane {
		muBytes, present, err := decodeOptionalHex("mu", test.Mu)
		if err != nil || !present {
			outcome.RuntimeError = true
			outcome.ObservedResult = "error"
			if err != nil {
				outcome.Reason = err.Error()
			} else {
				outcome.Reason = "Internal vector requires mu"
			}
			return outcome
		}
		if len(muBytes) != 64 {
			outcome.RuntimeError = true
			outcome.ObservedResult = "error"
			outcome.Reason = fmt.Sprintf("mu length %d, want 64", len(muBytes))
			return outcome
		}
		var mu [64]byte
		copy(mu[:], muBytes)
		generated, signErr, panicked = safeSignExternalMu(impl, setup.sk, mu, rnd)
		if !panicked && signErr == nil {
			verified, signErr, panicked = safeVerifyExternalMu(impl, setup.pk, mu, generated)
		}
	} else {
		msg, present, err := decodeOptionalHex("msg", test.Msg)
		if err != nil || !present {
			outcome.RuntimeError = true
			outcome.ObservedResult = "error"
			if err != nil {
				outcome.Reason = err.Error()
			} else {
				outcome.Reason = "non-Internal signing vector requires msg"
			}
			return outcome
		}
		ctx, _, err := decodeOptionalHex("ctx", test.Ctx)
		if err != nil {
			outcome.RuntimeError = true
			outcome.ObservedResult = "error"
			outcome.Reason = err.Error()
			return outcome
		}
		generated, signErr, panicked = safeSignFixedRnd(impl, setup.sk, msg, ctx, rnd)
		if !panicked && signErr == nil {
			verified, signErr, panicked = safeVerify(impl, setup.pk, msg, ctx, generated)
		}
	}

	if panicked {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		if signErr != nil {
			outcome.Reason = signErr.Error()
		} else {
			outcome.Reason = "panic during signing/verification"
		}
		return outcome
	}

	if signErr != nil {
		outcome.ObservedResult = "reject"
		outcome.RejectionStage = "sign_or_post_sign_verify"
		outcome.Reason = signErr.Error()
		outcome.Matched = !expectedValid
		return outcome
	}

	outcome.OperationSucceeded = true
	outcome.ObservedResult = "accept"
	outcome.GeneratedSignatureSHA = sha256Hex(generated)
	outcome.GeneratedSignatureValid = verified

	if !expectedValid {
		outcome.Matched = false
		outcome.Reason = "signing unexpectedly succeeded for invalid vector"
		return outcome
	}

	if !setup.publicKeyProvided {
		outcome.Matched = false
		outcome.Reason = "valid signing vector lacks public-key binding"
		return outcome
	}

	if !setup.publicKeyMatch {
		outcome.Matched = false
		outcome.Reason = "derived public key does not match vector public key"
		return outcome
	}

	expectedSig, err := decodeHexField("sig", test.Sig)
	if err != nil {
		outcome.RuntimeError = true
		outcome.ObservedResult = "error"
		outcome.Reason = err.Error()
		return outcome
	}

	outcome.SignatureExact = bytes.Equal(generated, expectedSig)
	outcome.Matched = outcome.SignatureExact && outcome.GeneratedSignatureValid

	if !outcome.SignatureExact {
		outcome.Reason = "generated signature differs from Wycheproof signature"
	} else if !outcome.GeneratedSignatureValid {
		outcome.Reason = "generated signature failed verification"
	} else {
		outcome.Reason = "signature exact and generated signature verified"
	}

	return outcome
}

func expectedVectorSchema(kind string) (string, error) {
	switch kind {
	case "verify":
		return "mldsa_verify_schema.json", nil
	case "sign_seed":
		return "mldsa_sign_seed_schema.json", nil
	case "sign_noseed":
		return "mldsa_sign_noseed_schema.json", nil
	default:
		return "", fmt.Errorf("unsupported kind %q", kind)
	}
}

func run(inputPath string, outputPath string, algorithm string, kind string) error {
	impl, err := implementationFor(algorithm)
	if err != nil {
		return err
	}

	expectedSchema, err := expectedVectorSchema(kind)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read vector file: %w", err)
	}

	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		return fmt.Errorf("decode vector JSON: %w", err)
	}

	if vectors.Algorithm != impl.algorithm {
		return fmt.Errorf("algorithm mismatch: file=%q expected=%q", vectors.Algorithm, impl.algorithm)
	}
	if vectors.Schema != expectedSchema {
		return fmt.Errorf("schema mismatch: file=%q expected=%q", vectors.Schema, expectedSchema)
	}

	actualCount := 0
	for _, group := range vectors.TestGroups {
		actualCount += len(group.Tests)
	}
	if actualCount != vectors.NumberOfTests {
		return fmt.Errorf("numberOfTests mismatch: declared=%d actual=%d", vectors.NumberOfTests, actualCount)
	}

	result := fileResult{
		Schema:                      harnessSchema,
		HarnessVersion:              harnessVersion,
		Implementation:              "CIRCL",
		ImplementationCommit:        circlCommit,
		ImplementationTree:          circlTree,
		OverlayGeneratorSHA256:      overlayGeneratorSHA256,
		WycheproofCommit:            wycheproofCommit,
		VectorFileSHA256:            sha256Hex(raw),
		Algorithm:                   impl.algorithm,
		Kind:                        kind,
		VectorSchema:                vectors.Schema,
		DeclaredVectorCount:         vectors.NumberOfTests,
		UnsupportedVectorCount:      0,
		SkippedVectorCount:          0,
		RawPrivateMaterialPersisted: false,
		Tests:                       make([]testOutcome, 0, vectors.NumberOfTests),
	}

	expectedGroupType := "MlDsaSign"
	if kind == "verify" {
		expectedGroupType = "MlDsaVerify"
	}

	for groupIndex, group := range vectors.TestGroups {
		if group.Type != expectedGroupType {
			return fmt.Errorf("group %d type mismatch: got=%q expected=%q", groupIndex, group.Type, expectedGroupType)
		}

		var setup groupSetup
		if kind == "verify" {
			setup = setupVerifyGroup(impl, group)
		} else {
			setup = setupSignGroup(kind, impl, group)
		}

		for _, test := range group.Tests {
			var outcome testOutcome
			if kind == "verify" {
				outcome = evaluateVerify(impl, groupIndex, setup, test)
			} else {
				outcome = evaluateSign(kind, impl, groupIndex, setup, test)
			}

			result.ExecutedVectorCount++
			switch test.Result {
			case "valid":
				result.ExpectedValidCount++
			case "invalid":
				result.ExpectedInvalidCount++
			default:
				// evaluate* already records this as a runtime error.
			}

			if outcome.RuntimeError {
				result.RuntimeErrorCount++
			}
			if outcome.Matched {
				result.MatchedCount++
			} else {
				result.MismatchedCount++
			}
			result.Tests = append(result.Tests, outcome)
		}
	}

	if result.ExecutedVectorCount == result.DeclaredVectorCount &&
		result.MismatchedCount == 0 &&
		result.RuntimeErrorCount == 0 &&
		result.UnsupportedVectorCount == 0 &&
		result.SkippedVectorCount == 0 {
		result.Decision = "circl_vector_file_verified"
	} else {
		result.Decision = "circl_vector_file_failed"
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	encoded = append(encoded, '\n')

	if outputPath != "" {
		if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
			return fmt.Errorf("write result: %w", err)
		}
	} else {
		if _, err := os.Stdout.Write(encoded); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "decision=%s\n", result.Decision)
	fmt.Fprintf(os.Stderr, "executed=%d\n", result.ExecutedVectorCount)
	fmt.Fprintf(os.Stderr, "matched=%d\n", result.MatchedCount)
	fmt.Fprintf(os.Stderr, "mismatched=%d\n", result.MismatchedCount)
	fmt.Fprintf(os.Stderr, "runtime_errors=%d\n", result.RuntimeErrorCount)
	fmt.Fprintf(os.Stderr, "unsupported=%d\n", result.UnsupportedVectorCount)
	fmt.Fprintf(os.Stderr, "skipped=%d\n", result.SkippedVectorCount)

	if result.Decision != "circl_vector_file_verified" {
		return fmt.Errorf("vector file did not satisfy fail-closed verification contract")
	}

	return nil
}

func main() {
	inputPath := flag.String("input", "", "Wycheproof ML-DSA JSON file")
	outputPath := flag.String("output", "", "result JSON path; stdout if omitted")
	algorithm := flag.String("algorithm", "", "44, 65, or 87")
	kind := flag.String("kind", "", "verify, sign_seed, or sign_noseed")
	flag.Parse()

	if strings.TrimSpace(*inputPath) == "" {
		fmt.Fprintln(os.Stderr, "FAIL: --input is required")
		os.Exit(2)
	}
	if strings.TrimSpace(*algorithm) == "" {
		fmt.Fprintln(os.Stderr, "FAIL: --algorithm is required")
		os.Exit(2)
	}
	if strings.TrimSpace(*kind) == "" {
		fmt.Fprintln(os.Stderr, "FAIL: --kind is required")
		os.Exit(2)
	}

	if err := run(*inputPath, *outputPath, *algorithm, *kind); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
