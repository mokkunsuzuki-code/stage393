package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func emit(
	classification string,
	accepted bool,
	exitCode int,
) {
	fmt.Println(
		"implementation = Cloudflare CIRCL",
	)

	fmt.Println(
		"algorithm = ML-DSA-65",
	)

	fmt.Println(
		"classification =",
		classification,
	)

	fmt.Println(
		"accepted =",
		accepted,
	)

	fmt.Println(
		"adapter_internal_exit =",
		exitCode,
	)
}

func main() {

	if len(os.Args) != 5 {

		emit(
			"adapter_execution_error",
			false,
			20,
		)

		os.Exit(20)
	}

	rawPublicKey, err :=
		os.ReadFile(
			os.Args[1],
		)

	if err != nil {

		emit(
			"adapter_execution_error",
			false,
			20,
		)

		os.Exit(20)
	}

	message, err :=
		os.ReadFile(
			os.Args[2],
		)

	if err != nil {

		emit(
			"adapter_execution_error",
			false,
			20,
		)

		os.Exit(20)
	}

	signature, err :=
		os.ReadFile(
			os.Args[3],
		)

	if err != nil {

		emit(
			"adapter_execution_error",
			false,
			20,
		)

		os.Exit(20)
	}

	context, err :=
		hex.DecodeString(
			os.Args[4],
		)

	if err != nil {

		emit(
			"adapter_execution_error",
			false,
			20,
		)

		os.Exit(20)
	}

	if len(context) > 255 {

		emit(
			"context_parameter_reject",
			false,
			3,
		)

		os.Exit(3)
	}

	if len(rawPublicKey) !=
		mldsa65.PublicKeySize {

		emit(
			"public_key_parse_reject",
			false,
			2,
		)

		os.Exit(2)
	}

	if len(signature) !=
		mldsa65.SignatureSize {

		emit(
			"cryptographic_reject",
			false,
			1,
		)

		os.Exit(1)
	}

	var publicKey mldsa65.PublicKey

	err = publicKey.UnmarshalBinary(
		rawPublicKey,
	)

	if err != nil {

		emit(
			"public_key_parse_reject",
			false,
			2,
		)

		os.Exit(2)
	}

	verified := mldsa65.Verify(
		&publicKey,
		message,
		context,
		signature,
	)

	if verified {

		emit(
			"accept",
			true,
			0,
		)

		os.Exit(0)
	}

	emit(
		"cryptographic_reject",
		false,
		1,
	)

	os.Exit(1)
}
