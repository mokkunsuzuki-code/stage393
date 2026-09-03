#!/usr/bin/env python3

"""
Stage393 test-only CIRCL External-Mu overlay generator.

This generator is bound to the pinned CIRCL v1.6.5 source commit.

It does not add or claim a CIRCL production API.

The generated files are intended only for a disposable pinned CIRCL
checkout used by QSP Stage393 compatibility testing.

For Wycheproof Internal vectors, the supplied 64-byte mu is already
precomputed. Therefore the generated External-Mu helpers MUST consume
mu directly and MUST NOT compute CRH(tr || message) again.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PINNED_CIRCL_COMMIT = (
    "cfa7c70defd831ffb0792ab2af560bfef43d60ca"
)

EXPECTED_INTERNAL_BLOB = (
    "7a370615a5d542e1f95ad840b2218d0aec91823d"
)

EXPECTED_WRAPPER_BLOBS = {
    "44":
        "6a9b3e31bfaa0195fe1087b166c6aac2a04e4e2e",

    "65":
        "6f8f182eb491ffb9e11cd37b9d0c68ebbedc264e",

    "87":
        "f9092c0eed90f9a23fc25c5e1e619cbc03ae4ede",
}


VERIFY_SIGNATURE = (
    "func Verify("
    "pk *PublicKey, "
    "msg func(io.Writer), "
    "signature []byte"
    ") bool {"
)

SIGN_SIGNATURE = (
    "func SignTo("
    "sk *PrivateKey, "
    "msg func(io.Writer), "
    "rnd [32]byte, "
    "signature []byte"
    ") {"
)


VERIFY_END_MARKER = (
    "\n// SignTo signs the given message"
)

SIGN_END_MARKER = (
    "\n// Computes the public key corresponding "
    "to this private key."
)


VERIFY_HASH_BLOCK = """\
\t// μ = CRH(tr ‖ msg)
\th := sha3.NewShake256()
\t_, _ = h.Write(pk.tr[:])
\tmsg(&h)
\t_, _ = h.Read(mu[:])
"""


SIGN_HASH_BLOCK = """\
\t//  μ = CRH(tr ‖ msg)
\th := sha3.NewShake256()
\t_, _ = h.Write(sk.tr[:])
\tmsg(&h)
\t_, _ = h.Read(mu[:])

\t// ρ' = CRH(key ‖ μ)
\th.Reset()
"""


def git_blob_sha(data: bytes) -> str:
    header = (
        f"blob {len(data)}\0"
    ).encode("ascii")

    return hashlib.sha1(
        header + data
    ).hexdigest()


def require(
    condition: bool,
    message: str,
) -> None:
    if not condition:
        raise SystemExit(
            "FAIL: " + message
        )


def extract_between(
    source: str,
    start_marker: str,
    end_marker: str,
) -> str:
    start = source.find(
        start_marker
    )

    require(
        start >= 0,
        "required function start marker missing",
    )

    end = source.find(
        end_marker,
        start,
    )

    require(
        end >= 0,
        "required function end marker missing",
    )

    return source[
        start:end
    ].rstrip() + "\n"


def build_internal_overlay(
    internal_source: str,
) -> str:

    verify_func = extract_between(
        internal_source,
        VERIFY_SIGNATURE,
        VERIFY_END_MARKER,
    )

    sign_func = extract_between(
        internal_source,
        SIGN_SIGNATURE,
        SIGN_END_MARKER,
    )


    verify_func = verify_func.replace(
        VERIFY_SIGNATURE,
        (
            "func Stage393VerifyMu("
            "pk *PublicKey, "
            "mu [64]byte, "
            "signature []byte"
            ") bool {"
        ),
        1,
    )

    verify_func = verify_func.replace(
        "\tvar sig unpackedSignature\n"
        "\tvar mu [64]byte\n",
        "\tvar sig unpackedSignature\n",
        1,
    )

    require(
        VERIFY_HASH_BLOCK
        in verify_func,
        "pinned Verify mu-computation block not found",
    )

    verify_func = verify_func.replace(
        VERIFY_HASH_BLOCK,
        (
            "\t// Stage393 test-only External-Mu path.\n"
            "\t// mu is already computed and MUST NOT be\n"
            "\t// hashed again as ordinary message input.\n"
            "\th := sha3.NewShake256()\n"
        ),
        1,
    )


    sign_func = sign_func.replace(
        SIGN_SIGNATURE,
        (
            "func Stage393SignMuTo("
            "sk *PrivateKey, "
            "mu [64]byte, "
            "rnd [32]byte, "
            "signature []byte"
            ") {"
        ),
        1,
    )

    sign_func = sign_func.replace(
        "\tvar mu, rhop [64]byte\n",
        "\tvar rhop [64]byte\n",
        1,
    )

    require(
        SIGN_HASH_BLOCK
        in sign_func,
        "pinned SignTo mu-computation block not found",
    )

    sign_func = sign_func.replace(
        SIGN_HASH_BLOCK,
        (
            "\t// Stage393 test-only External-Mu path.\n"
            "\t// mu is already computed and MUST NOT be\n"
            "\t// hashed again as ordinary message input.\n"
            "\th := sha3.NewShake256()\n"
        ),
        1,
    )


    forbidden = (
        "h.Write(pk.tr[:])",
        "h.Write(sk.tr[:])",
        "msg(&h)",
    )

    for marker in forbidden:

        require(
            marker not in verify_func,
            (
                "External-Mu verify still contains "
                + marker
            ),
        )

        require(
            marker not in sign_func,
            (
                "External-Mu sign still contains "
                + marker
            ),
        )


    return (
        "// Code generated by QSP Stage393.\n"
        "// TEST ONLY. NOT A CIRCL PRODUCTION API.\n"
        "// Source binding: CIRCL "
        + PINNED_CIRCL_COMMIT
        + "\n\n"
        "package internal\n\n"
        "import (\n"
        '\t"github.com/cloudflare/circl/internal/sha3"\n'
        '\tcommon "github.com/cloudflare/circl/sign/internal/dilithium"\n'
        ")\n\n"
        + verify_func
        + "\n"
        + sign_func
    )


def build_wrapper_overlay(
    algorithm: str,
) -> str:

    package = (
        "mldsa"
        + algorithm
    )

    return f"""// Code generated by QSP Stage393.
// TEST ONLY. NOT A CIRCL PRODUCTION API.
// Source binding: CIRCL {PINNED_CIRCL_COMMIT}

package {package}

import (
\t"io"

\t"github.com/cloudflare/circl/sign"
\t"github.com/cloudflare/circl/sign/mldsa/{package}/internal"
)

// Stage393SignFixedRnd is a Stage393 compatibility-test path.
//
// It reproduces:
//
//     M' = 0x00 || len(ctx) || ctx || msg
//
// and passes caller-supplied 32-byte test randomness to the pinned
// CIRCL internal signing implementation.
//
// TEST ONLY. This is not a production API.
func Stage393SignFixedRnd(
\tsk *PrivateKey,
\tmsg []byte,
\tctx []byte,
\trnd [32]byte,
) ([]byte, error) {{
\tif len(ctx) > 255 {{
\t\treturn nil, sign.ErrContextTooLong
\t}}

\tvar signature [SignatureSize]byte

\tinternal.SignTo(
\t\t(*internal.PrivateKey)(sk),
\t\tfunc(w io.Writer) {{
\t\t\t_, _ = w.Write([]byte{{0}})
\t\t\t_, _ = w.Write([]byte{{byte(len(ctx))}})
\t\t\tif ctx != nil {{
\t\t\t\t_, _ = w.Write(ctx)
\t\t\t}}
\t\t\t_, _ = w.Write(msg)
\t\t}},
\t\trnd,
\t\tsignature[:],
\t)

\treturn signature[:], nil
}}

// Stage393SignExternalMu signs an already-computed 64-byte mu.
//
// mu is consumed directly and MUST NOT be hashed again as a message.
//
// TEST ONLY. This is not a production API.
func Stage393SignExternalMu(
\tsk *PrivateKey,
\tmu [64]byte,
\trnd [32]byte,
) []byte {{
\tvar signature [SignatureSize]byte

\tinternal.Stage393SignMuTo(
\t\t(*internal.PrivateKey)(sk),
\t\tmu,
\t\trnd,
\t\tsignature[:],
\t)

\treturn signature[:]
}}

// Stage393VerifyExternalMu verifies against an already-computed
// 64-byte mu.
//
// TEST ONLY. This is not a production API.
func Stage393VerifyExternalMu(
\tpk *PublicKey,
\tmu [64]byte,
\tsignature []byte,
) bool {{
\treturn internal.Stage393VerifyMu(
\t\t(*internal.PublicKey)(pk),
\t\tmu,
\t\tsignature,
\t)
}}
"""


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=(
            "44",
            "65",
            "87",
        ),
    )

    parser.add_argument(
        "--internal-source",
        required=True,
    )

    parser.add_argument(
        "--wrapper-source",
        required=True,
    )

    parser.add_argument(
        "--internal-output",
        required=True,
    )

    parser.add_argument(
        "--wrapper-output",
        required=True,
    )

    args = parser.parse_args()


    internal_path = Path(
        args.internal_source
    )

    wrapper_path = Path(
        args.wrapper_source
    )

    internal_raw = internal_path.read_bytes()
    wrapper_raw = wrapper_path.read_bytes()


    actual_internal_blob = git_blob_sha(
        internal_raw
    )

    actual_wrapper_blob = git_blob_sha(
        wrapper_raw
    )


    require(
        actual_internal_blob
        == EXPECTED_INTERNAL_BLOB,
        (
            "CIRCL internal source blob mismatch: "
            + actual_internal_blob
        ),
    )

    require(
        actual_wrapper_blob
        == EXPECTED_WRAPPER_BLOBS[
            args.algorithm
        ],
        (
            "CIRCL wrapper source blob mismatch: "
            + actual_wrapper_blob
        ),
    )


    internal_source = internal_raw.decode(
        "utf-8"
    )

    wrapper_source = wrapper_raw.decode(
        "utf-8"
    )

    package = (
        "mldsa"
        + args.algorithm
    )


    require(
        (
            "package "
            + package
        )
        in wrapper_source,
        "wrapper package mismatch",
    )

    require(
        "type PrivateKey internal.PrivateKey"
        in wrapper_source,
        "PrivateKey internal binding missing",
    )

    require(
        "type PublicKey internal.PublicKey"
        in wrapper_source,
        "PublicKey internal binding missing",
    )

    require(
        "func SignTo("
        in wrapper_source,
        "public SignTo missing",
    )

    require(
        "func Verify("
        in wrapper_source,
        "public Verify missing",
    )

    require(
        "unsafeSignInternal("
        in wrapper_source,
        "test-only fixed-rnd path missing",
    )


    internal_overlay = build_internal_overlay(
        internal_source
    )

    wrapper_overlay = build_wrapper_overlay(
        args.algorithm
    )


    require(
        "func Stage393SignMuTo("
        in internal_overlay,
        "direct-mu signing helper missing",
    )

    require(
        "func Stage393VerifyMu("
        in internal_overlay,
        "direct-mu verification helper missing",
    )

    require(
        "func Stage393SignFixedRnd("
        in wrapper_overlay,
        "fixed-rnd wrapper missing",
    )

    require(
        "func Stage393SignExternalMu("
        in wrapper_overlay,
        "External-Mu wrapper missing",
    )

    require(
        "func Stage393VerifyExternalMu("
        in wrapper_overlay,
        "External-Mu verifier wrapper missing",
    )


    Path(
        args.internal_output
    ).write_text(
        internal_overlay,
        encoding="utf-8",
    )

    Path(
        args.wrapper_output
    ).write_text(
        wrapper_overlay,
        encoding="utf-8",
    )


    print("OVERLAY_GENERATION=PASS")

    print(
        "algorithm=ML-DSA-"
        + args.algorithm
    )

    print(
        "internal_git_blob="
        + actual_internal_blob
    )

    print(
        "wrapper_git_blob="
        + actual_wrapper_blob
    )

    print(
        "external_mu_rehashed=NO"
    )

    print(
        "production_api_claimed=NO"
    )


if __name__ == "__main__":
    main()
