#!/usr/bin/env python3

import argparse
import hashlib
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path


EXPECTED_ALGORITHM = "ML-DSA-65"

EXPECTED_SCHEMA = "mldsa_verify_schema.json"

EXPECTED_VECTOR_SHA256 = (
    "49ac366d76115eab56b7116f10d06e288"
    "e6f23fe6cfb90b26bfb2d731a8d1e02"
)

EXPECTED_TEST_COUNT = 210

EXPECTED_VALID_COUNT = 79

EXPECTED_INVALID_COUNT = 131


ALLOWED_INVALID_CLASSES = {
    "cryptographic_reject",
    "public_key_parse_reject",
    "context_parameter_reject",
}


def sha256(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def parse_adapter_output(text):

    result = {}

    for line in text.splitlines():

        if " = " not in line:
            continue

        key, value = line.split(
            " = ",
            1,
        )

        result[
            key.strip()
        ] = value.strip()

    return result


def fail(message):
    print(
        "FAIL:",
        message,
    )
    raise SystemExit(1)


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Reproduce QSP Stage392 ML-DSA-65 "
            "Wycheproof verification across OpenSSL "
            "and Cloudflare CIRCL adapters."
        )
    )

    parser.add_argument(
        "--vectors",
        required=True,
        help=(
            "Path to fixed Wycheproof "
            "mldsa_65_verify_test.json"
        ),
    )

    parser.add_argument(
        "--openssl-adapter",
        required=True,
        help="Path to compiled OpenSSL EVP adapter",
    )

    parser.add_argument(
        "--circl-adapter",
        required=True,
        help="Path to compiled CIRCL adapter",
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON path",
    )

    args = parser.parse_args()


    vector_path = Path(
        args.vectors
    ).resolve()

    openssl_adapter = Path(
        args.openssl_adapter
    ).resolve()

    circl_adapter = Path(
        args.circl_adapter
    ).resolve()

    output_path = Path(
        args.output
    ).resolve()


    if not vector_path.is_file():
        fail(
            "Wycheproof vector file missing"
        )

    if not openssl_adapter.is_file():
        fail(
            "OpenSSL adapter missing"
        )

    if not circl_adapter.is_file():
        fail(
            "CIRCL adapter missing"
        )


    vector_sha = sha256(
        vector_path
    )

    print(
        "vector_sha256 =",
        vector_sha
    )

    if vector_sha != EXPECTED_VECTOR_SHA256:
        fail(
            "wycheproof_vector_sha256_mismatch"
        )


    try:
        data = json.loads(
            vector_path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        fail(
            "malformed_vector_data: "
            + str(exc)
        )


    if data.get(
        "algorithm"
    ) != EXPECTED_ALGORITHM:
        fail(
            "algorithm_mismatch"
        )


    if data.get(
        "schema"
    ) != EXPECTED_SCHEMA:
        fail(
            "schema_mismatch"
        )


    if data.get(
        "numberOfTests"
    ) != EXPECTED_TEST_COUNT:
        fail(
            "declared_test_count_mismatch"
        )


    expected_counter = Counter()

    results = []

    failure_tcids = []

    adapter_error_tcids = []

    cross_mismatch_tcids = []

    unexpected_valid_rejection_tcids = []

    unexpected_invalid_accept_tcids = []

    openssl_class_counter = Counter()

    circl_class_counter = Counter()

    flag_counter = Counter()

    execution_index = 0


    with tempfile.TemporaryDirectory(
        prefix="qsp-stage392-reproduction-"
    ) as temporary:

        temp_root = Path(
            temporary
        )


        for group_index, group in enumerate(
            data.get(
                "testGroups",
                []
            ),
            start=1,
        ):

            try:
                raw_public_key = bytes.fromhex(
                    group["publicKey"]
                )

                der_public_key = bytes.fromhex(
                    group["publicKeyDer"]
                )

            except Exception as exc:
                fail(
                    "malformed_vector_data: "
                    + str(exc)
                )


            for test in group.get(
                "tests",
                []
            ):

                execution_index += 1

                try:
                    tcid = test["tcId"]

                    expected_result = (
                        test["result"]
                    )

                    message = bytes.fromhex(
                        test["msg"]
                    )

                    signature = bytes.fromhex(
                        test["sig"]
                    )

                    ctx_hex = test.get(
                        "ctx"
                    )

                    context = (
                        bytes.fromhex(
                            ctx_hex
                        )
                        if ctx_hex is not None
                        else b""
                    )

                except Exception as exc:
                    fail(
                        "malformed_vector_data: "
                        + str(exc)
                    )


                if expected_result not in {
                    "valid",
                    "invalid",
                }:
                    fail(
                        "unexpected_vector_result"
                    )


                expected_accept = (
                    expected_result
                    == "valid"
                )

                expected_counter[
                    expected_result
                ] += 1

                for flag in test.get(
                    "flags",
                    []
                ):
                    flag_counter[
                        flag
                    ] += 1


                case = (
                    temp_root
                    / f"tc{tcid}"
                )

                case.mkdir()


                raw_key_path = (
                    case
                    / "public-key.raw"
                )

                der_key_path = (
                    case
                    / "public-key.der"
                )

                message_path = (
                    case
                    / "message.bin"
                )

                signature_path = (
                    case
                    / "signature.bin"
                )

                context_path = (
                    case
                    / "context.bin"
                )


                raw_key_path.write_bytes(
                    raw_public_key
                )

                der_key_path.write_bytes(
                    der_public_key
                )

                message_path.write_bytes(
                    message
                )

                signature_path.write_bytes(
                    signature
                )

                context_path.write_bytes(
                    context
                )


                openssl_proc = subprocess.run(
                    [
                        str(openssl_adapter),
                        str(der_key_path),
                        str(message_path),
                        str(signature_path),
                        str(context_path),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )


                circl_proc = subprocess.run(
                    [
                        str(circl_adapter),
                        str(raw_key_path),
                        str(message_path),
                        str(signature_path),
                        context.hex(),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )


                openssl_fields = (
                    parse_adapter_output(
                        openssl_proc.stdout
                    )
                )

                circl_fields = (
                    parse_adapter_output(
                        circl_proc.stdout
                    )
                )


                openssl_class = (
                    openssl_fields.get(
                        "classification"
                    )
                )

                circl_class = (
                    circl_fields.get(
                        "classification"
                    )
                )


                openssl_accept = (
                    openssl_fields.get(
                        "accepted"
                    )
                    == "true"
                )

                circl_accept = (
                    circl_fields.get(
                        "accepted"
                    )
                    == "true"
                )


                openssl_class_counter[
                    str(openssl_class)
                ] += 1

                circl_class_counter[
                    str(circl_class)
                ] += 1


                openssl_adapter_error = (
                    openssl_class is None
                    or
                    openssl_class
                    == "adapter_execution_error"
                )

                circl_adapter_error = (
                    circl_class is None
                    or
                    circl_class
                    == "adapter_execution_error"
                )


                if expected_accept:

                    openssl_expected = (
                        openssl_class
                        == "accept"
                        and
                        openssl_accept
                    )

                    circl_expected = (
                        circl_class
                        == "accept"
                        and
                        circl_accept
                    )

                else:

                    openssl_expected = (
                        openssl_class
                        in ALLOWED_INVALID_CLASSES
                        and
                        not openssl_accept
                    )

                    circl_expected = (
                        circl_class
                        in ALLOWED_INVALID_CLASSES
                        and
                        not circl_accept
                    )


                cross_match = (
                    openssl_accept
                    == circl_accept
                )


                case_pass = (
                    not openssl_adapter_error
                    and
                    not circl_adapter_error
                    and
                    openssl_expected
                    and
                    circl_expected
                    and
                    cross_match
                )


                if (
                    openssl_adapter_error
                    or
                    circl_adapter_error
                ):
                    adapter_error_tcids.append(
                        tcid
                    )


                if not cross_match:
                    cross_mismatch_tcids.append(
                        tcid
                    )


                if (
                    expected_accept
                    and (
                        not openssl_accept
                        or
                        not circl_accept
                    )
                ):
                    unexpected_valid_rejection_tcids.append(
                        tcid
                    )


                if (
                    not expected_accept
                    and (
                        openssl_accept
                        or
                        circl_accept
                    )
                ):
                    unexpected_invalid_accept_tcids.append(
                        tcid
                    )


                if not case_pass:
                    failure_tcids.append(
                        tcid
                    )


                results.append({
                    "execution_index":
                        execution_index,

                    "group_index":
                        group_index,

                    "tcId":
                        tcid,

                    "expected_result":
                        expected_result,

                    "expected_accept":
                        expected_accept,

                    "flags":
                        test.get(
                            "flags",
                            []
                        ),

                    "comment":
                        test.get(
                            "comment",
                            ""
                        ),

                    "input_lengths": {
                        "raw_public_key":
                            len(
                                raw_public_key
                            ),

                        "der_public_key":
                            len(
                                der_public_key
                            ),

                        "message":
                            len(
                                message
                            ),

                        "signature":
                            len(
                                signature
                            ),

                        "context":
                            len(
                                context
                            ),
                    },

                    "openssl": {
                        "exit":
                            openssl_proc.returncode,

                        "classification":
                            openssl_class,

                        "accepted":
                            openssl_accept,

                        "matches_expected":
                            openssl_expected,

                        "adapter_error":
                            openssl_adapter_error,
                    },

                    "circl": {
                        "exit":
                            circl_proc.returncode,

                        "classification":
                            circl_class,

                        "accepted":
                            circl_accept,

                        "matches_expected":
                            circl_expected,

                        "adapter_error":
                            circl_adapter_error,
                    },

                    "cross_implementation_match":
                        cross_match,

                    "case_pass":
                        case_pass,
                })


    if len(
        results
    ) != EXPECTED_TEST_COUNT:
        fail(
            "computed_test_count_mismatch"
        )


    if expected_counter[
        "valid"
    ] != EXPECTED_VALID_COUNT:
        fail(
            "valid_count_mismatch"
        )


    if expected_counter[
        "invalid"
    ] != EXPECTED_INVALID_COUNT:
        fail(
            "invalid_count_mismatch"
        )


    summary = {
        "schema":
            "qsp.stage392.full-wycheproof-execution.v1",

        "stage":
            392,

        "authoritative_stage392_result":
            False,

        "execution_scope":
            "full_fixed_wycheproof_mldsa65_verify_vector_set",

        "wycheproof": {
            "repository":
                "C2SP/wycheproof",

            "commit":
                "dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166",

            "vector_file":
                "testvectors_v1/mldsa_65_verify_test.json",

            "vector_sha256":
                vector_sha,

            "algorithm":
                data[
                    "algorithm"
                ],

            "schema":
                data[
                    "schema"
                ],
        },

        "expected_distribution":
            dict(
                sorted(
                    expected_counter.items()
                )
            ),

        "execution_counts": {
            "total":
                len(
                    results
                ),

            "passed":
                sum(
                    1
                    for item in results
                    if item[
                        "case_pass"
                    ]
                ),

            "failed":
                len(
                    failure_tcids
                ),

            "adapter_errors":
                len(
                    adapter_error_tcids
                ),

            "cross_implementation_mismatches":
                len(
                    cross_mismatch_tcids
                ),

            "unexpected_valid_rejections":
                len(
                    unexpected_valid_rejection_tcids
                ),

            "unexpected_invalid_acceptances":
                len(
                    unexpected_invalid_accept_tcids
                ),
        },

        "failure_tcids":
            failure_tcids,

        "adapter_error_tcids":
            adapter_error_tcids,

        "cross_mismatch_tcids":
            cross_mismatch_tcids,

        "unexpected_valid_rejection_tcids":
            unexpected_valid_rejection_tcids,

        "unexpected_invalid_accept_tcids":
            unexpected_invalid_accept_tcids,

        "openssl_classification_distribution":
            dict(
                sorted(
                    openssl_class_counter.items()
                )
            ),

        "circl_classification_distribution":
            dict(
                sorted(
                    circl_class_counter.items()
                )
            ),

        "flag_distribution":
            dict(
                sorted(
                    flag_counter.items()
                )
            ),

        "all_vectors_match_expected":
            not failure_tcids,

        "all_cross_implementation_accept_reject_match":
            not cross_mismatch_tcids,

        "adapter_execution_error_count":
            len(
                adapter_error_tcids
            ),

        "results":
            results,
    }


    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    output_path.write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


    counts = summary[
        "execution_counts"
    ]


    print()
    print(
        "===== STAGE392 REPRODUCTION SUMMARY ====="
    )

    print(
        "total =",
        counts["total"]
    )

    print(
        "valid =",
        expected_counter["valid"]
    )

    print(
        "invalid =",
        expected_counter["invalid"]
    )

    print(
        "passed =",
        counts["passed"]
    )

    print(
        "failed =",
        counts["failed"]
    )

    print(
        "adapter_errors =",
        counts["adapter_errors"]
    )

    print(
        "cross_implementation_mismatches =",
        counts[
            "cross_implementation_mismatches"
        ]
    )

    print(
        "unexpected_valid_rejections =",
        counts[
            "unexpected_valid_rejections"
        ]
    )

    print(
        "unexpected_invalid_acceptances =",
        counts[
            "unexpected_invalid_acceptances"
        ]
    )


    if failure_tcids:
        fail(
            "one_or_more_vector_failures"
        )

    if adapter_error_tcids:
        fail(
            "adapter_execution_error"
        )

    if cross_mismatch_tcids:
        fail(
            "cross_implementation_result_mismatch"
        )

    if unexpected_valid_rejection_tcids:
        fail(
            "unexpected_valid_rejection"
        )

    if unexpected_invalid_accept_tcids:
        fail(
            "unexpected_invalid_acceptance"
        )


    print()
    print(
        "PASS: 210 / 210 Wycheproof "
        "ML-DSA-65 verify vectors reproduced"
    )

    print(
        "PASS: 79 / 79 valid vectors accepted "
        "by both implementations"
    )

    print(
        "PASS: 131 / 131 invalid vectors rejected "
        "by both implementations"
    )

    print(
        "PASS: OpenSSL / CIRCL accept-reject "
        "agreement 210 / 210"
    )

    print(
        "PASS: adapter execution errors = 0"
    )


    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
