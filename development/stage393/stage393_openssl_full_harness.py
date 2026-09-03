#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


HARNESS_SCHEMA = (
    "qsp.stage393.openssl-file-result.v1"
)

ALGORITHMS = {
    "44": {
        "name": "ML-DSA-44",
        "public_size": 1312,
        "private_size": 2560,
        "signature_size": 2420,
    },
    "65": {
        "name": "ML-DSA-65",
        "public_size": 1952,
        "private_size": 4032,
        "signature_size": 3309,
    },
    "87": {
        "name": "ML-DSA-87",
        "public_size": 2592,
        "private_size": 4896,
        "signature_size": 4627,
    },
}

EXPECTED_SCHEMAS = {
    "verify":
        "mldsa_verify_schema.json",

    "sign_seed":
        "mldsa_sign_seed_schema.json",

    "sign_noseed":
        "mldsa_sign_noseed_schema.json",
}


def sha256_file(filename: Path) -> str:
    return hashlib.sha256(
        filename.read_bytes()
    ).hexdigest()


def decode_hex(
    field_name: str,
    value: str,
) -> bytes:

    try:
        return bytes.fromhex(value)
    except Exception as exc:
        raise ValueError(
            f"{field_name} is not valid hexadecimal"
        ) from exc


def parse_probe_output(
    output: str,
) -> dict[str, str]:

    parsed: dict[str, str] = {}

    for line in output.splitlines():
        if "=" not in line:
            continue

        key, value = line.split(
            "=",
            1,
        )

        parsed[
            key.strip()
        ] = value.strip()

    return parsed


def is_valid_expectation(
    result: str,
) -> bool:

    if result == "valid":
        return True

    if result == "invalid":
        return False

    raise ValueError(
        f"unsupported Wycheproof result {result!r}"
    )


def sign_lane(
    test: dict,
) -> str:

    flags = set(
        test.get(
            "flags",
            [],
        )
    )

    external_mu = (
        "Internal"
        in flags
    )

    randomized = (
        "rnd" in test
    )

    if external_mu:
        return (
            "external_mu_randomized_fixed_rnd"
            if randomized
            else "external_mu_deterministic_zero_rnd"
        )

    return (
        "message_context_randomized_fixed_rnd"
        if randomized
        else "message_context_deterministic_zero_rnd"
    )


def materialize(
    directory: Path,
    filename: str,
    data: bytes,
) -> Path:

    destination = (
        directory
        / filename
    )

    destination.write_bytes(
        data
    )

    return destination


def run_probe(
    probe: Path,
    *,
    algorithm: str,
    operation: str,
    key_kind: str,
    key_data: bytes,
    public_data: bytes | None,
    input_data: bytes,
    context_data: bytes,
    signature_data: bytes,
    rnd_data: bytes | None,
    mu_mode: bool,
    workdir: Path,
    ordinal: int,
) -> tuple[int, dict[str, str], str]:

    prefix = f"{ordinal:04d}"

    key_file = materialize(
        workdir,
        prefix + ".key",
        key_data,
    )

    if public_data is None:
        public_argument = "-"
    else:
        public_argument = str(
            materialize(
                workdir,
                prefix + ".pub",
                public_data,
            )
        )

    input_file = materialize(
        workdir,
        prefix + ".input",
        input_data,
    )

    context_file = materialize(
        workdir,
        prefix + ".ctx",
        context_data,
    )

    signature_file = materialize(
        workdir,
        prefix + ".sig",
        signature_data,
    )

    if rnd_data is None:
        rnd_argument = "-"
    else:
        rnd_argument = str(
            materialize(
                workdir,
                prefix + ".rnd",
                rnd_data,
            )
        )

    command = [
        str(probe),
        algorithm,
        operation,
        key_kind,
        str(key_file),
        public_argument,
        str(input_file),
        str(context_file),
        str(signature_file),
        rnd_argument,
        "1" if mu_mode else "0",
    ]

    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (
            124,
            {},
            "probe timeout",
        )

    parsed = parse_probe_output(
        completed.stdout
    )

    if (
        completed.returncode == 0
        and
        parsed.get(
            "DIAGNOSTIC_COMPLETE"
        ) == "YES"
    ):
        detail = ""
    else:
        detail = (
            "probe process failure or incomplete result"
        )

    return (
        completed.returncode,
        parsed,
        detail,
    )


def setup_sign_group(
    kind: str,
    group: dict,
    algorithm_info: dict,
) -> tuple[
    str,
    bytes,
    bytes | None,
]:

    if kind == "sign_seed":

        key_kind = "seed"

        key_data = decode_hex(
            "privateSeed",
            group[
                "privateSeed"
            ],
        )

    elif kind == "sign_noseed":

        key_kind = "private"

        key_data = decode_hex(
            "privateKey",
            group[
                "privateKey"
            ],
        )

    else:
        raise ValueError(
            f"unsupported signing kind {kind}"
        )

    public_value = group.get(
        "publicKey"
    )

    if public_value is None:
        public_data = None
    else:
        public_data = decode_hex(
            "publicKey",
            public_value,
        )

        if (
            len(public_data)
            != algorithm_info[
                "public_size"
            ]
        ):
            raise ValueError(
                "public key size mismatch"
            )

    return (
        key_kind,
        key_data,
        public_data,
    )


def evaluate_verify(
    *,
    expected_valid: bool,
    parsed: dict[str, str],
) -> tuple[
    bool,
    str,
    str,
]:

    key_setup = (
        parsed.get(
            "KEY_SETUP_ACCEPTED"
        ) == "YES"
    )

    accepted = (
        key_setup
        and
        parsed.get(
            "VERIFY_ACCEPTED"
        ) == "YES"
    )

    matched = (
        accepted
        ==
        expected_valid
    )

    return (
        matched,
        "accept" if accepted else "reject",
        (
            "verification result compared "
            "with Wycheproof expectation"
        ),
    )


def evaluate_sign(
    *,
    expected_valid: bool,
    public_expected: bool,
    parsed: dict[str, str],
) -> tuple[
    bool,
    str,
    str,
]:

    key_setup = (
        parsed.get(
            "KEY_SETUP_ACCEPTED"
        ) == "YES"
    )

    sign_success = (
        parsed.get(
            "SIGN_SUCCESS"
        ) == "YES"
    )

    if not expected_valid:

        rejected = (
            not key_setup
            or
            not sign_success
        )

        return (
            rejected,
            "reject"
            if rejected
            else "accept",
            (
                "invalid signing vector rejected"
                if rejected
                else
                "signing unexpectedly succeeded for invalid vector"
            ),
        )

    if not key_setup:
        return (
            False,
            "reject",
            "valid signing key setup rejected",
        )

    if (
        public_expected
        and
        parsed.get(
            "PUBLIC_DERIVATION_SUCCESS"
        ) != "YES"
    ):
        return (
            False,
            "reject",
            (
                "valid signing vector lacks "
                "public-key derivation"
            ),
        )

    if (
        public_expected
        and
        parsed.get(
            "DERIVED_PUBLIC_MATCH_VECTOR"
        ) != "YES"
    ):
        return (
            False,
            "accept",
            (
                "derived public key does not "
                "match vector public key"
            ),
        )

    if not sign_success:
        return (
            False,
            "reject",
            "valid signing operation rejected",
        )

    if (
        parsed.get(
            "SIGNATURE_MATCH_EXPECTED"
        ) != "YES"
    ):
        return (
            False,
            "accept",
            (
                "generated signature differs "
                "from Wycheproof signature"
            ),
        )

    if (
        parsed.get(
            "GENERATED_VERIFY"
        ) != "YES"
    ):
        return (
            False,
            "accept",
            (
                "generated signature failed "
                "OpenSSL verification"
            ),
        )

    return (
        True,
        "accept",
        "exact signature generated and verified",
    )


def run(
    *,
    input_file: Path,
    output_file: Path | None,
    algorithm_id: str,
    kind: str,
    probe: Path,
) -> int:

    info = ALGORITHMS[
        algorithm_id
    ]

    algorithm = info[
        "name"
    ]

    expected_schema = (
        EXPECTED_SCHEMAS[
            kind
        ]
    )

    raw = input_file.read_bytes()

    vectors = json.loads(
        raw.decode(
            "utf-8"
        )
    )

    if (
        vectors.get(
            "algorithm"
        )
        != algorithm
    ):
        raise ValueError(
            "algorithm mismatch"
        )

    if (
        vectors.get(
            "schema"
        )
        != expected_schema
    ):
        raise ValueError(
            "schema mismatch"
        )

    groups = vectors[
        "testGroups"
    ]

    actual_count = sum(
        len(
            group[
                "tests"
            ]
        )
        for group in groups
    )

    declared_count = vectors[
        "numberOfTests"
    ]

    if actual_count != declared_count:
        raise ValueError(
            "numberOfTests mismatch"
        )

    result = {
        "schema":
            HARNESS_SCHEMA,

        "implementation":
            "OpenSSL",

        "algorithm":
            algorithm,

        "kind":
            kind,

        "vector_file":
            input_file.name,

        "vector_file_sha256":
            sha256_file(
                input_file
            ),

        "vector_schema":
            vectors[
                "schema"
            ],

        "declared_vector_count":
            declared_count,

        "executed_vector_count":
            0,

        "expected_valid_count":
            0,

        "expected_invalid_count":
            0,

        "matched_count":
            0,

        "mismatched_count":
            0,

        "runtime_error_count":
            0,

        "unsupported_vector_count":
            0,

        "skipped_vector_count":
            0,

        "decision":
            "openssl_vector_file_failed",

        "tests":
            [],
    }

    ordinal = 0

    with tempfile.TemporaryDirectory(
        prefix="stage393-openssl-file-"
    ) as temporary_directory:

        workdir = Path(
            temporary_directory
        )

        for group_index, group in enumerate(
            groups
        ):

            if kind == "verify":

                if (
                    group.get(
                        "type"
                    )
                    != "MlDsaVerify"
                ):
                    raise ValueError(
                        "verify group type mismatch"
                    )

                public_data = decode_hex(
                    "publicKey",
                    group[
                        "publicKey"
                    ],
                )

                # Stage393: Wycheproof intentionally includes malformed public-key lengths.
                # Delegate public-key length acceptance/rejection to OpenSSL key import.
                pass

                key_kind = "public"
                key_data = public_data

            else:

                if (
                    group.get(
                        "type"
                    )
                    != "MlDsaSign"
                ):
                    raise ValueError(
                        "sign group type mismatch"
                    )

                (
                    key_kind,
                    key_data,
                    public_data,
                ) = setup_sign_group(
                    kind,
                    group,
                    info,
                )

            for test in group[
                "tests"
            ]:

                ordinal += 1

                tcid = test[
                    "tcId"
                ]

                expected_result = (
                    test[
                        "result"
                    ]
                )

                expected_valid = (
                    is_valid_expectation(
                        expected_result
                    )
                )

                if expected_valid:
                    result[
                        "expected_valid_count"
                    ] += 1
                else:
                    result[
                        "expected_invalid_count"
                    ] += 1

                flags = set(
                    test.get(
                        "flags",
                        [],
                    )
                )

                if kind == "verify":

                    input_data = decode_hex(
                        "msg",
                        test[
                            "msg"
                        ],
                    )

                    context_data = decode_hex(
                        "ctx",
                        test.get(
                            "ctx",
                            "",
                        ),
                    )

                    signature_data = decode_hex(
                        "sig",
                        test[
                            "sig"
                        ],
                    )

                    rnd_data = None
                    mu_mode = False

                    lane = (
                        "verify_message_context"
                    )

                else:

                    signature_data = decode_hex(
                        "sig",
                        test[
                            "sig"
                        ],
                    )

                    mu_present = (
                        "mu" in test
                    )

                    internal = (
                        "Internal"
                        in flags
                    )

                    if internal and not mu_present:
                        raise ValueError(
                            "Internal vector requires mu"
                        )

                    if internal and "msg" in test:
                        raise ValueError(
                            (
                                "Internal vector unexpectedly "
                                "contains msg"
                            )
                        )

                    if internal:

                        mu = decode_hex(
                            "mu",
                            test[
                                "mu"
                            ],
                        )

                        if len(mu) != 64:
                            raise ValueError(
                                (
                                    "External-Mu length "
                                    "must equal 64"
                                )
                            )

                        input_data = mu
                        context_data = b""
                        mu_mode = True

                    else:

                        if "msg" not in test:
                            raise ValueError(
                                (
                                    "non-Internal signing "
                                    "vector requires msg"
                                )
                            )

                        input_data = decode_hex(
                            "msg",
                            test[
                                "msg"
                            ],
                        )

                        context_data = decode_hex(
                            "ctx",
                            test.get(
                                "ctx",
                                "",
                            ),
                        )

                        mu_mode = False

                    if "rnd" in test:

                        rnd_data = decode_hex(
                            "rnd",
                            test[
                                "rnd"
                            ],
                        )

                        if len(rnd_data) != 32:
                            raise ValueError(
                                "rnd length must equal 32"
                            )

                    else:

                        rnd_data = None

                    lane = sign_lane(
                        test
                    )

                result[
                    "executed_vector_count"
                ] += 1

                try:
                    (
                        returncode,
                        parsed,
                        runtime_detail,
                    ) = run_probe(
                        probe,
                        algorithm=algorithm,
                        operation=(
                            "verify"
                            if kind == "verify"
                            else "sign"
                        ),
                        key_kind=key_kind,
                        key_data=key_data,
                        public_data=public_data,
                        input_data=input_data,
                        context_data=context_data,
                        signature_data=signature_data,
                        rnd_data=rnd_data,
                        mu_mode=mu_mode,
                        workdir=workdir,
                        ordinal=ordinal,
                    )

                except Exception as exc:

                    result[
                        "runtime_error_count"
                    ] += 1

                    result[
                        "tests"
                    ].append(
                        {
                            "tcId":
                                tcid,

                            "group_index":
                                group_index,

                            "expected_result":
                                expected_result,

                            "observed_result":
                                "runtime_error",

                            "matched":
                                False,

                            "lane":
                                lane,

                            "reason":
                                (
                                    "probe exception: "
                                    + str(exc)
                                ),
                        }
                    )

                    continue

                if (
                    returncode != 0
                    or
                    parsed.get(
                        "DIAGNOSTIC_COMPLETE"
                    ) != "YES"
                ):

                    result[
                        "runtime_error_count"
                    ] += 1

                    result[
                        "tests"
                    ].append(
                        {
                            "tcId":
                                tcid,

                            "group_index":
                                group_index,

                            "expected_result":
                                expected_result,

                            "observed_result":
                                "runtime_error",

                            "matched":
                                False,

                            "lane":
                                lane,

                            "reason":
                                (
                                    runtime_detail
                                    or
                                    (
                                        "probe exit "
                                        + str(returncode)
                                    )
                                ),
                        }
                    )

                    continue

                if kind == "verify":

                    (
                        matched,
                        observed,
                        reason,
                    ) = evaluate_verify(
                        expected_valid=
                            expected_valid,
                        parsed=
                            parsed,
                    )

                else:

                    (
                        matched,
                        observed,
                        reason,
                    ) = evaluate_sign(
                        expected_valid=
                            expected_valid,
                        public_expected=
                            public_data
                            is not None,
                        parsed=
                            parsed,
                    )

                if matched:
                    result[
                        "matched_count"
                    ] += 1
                else:
                    result[
                        "mismatched_count"
                    ] += 1

                result[
                    "tests"
                ].append(
                    {
                        "tcId":
                            tcid,

                        "group_index":
                            group_index,

                        "expected_result":
                            expected_result,

                        "observed_result":
                            observed,

                        "matched":
                            matched,

                        "lane":
                            lane,

                        "reason":
                            reason,

                        "key_setup_accepted":
                            parsed.get(
                                "KEY_SETUP_ACCEPTED"
                            )
                            == "YES",

                        "public_derivation_success":
                            parsed.get(
                                "PUBLIC_DERIVATION_SUCCESS"
                            )
                            == "YES",

                        "derived_public_match_vector":
                            parsed.get(
                                "DERIVED_PUBLIC_MATCH_VECTOR"
                            )
                            == "YES",

                        "sign_success":
                            parsed.get(
                                "SIGN_SUCCESS"
                            )
                            == "YES",

                        "signature_match_expected":
                            parsed.get(
                                "SIGNATURE_MATCH_EXPECTED"
                            )
                            == "YES",

                        "generated_verify":
                            parsed.get(
                                "GENERATED_VERIFY"
                            )
                            == "YES",

                        "verify_accepted":
                            parsed.get(
                                "VERIFY_ACCEPTED"
                            )
                            == "YES",

                        "mu_mode":
                            mu_mode,

                        "rnd_present":
                            rnd_data
                            is not None,
                    }
                )

    if (
        result[
            "executed_vector_count"
        ]
        ==
        result[
            "declared_vector_count"
        ]
        and
        result[
            "mismatched_count"
        ]
        == 0
        and
        result[
            "runtime_error_count"
        ]
        == 0
        and
        result[
            "unsupported_vector_count"
        ]
        == 0
        and
        result[
            "skipped_vector_count"
        ]
        == 0
    ):
        result[
            "decision"
        ] = (
            "openssl_vector_file_verified"
        )

    encoded = (
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    if output_file is None:
        sys.stdout.write(
            encoded
        )
    else:
        output_file.write_text(
            encoded,
            encoding="utf-8",
        )

    print(
        (
            "decision="
            + result[
                "decision"
            ]
        ),
        file=sys.stderr,
    )

    print(
        (
            "executed="
            + str(
                result[
                    "executed_vector_count"
                ]
            )
        ),
        file=sys.stderr,
    )

    print(
        (
            "matched="
            + str(
                result[
                    "matched_count"
                ]
            )
        ),
        file=sys.stderr,
    )

    print(
        (
            "mismatched="
            + str(
                result[
                    "mismatched_count"
                ]
            )
        ),
        file=sys.stderr,
    )

    print(
        (
            "runtime_errors="
            + str(
                result[
                    "runtime_error_count"
                ]
            )
        ),
        file=sys.stderr,
    )

    print(
        (
            "unsupported="
            + str(
                result[
                    "unsupported_vector_count"
                ]
            )
        ),
        file=sys.stderr,
    )

    print(
        (
            "skipped="
            + str(
                result[
                    "skipped_vector_count"
                ]
            )
        ),
        file=sys.stderr,
    )

    return (
        0
        if result[
            "decision"
        ]
        ==
        "openssl_vector_file_verified"
        else 1
    )


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Stage393 pinned OpenSSL 3.6.3 "
            "Wycheproof ML-DSA full-file harness"
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Wycheproof ML-DSA JSON file",
    )

    parser.add_argument(
        "--output",
        type=Path,
        help="result JSON path; stdout if omitted",
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=sorted(
            ALGORITHMS
        ),
        help="44, 65, or 87",
    )

    parser.add_argument(
        "--kind",
        required=True,
        choices=sorted(
            EXPECTED_SCHEMAS
        ),
        help=(
            "verify, sign_seed, or sign_noseed"
        ),
    )

    parser.add_argument(
        "--probe",
        required=True,
        type=Path,
        help=(
            "compiled pinned OpenSSL "
            "stage393_openssl_full_probe"
        ),
    )

    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(
            "--input must be a file"
        )

    if not args.probe.is_file():
        parser.error(
            "--probe must be a file"
        )

    try:
        return run(
            input_file=
                args.input,

            output_file=
                args.output,

            algorithm_id=
                args.algorithm,

            kind=
                args.kind,

            probe=
                args.probe,
        )

    except Exception as exc:
        print(
            "FAIL:",
            str(exc),
            file=sys.stderr,
        )

        return 2


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
