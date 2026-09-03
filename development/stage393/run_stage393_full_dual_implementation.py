#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = (
    "qsp.stage393.dual-full-result.v1"
)

ZERO_MISMATCH_CANDIDATE_DECISION = (
    "dual_implementation_diagnostic_execution_complete_zero_mismatch_candidate"
)

DIAGNOSTIC_MISMATCH_DECISION = (
    "dual_implementation_diagnostic_execution_complete_with_mismatches"
)

INCOMPLETE_DECISION = (
    "dual_implementation_execution_incomplete_fail_closed"
)


@dataclass(frozen=True)
class VectorSpec:
    filename: str
    algorithm: str
    kind: str
    count: int
    sha256: str


VECTOR_SPECS = (
    VectorSpec(
        filename="mldsa_44_verify_test.json",
        algorithm="44",
        kind="verify",
        count=180,
        sha256=(
            "0ca1b5df4575263e29b31fae7569a3da"
            "41df9a3b6fee56720a992d0cd1153b68"
        ),
    ),
    VectorSpec(
        filename="mldsa_44_sign_seed_test.json",
        algorithm="44",
        kind="sign_seed",
        count=86,
        sha256=(
            "b29b0dcca2e52c988e1b9c06f8b52188"
            "9ffbaadfc6a9dbf52f0f0f8f4c5b6b92"
        ),
    ),
    VectorSpec(
        filename="mldsa_44_sign_noseed_test.json",
        algorithm="44",
        kind="sign_noseed",
        count=73,
        sha256=(
            "ee55e18b1944db496b2539d3884dfacc"
            "04a96db21bcec239063df5e4cd1ee6cb"
        ),
    ),
    VectorSpec(
        filename="mldsa_65_verify_test.json",
        algorithm="65",
        kind="verify",
        count=210,
        sha256=(
            "49ac366d76115eab56b7116f10d06e28"
            "8e6f23fe6cfb90b26bfb2d731a8d1e02"
        ),
    ),
    VectorSpec(
        filename="mldsa_65_sign_seed_test.json",
        algorithm="65",
        kind="sign_seed",
        count=105,
        sha256=(
            "d72e9c2f514c9f7490c33785ae0027d9"
            "42ba2c45a9b8ebfc8fb1802b4913bf38"
        ),
    ),
    VectorSpec(
        filename="mldsa_65_sign_noseed_test.json",
        algorithm="65",
        kind="sign_noseed",
        count=78,
        sha256=(
            "8587a53e7e3ca20b006b661316b89c76"
            "2acdecf3fa902746b01cbc09fe14130d"
        ),
    ),
    VectorSpec(
        filename="mldsa_87_verify_test.json",
        algorithm="87",
        kind="verify",
        count=241,
        sha256=(
            "e9e04216d4217265a5affba2568476d3"
            "5742dbd8ffc9d4c23b3441334a08a224"
        ),
    ),
    VectorSpec(
        filename="mldsa_87_sign_seed_test.json",
        algorithm="87",
        kind="sign_seed",
        count=96,
        sha256=(
            "e83c292318134faa6af777e86c619c46"
            "43e2705dba91dfa5adcd1fddfd4f40ce"
        ),
    ),
    VectorSpec(
        filename="mldsa_87_sign_noseed_test.json",
        algorithm="87",
        kind="sign_noseed",
        count=69,
        sha256=(
            "bd4c997f1fb90d985dbcca9a5ab52cef"
            "1f5c22d2cc0ba332d8dbe68703a5b40d"
        ),
    ),
)


def sha256_file(
    filename: Path,
) -> str:

    return hashlib.sha256(
        filename.read_bytes()
    ).hexdigest()


def load_json(
    filename: Path,
) -> dict[str, Any]:

    value = json.loads(
        filename.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        value,
        dict,
    ):
        raise ValueError(
            f"JSON root is not object: {filename}"
        )

    return value


def flatten_source_tests(
    vector_document: dict[str, Any],
) -> list[dict[str, Any]]:

    flattened: list[dict[str, Any]] = []

    groups = vector_document.get(
        "testGroups"
    )

    if not isinstance(
        groups,
        list,
    ):
        raise ValueError(
            "testGroups is not a list"
        )

    for group_index, group in enumerate(
        groups
    ):

        tests = group.get(
            "tests"
        )

        if not isinstance(
            tests,
            list,
        ):
            raise ValueError(
                f"group {group_index} tests is not list"
            )

        for test in tests:

            flattened.append(
                {
                    "group_index":
                        group_index,

                    "tcId":
                        test.get(
                            "tcId"
                        ),

                    "expected_result":
                        test.get(
                            "result"
                        ),

                    "flags":
                        list(
                            test.get(
                                "flags",
                                [],
                            )
                        ),
                }
            )

    return flattened


def require_integer(
    document: dict[str, Any],
    key: str,
) -> int:

    value = document.get(
        key
    )

    if not isinstance(
        value,
        int,
    ):
        raise ValueError(
            f"{key} is not integer"
        )

    return value


def run_command(
    command: list[str],
) -> tuple[int, str]:

    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    return (
        completed.returncode,
        completed.stdout,
    )


def validate_file_result(
    *,
    implementation: str,
    document: dict[str, Any],
    spec: VectorSpec,
    expected_schema: str,
) -> list[str]:

    errors: list[str] = []

    if document.get(
        "schema"
    ) != expected_schema:

        errors.append(
            f"{implementation}: result schema mismatch"
        )

    if document.get(
        "vector_file_sha256"
    ) != spec.sha256:

        errors.append(
            f"{implementation}: vector SHA mismatch"
        )

    try:
        declared = require_integer(
            document,
            "declared_vector_count",
        )

        executed = require_integer(
            document,
            "executed_vector_count",
        )

        runtime_errors = require_integer(
            document,
            "runtime_error_count",
        )

        unsupported = require_integer(
            document,
            "unsupported_vector_count",
        )

        skipped = require_integer(
            document,
            "skipped_vector_count",
        )

    except ValueError as exc:

        errors.append(
            f"{implementation}: {exc}"
        )

        return errors

    if declared != spec.count:

        errors.append(
            (
                f"{implementation}: declared count "
                f"{declared} != {spec.count}"
            )
        )

    if executed != spec.count:

        errors.append(
            (
                f"{implementation}: executed count "
                f"{executed} != {spec.count}"
            )
        )

    if runtime_errors != 0:

        errors.append(
            (
                f"{implementation}: runtime_error_count="
                f"{runtime_errors}"
            )
        )

    if unsupported != 0:

        errors.append(
            (
                f"{implementation}: unsupported_vector_count="
                f"{unsupported}"
            )
        )

    if skipped != 0:

        errors.append(
            (
                f"{implementation}: skipped_vector_count="
                f"{skipped}"
            )
        )

    tests = document.get(
        "tests"
    )

    if not isinstance(
        tests,
        list,
    ):

        errors.append(
            f"{implementation}: tests is not list"
        )

    elif len(tests) != spec.count:

        errors.append(
            (
                f"{implementation}: test result count "
                f"{len(tests)} != {spec.count}"
            )
        )

    return errors


def bool_or_missing(
    document: dict[str, Any],
    key: str,
) -> bool | None:

    value = document.get(
        key
    )

    if isinstance(
        value,
        bool,
    ):
        return value

    return None


def compare_file_results(
    *,
    spec: VectorSpec,
    source_tests: list[dict[str, Any]],
    circl: dict[str, Any],
    openssl: dict[str, Any],
) -> dict[str, Any]:

    circl_tests = circl[
        "tests"
    ]

    openssl_tests = openssl[
        "tests"
    ]

    cross_mismatches: list[
        dict[str, Any]
    ] = []

    comparison_field_missing_count = 0

    signature_byte_mismatch_count = 0
    key_derivation_mismatch_count = 0
    verification_mismatch_count = 0

    semantic_behavior_mismatch_count = 0
    unclassified_cross_mismatch_count = 0

    for index, source in enumerate(
        source_tests
    ):

        circl_test = circl_tests[
            index
        ]

        openssl_test = openssl_tests[
            index
        ]

        expected = source[
            "expected_result"
        ]

        circl_expected = circl_test.get(
            "expected_result"
        )

        openssl_expected = openssl_test.get(
            "expected_result"
        )

        if circl_expected != expected:
            raise ValueError(
                (
                    f"CIRCL expected-result ordering mismatch "
                    f"{spec.filename} index={index}"
                )
            )

        if openssl_expected != expected:
            raise ValueError(
                (
                    f"OpenSSL expected-result ordering mismatch "
                    f"{spec.filename} index={index}"
                )
            )

        circl_observed = circl_test.get(
            "observed_result"
        )

        openssl_observed = openssl_test.get(
            "observed_result"
        )

        circl_matched = bool_or_missing(
            circl_test,
            "matched",
        )

        openssl_matched = bool_or_missing(
            openssl_test,
            "matched",
        )

        fields_missing: list[str] = []

        if not isinstance(
            circl_observed,
            str,
        ):
            fields_missing.append(
                "circl.observed_result"
            )

        if not isinstance(
            openssl_observed,
            str,
        ):
            fields_missing.append(
                "openssl.observed_result"
            )

        if circl_matched is None:
            fields_missing.append(
                "circl.matched"
            )

        if openssl_matched is None:
            fields_missing.append(
                "openssl.matched"
            )

        if fields_missing:

            comparison_field_missing_count += len(
                fields_missing
            )

        observed_difference = (
            isinstance(
                circl_observed,
                str,
            )
            and
            isinstance(
                openssl_observed,
                str,
            )
            and
            circl_observed != openssl_observed
        )

        matched_difference = (
            circl_matched is not None
            and
            openssl_matched is not None
            and
            circl_matched != openssl_matched
        )

        if not observed_difference \
        and not matched_difference:

            continue

        circl_reason = str(
            circl_test.get(
                "reason",
                "",
            )
        )

        openssl_reason = str(
            openssl_test.get(
                "reason",
                "",
            )
        )

        combined_reason = (
            circl_reason
            + " "
            + openssl_reason
        ).lower()

        classified = False

        if spec.kind == "verify":

            verification_mismatch_count += 1
            classified = True

        if observed_difference:

            semantic_behavior_mismatch_count += 1
            classified = True

        if (
            "signature" in combined_reason
            and
            (
                "differ" in combined_reason
                or
                "exact" in combined_reason
            )
        ):

            signature_byte_mismatch_count += 1
            classified = True

        if (
            "derived public" in combined_reason
            or
            "public key does not match" in combined_reason
        ):

            key_derivation_mismatch_count += 1
            classified = True

        if (
            spec.kind != "verify"
            and
            (
                "verify" in combined_reason
                or
                "verification" in combined_reason
            )
        ):

            verification_mismatch_count += 1
            classified = True

        if not classified:

            unclassified_cross_mismatch_count += 1

        cross_mismatches.append(
            {
                "vector_file":
                    spec.filename,

                "algorithm":
                    spec.algorithm,

                "kind":
                    spec.kind,

                "index":
                    index,

                "group_index":
                    source[
                        "group_index"
                    ],

                "tcId":
                    source[
                        "tcId"
                    ],

                "expected_result":
                    expected,

                "flags":
                    source[
                        "flags"
                    ],

                "circl_observed_result":
                    circl_observed,

                "openssl_observed_result":
                    openssl_observed,

                "circl_matched":
                    circl_matched,

                "openssl_matched":
                    openssl_matched,

                "circl_reason":
                    circl_reason,

                "openssl_reason":
                    openssl_reason,

                "observed_result_difference":
                    observed_difference,

                "matched_difference":
                    matched_difference,

                "missing_fields":
                    fields_missing,
            }
        )

    return {
        "cross_implementation_mismatch_count":
            len(
                cross_mismatches
            ),

        "signature_byte_mismatch_count":
            signature_byte_mismatch_count,

        "key_derivation_mismatch_count":
            key_derivation_mismatch_count,

        "verification_mismatch_count":
            verification_mismatch_count,

        "semantic_behavior_mismatch_count":
            semantic_behavior_mismatch_count,

        "unclassified_cross_mismatch_count":
            unclassified_cross_mismatch_count,

        "comparison_field_missing_count":
            comparison_field_missing_count,

        "mismatches":
            cross_mismatches,
    }


def execute(
    *,
    vector_dir: Path,
    circl_harness: Path,
    openssl_harness: Path,
    openssl_probe: Path,
    output_dir: Path,
    summary_file: Path,
) -> int:

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    total_expected = sum(
        spec.count
        for spec in VECTOR_SPECS
    )

    if total_expected != 1138:

        raise ValueError(
            "internal vector population is not 1138"
        )

    summary: dict[str, Any] = {
        "schema":
            SCHEMA,

        "purpose":
            "diagnostic_characterization",

        "target_vector_count":
            1138,

        "target_file_count":
            9,

        "known_mismatch_minimum_before_execution":
            6,

        "final_acceptance_preauthorized":
            False,

        "final_acceptance_requires_separate_gate":
            True,

        "diagnostic_runner_may_issue_final_acceptance":
            False,

        "circl_executed_vector_count":
            0,

        "circl_mismatched_count":
            0,

        "circl_runtime_error_count":
            0,

        "circl_unsupported_vector_count":
            0,

        "circl_skipped_vector_count":
            0,

        "openssl_executed_vector_count":
            0,

        "openssl_mismatched_count":
            0,

        "openssl_runtime_error_count":
            0,

        "openssl_unsupported_vector_count":
            0,

        "openssl_skipped_vector_count":
            0,

        "cross_implementation_mismatch_count":
            0,

        "signature_byte_mismatch_count":
            0,

        "key_derivation_mismatch_count":
            0,

        "verification_mismatch_count":
            0,

        "semantic_behavior_mismatch_count":
            0,

        "unclassified_cross_mismatch_count":
            0,

        "comparison_field_missing_count":
            0,

        "execution_integrity_failure_count":
            0,

        "files":
            [],

        "cross_implementation_mismatches":
            [],

        "all_1138_wycheproof_mldsa_vectors_verified":
            False,

        "stage393_final_acceptance":
            False,

        "decision":
            INCOMPLETE_DECISION,
    }

    for spec in VECTOR_SPECS:

        vector_file = (
            vector_dir
            / spec.filename
        )

        if not vector_file.is_file():

            raise ValueError(
                f"vector file missing: {vector_file}"
            )

        actual_sha = sha256_file(
            vector_file
        )

        if actual_sha != spec.sha256:

            raise ValueError(
                (
                    f"vector SHA mismatch: "
                    f"{spec.filename}"
                )
            )

        vector_document = load_json(
            vector_file
        )

        source_tests = flatten_source_tests(
            vector_document
        )

        if len(
            source_tests
        ) != spec.count:

            raise ValueError(
                (
                    f"source vector count mismatch: "
                    f"{spec.filename}"
                )
            )

        declared_source = vector_document.get(
            "numberOfTests"
        )

        if declared_source != spec.count:

            raise ValueError(
                (
                    f"source declared vector count mismatch: "
                    f"{spec.filename}"
                )
            )

        circl_output = (
            output_dir
            / (
                spec.filename
                + ".circl.json"
            )
        )

        openssl_output = (
            output_dir
            / (
                spec.filename
                + ".openssl.json"
            )
        )

        circl_command = [
            str(
                circl_harness
            ),
            "-input",
            str(
                vector_file
            ),
            "-output",
            str(
                circl_output
            ),
            "-algorithm",
            spec.algorithm,
            "-kind",
            spec.kind,
        ]

        openssl_command = [
            sys.executable,
            str(
                openssl_harness
            ),
            "--input",
            str(
                vector_file
            ),
            "--output",
            str(
                openssl_output
            ),
            "--algorithm",
            spec.algorithm,
            "--kind",
            spec.kind,
            "--probe",
            str(
                openssl_probe
            ),
        ]

        (
            circl_exit,
            circl_console,
        ) = run_command(
            circl_command
        )

        (
            openssl_exit,
            openssl_console,
        ) = run_command(
            openssl_command
        )

        file_integrity_errors: list[str] = []

        if circl_exit not in (
            0,
            1,
        ):

            file_integrity_errors.append(
                (
                    "CIRCL process exit "
                    + str(
                        circl_exit
                    )
                )
            )

        if openssl_exit not in (
            0,
            1,
        ):

            file_integrity_errors.append(
                (
                    "OpenSSL process exit "
                    + str(
                        openssl_exit
                    )
                )
            )

        if not circl_output.is_file():

            file_integrity_errors.append(
                "CIRCL result JSON missing"
            )

        if not openssl_output.is_file():

            file_integrity_errors.append(
                "OpenSSL result JSON missing"
            )

        if file_integrity_errors:

            summary[
                "execution_integrity_failure_count"
            ] += len(
                file_integrity_errors
            )

            summary[
                "files"
            ].append(
                {
                    "vector_file":
                        spec.filename,

                    "algorithm":
                        spec.algorithm,

                    "kind":
                        spec.kind,

                    "expected_count":
                        spec.count,

                    "circl_exit":
                        circl_exit,

                    "openssl_exit":
                        openssl_exit,

                    "integrity_errors":
                        file_integrity_errors,

                    "circl_console_tail":
                        circl_console[
                            -2000:
                        ],

                    "openssl_console_tail":
                        openssl_console[
                            -2000:
                        ],
                }
            )

            continue

        circl_result = load_json(
            circl_output
        )

        openssl_result = load_json(
            openssl_output
        )

        file_integrity_errors.extend(
            validate_file_result(
                implementation=
                    "CIRCL",

                document=
                    circl_result,

                spec=
                    spec,

                expected_schema=
                    "qsp.stage393.circl-file-result.v1",
            )
        )

        file_integrity_errors.extend(
            validate_file_result(
                implementation=
                    "OpenSSL",

                document=
                    openssl_result,

                spec=
                    spec,

                expected_schema=
                    "qsp.stage393.openssl-file-result.v1",
            )
        )

        if file_integrity_errors:

            summary[
                "execution_integrity_failure_count"
            ] += len(
                file_integrity_errors
            )

            summary[
                "files"
            ].append(
                {
                    "vector_file":
                        spec.filename,

                    "algorithm":
                        spec.algorithm,

                    "kind":
                        spec.kind,

                    "expected_count":
                        spec.count,

                    "circl_exit":
                        circl_exit,

                    "openssl_exit":
                        openssl_exit,

                    "integrity_errors":
                        file_integrity_errors,
                }
            )

            continue

        circl_executed = require_integer(
            circl_result,
            "executed_vector_count",
        )

        openssl_executed = require_integer(
            openssl_result,
            "executed_vector_count",
        )

        circl_mismatched = require_integer(
            circl_result,
            "mismatched_count",
        )

        openssl_mismatched = require_integer(
            openssl_result,
            "mismatched_count",
        )

        circl_runtime = require_integer(
            circl_result,
            "runtime_error_count",
        )

        openssl_runtime = require_integer(
            openssl_result,
            "runtime_error_count",
        )

        circl_unsupported = require_integer(
            circl_result,
            "unsupported_vector_count",
        )

        openssl_unsupported = require_integer(
            openssl_result,
            "unsupported_vector_count",
        )

        circl_skipped = require_integer(
            circl_result,
            "skipped_vector_count",
        )

        openssl_skipped = require_integer(
            openssl_result,
            "skipped_vector_count",
        )

        summary[
            "circl_executed_vector_count"
        ] += circl_executed

        summary[
            "openssl_executed_vector_count"
        ] += openssl_executed

        summary[
            "circl_mismatched_count"
        ] += circl_mismatched

        summary[
            "openssl_mismatched_count"
        ] += openssl_mismatched

        summary[
            "circl_runtime_error_count"
        ] += circl_runtime

        summary[
            "openssl_runtime_error_count"
        ] += openssl_runtime

        summary[
            "circl_unsupported_vector_count"
        ] += circl_unsupported

        summary[
            "openssl_unsupported_vector_count"
        ] += openssl_unsupported

        summary[
            "circl_skipped_vector_count"
        ] += circl_skipped

        summary[
            "openssl_skipped_vector_count"
        ] += openssl_skipped

        comparison = compare_file_results(
            spec=
                spec,

            source_tests=
                source_tests,

            circl=
                circl_result,

            openssl=
                openssl_result,
        )

        for counter_name in (
            "cross_implementation_mismatch_count",
            "signature_byte_mismatch_count",
            "key_derivation_mismatch_count",
            "verification_mismatch_count",
            "semantic_behavior_mismatch_count",
            "unclassified_cross_mismatch_count",
            "comparison_field_missing_count",
        ):

            summary[
                counter_name
            ] += comparison[
                counter_name
            ]

        summary[
            "cross_implementation_mismatches"
        ].extend(
            comparison[
                "mismatches"
            ]
        )

        summary[
            "files"
        ].append(
            {
                "vector_file":
                    spec.filename,

                "vector_file_sha256":
                    spec.sha256,

                "algorithm":
                    spec.algorithm,

                "kind":
                    spec.kind,

                "expected_count":
                    spec.count,

                "circl_exit":
                    circl_exit,

                "openssl_exit":
                    openssl_exit,

                "circl_decision":
                    circl_result.get(
                        "decision"
                    ),

                "openssl_decision":
                    openssl_result.get(
                        "decision"
                    ),

                "circl_executed":
                    circl_executed,

                "openssl_executed":
                    openssl_executed,

                "circl_mismatched":
                    circl_mismatched,

                "openssl_mismatched":
                    openssl_mismatched,

                "cross_mismatch_count":
                    comparison[
                        "cross_implementation_mismatch_count"
                    ],

                "integrity_errors":
                    [],
            }
        )

    integrity_ok = (
        summary[
            "execution_integrity_failure_count"
        ]
        == 0
        and
        summary[
            "circl_executed_vector_count"
        ]
        == 1138
        and
        summary[
            "openssl_executed_vector_count"
        ]
        == 1138
        and
        summary[
            "circl_runtime_error_count"
        ]
        == 0
        and
        summary[
            "openssl_runtime_error_count"
        ]
        == 0
        and
        summary[
            "circl_unsupported_vector_count"
        ]
        == 0
        and
        summary[
            "openssl_unsupported_vector_count"
        ]
        == 0
        and
        summary[
            "circl_skipped_vector_count"
        ]
        == 0
        and
        summary[
            "openssl_skipped_vector_count"
        ]
        == 0
        and
        len(
            summary[
                "files"
            ]
        )
        == 9
    )

    conformance_ok = (
        integrity_ok
        and
        summary[
            "circl_mismatched_count"
        ]
        == 0
        and
        summary[
            "openssl_mismatched_count"
        ]
        == 0
        and
        summary[
            "cross_implementation_mismatch_count"
        ]
        == 0
        and
        summary[
            "signature_byte_mismatch_count"
        ]
        == 0
        and
        summary[
            "key_derivation_mismatch_count"
        ]
        == 0
        and
        summary[
            "verification_mismatch_count"
        ]
        == 0
        and
        summary[
            "comparison_field_missing_count"
        ]
        == 0
    )

    summary[
        "execution_integrity_verified"
    ] = integrity_ok

    if conformance_ok:

        summary[
            "decision"
        ] = ZERO_MISMATCH_CANDIDATE_DECISION

        summary[
            "all_1138_wycheproof_mldsa_vectors_verified"
        ] = True

        summary[
            "stage393_final_acceptance"
        ] = False

    elif integrity_ok:

        summary[
            "decision"
        ] = DIAGNOSTIC_MISMATCH_DECISION

        summary[
            "all_1138_wycheproof_mldsa_vectors_verified"
        ] = False

        summary[
            "stage393_final_acceptance"
        ] = False

    else:

        summary[
            "decision"
        ] = INCOMPLETE_DECISION

        summary[
            "all_1138_wycheproof_mldsa_vectors_verified"
        ] = False

        summary[
            "stage393_final_acceptance"
        ] = False

    encoded = (
        json.dumps(
            summary,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )

    summary_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    summary_file.write_text(
        encoded,
        encoding="utf-8",
    )

    print(
        "decision="
        + str(
            summary[
                "decision"
            ]
        )
    )

    print(
        "circl_executed="
        + str(
            summary[
                "circl_executed_vector_count"
            ]
        )
    )

    print(
        "openssl_executed="
        + str(
            summary[
                "openssl_executed_vector_count"
            ]
        )
    )

    print(
        "circl_mismatched="
        + str(
            summary[
                "circl_mismatched_count"
            ]
        )
    )

    print(
        "openssl_mismatched="
        + str(
            summary[
                "openssl_mismatched_count"
            ]
        )
    )

    print(
        "cross_implementation_mismatch="
        + str(
            summary[
                "cross_implementation_mismatch_count"
            ]
        )
    )

    print(
        "execution_integrity_failure_count="
        + str(
            summary[
                "execution_integrity_failure_count"
            ]
        )
    )

    print(
        "comparison_field_missing_count="
        + str(
            summary[
                "comparison_field_missing_count"
            ]
        )
    )

    print(
        "ALL_1138_WYCHEPROOF_MLDSA_VECTORS_VERIFIED="
        + (
            "YES"
            if summary[
                "all_1138_wycheproof_mldsa_vectors_verified"
            ]
            else "NO"
        )
    )

    print(
        "STAGE393_FINAL_ACCEPTANCE="
        + (
            "YES"
            if summary[
                "stage393_final_acceptance"
            ]
            else "NO"
        )
    )

    if not integrity_ok:
        return 2

    return 0


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Stage393 complete 1,138-vector "
            "CIRCL/OpenSSL diagnostic runner"
        )
    )

    parser.add_argument(
        "--vector-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--circl-harness",
        required=True,
        type=Path,
        help=(
            "compiled Stage393 CIRCL full harness"
        ),
    )

    parser.add_argument(
        "--openssl-harness",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--openssl-probe",
        required=True,
        type=Path,
        help=(
            "compiled pinned OpenSSL full probe"
        ),
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--summary",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    if not args.vector_dir.is_dir():
        parser.error(
            "--vector-dir must be directory"
        )

    if not args.circl_harness.is_file():
        parser.error(
            "--circl-harness must be file"
        )

    if not args.openssl_harness.is_file():
        parser.error(
            "--openssl-harness must be file"
        )

    if not args.openssl_probe.is_file():
        parser.error(
            "--openssl-probe must be file"
        )

    try:

        return execute(
            vector_dir=
                args.vector_dir,

            circl_harness=
                args.circl_harness,

            openssl_harness=
                args.openssl_harness,

            openssl_probe=
                args.openssl_probe,

            output_dir=
                args.output_dir,

            summary_file=
                args.summary,
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
