#!/usr/bin/env python3

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

SOURCE_STAGE392 = (
    ROOT
    / "development"
    / "stage392"
)

EXPECTED_HASHES = {
    "stage392_verification_result.json":
        "c44ad9053429f8a8b36f6739af5982736abd98ea4860bddc3c0e1c216ca6633c",

    "stage392_wycheproof_full_execution_result.json":
        "1d2b89faf072eb527c442b1057eeec443abb77375665bc51da34fda321f43314",

    "stage392_evidence_manifest.json":
        "b1e976a9d1b0e1f7305144921a28ad7acff4d3adbe946c13d41b8ba9e2a82e71",
}


def sha256(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def write_json(path, data):
    path.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def verifier_path(case_root):
    return (
        case_root
        / "development"
        / "stage392"
        / "verify_stage392_wycheproof.py"
    )


def stage392_path(case_root):
    return (
        case_root
        / "development"
        / "stage392"
    )


def run_verifier(case_root):
    return subprocess.run(
        [
            "python3",
            str(
                verifier_path(
                    case_root
                )
            ),
        ],
        cwd=case_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def copy_case(
    baseline,
    cases,
    name,
):
    target = (
        cases
        / name
    )

    shutil.copytree(
        baseline,
        target,
    )

    return target


def mutate_json(
    case_root,
    filename,
    callback,
):
    path = (
        stage392_path(
            case_root
        )
        / filename
    )

    data = load_json(
        path
    )

    callback(
        data
    )

    write_json(
        path,
        data,
    )


def rebind_verifier_hash(
    case_root,
    filename,
):
    stage392 = stage392_path(
        case_root
    )

    artifact = (
        stage392
        / filename
    )

    verifier = (
        stage392
        / "verify_stage392_wycheproof.py"
    )

    old_hash = EXPECTED_HASHES[
        filename
    ]

    new_hash = sha256(
        artifact
    )

    text = verifier.read_text(
        encoding="utf-8"
    )

    count = text.count(
        old_hash
    )

    if count != 1:
        raise RuntimeError(
            "expected exactly one verifier "
            f"binding for {filename}; got {count}"
        )

    text = text.replace(
        old_hash,
        new_hash,
        1,
    )

    verifier.write_text(
        text,
        encoding="utf-8",
    )


#
# First-layer mutations.
# These must be rejected by fixed artifact bindings.
#

def first_decision(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d.__setitem__(
                "decision",
                "tampered_success",
            ),
    )


def first_total(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["verification_counts"].__setitem__(
                "total_vectors",
                209,
            ),
    )


def first_valid(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["verification_counts"].__setitem__(
                "valid_vectors",
                78,
            ),
    )


def first_invalid(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["verification_counts"].__setitem__(
                "invalid_vectors",
                130,
            ),
    )


def first_failed(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["verification_counts"].__setitem__(
                "failed_vectors",
                1,
            ),
    )


def first_adapter_error(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["verification_counts"].__setitem__(
                "adapter_execution_errors",
                1,
            ),
    )


def first_cross_mismatch(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["verification_counts"].__setitem__(
                "cross_implementation_accept_reject_mismatches",
                1,
            ),
    )


def first_invalid_accept(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["verification_counts"].__setitem__(
                "unexpected_invalid_acceptances",
                1,
            ),
    )


def first_wycheproof_commit(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["wycheproof_binding"].__setitem__(
                "commit",
                "0" * 40,
            ),
    )


def first_certification(case):
    mutate_json(
        case,
        "stage392_verification_result.json",
        lambda d:
            d["non_claims"].__setitem__(
                "formal_certification",
                True,
            ),
    )


def first_manifest_sha(case):
    mutate_json(
        case,
        "stage392_evidence_manifest.json",
        lambda d:
            d["artifacts"][0].__setitem__(
                "sha256",
                "0" * 64,
            ),
    )


def first_missing_contract(case):
    (
        stage392_path(case)
        / "stage392_adapter_contract.json"
    ).unlink()


FIRST_LAYER_TESTS = [
    (
        "hash_decision_tamper",
        first_decision,
    ),
    (
        "hash_total_vectors_209",
        first_total,
    ),
    (
        "hash_valid_vectors_78",
        first_valid,
    ),
    (
        "hash_invalid_vectors_130",
        first_invalid,
    ),
    (
        "hash_failed_vectors_1",
        first_failed,
    ),
    (
        "hash_adapter_errors_1",
        first_adapter_error,
    ),
    (
        "hash_cross_mismatch_1",
        first_cross_mismatch,
    ),
    (
        "hash_unexpected_invalid_acceptance_1",
        first_invalid_accept,
    ),
    (
        "hash_wycheproof_commit_tamper",
        first_wycheproof_commit,
    ),
    (
        "hash_formal_certification_true",
        first_certification,
    ),
    (
        "hash_manifest_sha_tamper",
        first_manifest_sha,
    ),
    (
        "hash_missing_adapter_contract",
        first_missing_contract,
    ),
]


#
# Second-layer mutations.
# The changed artifact SHA is rebound in the isolated verifier.
# Therefore rejection must come from semantic validation.
#

def canonical_semantic_mutation(
    case,
    callback,
):
    mutate_json(
        case,
        "stage392_verification_result.json",
        callback,
    )

    rebind_verifier_hash(
        case,
        "stage392_verification_result.json",
    )


def semantic_decision(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d.__setitem__(
                "decision",
                "tampered_success",
            ),
    )


def semantic_total(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d["verification_counts"].__setitem__(
                "total_vectors",
                209,
            ),
    )


def semantic_valid(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d["verification_counts"].__setitem__(
                "valid_vectors",
                78,
            ),
    )


def semantic_invalid(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d["verification_counts"].__setitem__(
                "invalid_vectors",
                130,
            ),
    )


def semantic_failed(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d["verification_counts"].__setitem__(
                "failed_vectors",
                1,
            ),
    )


def semantic_adapter_error(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d["verification_counts"].__setitem__(
                "adapter_execution_errors",
                1,
            ),
    )


def semantic_cross_mismatch(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d["verification_counts"].__setitem__(
                "cross_implementation_accept_reject_mismatches",
                1,
            ),
    )


def semantic_certification(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d["non_claims"].__setitem__(
                "formal_certification",
                True,
            ),
    )


def semantic_wycheproof_commit(case):
    canonical_semantic_mutation(
        case,
        lambda d:
            d["wycheproof_binding"].__setitem__(
                "commit",
                "0" * 40,
            ),
    )


def semantic_full_total(case):
    mutate_json(
        case,
        "stage392_wycheproof_full_execution_result.json",
        lambda d:
            d["execution_counts"].__setitem__(
                "total",
                209,
            ),
    )

    rebind_verifier_hash(
        case,
        "stage392_wycheproof_full_execution_result.json",
    )


def semantic_manifest_sha(case):
    mutate_json(
        case,
        "stage392_evidence_manifest.json",
        lambda d:
            d["artifacts"][0].__setitem__(
                "sha256",
                "0" * 64,
            ),
    )

    rebind_verifier_hash(
        case,
        "stage392_evidence_manifest.json",
    )


SECOND_LAYER_TESTS = [
    (
        "semantic_decision_tamper",
        semantic_decision,
    ),
    (
        "semantic_total_vectors_209",
        semantic_total,
    ),
    (
        "semantic_valid_vectors_78",
        semantic_valid,
    ),
    (
        "semantic_invalid_vectors_130",
        semantic_invalid,
    ),
    (
        "semantic_failed_vectors_1",
        semantic_failed,
    ),
    (
        "semantic_adapter_errors_1",
        semantic_adapter_error,
    ),
    (
        "semantic_cross_mismatch_1",
        semantic_cross_mismatch,
    ),
    (
        "semantic_formal_certification_true",
        semantic_certification,
    ),
    (
        "semantic_wycheproof_commit_tamper",
        semantic_wycheproof_commit,
    ),
    (
        "semantic_full_execution_total_209",
        semantic_full_total,
    ),
    (
        "semantic_manifest_internal_sha_tamper",
        semantic_manifest_sha,
    ),
]


def main():

    for name, expected in EXPECTED_HASHES.items():

        path = (
            SOURCE_STAGE392
            / name
        )

        if not path.is_file():

            print(
                "FAIL: baseline artifact missing:",
                name,
            )

            return 1

        actual = sha256(
            path
        )

        if actual != expected:

            print(
                "FAIL: baseline SHA mismatch:",
                name,
            )

            return 1


    with tempfile.TemporaryDirectory(
        prefix="qsp-stage392-regression-"
    ) as temporary:

        temp = Path(
            temporary
        )

        baseline = (
            temp
            / "baseline"
        )

        cases = (
            temp
            / "cases"
        )

        baseline.mkdir(
            parents=True
        )

        (
            baseline
            / "development"
        ).mkdir()

        shutil.copytree(
            SOURCE_STAGE392,
            baseline
            / "development"
            / "stage392",
        )


        results = []


        print(
            "===== STAGE392 PUBLIC FAIL-CLOSED REGRESSION ====="
        )


        #
        # Layer 1
        #

        print()
        print(
            "===== LAYER 1 — FIXED HASH BINDING ====="
        )

        for name, mutation in FIRST_LAYER_TESTS:

            case = copy_case(
                baseline,
                cases,
                name,
            )

            mutation(
                case
            )

            proc = run_verifier(
                case
            )

            rejected = (
                proc.returncode != 0
            )

            output = (
                proc.stdout
                + "\n"
                + proc.stderr
            )

            hash_rejection = (
                rejected
                and (
                    "artifact_sha256_mismatch"
                    in output
                    or
                    "missing_artifact"
                    in output
                )
            )

            print(
                name,
                "=",
                "PASS"
                if hash_rejection
                else "FAIL",
            )

            results.append({
                "layer":
                    "fixed_hash_binding",

                "name":
                    name,

                "rejected":
                    rejected,

                "expected_rejection_type":
                    "hash_or_missing_artifact",

                "correct_rejection":
                    hash_rejection,
            })


        #
        # Layer 2
        #

        print()
        print(
            "===== LAYER 2 — SEMANTIC VALIDATION ====="
        )

        for name, mutation in SECOND_LAYER_TESTS:

            case = copy_case(
                baseline,
                cases,
                name,
            )

            mutation(
                case
            )

            proc = run_verifier(
                case
            )

            rejected = (
                proc.returncode != 0
            )

            output = (
                proc.stdout
                + "\n"
                + proc.stderr
            )

            original_hash_failure = (
                "FAIL: artifact_sha256_mismatch"
                in output
            )

            semantic_rejection = (
                rejected
                and
                not original_hash_failure
            )

            print(
                name,
                "=",
                "PASS"
                if semantic_rejection
                else "FAIL",
            )

            results.append({
                "layer":
                    "semantic_validation",

                "name":
                    name,

                "rejected":
                    rejected,

                "original_hash_failure":
                    original_hash_failure,

                "expected_rejection_type":
                    "semantic",

                "correct_rejection":
                    semantic_rejection,
            })


    passed = sum(
        1
        for result in results
        if result[
            "correct_rejection"
        ]
    )

    failed = (
        len(results)
        - passed
    )


    print()
    print(
        "===== REGRESSION SUMMARY ====="
    )

    print(
        "test_count =",
        len(results)
    )

    print(
        "layer1_count =",
        len(FIRST_LAYER_TESTS)
    )

    print(
        "layer2_count =",
        len(SECOND_LAYER_TESTS)
    )

    print(
        "passed =",
        passed
    )

    print(
        "failed =",
        failed
    )


    if len(results) != 23:

        print(
            "FAIL: expected exactly 23 tests"
        )

        return 1


    if passed != 23:

        print(
            "FAIL: not all mutations rejected correctly"
        )

        return 1


    print()
    print(
        "PASS: 23 / 23 Stage392 Fail-Closed tests"
    )

    print(
        "PASS: fixed hash integrity layer verified"
    )

    print(
        "PASS: semantic consistency layer verified"
    )

    print(
        "PASS: all tests use isolated temporary copies"
    )


    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
