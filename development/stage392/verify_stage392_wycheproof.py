#!/usr/bin/env python3

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STAGE392 = ROOT / "development" / "stage392"

EXPECTED = {
    "stage392_preimplementation_contract.json":
        "f6a8cbfd952992398feb51e06b7640b3cabd91b4718a2867495004518bf2e706",
    "stage392_adapter_contract.json":
        "a649897d1e6d00202a2ba79ffb766462e712c6bacc35d9c0344fd38ba0b8a62a",
    "stage392_wycheproof_full_execution_result.json":
        "1d2b89faf072eb527c442b1057eeec443abb77375665bc51da34fda321f43314",
    "stage392_verification_result.json":
        "c44ad9053429f8a8b36f6739af5982736abd98ea4860bddc3c0e1c216ca6633c",
    "stage392_evidence_manifest.json":
        "b1e976a9d1b0e1f7305144921a28ad7acff4d3adbe946c13d41b8ba9e2a82e71",
}

EXPECTED_DECISION = (
    "wycheproof_mldsa65_cross_implementation_verified"
)

EXPECTED_WYCHEPROOF_COMMIT = (
    "dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166"
)

EXPECTED_VECTOR_SHA = (
    "49ac366d76115eab56b7116f10d06e288e6f23fe6cfb90b26bfb2d731a8d1e02"
)


def sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def fail(code, message):
    print(f"FAIL: {code}")
    print(message)
    raise SystemExit(1)


def require(condition, code, message):
    if not condition:
        fail(code, message)


def load_json(path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        fail(
            "malformed_json",
            f"{path}: {exc}",
        )


print(
    "===== STAGE392 DETERMINISTIC VERIFIER ====="
)

print()
print("===== ARTIFACT SHA-256 VERIFICATION =====")

for name, expected in EXPECTED.items():
    path = STAGE392 / name

    require(
        path.is_file(),
        "missing_artifact",
        str(path),
    )

    actual = sha256(path)

    print(f"{name}")
    print(f"  actual   = {actual}")
    print(f"  expected = {expected}")

    require(
        actual == expected,
        "artifact_sha256_mismatch",
        name,
    )

print()
print("PASS: all fixed Stage392 artifact hashes exact")

result_path = (
    STAGE392 /
    "stage392_verification_result.json"
)

full_path = (
    STAGE392 /
    "stage392_wycheproof_full_execution_result.json"
)

manifest_path = (
    STAGE392 /
    "stage392_evidence_manifest.json"
)

result = load_json(result_path)
full = load_json(full_path)
manifest = load_json(manifest_path)

print()
print("===== CANONICAL RESULT SEMANTICS =====")

require(
    result.get("stage") == 392,
    "stage_mismatch",
    "stage must equal 392",
)

require(
    result.get("source_stage") == 391,
    "source_stage_mismatch",
    "source_stage must equal 391",
)

require(
    result.get("algorithm") == "ML-DSA-65",
    "algorithm_mismatch",
    "algorithm must remain ML-DSA-65",
)

require(
    result.get("decision") == EXPECTED_DECISION,
    "decision_mismatch",
    "unexpected Stage392 decision",
)

require(
    result.get("verification_status") == "verified",
    "verification_status_mismatch",
    "verification_status must be verified",
)

counts = result.get("verification_counts", {})

required_counts = {
    "total_vectors": 210,
    "valid_vectors": 79,
    "invalid_vectors": 131,
    "passed_vectors": 210,
    "failed_vectors": 0,
    "openssl_valid_accepts": 79,
    "circl_valid_accepts": 79,
    "openssl_invalid_rejects": 131,
    "circl_invalid_rejects": 131,
    "cross_implementation_accept_reject_matches": 210,
    "cross_implementation_accept_reject_mismatches": 0,
    "adapter_execution_errors": 0,
    "unexpected_invalid_acceptances": 0,
    "unexpected_valid_rejections": 0,
}

for key, expected in required_counts.items():
    actual = counts.get(key)

    print(
        f"{key} = {actual}"
    )

    require(
        actual == expected,
        "verification_count_mismatch",
        f"{key}: expected {expected}, got {actual}",
    )

checks = result.get("checks", {})

required_true_checks = [
    "adapter_execution_errors_absent",
    "algorithm_verified",
    "all_invalid_vectors_rejected_by_circl",
    "all_invalid_vectors_rejected_by_openssl",
    "all_valid_vectors_accepted_by_circl",
    "all_valid_vectors_accepted_by_openssl",
    "all_vectors_match_wycheproof_expected_result",
    "cross_implementation_accept_reject_match",
    "fail_closed",
    "test_count_verified",
    "wycheproof_commit_binding_verified",
    "wycheproof_vector_sha256_verified",
]

for key in required_true_checks:
    require(
        checks.get(key) is True,
        "required_check_false",
        key,
    )

binding = result.get("wycheproof_binding", {})

require(
    binding.get("commit")
    == EXPECTED_WYCHEPROOF_COMMIT,
    "wycheproof_commit_mismatch",
    "unexpected Wycheproof commit",
)

require(
    binding.get("vector_sha256")
    == EXPECTED_VECTOR_SHA,
    "wycheproof_vector_sha256_mismatch",
    "unexpected Wycheproof vector SHA-256",
)

non_claims = result.get("non_claims", {})

required_false_claims = [
    "complete_fips204_conformance",
    "entire_system_quantum_safe",
    "formal_certification",
    "formal_external_assessment_completed",
    "stage389_dual_timestamp_verified",
    "system_wide_formal_acceptance",
    "wycheproof_is_formal_proof",
]

for key in required_false_claims:
    require(
        non_claims.get(key) is False,
        "invalid_scope_claim",
        key,
    )

print()
print("PASS: canonical Stage392 semantics exact")

print()
print("===== FULL EXECUTION CROSS-CHECK =====")

execution_counts = full.get(
    "execution_counts"
)

require(
    isinstance(execution_counts, dict),
    "full_execution_counts_missing",
    "execution_counts must be a dictionary",
)


def find_count(name):
    return execution_counts.get(name)


full_expectations = {
    "total": 210,
    "passed": 210,
    "failed": 0,
    "adapter_errors": 0,
    "cross_implementation_mismatches": 0,
    "unexpected_valid_rejections": 0,
    "unexpected_invalid_acceptances": 0,
}

for key, expected in full_expectations.items():
    actual = find_count(key)

    require(
        actual == expected,
        "full_execution_summary_mismatch",
        f"{key}: expected {expected}, got {actual}",
    )

print(
    "PASS: full execution summary matches "
    "canonical decision"
)

print()
print("===== MANIFEST CROSS-CHECK =====")

artifacts = manifest.get("artifacts")

require(
    isinstance(artifacts, list),
    "manifest_artifacts_missing",
    "manifest artifacts must be a list",
)

require(
    len(artifacts) == 10,
    "manifest_artifact_count_mismatch",
    f"expected 10 artifacts, got {len(artifacts)}",
)

for entry in artifacts:
    require(
        isinstance(entry, dict),
        "malformed_manifest_entry",
        repr(entry),
    )

    rel = entry.get("path")
    expected_sha = entry.get("sha256")

    require(
        isinstance(rel, str)
        and isinstance(expected_sha, str),
        "malformed_manifest_entry",
        repr(entry),
    )

    path = ROOT / rel

    require(
        path.is_file(),
        "manifest_artifact_missing",
        rel,
    )

    actual_sha = sha256(path)

    require(
        actual_sha == expected_sha,
        "manifest_artifact_sha256_mismatch",
        rel,
    )

print("PASS: all manifest artifact hashes exact")

print()
print("===== FINAL DECISION =====")
print(
    "decision = "
    + EXPECTED_DECISION
)
print(
    "verified_vectors = 210"
)
print(
    "valid_vectors = 79"
)
print(
    "invalid_vectors = 131"
)
print(
    "cross_implementation_mismatches = 0"
)
print(
    "adapter_execution_errors = 0"
)
print()
print(
    "PASS: deterministic Stage392 verification complete"
)

sys.exit(0)
