#!/usr/bin/env python3

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]

SRC = ROOT / "development/stage393/authoritative-rebind"
PUB = ROOT / "docs/verification/stage393/authoritative-rebind"

EVIDENCE = (
    ROOT
    / "development/stage393/"
    "stage393_full_1138_dual_diagnostic_evidence"
)

SUMMARY = EVIDENCE / "summary.json"
DIAG_MANIFEST = EVIDENCE / "manifest.json"
FREEZE = (
    EVIDENCE
    / "stage393_full_1138_evidence_freeze_manifest.json"
)
ADJUDICATION = (
    EVIDENCE
    / "stage393_full_1138_result_adjudication.json"
)
CONTRACT = (
    ROOT
    / "development/stage393/"
    "stage393_full_wycheproof_execution_contract.json"
)

checks = 0
failures = []


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


def check(name, condition):
    global checks

    checks += 1

    if not condition:
        failures.append(name)


def sidecar_hash(path):
    return (
        path.read_text(
            encoding="utf-8"
        )
        .split()[0]
    )


expected = {
    "base_commit":
        "2bc09de5115016809083659d70608c54eadee6a6",
    "base_tree":
        "cd0e52f3eadafb3b0ca4fa94edf289512d3bfd37",
    "old_stage392_commit":
        "ab2552e5eb3f8701330608e3b74ee2b0396f966b",
    "stage392_commit":
        "0c518ac813f972e82a83bac340ddcc2b4d0b7a38",
    "stage392_tree":
        "fdb949418477a00f3860855a646874c33b2a6605",
    "stage392_snapshot":
        "347f29f2e6e9721168c7f195c1063cc040c7641751d9180c3269269890dddc36",
    "stage392_upstream":
        "40a855b8fa57a8ac202bbe5b9eb201a583735f128d8e5740128983a7a8d69c1f",
    "stage392_result":
        "1b9942c7de34f71328c2302bd5902223c833c1607489e33b9f4247582a08d9e4",
    "stage392_manifest":
        "3c52157fbd88eb07138842348f0ed6b3935b95721e0c4da6e16e48b62a643606",
    "summary":
        "feaa8e3cb3b77d61a5aaa3298827e808e7da855cd7064a89b18ca57ef003043e",
    "diagnostic_manifest":
        "de2c5cc9a8264028646fa1301296665727399d052c72c22ba61738c98766e31e",
    "freeze":
        "13f6f83dd858912891e870e03260103f0823faae60aa4d55ecec67241604d7c2",
    "adjudication":
        "c4f70d0456c4f566882e518c11092dce9ecd9ddbacc7314584d35995c2391fd7",
    "contract":
        "eef3469aea44dbf459a0a04236a751e81d92106c766c55cf46e09b085484da91",
}


for path in (
    SUMMARY,
    DIAG_MANIFEST,
    FREEZE,
    ADJUDICATION,
    CONTRACT,
):
    check(
        "historical file exists: " + str(path),
        path.is_file(),
    )


check(
    "summary hash",
    sha256(SUMMARY) == expected["summary"],
)
check(
    "diagnostic manifest hash",
    sha256(DIAG_MANIFEST)
    == expected["diagnostic_manifest"],
)
check(
    "freeze hash",
    sha256(FREEZE) == expected["freeze"],
)
check(
    "adjudication hash",
    sha256(ADJUDICATION)
    == expected["adjudication"],
)
check(
    "contract hash",
    sha256(CONTRACT) == expected["contract"],
)


summary = load_json(SUMMARY)
freeze = load_json(FREEZE)
adjudication = load_json(ADJUDICATION)
contract = load_json(CONTRACT)


check(
    "summary decision",
    summary.get("decision")
    ==
    "dual_implementation_diagnostic_execution_complete_with_mismatches",
)
check(
    "target vectors",
    summary.get("target_vector_count") == 1138,
)
check(
    "circl executed",
    summary.get("circl_executed_vector_count") == 1138,
)
check(
    "openssl executed",
    summary.get("openssl_executed_vector_count") == 1138,
)
check(
    "circl skipped zero",
    summary.get("circl_skipped_vector_count") == 0,
)
check(
    "openssl skipped zero",
    summary.get("openssl_skipped_vector_count") == 0,
)
check(
    "circl unsupported zero",
    summary.get("circl_unsupported_vector_count") == 0,
)
check(
    "openssl unsupported zero",
    summary.get("openssl_unsupported_vector_count") == 0,
)
check(
    "circl runtime errors zero",
    summary.get("circl_runtime_error_count") == 0,
)
check(
    "openssl runtime errors zero",
    summary.get("openssl_runtime_error_count") == 0,
)
check(
    "circl mismatches six",
    summary.get("circl_mismatched_count") == 6,
)
check(
    "openssl mismatches three",
    summary.get("openssl_mismatched_count") == 3,
)
check(
    "cross mismatches nine",
    summary.get("cross_implementation_mismatch_count") == 9,
)
check(
    "semantic mismatches nine",
    summary.get("semantic_behavior_mismatch_count") == 9,
)
check(
    "signature mismatches zero",
    summary.get("signature_byte_mismatch_count") == 0,
)
check(
    "verification mismatches zero",
    summary.get("verification_mismatch_count") == 0,
)
check(
    "key derivation mismatches zero",
    summary.get("key_derivation_mismatch_count") == 0,
)
check(
    "unclassified mismatches zero",
    summary.get("unclassified_cross_mismatch_count") == 0,
)
check(
    "all 1138 verified false",
    summary.get(
        "all_1138_wycheproof_mldsa_vectors_verified"
    )
    is False,
)
check(
    "stage393 acceptance false",
    summary.get("stage393_final_acceptance")
    is False,
)
check(
    "separate acceptance gate required",
    summary.get(
        "final_acceptance_requires_separate_gate"
    )
    is True,
)
check(
    "diagnostic runner cannot accept",
    summary.get(
        "diagnostic_runner_may_issue_final_acceptance"
    )
    is False,
)


check(
    "freeze decision",
    freeze.get("decision")
    == "local_evidence_frozen_non_acceptance",
)
check(
    "freeze stage393 acceptance false",
    freeze.get("stage393_final_acceptance")
    is False,
)
check(
    "freeze all 1138 false",
    freeze.get(
        "claim_boundary",
        {},
    ).get(
        "all_1138_wycheproof_mldsa_vectors_verified"
    )
    is False,
)

frozen = freeze.get("frozen_result", {})

check(
    "freeze circl 1138",
    frozen.get("circl_execution_count") == 1138,
)
check(
    "freeze openssl 1138",
    frozen.get("openssl_execution_count") == 1138,
)
check(
    "freeze total 2276",
    frozen.get(
        "total_cryptographic_execution_count"
    )
    == 2276,
)
check(
    "freeze cross mismatch nine",
    frozen.get(
        "cross_implementation_mismatch_count"
    )
    == 9,
)
check(
    "freeze semantic mismatch nine",
    frozen.get(
        "semantic_behavior_mismatch_count"
    )
    == 9,
)


mismatches = adjudication.get("mismatches", [])

check(
    "adjudication mismatch count nine",
    len(mismatches) == 9,
)

for index, item in enumerate(mismatches):
    check(
        f"mismatch {index} semantic true",
        item.get("semantic_behavior_difference")
        is True,
    )
    check(
        f"mismatch {index} no confirmed fips nonconformance",
        item.get("fips204_nonconformance_confirmed")
        is False,
    )
    check(
        f"mismatch {index} no confirmed bug",
        item.get("implementation_bug_confirmed")
        is False,
    )
    check(
        f"mismatch {index} no confirmed vulnerability",
        item.get("security_vulnerability_confirmed")
        is False,
    )
    check(
        f"mismatch {index} no key recovery",
        item.get("secret_key_recovery_demonstrated")
        is False,
    )


check(
    "historical contract old Stage392 binding",
    contract.get(
        "base_binding",
        {},
    ).get(
        "stage392_anchor_commit"
    )
    == expected["old_stage392_commit"],
)

check(
    "historical contract immutable Stage392",
    contract.get(
        "base_binding",
        {},
    ).get(
        "stage392_must_remain_immutable"
    )
    is True,
)


snapshot_path = (
    SRC
    / "stage393_authoritative_historical_snapshot.json"
)
upstream_path = (
    SRC
    / "stage393_authoritative_upstream_binding.json"
)
result_path = (
    SRC
    / "stage393_authoritative_non_acceptance_reverification_result.json"
)
manifest_path = (
    SRC
    / "stage393_authoritative_rebind_manifest.json"
)

for path in (
    snapshot_path,
    upstream_path,
    result_path,
    manifest_path,
):
    check(
        "authority artifact exists: " + path.name,
        path.is_file(),
    )
    check(
        "authority sidecar exists: " + path.name,
        Path(str(path) + ".sha256").is_file(),
    )

    sidecar = Path(str(path) + ".sha256")

    check(
        "authority sidecar matches: " + path.name,
        sidecar_hash(sidecar)
        == sha256(path),
    )


snapshot = load_json(snapshot_path)
upstream = load_json(upstream_path)
result = load_json(result_path)
manifest = load_json(manifest_path)


check(
    "snapshot base commit",
    snapshot.get(
        "historical_stage393",
        {},
    ).get("commit")
    == expected["base_commit"],
)
check(
    "snapshot base tree",
    snapshot.get(
        "historical_stage393",
        {},
    ).get("tree")
    == expected["base_tree"],
)
check(
    "snapshot preserved",
    snapshot.get(
        "historical_stage393",
        {},
    ).get("preserved")
    is True,
)
check(
    "snapshot rewritten false",
    snapshot.get(
        "historical_stage393",
        {},
    ).get("rewritten")
    is False,
)

inventory = snapshot.get(
    "historical_stage393",
    {},
).get(
    "tracked_stage393_files",
    [],
)

check(
    "snapshot historical file count 39",
    len(inventory) == 39,
)

for item in inventory:
    path = ROOT / item["path"]

    check(
        "snapshot historical exists: "
        + item["path"],
        path.is_file(),
    )

    if path.is_file():
        check(
            "snapshot historical hash: "
            + item["path"],
            sha256(path)
            == item["sha256"],
        )


auth392 = upstream.get(
    "authoritative_stage392",
    {},
)

check(
    "upstream Stage392 commit",
    auth392.get("commit")
    == expected["stage392_commit"],
)
check(
    "upstream Stage392 tree",
    auth392.get("tree")
    == expected["stage392_tree"],
)
check(
    "upstream Stage392 closed",
    auth392.get("closed")
    is True,
)

hashes392 = auth392.get(
    "artifact_sha256",
    {},
)

check(
    "upstream Stage392 snapshot hash",
    hashes392.get("historical_snapshot")
    == expected["stage392_snapshot"],
)
check(
    "upstream Stage392 upstream hash",
    hashes392.get("upstream_binding")
    == expected["stage392_upstream"],
)
check(
    "upstream Stage392 result hash",
    hashes392.get("reverification_result")
    == expected["stage392_result"],
)
check(
    "upstream Stage392 manifest hash",
    hashes392.get("rebind_manifest")
    == expected["stage392_manifest"],
)


imported = (
    SRC
    / "upstream-stage392"
)

imported_expected = {
    "stage392_authoritative_historical_snapshot.json":
        expected["stage392_snapshot"],
    "stage392_authoritative_upstream_binding.json":
        expected["stage392_upstream"],
    "stage392_authoritative_reverification_result.json":
        expected["stage392_result"],
    "stage392_authoritative_rebind_manifest.json":
        expected["stage392_manifest"],
}

for name, expected_hash in imported_expected.items():
    path = imported / name
    sidecar = Path(str(path) + ".sha256")

    check(
        "imported Stage392 exists: " + name,
        path.is_file(),
    )

    if path.is_file():
        check(
            "imported Stage392 hash: " + name,
            sha256(path) == expected_hash,
        )

    check(
        "imported Stage392 sidecar exists: " + name,
        sidecar.is_file(),
    )

    if sidecar.is_file():
        check(
            "imported Stage392 sidecar: " + name,
            sidecar_hash(sidecar)
            == expected_hash,
        )


check(
    "result decision",
    result.get("decision")
    ==
    "authoritative_stage393_non_acceptance_lineage_reverified",
)
check(
    "result verification status",
    result.get("verification_status")
    ==
    "verified_non_acceptance_authoritative_upstream_lineage",
)
check(
    "result historical preserved",
    result.get(
        "historical_stage393",
        {},
    ).get("preserved")
    is True,
)
check(
    "result historical rewritten false",
    result.get(
        "historical_stage393",
        {},
    ).get("rewritten")
    is False,
)
check(
    "result no new crypto execution",
    result.get(
        "cryptographic_evidence",
        {},
    ).get(
        "new_cryptographic_execution_performed"
    )
    is False,
)

crypto = result.get(
    "cryptographic_evidence",
    {},
)

check(
    "result 1138 population",
    crypto.get("wycheproof_vector_count")
    == 1138,
)
check(
    "result circl 1138",
    crypto.get("circl_executed_vector_count")
    == 1138,
)
check(
    "result openssl 1138",
    crypto.get("openssl_executed_vector_count")
    == 1138,
)
check(
    "result total 2276",
    crypto.get(
        "total_cryptographic_execution_count"
    )
    == 2276,
)
check(
    "result cross mismatch nine",
    crypto.get(
        "cross_implementation_mismatch_count"
    )
    == 9,
)
check(
    "result semantic mismatch nine",
    crypto.get(
        "semantic_behavior_mismatch_count"
    )
    == 9,
)
check(
    "result all 1138 false",
    crypto.get(
        "all_1138_wycheproof_mldsa_vectors_verified"
    )
    is False,
)
check(
    "result acceptance false",
    crypto.get("stage393_final_acceptance")
    is False,
)


boundary = result.get(
    "adjudication_boundary",
    {},
)

for key in (
    "confirmed_fips204_nonconformance",
    "confirmed_implementation_bug",
    "confirmed_security_vulnerability",
    "secret_key_recovery_demonstrated",
):
    check(
        "result boundary false: " + key,
        boundary.get(key) is False,
    )


nonclaims = result.get(
    "non_claims",
    {},
)

for key in (
    "all_1138_wycheproof_mldsa_vectors_verified",
    "stage393_final_acceptance",
    "formal_external_assessment_completed",
    "formal_certification",
    "system_wide_formal_acceptance",
    "entire_system_quantum_safe",
    "pipeline_completed",
    "system_wide_public_release_allowed",
    "confirmed_fips204_nonconformance",
    "confirmed_implementation_bug",
    "confirmed_security_vulnerability",
):
    check(
        "nonclaim false: " + key,
        nonclaims.get(key) is False,
    )


check(
    "manifest decision",
    manifest.get("decision")
    ==
    "authoritative_stage393_non_acceptance_lineage_reverified",
)
check(
    "manifest historical preserved",
    manifest.get(
        "historical_stage393",
        {},
    ).get("preserved")
    is True,
)
check(
    "manifest historical rewritten false",
    manifest.get(
        "historical_stage393",
        {},
    ).get("rewritten")
    is False,
)
check(
    "manifest Stage392 binding true",
    manifest.get(
        "authoritative_stage392",
        {},
    ).get("binding_verified")
    is True,
)
check(
    "manifest all 1138 false",
    manifest.get(
        "frozen_non_acceptance",
        {},
    ).get(
        "all_1138_wycheproof_mldsa_vectors_verified"
    )
    is False,
)
check(
    "manifest acceptance false",
    manifest.get(
        "frozen_non_acceptance",
        {},
    ).get("stage393_final_acceptance")
    is False,
)


mirror_names = (
    "stage393_authoritative_historical_snapshot.json",
    "stage393_authoritative_historical_snapshot.json.sha256",
    "stage393_authoritative_upstream_binding.json",
    "stage393_authoritative_upstream_binding.json.sha256",
    "stage393_authoritative_non_acceptance_reverification_result.json",
    "stage393_authoritative_non_acceptance_reverification_result.json.sha256",
    "stage393_authoritative_rebind_manifest.json",
    "stage393_authoritative_rebind_manifest.json.sha256",
)

for name in mirror_names:
    check(
        "source/public mirror: " + name,
        (SRC / name).read_bytes()
        == (PUB / name).read_bytes(),
    )


for name in (
    "stage392_authoritative_historical_snapshot.json",
    "stage392_authoritative_historical_snapshot.json.sha256",
    "stage392_authoritative_upstream_binding.json",
    "stage392_authoritative_upstream_binding.json.sha256",
    "stage392_authoritative_reverification_result.json",
    "stage392_authoritative_reverification_result.json.sha256",
    "stage392_authoritative_rebind_manifest.json",
    "stage392_authoritative_rebind_manifest.json.sha256",
):
    check(
        "Stage392 source/public mirror: " + name,
        (
            SRC
            / "upstream-stage392"
            / name
        ).read_bytes()
        ==
        (
            PUB
            / "upstream-stage392"
            / name
        ).read_bytes(),
    )


status_path = (
    PUB
    / "status-authoritative-rebind.html"
)
status_sidecar = (
    PUB
    / "status-authoritative-rebind.html.sha256"
)

check(
    "public status exists",
    status_path.is_file(),
)
check(
    "public status sidecar exists",
    status_sidecar.is_file(),
)

if (
    status_path.is_file()
    and status_sidecar.is_file()
):
    check(
        "public status sidecar matches",
        sidecar_hash(status_sidecar)
        == sha256(status_path),
    )

status = status_path.read_text(
    encoding="utf-8"
)

required_status_text = (
    "All 1138 Wycheproof ML-DSA vectors verified: false",
    "Stage393 final acceptance: false",
    "Cross-implementation mismatches: 9",
    "Semantic behavior differences: 9",
    "Confirmed FIPS 204 nonconformance: false",
    "Confirmed implementation bug: false",
    "Confirmed security vulnerability: false",
    "Stage392 authoritative binding verified: true",
    "New cryptographic execution performed by this rebind: false",
)

for text in required_status_text:
    check(
        "status text: " + text,
        text in status,
    )


private_re = re.compile(
    rb"(?m)^-----BEGIN "
    rb"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?"
    rb"PRIVATE KEY-----\r?$"
)

forbidden_suffixes = (
    ".ots",
    ".tsr",
    ".tsq",
    ".key",
    ".p12",
    ".pfx",
)

for path in PUB.rglob("*"):
    if not path.is_file():
        continue

    check(
        "public forbidden extension: "
        + str(path),
        not path.name.lower().endswith(
            forbidden_suffixes
        ),
    )

    check(
        "public private key marker: "
        + str(path),
        private_re.search(
            path.read_bytes()
        )
        is None,
    )



# BEGIN STAGE393_HARDENED_INVARIANTS_V2

# Bind the historical snapshot to the actual repository ignore
# policy present when the append-only rebind was constructed.
check(
    "snapshot gitignore hash",
    snapshot.get(
        "historical_stage393",
        {},
    ).get(
        "gitignore_sha256"
    )
    == sha256(
        ROOT / ".gitignore"
    ),
)


snapshot_frozen = snapshot.get(
    "frozen_stage393_evidence",
    {},
)

snapshot_frozen_expected = {
    "contract_sha256":
        expected["contract"],
    "diagnostic_manifest_sha256":
        expected["diagnostic_manifest"],
    "summary_sha256":
        expected["summary"],
    "evidence_freeze_manifest_sha256":
        expected["freeze"],
    "result_adjudication_sha256":
        expected["adjudication"],
}

for key, expected_hash in snapshot_frozen_expected.items():
    check(
        "snapshot frozen evidence hash: " + key,
        snapshot_frozen.get(key)
        == expected_hash,
    )


snapshot_hist392 = snapshot.get(
    "historical_stage392_binding",
    {},
)

check(
    "snapshot historical Stage392 commit",
    snapshot_hist392.get("commit")
    == expected["old_stage392_commit"],
)

check(
    "snapshot historical Stage392 preserved",
    snapshot_hist392.get("preserved")
    is True,
)

check(
    "snapshot historical Stage392 rewritten false",
    snapshot_hist392.get("rewritten")
    is False,
)


upstream_hist392 = upstream.get(
    "historical_stage392_binding",
    {},
)

check(
    "upstream historical Stage392 commit",
    upstream_hist392.get("commit")
    == expected["old_stage392_commit"],
)

check(
    "upstream historical Stage392 preserved",
    upstream_hist392.get("preserved")
    is True,
)

check(
    "upstream historical Stage392 rewritten false",
    upstream_hist392.get("rewritten")
    is False,
)


transition = upstream.get(
    "lineage_transition",
    {},
)

check(
    "lineage historical Stage393 rewritten false",
    transition.get(
        "historical_stage393_rewritten"
    )
    is False,
)

check(
    "lineage historical Stage392 rewritten false",
    transition.get(
        "historical_stage392_reference_rewritten"
    )
    is False,
)

check(
    "lineage closed Stage392 authority append-only true",
    transition.get(
        "closed_stage392_authority_added_append_only"
    )
    is True,
)

check(
    "lineage new cryptographic execution required false",
    transition.get(
        "new_cryptographic_execution_required"
    )
    is False,
)


result_auth392 = result.get(
    "authoritative_stage392",
    {},
)

check(
    "result Stage392 commit",
    result_auth392.get("commit")
    == expected["stage392_commit"],
)

check(
    "result Stage392 tree",
    result_auth392.get("tree")
    == expected["stage392_tree"],
)

check(
    "result Stage392 closed true",
    result_auth392.get("closed")
    is True,
)

check(
    "result Stage392 binding verified true",
    result_auth392.get("binding_verified")
    is True,
)

check(
    "result Stage392 result hash",
    result_auth392.get(
        "reverification_result_sha256"
    )
    == expected["stage392_result"],
)

check(
    "result Stage392 manifest hash",
    result_auth392.get(
        "rebind_manifest_sha256"
    )
    == expected["stage392_manifest"],
)


result_frozen = result.get(
    "frozen_evidence_sha256",
    {},
)

result_frozen_expected = {
    "contract":
        expected["contract"],
    "diagnostic_manifest":
        expected["diagnostic_manifest"],
    "summary":
        expected["summary"],
    "evidence_freeze_manifest":
        expected["freeze"],
    "result_adjudication":
        expected["adjudication"],
}

for key, expected_hash in result_frozen_expected.items():
    check(
        "result frozen evidence hash: " + key,
        result_frozen.get(key)
        == expected_hash,
    )


check(
    "result downstream reverification required true",
    result.get(
        "downstream",
        {},
    ).get(
        "reverification_required"
    )
    is True,
)


manifest_artifacts = manifest.get(
    "authoritative_artifacts",
    {},
)

check(
    "manifest snapshot artifact hash",
    manifest_artifacts.get(
        "historical_snapshot_sha256"
    )
    == sha256(snapshot_path),
)

check(
    "manifest upstream artifact hash",
    manifest_artifacts.get(
        "upstream_binding_sha256"
    )
    == sha256(upstream_path),
)

check(
    "manifest result artifact hash",
    manifest_artifacts.get(
        "non_acceptance_reverification_result_sha256"
    )
    == sha256(result_path),
)

check(
    "manifest public status artifact hash",
    manifest_artifacts.get(
        "public_status_sha256"
    )
    == sha256(status_path),
)


manifest_hist393 = manifest.get(
    "historical_stage393",
    {},
)

check(
    "manifest historical Stage393 commit",
    manifest_hist393.get("commit")
    == expected["base_commit"],
)

check(
    "manifest historical Stage393 tree",
    manifest_hist393.get("tree")
    == expected["base_tree"],
)


manifest_auth392 = manifest.get(
    "authoritative_stage392",
    {},
)

check(
    "manifest Stage392 commit",
    manifest_auth392.get("commit")
    == expected["stage392_commit"],
)

check(
    "manifest Stage392 tree",
    manifest_auth392.get("tree")
    == expected["stage392_tree"],
)

check(
    "manifest Stage392 closed true",
    manifest_auth392.get("closed")
    is True,
)


manifest_historical_evidence = manifest.get(
    "historical_evidence",
    {},
)

manifest_historical_expected = {
    "contract_sha256":
        expected["contract"],
    "diagnostic_manifest_sha256":
        expected["diagnostic_manifest"],
    "summary_sha256":
        expected["summary"],
    "evidence_freeze_manifest_sha256":
        expected["freeze"],
    "result_adjudication_sha256":
        expected["adjudication"],
}

for key, expected_hash in manifest_historical_expected.items():
    check(
        "manifest historical evidence hash: " + key,
        manifest_historical_evidence.get(key)
        == expected_hash,
    )


manifest_frozen = manifest.get(
    "frozen_non_acceptance",
    {},
)

check(
    "manifest vector count 1138",
    manifest_frozen.get(
        "wycheproof_vector_count"
    )
    == 1138,
)

check(
    "manifest CIRCL execution 1138",
    manifest_frozen.get(
        "circl_execution_count"
    )
    == 1138,
)

check(
    "manifest OpenSSL execution 1138",
    manifest_frozen.get(
        "openssl_execution_count"
    )
    == 1138,
)

check(
    "manifest total execution 2276",
    manifest_frozen.get(
        "total_cryptographic_execution_count"
    )
    == 2276,
)

check(
    "manifest cross mismatch nine",
    manifest_frozen.get(
        "cross_implementation_mismatch_count"
    )
    == 9,
)

check(
    "manifest semantic mismatch nine",
    manifest_frozen.get(
        "semantic_behavior_mismatch_count"
    )
    == 9,
)


publication = manifest.get(
    "publication_boundary",
    {},
)

check(
    "manifest publication default deny true",
    publication.get("default_deny")
    is True,
)

check(
    "manifest raw test vector private publication false",
    publication.get(
        "raw_test_vector_private_material_publication_allowed"
    )
    is False,
)

check(
    "manifest private material publication false",
    publication.get(
        "private_material_publication_allowed"
    )
    is False,
)

check(
    "manifest secret material publication false",
    publication.get(
        "secret_material_publication_allowed"
    )
    is False,
)

check(
    "manifest raw timestamp publication false",
    publication.get(
        "raw_timestamp_proof_publication_allowed"
    )
    is False,
)


manifest_nonclaims = manifest.get(
    "non_claims",
    {},
)

for key in (
    "formal_external_assessment_completed",
    "formal_certification",
    "system_wide_formal_acceptance",
    "entire_system_quantum_safe",
    "pipeline_completed",
    "system_wide_public_release_allowed",
    "confirmed_fips204_nonconformance",
    "confirmed_implementation_bug",
    "confirmed_security_vulnerability",
):
    check(
        "manifest nonclaim false: " + key,
        manifest_nonclaims.get(key)
        is False,
    )


check(
    "manifest downstream reverification required true",
    manifest.get(
        "downstream",
        {},
    ).get(
        "reverification_required"
    )
    is True,
)

# END STAGE393_HARDENED_INVARIANTS_V2


print(
    "stage393_authoritative_rebind_check_count="
    + str(checks)
)

print(
    "stage393_authoritative_rebind_pass_count="
    + str(checks - len(failures))
)

print(
    "stage393_authoritative_rebind_failure_count="
    + str(len(failures))
)

print(
    "decision="
    + str(result.get("decision"))
)

print(
    "historical_stage393_decision="
    + str(
        result.get(
            "historical_stage393",
            {},
        ).get(
            "diagnostic_decision"
        )
    )
)

print(
    "circl_executed_vector_count="
    + str(
        crypto.get(
            "circl_executed_vector_count"
        )
    )
)

print(
    "openssl_executed_vector_count="
    + str(
        crypto.get(
            "openssl_executed_vector_count"
        )
    )
)

print(
    "cross_implementation_mismatch_count="
    + str(
        crypto.get(
            "cross_implementation_mismatch_count"
        )
    )
)

print(
    "semantic_behavior_mismatch_count="
    + str(
        crypto.get(
            "semantic_behavior_mismatch_count"
        )
    )
)

print(
    "all_1138_wycheproof_mldsa_vectors_verified="
    + str(
        crypto.get(
            "all_1138_wycheproof_mldsa_vectors_verified"
        )
    ).lower()
)

print(
    "stage393_final_acceptance="
    + str(
        crypto.get(
            "stage393_final_acceptance"
        )
    ).lower()
)

print(
    "new_cryptographic_execution_performed="
    + str(
        crypto.get(
            "new_cryptographic_execution_performed"
        )
    ).lower()
)

print(
    "stage392_authoritative_binding_verified="
    + str(
        result.get(
            "authoritative_stage392",
            {},
        ).get(
            "binding_verified"
        )
    ).lower()
)


if failures:
    for name in failures:
        print(
            "FAIL:",
            name,
        )

    raise SystemExit(1)


print(
    "STAGE393_AUTHORITATIVE_REBIND_VERIFICATION=PASS"
)
