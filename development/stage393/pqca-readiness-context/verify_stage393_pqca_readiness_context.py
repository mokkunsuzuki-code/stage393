#!/usr/bin/env python3

import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]

SRC = (
    ROOT
    / "development/stage393/pqca-readiness-context"
)

PUB = (
    ROOT
    / "docs/verification/stage393/pqca-readiness-context"
)

AUTH_SRC = (
    ROOT
    / "development/stage393/authoritative-rebind"
)

AUTH_PUB = (
    ROOT
    / "docs/verification/stage393/authoritative-rebind"
)

FULL_CONTRACT = (
    ROOT
    / "development/stage393/"
    "stage393_full_wycheproof_execution_contract.json"
)

README = ROOT / "README.md"
INDEX = ROOT / "docs/index.html"

SELF_SIDECAR = Path(
    str(HERE) + ".sha256"
)

EXPECTED = {
    "closed_commit":
        "5fe905740711b100280ab491ea377529042e89c7",

    "closed_tree":
        "ecc9a7679c10d408829a3a34ba27c9af7bddb1e0",

    "closed_result":
        "ddfad469dcd980f195b5b5042bd9fc5fa2085ed8d974f0f9df80660ae30b1026",

    "closed_manifest":
        "be6dba1f9d2507c5f55ba942ee3dd6d92af30a4f69d1c3fe81ac86800246efcf",

    "closed_status":
        "f20d72079b6623b74407618993e20564898d94a5e6b3343c1ba5cc13028665a1",

    "closed_verifier":
        "1e88d63ed2b00438f7e88ad50d0bb64aa894df2671fe7945325dad44fb8754e1",

    "full_contract":
        "eef3469aea44dbf459a0a04236a751e81d92106c766c55cf46e09b085484da91",

    "prior_readme":
        "16329a6528be493289980c4ba17c2c36a7b10fe66a3940fb976eb76721cf21fc",

    "prior_index":
        "f386a01c7f186985e3d1f96e047d0c6f9a2910c48a092cb2f11c57d228c496bc",

    "wycheproof_commit":
        "dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166",

    "openssl_commit":
        "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f",

    "circl_commit":
        "cfa7c70defd831ffb0792ab2af560bfef43d60ca",
}

JSON_NAMES = (
    "stage393_tool_execution_context.json",
    "stage393_input_contract.json",
    "stage393_output_contract.json",
    "stage393_assumptions_and_scope.json",
    "stage393_cbom_readiness_mapping.json",
    "stage393_concrete_example.json",
    "stage393_pqca_external_review_handoff.json",
)

EXPECTED_SOURCE_FILES = set(
    JSON_NAMES
) | {
    name + ".sha256"
    for name in JSON_NAMES
} | {
    "verify_stage393_pqca_readiness_context.py",
    "verify_stage393_pqca_readiness_context.py.sha256",
}

EXPECTED_PUBLIC_FILES = set(
    JSON_NAMES
) | {
    name + ".sha256"
    for name in JSON_NAMES
} | {
    "index.html",
    "index.html.sha256",
}

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


# Fail-closed package shape and front-door invariants.

actual_source_files = {
    path.relative_to(SRC).as_posix()
    for path in SRC.rglob("*")
    if path.is_file()
}

actual_public_files = {
    path.relative_to(PUB).as_posix()
    for path in PUB.rglob("*")
    if path.is_file()
}

check(
    "exact source context fileset",
    actual_source_files
    == EXPECTED_SOURCE_FILES,
)

check(
    "exact public context fileset",
    actual_public_files
    == EXPECTED_PUBLIC_FILES,
)

check(
    "verifier self sidecar exists",
    SELF_SIDECAR.is_file(),
)

if SELF_SIDECAR.is_file():
    check(
        "verifier self sidecar exact",
        sidecar_hash(SELF_SIDECAR)
        == sha256(HERE),
    )
else:
    check(
        "verifier self sidecar exact",
        False,
    )

readme_text = README.read_text(
    encoding="utf-8"
)

index_text = INDEX.read_text(
    encoding="utf-8"
)

check(
    "README Stage393 start marker exactly once",
    readme_text.count(
        "<!-- STAGE393_PQCA_FRONTDOOR_START -->"
    )
    == 1,
)

check(
    "README Stage393 end marker exactly once",
    readme_text.count(
        "<!-- STAGE393_PQCA_FRONTDOOR_END -->"
    )
    == 1,
)

check(
    "README formal tool role exactly once",
    readme_text.count(
        "Tool role: `verification_and_evidence_binding_layer`"
    )
    == 1,
)

check(
    "README PQCA context URL present",
    "https://mokkunsuzuki-code.github.io/stage393/"
    "verification/stage393/pqca-readiness-context/"
    in readme_text,
)

check(
    "docs index Stage393 start marker exactly once",
    index_text.count(
        "<!-- STAGE393_CURRENT_PAGE_HEADER_START -->"
    )
    == 1,
)

check(
    "docs index Stage393 end marker exactly once",
    index_text.count(
        "<!-- STAGE393_CURRENT_PAGE_HEADER_END -->"
    )
    == 1,
)

check(
    "docs index formal tool role exactly once",
    index_text.count(
        "verification_and_evidence_binding_layer"
    )
    == 1,
)

check(
    "docs index PQCA context link present",
    'href="verification/stage393/'
    'pqca-readiness-context/"'
    in index_text,
)


# Closed authority must remain byte-exact.

check(
    "closed authority result hash",
    sha256(
        AUTH_SRC
        / "stage393_authoritative_non_acceptance_reverification_result.json"
    )
    == EXPECTED["closed_result"],
)

check(
    "closed authority manifest hash",
    sha256(
        AUTH_SRC
        / "stage393_authoritative_rebind_manifest.json"
    )
    == EXPECTED["closed_manifest"],
)

check(
    "closed authority public status hash",
    sha256(
        AUTH_PUB
        / "status-authoritative-rebind.html"
    )
    == EXPECTED["closed_status"],
)

check(
    "closed authority verifier hash",
    sha256(
        AUTH_SRC
        / "verify_stage393_authoritative_rebind.py"
    )
    == EXPECTED["closed_verifier"],
)

check(
    "historical full execution contract hash",
    sha256(FULL_CONTRACT)
    == EXPECTED["full_contract"],
)


# Context artifacts and sidecars.

for name in JSON_NAMES:
    source = SRC / name
    public = PUB / name

    source_sidecar = Path(
        str(source) + ".sha256"
    )

    public_sidecar = Path(
        str(public) + ".sha256"
    )

    check(
        "source exists: " + name,
        source.is_file(),
    )

    check(
        "public exists: " + name,
        public.is_file(),
    )

    check(
        "source sidecar exists: " + name,
        source_sidecar.is_file(),
    )

    check(
        "public sidecar exists: " + name,
        public_sidecar.is_file(),
    )

    if (
        source.is_file()
        and public.is_file()
    ):
        check(
            "source/public exact mirror: " + name,
            source.read_bytes()
            == public.read_bytes(),
        )

    if (
        source.is_file()
        and source_sidecar.is_file()
    ):
        check(
            "source sidecar exact: " + name,
            sidecar_hash(source_sidecar)
            == sha256(source),
        )

    if (
        public.is_file()
        and public_sidecar.is_file()
    ):
        check(
            "public sidecar exact: " + name,
            sidecar_hash(public_sidecar)
            == sha256(public),
        )


tool = load_json(
    SRC
    / "stage393_tool_execution_context.json"
)

input_contract = load_json(
    SRC
    / "stage393_input_contract.json"
)

output_contract = load_json(
    SRC
    / "stage393_output_contract.json"
)

scope = load_json(
    SRC
    / "stage393_assumptions_and_scope.json"
)

mapping = load_json(
    SRC
    / "stage393_cbom_readiness_mapping.json"
)

example = load_json(
    SRC
    / "stage393_concrete_example.json"
)

handoff = load_json(
    SRC
    / "stage393_pqca_external_review_handoff.json"
)


# Tool role.

role = tool.get(
    "tool_role",
    {}
)

check(
    "tool role verification layer",
    role.get("primary_role")
    == "verification_and_evidence_binding_layer",
)

check(
    "tool is not inventory scanner",
    role.get("is_inventory_scanner")
    is False,
)

check(
    "tool is not cbom generator",
    role.get("is_cbom_generator")
    is False,
)

check(
    "tool is not readiness tracker",
    role.get("is_package_readiness_tracker")
    is False,
)

check(
    "tool is not certification",
    role.get("is_formal_certification_system")
    is False,
)

check(
    "tool may consume CBOM",
    role.get(
        "may_consume_inventory_or_cbom_metadata"
    )
    is True,
)

runners = tool.get(
    "intended_runners",
    []
)

runner_types = {
    item.get("runner_type")
    for item in runners
}

for expected_runner in (
    "developer_local",
    "ci",
    "independent_reviewer",
):
    check(
        "runner present: " + expected_runner,
        expected_runner in runner_types,
    )

phases = tool.get(
    "execution_phases",
    []
)

check(
    "execution phase count nine",
    len(phases) == 9,
)

check(
    "new crypto false in context",
    tool.get(
        "current_stage393_mode",
        {},
    ).get(
        "current_context_addition_performs_new_cryptographic_execution"
    )
    is False,
)

tool_nonclaims = tool.get(
    "non_claims",
    {},
)

for key in (
    "pqca_endorsement",
    "pqca_adoption",
    "formal_external_assessment_completed",
    "formal_certification",
    "entire_system_quantum_safe",
):
    check(
        "tool nonclaim false: " + key,
        tool_nonclaims.get(key)
        is False,
    )


# Input contract.

required_groups = input_contract.get(
    "required_input_groups",
    {}
)

for group in (
    "target_identity",
    "claim",
    "cryptographic_scope",
    "implementation_identity",
    "evidence_identity",
    "execution_profile",
    "environment",
):
    check(
        "input group present: " + group,
        group in required_groups,
    )

check(
    "unknown values explicit",
    input_contract.get(
        "unknown_value_policy",
        {},
    ).get(
        "silent_guessing_allowed"
    )
    is False,
)

check(
    "optional unknown allowed",
    input_contract.get(
        "unknown_value_policy",
        {},
    ).get(
        "unknown_values_allowed"
    )
    is True,
)

private_policy = input_contract.get(
    "private_input_policy",
    {},
)

for key in (
    "raw_private_key_publication_allowed",
    "credentials_publication_allowed",
    "sensitive_environment_secret_publication_allowed",
):
    check(
        "input private policy false: " + key,
        private_policy.get(key)
        is False,
    )


# Output contract.

output_groups = output_contract.get(
    "required_output_groups",
    {}
)

for group in (
    "schema_and_tool",
    "run_identity",
    "target",
    "claim",
    "cryptographic_scope",
    "implementation_bindings",
    "evidence_bindings",
    "environment",
    "execution_result",
    "comparison_result",
    "decision",
    "scope_and_assumptions",
    "non_claims",
):
    check(
        "output group present: " + group,
        group in output_groups,
    )

relationship = output_contract.get(
    "readiness_tracker_relationship",
    {},
)

check(
    "not universal classification",
    relationship.get(
        "output_is_itself_a_universal_readiness_classification"
    )
    is False,
)

check(
    "can support tracker",
    relationship.get(
        "output_can_support_a_readiness_tracker_record"
    )
    is True,
)

check(
    "tracker retains classification policy",
    relationship.get(
        "tracker_remains_responsible_for_its_own_classification_policy"
    )
    is True,
)


# Scope and assumptions.

limitations = scope.get(
    "known_limitations",
    []
)

check(
    "known limitations nonempty",
    len(limitations) >= 5,
)

assumptions = scope.get(
    "assumptions",
    {}
)

for key in (
    "hash_function",
    "source_revision",
    "implementation_version",
    "environment",
    "test_vectors",
    "cross_implementation_agreement",
    "cross_implementation_disagreement",
):
    check(
        "assumption present: " + key,
        bool(assumptions.get(key)),
    )


# CBOM mapping.

relationship = mapping.get(
    "relationship",
    {},
)

check(
    "QSP does not replace CBOM",
    relationship.get(
        "qsp_replaces_cbom"
    )
    is False,
)

check(
    "QSP does not generate CBOM",
    relationship.get(
        "qsp_generates_cbom"
    )
    is False,
)

check(
    "QSP does not require one CBOM schema",
    relationship.get(
        "qsp_requires_one_specific_cbom_schema"
    )
    is False,
)

check(
    "QSP can consume CBOM metadata",
    relationship.get(
        "qsp_can_consume_cbom_or_inventory_metadata"
    )
    is True,
)

compat = mapping.get(
    "loose_classification_compatibility",
    {},
)

check(
    "no fixed universal taxonomy",
    compat.get(
        "fixed_universal_package_taxonomy_required"
    )
    is False,
)

check(
    "minimal reproducibility contract required",
    compat.get(
        "minimal_reproducibility_contract_required"
    )
    is True,
)

check(
    "tracker-specific metadata allowed",
    compat.get(
        "tracker_specific_metadata_allowed"
    )
    is True,
)


# Concrete Stage393 example.

prior = example.get(
    "prior_closed_authority",
    {},
)

check(
    "example closed commit",
    prior.get("commit")
    == EXPECTED["closed_commit"],
)

check(
    "example closed tree",
    prior.get("tree")
    == EXPECTED["closed_tree"],
)

check(
    "example closed result hash",
    prior.get("result_sha256")
    == EXPECTED["closed_result"],
)

inputs = example.get(
    "inputs",
    {}
)

wycheproof = inputs.get(
    "wycheproof",
    {}
)

check(
    "example Wycheproof commit",
    wycheproof.get("commit")
    == EXPECTED["wycheproof_commit"],
)

check(
    "example vector files nine",
    wycheproof.get("vector_file_count")
    == 9,
)

check(
    "example vectors 1138",
    wycheproof.get("target_vector_count")
    == 1138,
)

impls = {
    item.get("name"):
        item.get("commit")
    for item in inputs.get(
        "implementations",
        []
    )
}

check(
    "example OpenSSL commit",
    impls.get("OpenSSL")
    == EXPECTED["openssl_commit"],
)

check(
    "example CIRCL commit",
    impls.get("Cloudflare CIRCL")
    == EXPECTED["circl_commit"],
)

check(
    "example contract hash",
    inputs.get(
        "execution_contract_sha256"
    )
    == EXPECTED["full_contract"],
)

execution = example.get(
    "execution",
    {}
)

check(
    "example CIRCL 1138",
    execution.get(
        "circl_executed_vector_count"
    )
    == 1138,
)

check(
    "example OpenSSL 1138",
    execution.get(
        "openssl_executed_vector_count"
    )
    == 1138,
)

check(
    "example total 2276",
    execution.get(
        "total_cryptographic_execution_count"
    )
    == 2276,
)

for key in (
    "circl_runtime_error_count",
    "openssl_runtime_error_count",
    "circl_skipped_vector_count",
    "openssl_skipped_vector_count",
    "circl_unsupported_vector_count",
    "openssl_unsupported_vector_count",
):
    check(
        "example zero: " + key,
        execution.get(key)
        == 0,
    )

comparison = example.get(
    "comparison",
    {}
)

expected_counts = {
    "circl_wycheproof_mismatch_count": 6,
    "openssl_wycheproof_mismatch_count": 3,
    "cross_implementation_mismatch_count": 9,
    "semantic_behavior_mismatch_count": 9,
    "signature_byte_mismatch_count": 0,
    "verification_mismatch_count": 0,
    "key_derivation_mismatch_count": 0,
    "unclassified_cross_mismatch_count": 0,
}

for key, value in expected_counts.items():
    check(
        "example comparison: " + key,
        comparison.get(key)
        == value,
    )

decision = example.get(
    "decision",
    {}
)

check(
    "example all 1138 false",
    decision.get(
        "all_1138_wycheproof_mldsa_vectors_verified"
    )
    is False,
)

check(
    "example final acceptance false",
    decision.get(
        "stage393_final_acceptance"
    )
    is False,
)

boundary = example.get(
    "adjudication_boundary",
    {}
)

for key in (
    "confirmed_fips204_nonconformance",
    "confirmed_implementation_bug",
    "confirmed_security_vulnerability",
    "secret_key_recovery_demonstrated",
):
    check(
        "example boundary false: " + key,
        boundary.get(key)
        is False,
    )

check(
    "example context new crypto false",
    example.get(
        "new_cryptographic_execution_performed_by_context_package"
    )
    is False,
)


# External review handoff.

discussion = handoff.get(
    "external_discussion",
    {}
)

check(
    "handoff repository",
    discussion.get(
        "working_group_repository"
    )
    == "PQCA/wg-readiness-tracking",
)

check(
    "handoff issue 41",
    discussion.get("issue")
    == 41,
)

questions = handoff.get(
    "questions_this_package_is_designed_to_answer",
    []
)

check(
    "handoff question mapping six",
    len(questions) == 6,
)

requested = handoff.get(
    "requested_external_feedback",
    []
)

check(
    "external feedback questions nonempty",
    len(requested) >= 5,
)

preservation = handoff.get(
    "historical_authority_preservation",
    {},
)

check(
    "handoff closed commit",
    preservation.get(
        "prior_closed_stage393_commit"
    )
    == EXPECTED["closed_commit"],
)

check(
    "handoff historical rewrite false",
    preservation.get(
        "cryptographic_result_rewritten"
    )
    is False,
)

check(
    "handoff new crypto false",
    preservation.get(
        "new_cryptographic_execution_performed"
    )
    is False,
)

frontdoor = handoff.get(
    "frontdoor_before_completion",
    {},
)

check(
    "handoff prior README hash",
    frontdoor.get(
        "readme_sha256"
    )
    == EXPECTED["prior_readme"],
)

check(
    "handoff prior index hash",
    frontdoor.get(
        "docs_index_sha256"
    )
    == EXPECTED["prior_index"],
)

for key in (
    "pqca_endorsement",
    "pqca_acceptance",
    "pqca_adoption",
    "external_assessment_completed",
    "formal_certification",
):
    check(
        "handoff nonclaim false: " + key,
        handoff.get(
            "non_claims",
            {},
        ).get(key)
        is False,
    )


# Public HTML.

html = (
    PUB
    / "index.html"
)

html_sidecar = Path(
    str(html) + ".sha256"
)

check(
    "public review HTML exists",
    html.is_file(),
)

check(
    "public review HTML sidecar exists",
    html_sidecar.is_file(),
)

if (
    html.is_file()
    and html_sidecar.is_file()
):
    check(
        "public review HTML sidecar",
        sidecar_hash(html_sidecar)
        == sha256(html),
    )

    html_text = html.read_text(
        encoding="utf-8"
    )

    for text in (
        "Who runs it?",
        "What are the inputs?",
        "How does execution work?",
        "What are the outputs?",
        "Concrete Stage393 example",
        "CBOM / readiness relationship",
        "What feedback would be useful?",
        "Stage393 final acceptance: <strong>false</strong>",
        "Cross-implementation mismatches: <strong>9</strong>",
        "does not claim PQCA endorsement",
    ):
        check(
            "HTML text: " + text,
            text in html_text,
        )


# Publication safety.

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
        "no forbidden public extension: "
        + str(path),
        not path.name.lower().endswith(
            forbidden_suffixes
        ),
    )

    check(
        "no private key marker: "
        + str(path),
        private_re.search(
            path.read_bytes()
        )
        is None,
    )


print(
    "stage393_pqca_context_check_count="
    + str(checks)
)

print(
    "stage393_pqca_context_pass_count="
    + str(checks - len(failures))
)

print(
    "stage393_pqca_context_failure_count="
    + str(len(failures))
)

print(
    "prior_closed_stage393_commit="
    + EXPECTED["closed_commit"]
)

print(
    "tool_role="
    + str(
        role.get(
            "primary_role"
        )
    )
)

print(
    "example_circl_executed_vector_count="
    + str(
        execution.get(
            "circl_executed_vector_count"
        )
    )
)

print(
    "example_openssl_executed_vector_count="
    + str(
        execution.get(
            "openssl_executed_vector_count"
        )
    )
)

print(
    "example_cross_implementation_mismatch_count="
    + str(
        comparison.get(
            "cross_implementation_mismatch_count"
        )
    )
)

print(
    "example_stage393_final_acceptance="
    + str(
        decision.get(
            "stage393_final_acceptance"
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
    "STAGE393_PQCA_READINESS_CONTEXT_VERIFICATION=PASS"
)
