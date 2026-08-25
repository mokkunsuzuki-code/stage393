#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path


STAGE = 393
SOURCE_STAGE = 392
ALGORITHM = "ML-DSA-65"

EXPECTED_FILES = {
    "public-key.raw",
    "message.bin",
    "context.bin",
    "signature.bin",
}


def fail(message):
    print("FAIL:", message)
    raise SystemExit(1)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_path(path):
    return sha256_bytes(
        path.read_bytes()
    )


def run_command(command, cwd=None, env=None):
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if result.stdout:
        print(
            result.stdout,
            end=""
            if result.stdout.endswith("\n")
            else "\n",
        )

    if result.stderr:
        print(
            result.stderr,
            end=""
            if result.stderr.endswith("\n")
            else "\n",
        )

    if result.returncode != 0:
        fail(
            "command failed: "
            + " ".join(
                str(x)
                for x in command
            )
        )

    return result


def load_contract(repo_root):
    stage393 = (
        repo_root
        / "development"
        / "stage393"
    )

    contract_path = (
        stage393
        / "stage393_executable_contract.json"
    )

    sha_path = (
        stage393
        / "stage393_executable_contract.sha256"
    )

    if not contract_path.is_file():
        fail(
            "Stage393 contract missing"
        )

    if not sha_path.is_file():
        fail(
            "Stage393 contract SHA-256 record missing"
        )

    recorded = (
        sha_path.read_text(
            encoding="utf-8"
        )
        .strip()
        .split()[0]
    )

    actual = sha256_path(
        contract_path
    )

    if actual != recorded:
        fail(
            "Stage393 contract hash mismatch"
        )

    data = json.loads(
        contract_path.read_text(
            encoding="utf-8"
        )
    )

    if data.get("stage") != STAGE:
        fail(
            "contract stage mismatch"
        )

    if (
        data.get("source_stage")
        != SOURCE_STAGE
    ):
        fail(
            "contract source-stage mismatch"
        )

    if (
        data.get("algorithm")
        != ALGORITHM
    ):
        fail(
            "contract algorithm mismatch"
        )

    return data, actual


def make_writable_directory(path):
    mode = path.stat().st_mode

    path.chmod(
        mode
        | stat.S_IWUSR
    )


def verify_exact_output_files(path):
    actual = {
        p.name
        for p in path.iterdir()
        if p.is_file()
    }

    if actual != EXPECTED_FILES:
        fail(
            "unexpected temporary public artifact set: "
            + repr(
                sorted(actual)
            )
        )


def derive_fixture_fingerprints(contract):
    fixture = contract[
        "canonical_test_fixture"
    ]

    seed_label = fixture[
        "test_seed_derivation_label"
    ].encode("utf-8")

    fixed_label = fixture[
        "fixed_randomness_derivation_label"
    ].encode("utf-8")

    raw_seed = hashlib.sha256(
        seed_label
    ).digest()

    raw_fixed_randomness = (
        hashlib.sha256(
            fixed_label
        ).digest()
    )

    return {
        "test_seed":
            sha256_bytes(
                raw_seed
            ),

        "fixed_randomness":
            sha256_bytes(
                raw_fixed_randomness
            ),
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Execute QSP Stage393 deterministic "
            "ML-DSA-65 fixed-randomness signing "
            "and OpenSSL/CIRCL cross-verification."
        )
    )

    parser.add_argument(
        "--circl-source",
        required=True,
        help=(
            "Path to fixed Cloudflare CIRCL "
            "v1.6.5 source tree"
        ),
    )

    parser.add_argument(
        "--openssl-verifier",
        required=True,
        help=(
            "Path to compiled Stage393 "
            "OpenSSL verifier"
        ),
    )

    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Path for deterministic "
            "Stage393 execution result JSON"
        ),
    )

    args = parser.parse_args()

    repo_root = (
        Path(__file__)
        .resolve()
        .parents[2]
    )

    stage393 = (
        repo_root
        / "development"
        / "stage393"
    )

    harness_source = (
        stage393
        / "stage393_circl_fixedrnd_harness_test.go"
    )

    circl_source = Path(
        args.circl_source
    ).resolve()

    openssl_verifier = Path(
        args.openssl_verifier
    ).resolve()

    output_path = Path(
        args.output
    ).resolve()

    if not harness_source.is_file():
        fail(
            "Stage393 CIRCL harness missing"
        )

    if not circl_source.is_dir():
        fail(
            "CIRCL source tree missing"
        )

    if not openssl_verifier.is_file():
        fail(
            "OpenSSL verifier missing"
        )

    contract, contract_sha256 = (
        load_contract(
            repo_root
        )
    )

    fixture = contract[
        "canonical_test_fixture"
    ]

    expected_hashes = fixture[
        "expected_sha256"
    ]

    derived = (
        derive_fixture_fingerprints(
            contract
        )
    )

    if (
        derived["test_seed"]
        != expected_hashes[
            "test_seed"
        ]
    ):
        fail(
            "test-seed fingerprint mismatch"
        )

    if (
        derived["fixed_randomness"]
        != expected_hashes[
            "fixed_randomness"
        ]
    ):
        fail(
            "fixed-randomness fingerprint mismatch"
        )

    with tempfile.TemporaryDirectory(
        prefix="qsp-stage393-execution-"
    ) as temporary:
        temp_root = Path(
            temporary
        )

        circl_copy = (
            temp_root
            / "circl"
        )

        run_one = (
            temp_root
            / "run1"
        )

        run_two = (
            temp_root
            / "run2"
        )

        shutil.copytree(
            circl_source,
            circl_copy,
        )

        package_dir = (
            circl_copy
            / "sign"
            / "mldsa"
            / "mldsa65"
        )

        if not package_dir.is_dir():
            fail(
                "unexpected CIRCL source layout"
            )

        make_writable_directory(
            package_dir
        )

        harness_target = (
            package_dir
            / "stage393_fixedrnd_harness_test.go"
        )

        shutil.copyfile(
            harness_source,
            harness_target,
        )

        outputs = []

        for index, destination in (
            (1, run_one),
            (2, run_two),
        ):
            destination.mkdir(
                mode=0o700
            )

            env = os.environ.copy()

            env[
                "STAGE393_OUTPUT_DIR"
            ] = str(destination)

            result = run_command(
                [
                    "go",
                    "test",
                    "./sign/mldsa/mldsa65",
                    "-run",
                    (
                        "^TestStage393"
                        "DeterministicFixedRandomness$"
                    ),
                    "-count=1",
                    "-v",
                ],
                cwd=circl_copy,
                env=env,
            )

            required_markers = [
                (
                    "repeat_signature_"
                    "byte_equality = true"
                ),
                "circl_public_verify = true",
                "private_key_persisted = false",
                "raw_test_seed_persisted = false",
                (
                    "raw_fixed_randomness_"
                    "persisted = false"
                ),
            ]

            for marker in required_markers:
                if marker not in result.stdout:
                    fail(
                        "CIRCL harness marker missing: "
                        + marker
                    )

            verify_exact_output_files(
                destination
            )

            outputs.append(
                destination
            )

        for name in sorted(
            EXPECTED_FILES
        ):
            first = (
                run_one
                / name
            ).read_bytes()

            second = (
                run_two
                / name
            ).read_bytes()

            if first != second:
                fail(
                    "cross-execution mismatch: "
                    + name
                )

        public_key = (
            run_one
            / "public-key.raw"
        ).read_bytes()

        message = (
            run_one
            / "message.bin"
        ).read_bytes()

        context = (
            run_one
            / "context.bin"
        ).read_bytes()

        signature = (
            run_one
            / "signature.bin"
        ).read_bytes()

        observed_hashes = {
            "public_key":
                sha256_bytes(
                    public_key
                ),

            "signature":
                sha256_bytes(
                    signature
                ),

            "message":
                sha256_bytes(
                    message
                ),

            "context":
                sha256_bytes(
                    context
                ),

            "test_seed":
                derived[
                    "test_seed"
                ],

            "fixed_randomness":
                derived[
                    "fixed_randomness"
                ],
        }

        for name, expected in (
            expected_hashes.items()
        ):
            observed = (
                observed_hashes.get(
                    name
                )
            )

            if observed != expected:
                fail(
                    "canonical hash mismatch: "
                    + name
                )

        if (
            len(public_key)
            != fixture[
                "raw_public_key_size"
            ]
        ):
            fail(
                "raw public-key size mismatch"
            )

        if (
            len(signature)
            != fixture[
                "signature_size"
            ]
        ):
            fail(
                "signature size mismatch"
            )

        openssl_results = []

        for destination in outputs:
            result = run_command(
                [
                    str(
                        openssl_verifier
                    ),
                    str(
                        destination
                        / "public-key.raw"
                    ),
                    str(
                        destination
                        / "message.bin"
                    ),
                    str(
                        destination
                        / "context.bin"
                    ),
                    str(
                        destination
                        / "signature.bin"
                    ),
                ]
            )

            if (
                "openssl_mldsa65_verified = true"
                not in result.stdout
            ):
                fail(
                    "OpenSSL verification marker missing"
                )

            openssl_results.append(
                True
            )

        result = {
            "schema":
                (
                    "qsp.stage393."
                    "deterministic-fixed-randomness-"
                    "execution.v1"
                ),

            "stage":
                STAGE,

            "source_stage":
                SOURCE_STAGE,

            "algorithm":
                ALGORITHM,

            "contract_revision":
                contract.get(
                    "contract_revision"
                ),

            "contract_sha256":
                contract_sha256,

            "fixture_classification":
                fixture[
                    "classification"
                ],

            "circl_version":
                fixture[
                    "circl_version"
                ],

            "execution": {
                "separate_execution_count":
                    2,

                "cross_execution_public_key_byte_equality":
                    True,

                "cross_execution_signature_byte_equality":
                    True,

                "repeat_signature_byte_equality":
                    True,

                "circl_public_verification":
                    True,

                "openssl_verification_run1":
                    openssl_results[0],

                "openssl_verification_run2":
                    openssl_results[1],
            },

            "artifact_sizes": {
                "raw_public_key":
                    len(
                        public_key
                    ),

                "signature":
                    len(
                        signature
                    ),

                "message":
                    len(
                        message
                    ),

                "context":
                    len(
                        context
                    ),
            },

            "canonical_sha256":
                observed_hashes,

            "safety_boundary": {
                "production_key_material":
                    False,

                "private_key_persisted":
                    False,

                "raw_test_seed_persisted":
                    False,

                "raw_fixed_randomness_persisted":
                    False,

                "external_mu_tested":
                    False,

                "openssl_fixed_randomness_signing":
                    False,
            },

            "decision":
                (
                    "mldsa65_deterministic_"
                    "fixed_randomness_"
                    "cross_implementation_verified"
                ),
        }

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path.write_text(
            json.dumps(
                result,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    print(
        "PASS: Stage393 deterministic execution complete"
    )

    print(
        "decision =",
        result[
            "decision"
        ],
    )


if __name__ == "__main__":
    main()
