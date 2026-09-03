#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static unsigned char *read_file(
    const char *filename,
    size_t *length)
{
    FILE *fp = NULL;
    long size = 0;
    unsigned char *buffer = NULL;

    fp = fopen(filename, "rb");
    if (fp == NULL)
        return NULL;

    if (fseek(fp, 0, SEEK_END) != 0)
        goto err;

    size = ftell(fp);
    if (size < 0)
        goto err;

    if (fseek(fp, 0, SEEK_SET) != 0)
        goto err;

    buffer = malloc(size == 0 ? 1 : (size_t)size);
    if (buffer == NULL)
        goto err;

    if (size != 0
        && fread(buffer, 1, (size_t)size, fp) != (size_t)size)
        goto err;

    fclose(fp);
    *length = (size_t)size;
    return buffer;

err:
    if (fp != NULL)
        fclose(fp);

    free(buffer);
    return NULL;
}

static void print_errors(void)
{
    unsigned long code;

    while ((code = ERR_get_error()) != 0) {
        const char *reason = ERR_reason_error_string(code);

        printf(
            "OPENSSL_ERROR_REASON=%s\n",
            reason != NULL ? reason : "UNKNOWN"
        );
    }
}

static EVP_PKEY *setup_public_key(
    const char *algorithm,
    const unsigned char *data,
    size_t data_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_PKEY_CTX_new_from_name(
        NULL,
        algorithm,
        NULL
    );

    if (ctx == NULL)
        goto done;

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY,
        (void *)data,
        data_len
    );

    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(
            ctx,
            &pkey,
            EVP_PKEY_PUBLIC_KEY,
            params) <= 0) {

        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *setup_private_key(
    const char *algorithm,
    const unsigned char *data,
    size_t data_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_PKEY_CTX_new_from_name(
        NULL,
        algorithm,
        NULL
    );

    if (ctx == NULL)
        goto done;

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PRIV_KEY,
        (void *)data,
        data_len
    );

    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(
            ctx,
            &pkey,
            EVP_PKEY_KEYPAIR,
            params) <= 0) {

        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static EVP_PKEY *setup_seed_key(
    const char *algorithm,
    const unsigned char *seed,
    size_t seed_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];

    ctx = EVP_PKEY_CTX_new_from_name(
        NULL,
        algorithm,
        NULL
    );

    if (ctx == NULL)
        goto done;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_ML_DSA_SEED,
        (void *)seed,
        seed_len
    );

    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(
            ctx,
            params) <= 0)
        goto done;

    if (EVP_PKEY_generate(
            ctx,
            &pkey) <= 0) {

        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int derive_public(
    EVP_PKEY *pkey,
    unsigned char *output,
    size_t output_size,
    size_t *output_len)
{
    return EVP_PKEY_get_octet_string_param(
        pkey,
        OSSL_PKEY_PARAM_PUB_KEY,
        output,
        output_size,
        output_len
    );
}

static int verify_signature(
    EVP_PKEY *pkey,
    const char *algorithm,
    const unsigned char *input,
    size_t input_len,
    const unsigned char *context,
    size_t context_len,
    const unsigned char *signature,
    size_t signature_len,
    int mu_mode)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *signature_algorithm = NULL;
    OSSL_PARAM params[3];
    OSSL_PARAM *param = params;

    int mu = 1;
    int result = -1;

    ctx = EVP_PKEY_CTX_new_from_pkey(
        NULL,
        pkey,
        NULL
    );

    signature_algorithm = EVP_SIGNATURE_fetch(
        NULL,
        algorithm,
        NULL
    );

    if (ctx == NULL || signature_algorithm == NULL)
        goto done;

    if (mu_mode) {

        *param++ = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MU,
            &mu
        );

    } else {

        *param++ = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            (void *)context,
            context_len
        );
    }

    *param = OSSL_PARAM_construct_end();

    if (EVP_PKEY_verify_message_init(
            ctx,
            signature_algorithm,
            params) <= 0)
        goto done;

    result = EVP_PKEY_verify(
        ctx,
        signature,
        signature_len,
        input,
        input_len
    );

done:
    EVP_SIGNATURE_free(signature_algorithm);
    EVP_PKEY_CTX_free(ctx);

    return result;
}

static int sign_message(
    EVP_PKEY *pkey,
    const char *algorithm,
    const unsigned char *input,
    size_t input_len,
    const unsigned char *context,
    size_t context_len,
    const unsigned char *rnd,
    size_t rnd_len,
    int rnd_present,
    int mu_mode,
    unsigned char **signature,
    size_t *signature_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *signature_algorithm = NULL;

    OSSL_PARAM params[5];
    OSSL_PARAM *param = params;

    int deterministic = 1;
    int mu = 1;

    unsigned char *generated = NULL;
    size_t generated_len = 0;

    int result = 0;

    *signature = NULL;
    *signature_len = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(
        NULL,
        pkey,
        NULL
    );

    signature_algorithm = EVP_SIGNATURE_fetch(
        NULL,
        algorithm,
        NULL
    );

    if (ctx == NULL || signature_algorithm == NULL)
        goto done;

    *param++ = OSSL_PARAM_construct_int(
        OSSL_SIGNATURE_PARAM_DETERMINISTIC,
        &deterministic
    );

    if (rnd_present) {
        *param++ = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
            (void *)rnd,
            rnd_len
        );
    }

    if (mu_mode) {

        *param++ = OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MU,
            &mu
        );

    } else {

        *param++ = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            (void *)context,
            context_len
        );
    }

    *param = OSSL_PARAM_construct_end();

    if (EVP_PKEY_sign_message_init(
            ctx,
            signature_algorithm,
            params) <= 0)
        goto done;

    if (EVP_PKEY_sign(
            ctx,
            NULL,
            &generated_len,
            input,
            input_len) <= 0)
        goto done;

    generated = OPENSSL_zalloc(generated_len);
    if (generated == NULL)
        goto done;

    if (EVP_PKEY_sign(
            ctx,
            generated,
            &generated_len,
            input,
            input_len) <= 0)
        goto done;

    *signature = generated;
    *signature_len = generated_len;

    generated = NULL;
    result = 1;

done:
    OPENSSL_free(generated);
    EVP_SIGNATURE_free(signature_algorithm);
    EVP_PKEY_CTX_free(ctx);

    return result;
}

int main(int argc, char **argv)
{
    const char *algorithm;
    const char *operation;
    const char *key_kind;

    const char *key_filename;
    const char *public_filename;
    const char *input_filename;
    const char *context_filename;
    const char *signature_filename;
    const char *rnd_filename;

    int mu_mode;

    unsigned char *key_data = NULL;
    size_t key_len = 0;

    unsigned char *vector_public = NULL;
    size_t vector_public_len = 0;

    unsigned char *input = NULL;
    size_t input_len = 0;

    unsigned char *context = NULL;
    size_t context_len = 0;

    unsigned char *expected_signature = NULL;
    size_t expected_signature_len = 0;

    unsigned char *rnd = NULL;
    size_t rnd_len = 0;
    int rnd_present = 0;

    EVP_PKEY *pkey = NULL;

    unsigned char derived_public[3000];
    size_t derived_public_len = 0;
    int derived_ok = 0;
    int derived_match = 0;

    unsigned char *generated = NULL;
    size_t generated_len = 0;

    int operation_result = 0;
    int generated_verify = 0;

    int return_code = 1;

    if (argc != 11) {
        fprintf(
            stderr,
            "usage: probe ALG OP KEY_KIND KEY PUB INPUT CTX SIG RND MU\n"
        );

        return 2;
    }

    algorithm = argv[1];
    operation = argv[2];
    key_kind = argv[3];

    key_filename = argv[4];
    public_filename = argv[5];
    input_filename = argv[6];
    context_filename = argv[7];
    signature_filename = argv[8];
    rnd_filename = argv[9];

    mu_mode = strcmp(argv[10], "1") == 0;

    key_data = read_file(
        key_filename,
        &key_len
    );

    if (key_data == NULL)
        goto cleanup;

    if (strcmp(public_filename, "-") != 0) {
        vector_public = read_file(
            public_filename,
            &vector_public_len
        );

        if (vector_public == NULL)
            goto cleanup;
    }

    input = read_file(
        input_filename,
        &input_len
    );

    if (input == NULL)
        goto cleanup;

    if (strcmp(context_filename, "-") != 0) {
        context = read_file(
            context_filename,
            &context_len
        );

        if (context == NULL)
            goto cleanup;
    } else {
        context = malloc(1);

        if (context == NULL)
            goto cleanup;

        context_len = 0;
    }

    expected_signature = read_file(
        signature_filename,
        &expected_signature_len
    );

    if (expected_signature == NULL)
        goto cleanup;

    if (strcmp(rnd_filename, "-") != 0) {
        rnd = read_file(
            rnd_filename,
            &rnd_len
        );

        if (rnd == NULL)
            goto cleanup;

        rnd_present = 1;
    }

    printf("algorithm=%s\n", algorithm);
    printf("operation=%s\n", operation);
    printf("key_kind=%s\n", key_kind);

    printf("key_bytes=%zu\n", key_len);

    printf(
        "public_vector_present=%s\n",
        vector_public != NULL ? "YES" : "NO"
    );

    printf("input_bytes=%zu\n", input_len);
    printf("context_bytes=%zu\n", context_len);

    printf(
        "expected_signature_bytes=%zu\n",
        expected_signature_len
    );

    printf(
        "rnd_present=%s\n",
        rnd_present ? "YES" : "NO"
    );

    printf("rnd_bytes=%zu\n", rnd_len);

    printf(
        "mu_mode=%s\n",
        mu_mode ? "YES" : "NO"
    );

    ERR_clear_error();

    if (strcmp(key_kind, "public") == 0) {

        pkey = setup_public_key(
            algorithm,
            key_data,
            key_len
        );

    } else if (strcmp(key_kind, "private") == 0) {

        pkey = setup_private_key(
            algorithm,
            key_data,
            key_len
        );

    } else if (strcmp(key_kind, "seed") == 0) {

        pkey = setup_seed_key(
            algorithm,
            key_data,
            key_len
        );

    } else {

        fprintf(
            stderr,
            "unsupported key kind\n"
        );

        goto cleanup;
    }

    printf(
        "KEY_SETUP_ACCEPTED=%s\n",
        pkey != NULL ? "YES" : "NO"
    );

    if (pkey == NULL) {
        print_errors();

        printf(
            "OPERATION_ATTEMPTED=NO\n"
        );

        printf(
            "DIAGNOSTIC_COMPLETE=YES\n"
        );

        return_code = 0;
        goto cleanup;
    }

    if (strcmp(operation, "sign") == 0) {

        derived_ok = derive_public(
            pkey,
            derived_public,
            sizeof(derived_public),
            &derived_public_len
        ) > 0;

        printf(
            "PUBLIC_DERIVATION_SUCCESS=%s\n",
            derived_ok ? "YES" : "NO"
        );

        printf(
            "DERIVED_PUBLIC_BYTES=%zu\n",
            derived_ok ? derived_public_len : 0
        );

        if (derived_ok && vector_public != NULL) {
            derived_match =
                derived_public_len == vector_public_len
                &&
                CRYPTO_memcmp(
                    derived_public,
                    vector_public,
                    derived_public_len
                ) == 0;
        }

        printf(
            "DERIVED_PUBLIC_MATCH_VECTOR=%s\n",
            (
                derived_ok
                &&
                vector_public != NULL
                &&
                derived_match
            ) ? "YES" : "NO"
        );

        printf(
            "OPERATION_ATTEMPTED=YES\n"
        );

        ERR_clear_error();

        operation_result = sign_message(
            pkey,
            algorithm,
            input,
            input_len,
            context,
            context_len,
            rnd,
            rnd_len,
            rnd_present,
            mu_mode,
            &generated,
            &generated_len
        );

        printf(
            "SIGN_SUCCESS=%s\n",
            operation_result ? "YES" : "NO"
        );

        if (!operation_result) {
            print_errors();

            printf(
                "SIGNATURE_MATCH_EXPECTED=NO\n"
            );

            printf(
                "GENERATED_VERIFY=NO\n"
            );

            printf(
                "DIAGNOSTIC_COMPLETE=YES\n"
            );

            return_code = 0;
            goto cleanup;
        }

        printf(
            "GENERATED_SIGNATURE_BYTES=%zu\n",
            generated_len
        );

        printf(
            "SIGNATURE_MATCH_EXPECTED=%s\n",
            (
                generated_len == expected_signature_len
                &&
                CRYPTO_memcmp(
                    generated,
                    expected_signature,
                    generated_len
                ) == 0
            ) ? "YES" : "NO"
        );

        generated_verify = verify_signature(
            pkey,
            algorithm,
            input,
            input_len,
            context,
            context_len,
            generated,
            generated_len,
            mu_mode
        );

        printf(
            "GENERATED_VERIFY=%s\n",
            generated_verify == 1 ? "YES" : "NO"
        );

    } else if (strcmp(operation, "verify") == 0) {

        printf(
            "OPERATION_ATTEMPTED=YES\n"
        );

        ERR_clear_error();

        operation_result = verify_signature(
            pkey,
            algorithm,
            input,
            input_len,
            context,
            context_len,
            expected_signature,
            expected_signature_len,
            mu_mode
        );

        printf(
            "VERIFY_ACCEPTED=%s\n",
            operation_result == 1 ? "YES" : "NO"
        );

        if (
            operation_result != 1
            &&
            operation_result != 0
        ) {
            print_errors();
        }

    } else {

        fprintf(
            stderr,
            "unsupported operation\n"
        );

        goto cleanup;
    }

    printf(
        "RAW_PRIVATE_KEY_VALUES_PRINTED=NO\n"
    );

    printf(
        "RAW_SEED_VALUES_PRINTED=NO\n"
    );

    printf(
        "RAW_SIGNATURE_VALUES_PRINTED=NO\n"
    );

    printf(
        "DIAGNOSTIC_COMPLETE=YES\n"
    );

    return_code = 0;

cleanup:

    OPENSSL_free(generated);
    EVP_PKEY_free(pkey);

    if (rnd != NULL) {
        OPENSSL_cleanse(
            rnd,
            rnd_len
        );
    }

    if (key_data != NULL) {
        OPENSSL_cleanse(
            key_data,
            key_len
        );
    }

    free(rnd);
    free(expected_signature);
    free(context);
    free(input);
    free(vector_public);
    free(key_data);

    return return_code;
}
