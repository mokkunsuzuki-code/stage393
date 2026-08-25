#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <stdio.h>
#include <stdlib.h>

static unsigned char *
read_file(
    const char *path,
    size_t *length
)
{
    FILE *fp = NULL;
    long size = 0;
    unsigned char *buffer = NULL;

    fp = fopen(path, "rb");

    if (fp == NULL)
        return NULL;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    size = ftell(fp);

    if (size < 0) {
        fclose(fp);
        return NULL;
    }

    rewind(fp);

    buffer = malloc(
        size == 0
            ? 1
            : (size_t) size
    );

    if (buffer == NULL) {
        fclose(fp);
        return NULL;
    }

    if (
        size > 0
        &&
        fread(
            buffer,
            1,
            (size_t) size,
            fp
        ) != (size_t) size
    ) {
        free(buffer);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    *length = (size_t) size;

    return buffer;
}

static int
fail(
    const char *message
)
{
    fprintf(
        stderr,
        "FAIL: %s\n",
        message
    );

    return 1;
}

int
main(
    int argc,
    char **argv
)
{
    unsigned char *public_key = NULL;
    unsigned char *message = NULL;
    unsigned char *context = NULL;
    unsigned char *signature = NULL;

    size_t public_key_length = 0;
    size_t message_length = 0;
    size_t context_length = 0;
    size_t signature_length = 0;

    EVP_PKEY_CTX *import_ctx = NULL;
    EVP_PKEY_CTX *verify_ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sigalg = NULL;

    OSSL_PARAM import_params[2];
    OSSL_PARAM verify_params[2];

    int verify_result = 0;
    int rc = 1;

    if (argc != 5)
        return fail(
            "expected public-key.raw message.bin context.bin signature.bin"
        );

    public_key =
        read_file(
            argv[1],
            &public_key_length
        );

    message =
        read_file(
            argv[2],
            &message_length
        );

    context =
        read_file(
            argv[3],
            &context_length
        );

    signature =
        read_file(
            argv[4],
            &signature_length
        );

    if (
        public_key == NULL
        ||
        message == NULL
        ||
        context == NULL
        ||
        signature == NULL
    ) {
        rc = fail(
            "input read failed"
        );
        goto cleanup;
    }

    if (public_key_length != 1952) {
        rc = fail(
            "ML-DSA-65 raw public-key size mismatch"
        );
        goto cleanup;
    }

    if (signature_length != 3309) {
        rc = fail(
            "ML-DSA-65 signature size mismatch"
        );
        goto cleanup;
    }

    import_ctx =
        EVP_PKEY_CTX_new_from_name(
            NULL,
            "ML-DSA-65",
            NULL
        );

    if (import_ctx == NULL) {
        rc = fail(
            "EVP_PKEY_CTX_new_from_name failed"
        );
        goto cleanup;
    }

    if (
        EVP_PKEY_fromdata_init(
            import_ctx
        ) <= 0
    ) {
        rc = fail(
            "EVP_PKEY_fromdata_init failed"
        );
        goto cleanup;
    }

    import_params[0] =
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            public_key,
            public_key_length
        );

    import_params[1] =
        OSSL_PARAM_construct_end();

    if (
        EVP_PKEY_fromdata(
            import_ctx,
            &pkey,
            EVP_PKEY_PUBLIC_KEY,
            import_params
        ) <= 0
    ) {
        rc = fail(
            "raw ML-DSA-65 public-key import failed"
        );
        goto cleanup;
    }

    if (
        pkey == NULL
        ||
        !EVP_PKEY_is_a(
            pkey,
            "ML-DSA-65"
        )
    ) {
        rc = fail(
            "imported key algorithm mismatch"
        );
        goto cleanup;
    }

    verify_ctx =
        EVP_PKEY_CTX_new_from_pkey(
            NULL,
            pkey,
            NULL
        );

    sigalg =
        EVP_SIGNATURE_fetch(
            NULL,
            "ML-DSA-65",
            NULL
        );

    if (
        verify_ctx == NULL
        ||
        sigalg == NULL
    ) {
        rc = fail(
            "verification context creation failed"
        );
        goto cleanup;
    }

    verify_params[0] =
        OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            context,
            context_length
        );

    verify_params[1] =
        OSSL_PARAM_construct_end();

    if (
        EVP_PKEY_verify_message_init(
            verify_ctx,
            sigalg,
            verify_params
        ) <= 0
    ) {
        rc = fail(
            "EVP_PKEY_verify_message_init failed"
        );
        goto cleanup;
    }

    verify_result =
        EVP_PKEY_verify(
            verify_ctx,
            signature,
            signature_length,
            message,
            message_length
        );

    if (verify_result != 1) {
        rc = fail(
            "OpenSSL rejected Stage393 signature"
        );
        goto cleanup;
    }

    printf(
        "implementation = OpenSSL\n"
    );

    printf(
        "algorithm = ML-DSA-65\n"
    );

    printf(
        "raw_public_key_size = %zu\n",
        public_key_length
    );

    printf(
        "signature_size = %zu\n",
        signature_length
    );

    printf(
        "raw_public_key_import = true\n"
    );

    printf(
        "openssl_mldsa65_verified = true\n"
    );

    printf(
        "PASS: OpenSSL independently verified Stage393 ML-DSA-65 signature\n"
    );

    rc = 0;

cleanup:

    EVP_SIGNATURE_free(
        sigalg
    );

    EVP_PKEY_CTX_free(
        verify_ctx
    );

    EVP_PKEY_free(
        pkey
    );

    EVP_PKEY_CTX_free(
        import_ctx
    );

    free(signature);
    free(context);
    free(message);
    free(public_key);

    return rc;
}
