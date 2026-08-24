#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static unsigned char *
read_file(
    const char *path,
    size_t *length
)
{
    FILE *fp = NULL;
    long size = 0;
    unsigned char *buffer = NULL;

    fp = fopen(
        path,
        "rb"
    );

    if (fp == NULL) {
        return NULL;
    }

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
        )
        != (size_t) size
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
emit(
    const char *classification,
    int accepted,
    int internal_exit
)
{
    printf(
        "implementation = OpenSSL\n"
    );

    printf(
        "algorithm = ML-DSA-65\n"
    );

    printf(
        "classification = %s\n",
        classification
    );

    printf(
        "accepted = %s\n",
        accepted
            ? "true"
            : "false"
    );

    printf(
        "adapter_internal_exit = %d\n",
        internal_exit
    );

    return internal_exit;
}


int main(
    int argc,
    char **argv
)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *sigalg = NULL;

    unsigned char *message = NULL;
    unsigned char *signature = NULL;
    unsigned char *context = NULL;

    size_t message_length = 0;
    size_t signature_length = 0;
    size_t context_length = 0;

    OSSL_PARAM params[2];

    int init_result = 0;
    int verify_result = 0;
    int rc = 20;

    if (argc != 5) {
        fprintf(
            stderr,
            "usage: %s public-key.der message.bin signature.bin context.bin\n",
            argv[0]
        );

        return emit(
            "adapter_execution_error",
            0,
            20
        );
    }

    bio = BIO_new_file(
        argv[1],
        "rb"
    );

    if (bio == NULL) {
        return emit(
            "adapter_execution_error",
            0,
            20
        );
    }

    pkey = d2i_PUBKEY_bio(
        bio,
        NULL
    );

    BIO_free(
        bio
    );

    if (pkey == NULL) {
        return emit(
            "public_key_parse_reject",
            0,
            2
        );
    }

    message = read_file(
        argv[2],
        &message_length
    );

    signature = read_file(
        argv[3],
        &signature_length
    );

    context = read_file(
        argv[4],
        &context_length
    );

    if (
        message == NULL
        ||
        signature == NULL
        ||
        context == NULL
    ) {
        rc = emit(
            "adapter_execution_error",
            0,
            20
        );
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(
        NULL,
        pkey,
        NULL
    );

    sigalg = EVP_SIGNATURE_fetch(
        NULL,
        "ML-DSA-65",
        NULL
    );

    if (
        ctx == NULL
        ||
        sigalg == NULL
    ) {
        rc = emit(
            "adapter_execution_error",
            0,
            20
        );
        goto cleanup;
    }

    params[0] =
        OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
            context,
            context_length
        );

    params[1] =
        OSSL_PARAM_construct_end();

    init_result =
        EVP_PKEY_verify_message_init(
            ctx,
            sigalg,
            params
        );

    if (init_result <= 0) {
        rc = emit(
            "context_parameter_reject",
            0,
            3
        );
        goto cleanup;
    }

    verify_result =
        EVP_PKEY_verify(
            ctx,
            signature,
            signature_length,
            message,
            message_length
        );

    if (verify_result == 1) {
        rc = emit(
            "accept",
            1,
            0
        );
    } else if (verify_result == 0) {
        rc = emit(
            "cryptographic_reject",
            0,
            1
        );
    } else {
        rc = emit(
            "adapter_execution_error",
            0,
            20
        );
    }

cleanup:

    EVP_SIGNATURE_free(
        sigalg
    );

    EVP_PKEY_CTX_free(
        ctx
    );

    EVP_PKEY_free(
        pkey
    );

    free(message);
    free(signature);
    free(context);

    return rc;
}
