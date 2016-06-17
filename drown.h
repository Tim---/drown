#ifndef DROWN_H
#define DROWN_H

#include <openssl/bn.h>

/*
    Global context of the drown search.

    At the beginning, we need to know :
      * c, the ciphertext we are trying to decrypt ;
      * hostport, the address for the oracle to connect, in the form "host:port" ;
      * n, the modulus of the public key ;
      * e, the exponent of the private key ;
*/
typedef struct
{
    char *hostport;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *c;
    BIGNUM *s;
    BIGNUM *mt;
    BN_CTX *ctx;
} drown_ctx;

void drown_new(drown_ctx * dctx);
void drown_free(drown_ctx * dctx);

#define SSL_ASSERT(cond) if(!(cond)) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
#define MY_ASSERT(cond, error) if(!(cond)) { fprintf(stderr, "ERROR : " error "\n"); exit(EXIT_FAILURE); }


#endif
