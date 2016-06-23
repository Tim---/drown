#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "utils.h"

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

void read_public_key(drown_ctx * dctx, char *filename)
{
    // Read file
    FILE * fp = fopen(filename, "r");
    MY_ASSERT(fp != NULL, "can't open certificate file");

    // Read cert
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    MY_ASSERT(cert != NULL, "file is not a certificate");

    // Read public key
    EVP_PKEY * pkey = X509_get_pubkey(cert);
    MY_ASSERT(pkey != NULL, "can't get public key from certificate");

    // Check RSA key
    MY_ASSERT(pkey->type == EVP_PKEY_RSA, "public key is not RSA");
    MY_ASSERT(EVP_PKEY_bits(pkey) == 2048, "only RSA-2048 is supported for now");

    // Read RSA key
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);

    // Copy the public key
    BN_copy(dctx->n, rsa->n);
    BN_copy(dctx->e, rsa->e);

    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    fclose(fp);
}

int pkcs1_v1_5_unpad(BIGNUM *src, BIGNUM *dst)
{
    unsigned char srcbin[256] = {0};
    BN_bn2bin(src, srcbin + 256 - BN_num_bytes(src));
    int i;

    if(srcbin[i++] != 0)
        return -1;
    if(srcbin[i++] != 2)
        return -1;
    while(srcbin[i])
    {
        i++;
        if(i >= 256)
            return -1;
    }
    i++;
    BN_bin2bn(&srcbin[i], 256 - i, dst);
    return 256 - i;
}

void print_hexbuf(const unsigned char *buffer, long len)
{
    char hexdigits[] = "0123456789abcdef";
    for(int i = 0; i < len; i++)
    {
        int nib1 = buffer[i] >> 4;
        int nib2 = buffer[i] & 15;
        printf("%c%c", hexdigits[nib1], hexdigits[nib2]);
    }
}

void dump_wireshark(char *c_hex, BIGNUM *mt)
{
    // Now PCKS#1 v1.5 unpad the message
    unsigned char bin[256] = {0};
    BN_bn2bin(mt, bin + 256 - BN_num_bytes(mt));
    MY_ASSERT(bin[0] == 0, "decrypted message is not properly padded");
    MY_ASSERT(bin[1] == 2, "decrypted message is not properly padded");
    int i = 2;
    while(bin[i])
    {
        i++;
        MY_ASSERT(i < 256, "decrypted message is not properly padded");
    }
    i++;

    // We can now print the unpadded message
    // (in Wireshark format)
    printf("RSA ");
    printf("%.16s ", c_hex);
    print_hexbuf(&bin[i], 256-i);
    printf("\n");
}
