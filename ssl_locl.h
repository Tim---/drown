#ifndef SSL_LOCL_H
#define SSL_LOCL_H

// Some functions and macros that are local to libssl and we shouldn't be using...

#define TWO_BYTE_BIT    0x80
#define TWO_BYTE_MASK   0x7fff
#define THREE_BYTE_MASK 0x3fff

#define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                          c[1]=(unsigned char)(((s)    )&0xff)),c+=2)
#define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)


int ssl_cipher_list_to_bytes(SSL *s,STACK_OF(SSL_CIPHER) *sk,unsigned char *p,
                             int (*put_cb)(const SSL_CIPHER *, unsigned char *));

int ssl_cipher_get_evp(const SSL_SESSION *s,const EVP_CIPHER **enc,
                       const EVP_MD **md,int *mac_pkey_type,int *mac_secret_size, SSL_COMP **comp);

int ssl2_enc_init(SSL *s, int client);

int ssl2_enc(SSL *s,int send_data);

void ssl2_mac(SSL *s,unsigned char *mac,int send_data);

int     ssl2_new(SSL *s);

int ssl_get_new_session(SSL *s, int session);

const SSL_METHOD *SSLv2_method(void);

#endif
