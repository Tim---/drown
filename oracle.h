#ifndef ORACLE_H
#define ORACLE_H

int run_oracle_guess(char *hostport, unsigned int keysize, unsigned char *encrypted_key, unsigned int encrypted_key_length, unsigned char *result);
int run_oracle_valid_multiple(char *hostport, unsigned char *encrypted_key, unsigned int encrypted_key_length);

#endif
