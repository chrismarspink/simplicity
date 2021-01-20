#ifndef _GZPKI_ECC_H_
#define _GZPKI_ECC_H_


#include <stdio.h>
#include <string.h>

# include <openssl/crypto.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/x509_vfy.h>
# include <openssl/x509v3.h>
# include <openssl/cms.h>
# include <openssl/evp.h>
# include <openssl/ui.h>

# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include <assert.h>
//# include "progs.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

# include "gzpki_types.h"

int GZPKI_do_ECPARAM(GZPKI_CTX *ctx);
//int ecparam_context_free(GZPKI_CTX *ctx);
//int set_eccparam_outfile(GZPKI_CTX *ctx, char *outfile, int outformat);

void print_bignum_var(BIO *out, const BIGNUM *in, const char *var, int len, unsigned char *buffer);
BIO *bio_open_owner(const char *filename, int format, int private);

int print_ecdsa_curves(int comment);
//int init_eccparam_ctx(GZPKI_CTX *ctx);
    

int ECPARAM_set_curve_name(GZPKI_CTX *ctx, char *curve_name);

int GZPKI_do_ECC(GZPKI_CTX *ctx);

int CMM_P1_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, int msg_len, int *ct_size);
int CMM_P1_plaintext_size(const EC_KEY *key, const EVP_MD *digest, int msg_len, int *pt_size);
int CMM_P1_encrypt(const EC_KEY *key, const EVP_MD *digest, unsigned char *msg, int msg_len, unsigned char *ciphertext_buf, int *ciphertext_len);
int CMM_P1_decrypt(const EC_KEY *key, const EVP_MD *digest, const unsigned char *ciphertext, unsigned long ciphertext_len, unsigned char *ptext_buf, int *ptext_len);

int CMM_P2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, int msg_len, int *ct_size);
int CMM_P2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, int msg_len, int *pt_size);
int CMM_P2_encrypt(const EC_KEY *key, const EVP_MD *digest,  unsigned char *msg, int msg_len, unsigned char *ciphertext_buf, int *ciphertext_len);
int CMM_P2_decrypt(const EC_KEY *key, const unsigned char *ciphertext, unsigned long ciphertext_len, unsigned char *ptext_buf, int *ptext_len);

//int CMM_P2_gen_secret(const EC_KEY *key,  char *share_k, char *share_x1, char *share_x2);
int CMM_P2_generate_secret(const EC_KEY *key,  char *share_k, char *share_x1, char *share_x2, char *path, int opt_save);

int CMM_P2_read_secret(char *path, int opt);
int CMM_P2_save_secret(char *path, int opt);

#define CMM_P1_PLAINTEXT_LEN 32768

char sharedK[256];
char sharedX1[256];
char sharedY1[256];

//int TEST_CMM_ENCRYPT_P1();
int CMM_P1_encrypt_file(char *infile, char *certin, char *outfile, int opt_secret) ;
int CMM_P1_decrypt_file(char *infile, char *keyin, char *passin,  char *outfile, int opt_secret) ;

int CMM_P2_encrypt_file(char *infile, char *cert_file, char *outfile, char *x1, char *x2, char *ke, int opt_secret) ; 
int CMM_P2_decrypt_file(char *infile, char *key_file, char *passin,  char *outfile, char *x1, char *x2, char *ke, int opt_secret) ;     
//char sharedK[256];
//char sharedX1[256];
//char sharedY1[256];


#define CMM_P1_SAVE_X1      0
#define CMM_P1_SAVE_Y1      1
#define CMM_P1_SAVE_KE      2
#define CMM_P1_SAVE_X1Y1    3
#define CMM_P1_SAVE_X1Y1KE  4

//#define CMM_P2_INPUT_FILE  1
//#define CMM_P2_ENCRYPT_FILE  1
//#define CMM_P2_ENCRYPT_FILE  1

//NEW API
//TODO: replace pld CMM_P2_xxxx api !
int encrypt_buffer_with_eckey(
    const EC_KEY *key,
    const EVP_MD *digest,
    unsigned char *msg,
    int msg_len, 
    unsigned char *ciphertext_buf, 
    int *ciphertext_len,
    char *ecpk, char *ecpx, char *ecpy, int opt
    );

int decrypt_buffer_with_eckey(const EC_KEY *key, 
    const unsigned char *ciphertext, 
    unsigned long ciphertext_len, 
    unsigned char *ptext_buf, 
    int *ptext_len,
    char *ecpk, char *ecpx, char *ecpy, 
    int opt);

int gzpki_eccp2_generate_secret(char *certfile ,  char *K, char *X, char *Y, unsigned int *size, int opt);
int gzpki_eccp2_save_secret(char *filename, char *value, int len, int opt);

int gzpki_eccp2_read_secret(char *filename, char *secret, unsigned int *datalen, int opt);
int gzpki_eccp2_read_file(char *filename, char *data, unsigned int *datalen, int opt);

int gzpki_eccp2_append_secret_to_certfile(char *filename, char *header, char *value, int len, int opt);
int gzpki_eccp2_read_secret_from_certfile(char *filename, char *header, char *secret, unsigned int *datalen, int opt);



char secretx[128];
char secrety[128];
char secretk[128];


#define ECCP2_HEADER_K "ecp.k"
#define ECCP2_HEADER_X "ecp.x1"
#define ECCP2_HEADER_Y "ecp.y1"

#define ECCP2_HEADER_DELIM ":"

#endif /* _GZPKI_ECC_H_ */
