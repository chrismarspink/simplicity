#ifndef HEADER_LEA_H
#define HEADER_LEA_H

#include <openssl/opensslconf.h>
#include <openssl/evp.h>

#ifdef OPENSSL_NO_LEA
#error LEA is disabled.
#endif

#include <stddef.h>

#define LEA_ENCRYPT	1
#define LEA_DECRYPT	0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define LEA_MAXNR	32
#define LEA_BLOCK_SIZE	16
#define LEA_RK_BSIZE	24
#define LEA_RK_WSIZE	6

#ifdef  __cplusplus
extern "C" {
#endif

/* This should be a hidden type, but EVP requires that the size be known */
struct lea_key_st {
#ifdef LEA_LONG
    unsigned long rd_key[LEA_RK_WSIZE *(LEA_MAXNR + 1)];
#else
    unsigned int rd_key[LEA_RK_WSIZE *(LEA_MAXNR + 1)];
#endif
    int rounds;
};
typedef struct lea_key_st LEA_KEY;

const char *LEA_options(void);

int LEA_set_encrypt_key(const unsigned char *userKey, const int bits,
	LEA_KEY *key);
int LEA_set_decrypt_key(const unsigned char *userKey, const int bits,
	LEA_KEY *key);

int private_LEA_set_encrypt_key(const unsigned char *userKey, const int bits,
	LEA_KEY *key);
int private_LEA_set_decrypt_key(const unsigned char *userKey, const int bits,
	LEA_KEY *key);

void LEA_encrypt(const unsigned char *in, unsigned char *out,
	const LEA_KEY *key);
void LEA_decrypt(const unsigned char *in, unsigned char *out,
	const LEA_KEY *key);

void LEA_ecb_encrypt(const unsigned char *in, unsigned char *out,
	const LEA_KEY *key, const int enc);
void LEA_cbc_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const LEA_KEY *key,
	unsigned char *ivec, const int enc);
void LEA_cfb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const LEA_KEY *key,
	unsigned char *ivec, int *num, const int enc);
void LEA_cfb1_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const LEA_KEY *key,
	unsigned char *ivec, int *num, const int enc);
void LEA_cfb8_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const LEA_KEY *key,
	unsigned char *ivec, int *num, const int enc);
void LEA_ofb128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const LEA_KEY *key,
	unsigned char *ivec, int *num);
void LEA_ctr128_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, const LEA_KEY *key,
	unsigned char ivec[LEA_BLOCK_SIZE],
	unsigned char ecount_buf[LEA_BLOCK_SIZE],
	unsigned int *num);

const EVP_CIPHER *EVP_lea_128_ecb(void);
const EVP_CIPHER *EVP_lea_128_cbc(void);
const EVP_CIPHER *EVP_lea_128_cfb1(void);
const EVP_CIPHER *EVP_lea_128_cfb8(void);
const EVP_CIPHER *EVP_lea_128_cfb(void);
const EVP_CIPHER *EVP_lea_128_ofb(void);
const EVP_CIPHER *EVP_lea_128_ctr(void);
const EVP_CIPHER *EVP_lea_128_ccm(void);
const EVP_CIPHER *EVP_lea_128_gcm(void);

const EVP_CIPHER *EVP_lea_192_ecb(void);
const EVP_CIPHER *EVP_lea_192_cbc(void);
const EVP_CIPHER *EVP_lea_192_cfb1(void);
const EVP_CIPHER *EVP_lea_192_cfb8(void);
const EVP_CIPHER *EVP_lea_192_cfb(void);
const EVP_CIPHER *EVP_lea_192_ofb(void);
const EVP_CIPHER *EVP_lea_192_ctr(void);
const EVP_CIPHER *EVP_lea_192_ccm(void);
const EVP_CIPHER *EVP_lea_192_gcm(void);

const EVP_CIPHER *EVP_lea_256_ecb(void);
const EVP_CIPHER *EVP_lea_256_cbc(void);
const EVP_CIPHER *EVP_lea_256_cfb1(void);
const EVP_CIPHER *EVP_lea_256_cfb8(void);
const EVP_CIPHER *EVP_lea_256_cfb(void);
const EVP_CIPHER *EVP_lea_256_ofb(void);
const EVP_CIPHER *EVP_lea_256_ctr(void);
const EVP_CIPHER *EVP_lea_256_ccm(void);
const EVP_CIPHER *EVP_lea_256_gcm(void);


#ifdef  __cplusplus
}
#endif

#endif /* !HEADER_LEA_H */
