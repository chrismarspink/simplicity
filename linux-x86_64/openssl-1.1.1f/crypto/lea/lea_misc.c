#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/lea.h>
#include "lea_locl.h"

//const char LEA_version[]="LEA" OPENSSL_VERSION_PTEXT;
//const char LEA_version[]="LEA" OPENSSL_VERSION_TEXT;
const char LEA_version[]="LEA 0.0.1";

const char *LEA_options(void) {
#ifdef FULL_UNROLL
        return "lea(full)";
#else   
        return "lea(partial)";
#endif
}

int LEA_set_encrypt_key(const unsigned char *userKey, const int bits,
			LEA_KEY *key)
	{

	return private_LEA_set_encrypt_key(userKey, bits, key);
	}

int LEA_set_decrypt_key(const unsigned char *userKey, const int bits,
			LEA_KEY *key)
	{

	return private_LEA_set_decrypt_key(userKey, bits, key);
	}
