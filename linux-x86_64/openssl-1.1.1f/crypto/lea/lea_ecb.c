#ifndef LEA_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

#include <openssl/lea.h>
#include "lea_locl.h"

void LEA_ecb_encrypt(const unsigned char *in, unsigned char *out,
		     const LEA_KEY *key, const int enc) {

        assert(in && out && key);
	assert((LEA_ENCRYPT == enc)||(LEA_DECRYPT == enc));

	if (LEA_ENCRYPT == enc)
		LEA_encrypt(in, out, key);
	else
		LEA_decrypt(in, out, key);
}

