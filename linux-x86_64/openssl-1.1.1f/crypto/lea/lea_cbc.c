#include <openssl/lea.h>

//#include "lea_locl.h"
#include <openssl/lea_locl.h>

#if 0 //jkkim fdef COMPILE_XOP
static void LEA_encrypt_xop(const unsigned char *in, unsigned char *out, const LEA_KEY *key){
	lea_encrypt_1blocks_xop(out, in, 1, key);
}
#endif

void LEA_cbc_encrypt(const unsigned char *in, unsigned char *out,
		     size_t len, const LEA_KEY *key,
		     unsigned char *ivec, const int enc) {
	if (enc)
	{
#if 0 //jkkim 
def COMPILE_XOP
		if (XOP_CAPABLE){
			CRYPTO_cbc128_encrypt(in,out,len,key,ivec,(block128_f)LEA_encrypt_xop);
			//Finished
			return;
		}
#endif
		CRYPTO_cbc128_encrypt(in,out,len,key,ivec,(block128_f)LEA_encrypt);
		return;
	}

	unsigned int remainBlock = len >> 4;
	const unsigned char *pIv = ivec;
	unsigned char tmp[128];// = {0, };

	if(out == NULL)
		return;
	else if(out == NULL)
		return;
	else if((len == 0) || (len & 0xf))
		return;
	else if(ivec == NULL)
		return;
	else if(key == NULL)
		return;

	out += len;
	in += len;

#if 0//jkkim
#ifdef COMPILE_AVX2
if(AVX2_CAPABLE){
		while (remainBlock > 8){
			out -= 0x80;
			in -= 0x80;

			lea_decrypt_8block_avx2(tmp, in, key);
			XOR8x128r(out, tmp, in - 16);

			remainBlock -= 8;
		}
	}
#endif
#ifdef COMPILE_XOP
	if (XOP_CAPABLE){
		while (remainBlock > 4){
			out -= 0x40;
			in -= 0x40;

			lea_decrypt_4block_xop(tmp, in, key);
			XOR8x64r(out, tmp, in - 16);

			remainBlock -= 4;
		}
	} else //XOP or SSE2!
#endif
#ifdef COMPILE_SSE2
	if (SSE2_CAPABLE){
		while (remainBlock > 4){
			out -= 0x40;
			in -= 0x40;

			lea_decrypt_4block_sse2(tmp, in, key);
			XOR8x64r(out, tmp, in - 16);

			remainBlock -= 4;
		}
	}
#endif
	{} // Empty block when ( XOP && !SSE2 ). See last line of COMPILE_XOP block.

#ifdef COMPILE_NEON
	if (NEON_CAPABLE){
		while (remainBlock > 4){
			out -= 0x40;
			in -= 0x40;

			lea_decrypt_4block_neon(tmp, in, key);
			XOR8x64r(out, tmp, in - 16);

			remainBlock -= 4;
		}
	}
#endif
#endif //jkkim-- end
	while (remainBlock > 1){ // > 1, not >= 1.
		out -= 0x10;
		in -= 0x10;
		pIv = in - 16;

		LEA_decrypt(in, out, key);

		XOR8x16(out, out, pIv);

		remainBlock -= 1;
	}
	
	out -= 0x10;
	in -= 0x10;
	LEA_decrypt(in, out, key);

	XOR8x16(out, out, ivec);

}