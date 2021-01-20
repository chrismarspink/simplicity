#include <openssl/lea.h>
#include "lea_locl.h"

/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter) {
	unsigned int n=16;
	unsigned char c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

void ctr128_inc_aligned(unsigned char *counter) {
	unsigned int *data,c,n;
	const union { long one; char little; } is_endian = {1};

	if (is_endian.little) {
		ctr128_inc(counter);
		return;
	}

	data = (unsigned int *)counter;
	n = 16/sizeof(unsigned int);
	do {
		--n;
		c = data[n];
		++c;
		data[n] = c;
		if (c) return;
	} while (n);
}

void LEA_ctr128_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const LEA_KEY *key,
			unsigned char ivec[LEA_BLOCK_SIZE],
			unsigned char ecount_buf[LEA_BLOCK_SIZE],
			unsigned int *num) {
	unsigned char block[128];
	unsigned int remainBlock = length >> 4;

	if (out == NULL)
		return;
	else if(in == NULL)
		return;
	else if(length == 0)
		return;
	else if(ivec == NULL)
		return;
	else if(key == NULL)
		return;

#if 0 //jkkim def COMPILE_AVX2
	if (AVX2_CAPABLE){
		for(;remainBlock>=8; remainBlock-=8, in += 0x80, out += 0x80){
			CPY8x16(block, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x10, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x20, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x30, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x40, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x50, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x60, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x70, ivec);
			ctr128_inc_aligned(ivec);

			lea_encrypt_8block_avx2(block, block, key);

			XOR8x128(out, block, in);
		}
	}
#endif
#if 0 //jkkim def COMPILE_XOP
	if (XOP_CAPABLE){
		_lea_ctr_enc_xop(out, in, remainBlock << 4 | length & 0xf, ivec, key);
		return;
	}
#endif
#if 0//jkkim def COMPILE_SSE2
	if (SSE2_CAPABLE){
		for (; remainBlock >= 4; remainBlock -= 4, in += 0x40, out += 0x40){
			CPY8x16(block, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x10, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x20, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x30, ivec);
			ctr128_inc_aligned(ivec);

			lea_encrypt_4block_sse2(block, block, key);

			XOR8x64(out, block, in);
		}
	}
#endif

#if 0 //jkkim def COMPILE_NEON
	if (NEON_CAPABLE){
		for (; remainBlock >= 4; remainBlock -= 4, in += 0x40, out += 0x40){
			CPY8x16(block, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x10, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x20, ivec);
			ctr128_inc_aligned(ivec);

			CPY8x16(block + 0x30, ivec);
			ctr128_inc_aligned(ivec);

			lea_encrypt_4block_neon(block, block, key);

			XOR8x64(out, block, in);
		}
	}
#endif
	
	for (; remainBlock >= 1; remainBlock -= 1, in += 0x10, out += 0x10){
		LEA_encrypt(ivec, block, key);
		
		XOR8x16(out, block, in);

		ctr128_inc_aligned(ivec);
	}

	if(length & 0xf)
	{
		unsigned int i;
		LEA_encrypt(ivec, block, key);

		for(i = 0; i < (length & 0xf); i++)
			out[i] = block[i] ^ in[i];
	}


}