#include "internal/cryptlib.h"
# include <openssl/evp.h>
# include <openssl/modes.h>
# include <openssl/rand.h>
# include <openssl/rand_drbg.h>
# include <openssl/lea.h>
# include "crypto/evp.h"
# include "crypto/modes/modes_local.h"
# include "evp_local.h"


//typedef unsigned char u8;
//typedef unsigned long u64;
//ypedef __uint128_t u128;


typedef struct
	{
	LEA_KEY ks;
	block128_f block;
	union {
		cbc128_f cbc;
		ctr128_f ctr;
	} stream;
	} EVP_LEA_KEY;

typedef struct
	{
	LEA_KEY ks;		/* LEA key schedule to use */
	int key_set;		/* Set if key initialised */
	int iv_set;		/* Set if an iv is set */
	int tag_set;		/* Set if tag is valid */
	int len_set;		/* Set if message length set */
	int L, M;		/* L and M parameters from RFC3610 */
	CCM128_CONTEXT ccm;
	ccm128_f str;
	} EVP_LEA_CCM_CTX;

typedef struct
	{
	LEA_KEY ks;		/* LEA key schedule to use */
	int key_set;		/* Set if key initialised */
	int iv_set;		/* Set if an iv is set */
	GCM128_CONTEXT gcm;
	unsigned char *iv;	/* Temporary IV store */
	int ivlen;		/* IV length */
	int taglen;
	int iv_gen;		/* It is OK to generate IVs */
	int tls_aad_len;	/* TLS AAD length */
	ctr128_f ctr;
	} EVP_LEA_GCM_CTX;


#define BLOCK_CIPHER_generic(nid,keylen,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER lea_##keylen##_##mode = { \
	nid##_##keylen##_##nmode,blocksize,keylen/8,ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	lea_init_key,			\
	lea_##mode##_cipher,		\
	NULL,				\
	sizeof(EVP_LEA_KEY),		\
	NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_lea_##keylen##_##mode(void) \
{ return &lea_##keylen##_##mode; }

#define BLOCK_CIPHER_generic_pack(nid,keylen,flags)		\
	BLOCK_CIPHER_generic(nid,keylen,16,16,cbc,cbc,CBC,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb1,cfb1,CFB,flags)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,cfb8,cfb8,CFB,flags)	\
	BLOCK_CIPHER_generic(nid,keylen,1,16,ctr,ctr,CTR,flags)

#define BLOCK_CIPHER_custom(nid,keylen,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER lea_##keylen##_##mode = { \
	nid##_##keylen##_##mode,blocksize, \
	(EVP_CIPH_##MODE##_MODE==EVP_CIPH_XTS_MODE?2:1)*keylen/8, ivlen, \
	flags|EVP_CIPH_##MODE##_MODE,	\
	lea_##mode##_init_key,		\
	lea_##mode##_cipher,		\
	lea_##mode##_cleanup,		\
	sizeof(EVP_LEA_##MODE##_CTX),	\
	NULL,NULL,lea_##mode##_ctrl,NULL }; \
const EVP_CIPHER *EVP_lea_##keylen##_##mode(void) \
{ return &lea_##keylen##_##mode; }

#define CUSTOM_FLAGS	(EVP_CIPH_FLAG_DEFAULT_ASN1 \
		| EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
		| EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
		| EVP_CIPH_CUSTOM_COPY)

#define MAXBITCHUNK	((size_t)1<<(sizeof(size_t)*8-4))

#if 0 //jkkim def COMPILE_XOP
static void LEA_encrypt_xop(const unsigned char *in, unsigned char *out, const LEA_KEY *key){
	lea_encrypt_1blocks_xop(out, in, 1, key);
}
#endif

static int lea_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		   const unsigned char *iv, int enc)
	{
	int ret, mode;
	EVP_LEA_KEY *dat = (EVP_LEA_KEY *)ctx->cipher_data;
	mode = ctx->cipher->flags & EVP_CIPH_MODE;
	if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE)
	    && !enc)
		{
		ret = LEA_set_decrypt_key(key,ctx->key_len*8,&dat->ks);
		dat->block	= (block128_f)LEA_decrypt;
		dat->stream.cbc	= mode==EVP_CIPH_CBC_MODE ?
					(cbc128_f)LEA_cbc_encrypt :
					NULL;
		}
	else
		{
		#if 0 //def COMPILE_XOP
		if(XOP_CAPABLE)
			{
			lea_set_key_xop(&dat->ks,key,ctx->key_len*8);
			dat->block	= (block128_f)LEA_encrypt_xop;
			ret = 0;
			
			}
		else
		#endif
			{
			ret = LEA_set_encrypt_key(key,ctx->key_len*8,&dat->ks);
			dat->block	= (block128_f)LEA_encrypt;
			}
		dat->stream.cbc	= mode==EVP_CIPH_CBC_MODE ?
					(cbc128_f)LEA_cbc_encrypt :
					NULL;
		
		}
	if(ret < 0)
		{
		/*kkim@
		XXXEVPerrXXX(XXEVP_F_AES_INIT_KEY,XXEVP_R_AES_KEY_SETUP_FAILED);
		*/
		return 0;
		}

	return 1;
	}

static int lea_cbc_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in, size_t len)
{
	EVP_LEA_KEY *dat = (EVP_LEA_KEY *)ctx->cipher_data;

	if(len & 0xf)
		return 0;
	else
		LEA_cbc_encrypt(in, out, len, &dat->ks, ctx->iv, ctx->encrypt);

	return 1;
}

static void lea_ecb_enc(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, const LEA_KEY *key)
{
	unsigned int remainBlock = pt_len >> 4;

	if (ct == NULL)
		return;
	else if (pt == NULL)
		return;
	else if ((pt_len == 0) || (pt_len & 0xf))
		return;
	else if (key == NULL)
		return;
#if 0 //jkkim ----- def COMPILE_AVX2
	if (AVX2_CAPABLE){
		for (; remainBlock >= 8; remainBlock -= 8, pt += 0x80, ct += 0x80){
			lea_encrypt_8block_avx2(ct, pt, key);
		}
	}
#endif

#if 0 //jkkim@ defined(COMPILE_XOP)
	if (XOP_CAPABLE){
		for (; remainBlock >= 4; remainBlock -= 4, pt += 0x40, ct += 0x40){
			lea_encrypt_4block_xop(ct, pt, key);
		}

		lea_encrypt_1blocks_xop(ct, pt, remainBlock, key);
		//Finished
		return;
	}
#endif
#if 0 //jkkim@ defined(COMPILE_SSE2)
	if (SSE2_CAPABLE){
		for (; remainBlock >= 4; remainBlock -= 4, pt += 0x40, ct += 0x40){
			lea_encrypt_4block_sse2(ct, pt, key);
		}
	}
#endif
#if 0 //jkkim  defined(COMPILE_NEON)
	if (NEON_CAPABLE){
		for (; remainBlock >= 4; remainBlock -= 4, pt += 0x40, ct += 0x40){
			lea_encrypt_4block_neon(ct, pt, key);
		}
	}
#endif
	for (; remainBlock >= 1; remainBlock -= 1, pt += 0x10, ct += 0x10){
		LEA_encrypt(pt, ct, key);
	}
}

static void lea_ecb_dec(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, const LEA_KEY *key)
{
	unsigned int remainBlock = ct_len >> 4;

	if (ct == NULL)
		return;
	else if (pt == NULL)
		return;
	else if ((ct_len == 0) || (ct_len & 0xf))
		return;
	else if (key == NULL)
		return;

#if 0 //jkkim
#ifdef COMPILE_AVX2
	if (AVX2_CAPABLE){
		for (; remainBlock >= 8; remainBlock -= 8, pt += 0x80, ct += 0x80){
			lea_decrypt_8block_avx2(pt, ct, key);
		}
	}
#endif
#if defined(COMPILE_XOP)
	if (XOP_CAPABLE){
		for (; remainBlock >= 4; remainBlock -= 4, pt += 0x40, ct += 0x40){
			lea_decrypt_4block_xop(pt, ct, key);
		}
	}
#endif
#if defined(COMPILE_SSE2)
	if (SSE2_CAPABLE){
		for (; remainBlock >= 4; remainBlock -= 4, pt += 0x40, ct += 0x40){
			lea_decrypt_4block_sse2(pt, ct, key);
		}
	}
#endif
#if defined(COMPILE_NEON)
	if (NEON_CAPABLE){
		for (; remainBlock >= 4; remainBlock -= 4, pt += 0x40, ct += 0x40){
			lea_decrypt_4block_neon(pt, ct, key);
		}
	}
#endif
#endif //jkkim
	for (; remainBlock >= 1; remainBlock -= 1, pt += 0x10, ct += 0x10){
		LEA_decrypt(ct, pt, key);
	}

}

static int lea_ecb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in, size_t len)
{
	EVP_LEA_KEY *dat = (EVP_LEA_KEY *)ctx->cipher_data;
	
	if(ctx->encrypt)
		lea_ecb_enc(out, in, len, &dat->ks);
	else
		lea_ecb_dec(out, in, len, &dat->ks);

	return 1;
}

static int lea_ofb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	EVP_LEA_KEY *dat = (EVP_LEA_KEY *)ctx->cipher_data;

	CRYPTO_ofb128_encrypt(in,out,len,&dat->ks,
			ctx->iv,&ctx->num,dat->block);
	return 1;
}

static int lea_cfb_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	EVP_LEA_KEY *dat = (EVP_LEA_KEY *)ctx->cipher_data;

	CRYPTO_cfb128_encrypt(in,out,len,&dat->ks,
			ctx->iv,&ctx->num,ctx->encrypt,dat->block);
	return 1;
}

static int lea_cfb8_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	EVP_LEA_KEY *dat = (EVP_LEA_KEY *)ctx->cipher_data;

	CRYPTO_cfb128_8_encrypt(in,out,len,&dat->ks,
			ctx->iv,&ctx->num,ctx->encrypt,dat->block);
	return 1;
}

static int lea_cfb1_cipher(EVP_CIPHER_CTX *ctx,unsigned char *out,
	const unsigned char *in,size_t len)
{
	EVP_LEA_KEY *dat = (EVP_LEA_KEY *)ctx->cipher_data;

	if (ctx->flags&EVP_CIPH_FLAG_LENGTH_BITS) {
		CRYPTO_cfb128_1_encrypt(in,out,len,&dat->ks,
			ctx->iv,&ctx->num,ctx->encrypt,dat->block);
		return 1;
	}

	while (len>=MAXBITCHUNK) {
		CRYPTO_cfb128_1_encrypt(in,out,MAXBITCHUNK*8,&dat->ks,
			ctx->iv,&ctx->num,ctx->encrypt,dat->block);
		len-=MAXBITCHUNK;
	}
	if (len)
		CRYPTO_cfb128_1_encrypt(in,out,len*8,&dat->ks,
			ctx->iv,&ctx->num,ctx->encrypt,dat->block);
	
	return 1;
}

static int lea_ctr_cipher (EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
{
	unsigned int num = ctx->num;
	EVP_LEA_KEY *dat = (EVP_LEA_KEY *)ctx->cipher_data;
	
	if(len < 0)
		return 0;
	else
		LEA_ctr128_encrypt(in, out, len, &dat->ks, ctx->iv, ctx->buf, &num);
	
	ctx->num = (size_t)num;
	return 1;
}

BLOCK_CIPHER_generic_pack(NID_lea,128,EVP_CIPH_FLAG_NON_FIPS_ALLOW)
BLOCK_CIPHER_generic_pack(NID_lea,192,EVP_CIPH_FLAG_NON_FIPS_ALLOW)
BLOCK_CIPHER_generic_pack(NID_lea,256,EVP_CIPH_FLAG_NON_FIPS_ALLOW)



static void ctr64_inc(unsigned char *counter) {
	unsigned int n=8;
	u8  c;

	counter += 8;
	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

int LEA_ccm128_encrypt(CCM128_CONTEXT *ctx,
	const unsigned char *inp, unsigned char *out,
	size_t len)
{
	size_t		n;
	unsigned int	i,L;
	unsigned char	flags0	= ctx->nonce.c[0];
	block128_f	block	= ctx->block;
	void *		key	= ctx->key;
#if 0 //jkkim def COMPILE_AVX2
	union { u64 u[16]; u8 c[128]; } scratch;
//jkkim#elif defined(COMPILE_SSE2) || defined(COMPILE_NEON) || defined(COMPILE_XOP)
//jkkim	union { u64 u[8]; u8 c[64]; } scratch;
#else
	union { u64 u[2]; u8 c[16]; } scratch;
#endif

#if 0 //jkkim defined(COMPILE_SSE2) || defined(COMPILE_NEON) || defined(COMPILE_XOP)
	void (*lea_encrypt_4block)(unsigned char*,const unsigned char*,const LEA_KEY*) = NULL;
#endif

	if (!(flags0&0x40))
		(*block)(ctx->nonce.c,ctx->cmac.c,key),
		ctx->blocks++;

	ctx->nonce.c[0] = L = flags0&7;
	for (n=0,i=15-L;i<15;++i) {
		n |= ctx->nonce.c[i];
		ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	if (n!=len) return -1;	/* length mismatch */

	ctx->blocks += ((len+15)>>3)|1;
	if (ctx->blocks > (U64(1)<<61))	return -2; /* too much data */

	//	encrypt 8block
#if 0 //jkkim def COMPILE_AVX2
	if(AVX2_CAPABLE){
		while(len >= 128)
		{
#if defined(STRICT_ALIGNMENT)
			union { u64 u[16]; u8 c[128]; } temp;

			memcpy (temp.c,inp,64); 
			for(i = 0; i < 8; i++)
			{
				ctx->cmac.u[0] ^= temp.u[(i << 1) + 0];
				ctx->cmac.u[1] ^= temp.u[(i << 1) + 1];
			
				(*block)(ctx->cmac.c,ctx->cmac.c,key);
			}
			
			memcpy(scratch.c, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 16, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 32, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 48, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 64, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 80, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 96, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 112, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			
			lea_encrypt_8block_avx2(scratch.c, scratch.c, key);
			
			temp.u[0] ^= scratch.u[0];
			temp.u[1] ^= scratch.u[1];
			temp.u[2] ^= scratch.u[2];
			temp.u[3] ^= scratch.u[3];
			temp.u[4] ^= scratch.u[4];
			temp.u[5] ^= scratch.u[5];
			temp.u[6] ^= scratch.u[6];
			temp.u[7] ^= scratch.u[7];
			temp.u[8] ^= scratch.u[8];
			temp.u[9] ^= scratch.u[9];
			temp.u[10] ^= scratch.u[10];
			temp.u[11] ^= scratch.u[11];
			temp.u[12] ^= scratch.u[12];
			temp.u[13] ^= scratch.u[13];
			temp.u[14] ^= scratch.u[14];
			temp.u[15] ^= scratch.u[15];
			memcpy(out,temp.c,128);
#else
			for(i = 0; i < 8; i++)
			{
				ctx->cmac.u[0] ^= ((u64*)inp)[(i << 1) + 0];
				ctx->cmac.u[1] ^= ((u64*)inp)[(i << 1) + 1];
			
				(*block)(ctx->cmac.c,ctx->cmac.c,key);
			}
			
			memcpy(scratch.c, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 16, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 32, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 48, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 64, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 80, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 96, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 112, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			
			lea_encrypt_8block_avx2(scratch.c, scratch.c, key);
			
			((u64*)out)[0] = scratch.u[0]^((u64*)inp)[0];
			((u64*)out)[1] = scratch.u[1]^((u64*)inp)[1];
			((u64*)out)[2] = scratch.u[2]^((u64*)inp)[2];
			((u64*)out)[3] = scratch.u[3]^((u64*)inp)[3];
			((u64*)out)[4] = scratch.u[4]^((u64*)inp)[4];
			((u64*)out)[5] = scratch.u[5]^((u64*)inp)[5];
			((u64*)out)[6] = scratch.u[6]^((u64*)inp)[6];
			((u64*)out)[7] = scratch.u[7]^((u64*)inp)[7];
			((u64*)out)[8] = scratch.u[8]^((u64*)inp)[8];
			((u64*)out)[9] = scratch.u[9]^((u64*)inp)[9];
			((u64*)out)[10] = scratch.u[10]^((u64*)inp)[10];
			((u64*)out)[11] = scratch.u[11]^((u64*)inp)[11];
			((u64*)out)[12] = scratch.u[12]^((u64*)inp)[12];
			((u64*)out)[13] = scratch.u[13]^((u64*)inp)[13];
			((u64*)out)[14] = scratch.u[14]^((u64*)inp)[14];
			((u64*)out)[15] = scratch.u[15]^((u64*)inp)[15];
#endif
			inp += 128;
			out += 128;
			len -= 128;
		}
	}
#endif	//#ifdef COMPILE_AVX2
	
	//	encrypt 4block
#if 0 // defined(COMPILE_XOP) || defined(COMPILE_SSE2) || defined(COMPILE_NEON)
	if(len >= 64){
#ifdef COMPILE_XOP
		if(XOP_CAPABLE){
			lea_encrypt_4block = lea_encrypt_4block_xop;
		} else 
#endif
#ifdef COMPILE_SSE2
		if(SSE2_CAPABLE){
			lea_encrypt_4block = lea_encrypt_4block_sse2;
		} else
#endif
#ifdef COMPILE_NEON
		if(NEON_CAPABLE){
			lea_encrypt_4block = lea_encrypt_4block_neon;
		} else
#endif
		{}
	
		if(lea_encrypt_4block){
			while(len >= 64)
			{
#if defined(STRICT_ALIGNMENT)
				union { u64 u[8]; u8 c[64]; } temp;

				memcpy (temp.c,inp,64); 
				for(i = 0; i < 4; i++)
				{
					ctx->cmac.u[0] ^= temp.u[(i << 1) + 0];
					ctx->cmac.u[1] ^= temp.u[(i << 1) + 1];
				
					(*block)(ctx->cmac.c,ctx->cmac.c,key);
				}
				
				memcpy(scratch.c, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 16, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 32, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 48, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				
				lea_encrypt_4block(scratch.c, scratch.c, key);
				
				//out[0] = inp.u[0] ^ scratch.u[0];
				temp.u[0] ^= scratch.u[0];
				temp.u[1] ^= scratch.u[1];
				temp.u[2] ^= scratch.u[2];
				temp.u[3] ^= scratch.u[3];
				temp.u[4] ^= scratch.u[4];
				temp.u[5] ^= scratch.u[5];
				temp.u[6] ^= scratch.u[6];
				temp.u[7] ^= scratch.u[7];
				memcpy(out,temp.c,64);
#else
				for(i = 0; i < 4; i++)
				{
					ctx->cmac.u[0] ^= ((u64*)inp)[(i << 1) + 0];
					ctx->cmac.u[1] ^= ((u64*)inp)[(i << 1) + 1];
				
					(*block)(ctx->cmac.c,ctx->cmac.c,key);
				}
				
				memcpy(scratch.c, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 16, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 32, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 48, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				
				lea_encrypt_4block(scratch.c, scratch.c, key);
				
				((u64*)out)[0] = scratch.u[0]^((u64*)inp)[0];
				((u64*)out)[1] = scratch.u[1]^((u64*)inp)[1];
				((u64*)out)[2] = scratch.u[2]^((u64*)inp)[2];
				((u64*)out)[3] = scratch.u[3]^((u64*)inp)[3];
				((u64*)out)[4] = scratch.u[4]^((u64*)inp)[4];
				((u64*)out)[5] = scratch.u[5]^((u64*)inp)[5];
				((u64*)out)[6] = scratch.u[6]^((u64*)inp)[6];
				((u64*)out)[7] = scratch.u[7]^((u64*)inp)[7];
#endif
				inp += 64;
				out += 64;
				len -= 64;
			}
		}
	}
#endif
	
	//	encrypt 1block
	while (len>=16) {
#if defined(STRICT_ALIGNMENT)
		union { u64 u[2]; u8 c[16]; } temp;

		memcpy (temp.c,inp,16);
		ctx->cmac.u[0] ^= temp.u[0];
		ctx->cmac.u[1] ^= temp.u[1];
#else
		ctx->cmac.u[0] ^= ((u64*)inp)[0];
		ctx->cmac.u[1] ^= ((u64*)inp)[1];
#endif
		(*block)(ctx->cmac.c,ctx->cmac.c,key);
		(*block)(ctx->nonce.c,scratch.c,key);
		ctr64_inc(ctx->nonce.c);
#if defined(STRICT_ALIGNMENT)
		temp.u[0] ^= scratch.u[0];
		temp.u[1] ^= scratch.u[1];
		memcpy(out,temp.c,16);
#else
		((u64*)out)[0] = scratch.u[0]^((u64*)inp)[0];
		((u64*)out)[1] = scratch.u[1]^((u64*)inp)[1];
#endif
		inp += 16;
		out += 16;
		len -= 16;
	}

	if (len) {
		for (i=0; i<len; ++i) ctx->cmac.c[i] ^= inp[i];
		(*block)(ctx->cmac.c,ctx->cmac.c,key);
		(*block)(ctx->nonce.c,scratch.c,key);
		for (i=0; i<len; ++i) out[i] = scratch.c[i]^inp[i];
	}

	for (i=15-L;i<16;++i)
		ctx->nonce.c[i]=0;

	(*block)(ctx->nonce.c,scratch.c,key);
	ctx->cmac.u[0] ^= scratch.u[0];
	ctx->cmac.u[1] ^= scratch.u[1];

	ctx->nonce.c[0] = flags0;

	return 0;
}

int LEA_ccm128_decrypt(CCM128_CONTEXT *ctx,
	const unsigned char *inp, unsigned char *out,
	size_t len)
{
	size_t		n;
	unsigned int	i,L;
	unsigned char	flags0	= ctx->nonce.c[0];
	block128_f	block	= ctx->block;
	void *		key	= ctx->key;
#if 0 //jkkim def COMPILE_AVX2
	union { u64 u[16]; u8 c[128]; } scratch;
//jkkim #elif defined(COMPILE_SSE2) || defined(COMPILE_NEON) || defined(COMPILE_XOP)
//jkkim 	union { u64 u[8]; u8 c[64]; } scratch;
#else
	union { u64 u[2]; u8 c[16]; } scratch;
#endif

#if 0 //jkkim defined(COMPILE_SSE2) || defined(COMPILE_NEON) || defined(COMPILE_XOP)
	void (*lea_encrypt_4block)(unsigned char*,const unsigned char*,const LEA_KEY*) = NULL;
#endif

	if (!(flags0&0x40))
		(*block)(ctx->nonce.c,ctx->cmac.c,key);

	ctx->nonce.c[0] = L = flags0&7;
	for (n=0,i=15-L;i<15;++i) {
		n |= ctx->nonce.c[i];
		ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	if (n!=len) return -1;

	//	encrypt 8block
#if 0 //jkkim def COMPILE_AVX2
	if(AVX2_CAPABLE){
		while (len>=128) {
	#if defined(STRICT_ALIGNMENT)
			union { u64 u[16]; u8 c[128]; } temp;

			memcpy(scratch.c, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 16, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 32, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 48, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 64, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 80, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 96, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 112, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);

			lea_encrypt_8block_avx2(scratch.c, scratch.c, key);

			memcpy (temp.c,inp,128);
			for(i = 0; i < 8; i++)
			{
				ctx->cmac.u[0] ^= (scratch.u[(i << 1) + 0] ^= temp.u[0]);
				ctx->cmac.u[1] ^= (scratch.u[(i << 1) + 1] ^= temp.u[1]);
				memcpy (out,scratch.c + (i << 4),16);

				(*block)(ctx->cmac.c,ctx->cmac.c,key);
			}
#else
			memcpy(scratch.c, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 16, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 32, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 48, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 64, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 80, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 96, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);
			memcpy(scratch.c + 112, ctx->nonce.c, 16);
			ctr64_inc(ctx->nonce.c);

			lea_encrypt_8block_avx2(scratch.c, scratch.c, key);

			for(i = 0; i < 8; i++)
			{
				ctx->cmac.u[0] ^= (((u64*)out)[(i << 1) + 0] = scratch.u[(i << 1) + 0]^((u64*)inp)[(i << 1) + 0]);
				ctx->cmac.u[1] ^= (((u64*)out)[(i << 1) + 1] = scratch.u[(i << 1) + 1]^((u64*)inp)[(i << 1) + 1]);

				(*block)(ctx->cmac.c,ctx->cmac.c,key);
			}
#endif
			inp += 128;
			out += 128;
			len -= 128;
		}
	}
#endif	//#ifdef COMPILE_AVX2


	//	encrypt 4block
#if 0 //jkkim defined(COMPILE_XOP) || defined(COMPILE_SSE2) || defined(COMPILE_NEON)
	if(len >= 64){
#ifdef COMPILE_XOP
		if(XOP_CAPABLE){
			lea_encrypt_4block = lea_encrypt_4block_xop;
		} else 
#endif
#ifdef COMPILE_SSE2
		if(SSE2_CAPABLE){
			lea_encrypt_4block = lea_encrypt_4block_sse2;
		} else
#endif
#ifdef COMPILE_NEON
		if(NEON_CAPABLE){
			lea_encrypt_4block = lea_encrypt_4block_neon;
		} else
#endif
		{}
	
		if(lea_encrypt_4block){
			while (len>=64) {
		#if defined(STRICT_ALIGNMENT)
				union { u64 u[8]; u8 c[64]; } temp;

				memcpy(scratch.c, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 16, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 32, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 48, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);

				lea_encrypt_4block(scratch.c, scratch.c, key);

				memcpy (temp.c,inp,64);
				for(i = 0; i < 4; i++)
				{
					// ^= -> ^
					ctx->cmac.u[0] ^= (temp.u[(i << 1) + 0] ^= scratch.u[(i << 1) + 0]);
					ctx->cmac.u[1] ^= (temp.u[(i << 1) + 1] ^= scratch.u[(i << 1) + 1]);

					(*block)(ctx->cmac.c,ctx->cmac.c,key);
				}
				memcpy (out,temp.c,64);
		#else
				memcpy(scratch.c, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 16, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 32, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);
				memcpy(scratch.c + 48, ctx->nonce.c, 16);
				ctr64_inc(ctx->nonce.c);

				lea_encrypt_4block(scratch.c, scratch.c, key);

				for(i = 0; i < 4; i++)
				{
					ctx->cmac.u[0] ^= (((u64*)out)[(i << 1) + 0] = scratch.u[(i << 1) + 0]^((u64*)inp)[(i << 1) + 0]);
					ctx->cmac.u[1] ^= (((u64*)out)[(i << 1) + 1] = scratch.u[(i << 1) + 1]^((u64*)inp)[(i << 1) + 1]);

					(*block)(ctx->cmac.c,ctx->cmac.c,key);
				}
		#endif
				inp += 64;
				out += 64;
				len -= 64;
			}
		}
	}
#endif //ifdef SSE2, XOP, NEON

	//	decrypt 1block
	while (len>=16) {
#if defined(STRICT_ALIGNMENT)
		union { u64 u[2]; u8 c[16]; } temp;
#endif
		(*block)(ctx->nonce.c,scratch.c,key);
		ctr64_inc(ctx->nonce.c);
#if defined(STRICT_ALIGNMENT)
		memcpy (temp.c,inp,16);
		ctx->cmac.u[0] ^= (temp.u[0] ^= scratch.u[0]);
		ctx->cmac.u[1] ^= (temp.u[1] ^= scratch.u[1]);
		memcpy (out,temp.c,16);
#else
		ctx->cmac.u[0] ^= (((u64*)out)[0] = scratch.u[0]^((u64*)inp)[0]);
		ctx->cmac.u[1] ^= (((u64*)out)[1] = scratch.u[1]^((u64*)inp)[1]);
#endif
		(*block)(ctx->cmac.c,ctx->cmac.c,key);

		inp += 16;
		out += 16;
		len -= 16;
	}

	if (len) {
		(*block)(ctx->nonce.c,scratch.c,key);
		for (i=0; i<len; ++i)
			ctx->cmac.c[i] ^= (out[i] = scratch.c[i]^inp[i]);
		(*block)(ctx->cmac.c,ctx->cmac.c,key);
	}

	for (i=15-L;i<16;++i)
		ctx->nonce.c[i]=0;

	(*block)(ctx->nonce.c,scratch.c,key);
	ctx->cmac.u[0] ^= scratch.u[0];
	ctx->cmac.u[1] ^= scratch.u[1];

	ctx->nonce.c[0] = flags0;

	return 0;
}

static int lea_ccm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
	{
	EVP_LEA_CCM_CTX *cctx = c->cipher_data;
	switch (type)
		{
	case EVP_CTRL_INIT:
		cctx->key_set = 0;
		cctx->iv_set = 0;
		cctx->L = 8;
		cctx->M = 12;
		cctx->tag_set = 0;
		cctx->len_set = 0;
		return 1;

	case EVP_CTRL_CCM_SET_IVLEN:
		arg = 15 - arg;
	case EVP_CTRL_CCM_SET_L:
		if (arg < 2 || arg > 8)
			return 0;
		cctx->L = arg;
		return 1;

	case EVP_CTRL_CCM_SET_TAG:
		if ((arg & 1) || arg < 4 || arg > 16)
			return 0;
		if ((c->encrypt && ptr) || (!c->encrypt && !ptr))
			return 0;
		if (ptr)
			{
			cctx->tag_set = 1;
			memcpy(c->buf, ptr, arg);
			}
		cctx->M = arg;
		return 1;

	case EVP_CTRL_CCM_GET_TAG:
		if (!c->encrypt || !cctx->tag_set)
			return 0;
		if(!CRYPTO_ccm128_tag(&cctx->ccm, ptr, (size_t)arg))
			return 0;
		cctx->tag_set = 0;
		cctx->iv_set = 0;
		cctx->len_set = 0;
		return 1;

	case EVP_CTRL_COPY:
		{
			EVP_CIPHER_CTX *out = ptr;
			EVP_LEA_CCM_CTX *cctx_out = out->cipher_data;
			if (cctx->ccm.key)
				{
				if (cctx->ccm.key != &cctx->ks)
					return 0;
				cctx_out->ccm.key = &cctx_out->ks;
				}
			return 1;
		}

	default:
		return -1;

		}
	}

static int lea_ccm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
	{
	EVP_LEA_CCM_CTX *cctx = ctx->cipher_data;
	if (!iv && !key)
		return 1;
	if (key) do
		{
		LEA_set_encrypt_key(key, ctx->key_len * 8, &cctx->ks);
		CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
					&cctx->ks, (block128_f)LEA_encrypt);
		cctx->str = NULL;
		cctx->key_set = 1;
		} while (0);
	if (iv)
		{
		memcpy(ctx->iv, iv, 15 - cctx->L);
		cctx->iv_set = 1;
		}
	return 1;
	}

static int lea_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
	{
	EVP_LEA_CCM_CTX *cctx = ctx->cipher_data;
	CCM128_CONTEXT *ccm = &cctx->ccm;
	/* If not set up, return error */
	if (!cctx->iv_set && !cctx->key_set)
		return -1;
	if (!ctx->encrypt && !cctx->tag_set)
		return -1;
	if (!out)
		{
		if (!in)
			{
			if (CRYPTO_ccm128_setiv(ccm, ctx->iv, 15 - cctx->L,len))
				return -1;
			cctx->len_set = 1;
			return len;
			}
		/* If have AAD need message length */
		if (!cctx->len_set && len)
			return -1;
		CRYPTO_ccm128_aad(ccm, in, len);
		return len;
		}
	/* EVP_*Final() doesn't return any data */
	if (!in)
		return 0;
	/* If not set length yet do it */
	if (!cctx->len_set)
		{
		if (CRYPTO_ccm128_setiv(ccm, ctx->iv, 15 - cctx->L, len))
			return -1;
		cctx->len_set = 1;
		}
	if (ctx->encrypt)
		{
		if (cctx->str ? CRYPTO_ccm128_encrypt_ccm64(ccm, in, out, len,
						cctx->str) :
				LEA_ccm128_encrypt(ccm, in, out, len))
			return -1;
		cctx->tag_set = 1;
		return len;
		}
	else
		{
		int rv = -1;
		if (cctx->str ? !CRYPTO_ccm128_decrypt_ccm64(ccm, in, out, len,
						cctx->str) :
				!LEA_ccm128_decrypt(ccm, in, out, len))
			{
			unsigned char tag[16];
			if (CRYPTO_ccm128_tag(ccm, tag, cctx->M))
				{
				if (!memcmp(tag, ctx->buf, cctx->M))
					rv = len;
				}
			}
		if (rv == -1)
			OPENSSL_cleanse(out, len);
		cctx->iv_set = 0;
		cctx->tag_set = 0;
		cctx->len_set = 0;
		return rv;
		}
	}

#define lea_ccm_cleanup NULL

BLOCK_CIPHER_custom(NID_lea,128,1,12,ccm,CCM,EVP_CIPH_FLAG_FIPS|CUSTOM_FLAGS)
BLOCK_CIPHER_custom(NID_lea,192,1,12,ccm,CCM,EVP_CIPH_FLAG_FIPS|CUSTOM_FLAGS)
BLOCK_CIPHER_custom(NID_lea,256,1,12,ccm,CCM,EVP_CIPH_FLAG_FIPS|CUSTOM_FLAGS)



static int lea_gcm_cleanup(EVP_CIPHER_CTX *c)
	{
	EVP_LEA_GCM_CTX *gctx = c->cipher_data;
	OPENSSL_cleanse(&gctx->gcm, sizeof(gctx->gcm));
	if (gctx->iv != c->iv)
		OPENSSL_free(gctx->iv);
	return 1;
	}

static int lea_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
	{
	EVP_LEA_GCM_CTX *gctx = c->cipher_data;
	switch (type)
		{
	case EVP_CTRL_INIT:
		gctx->key_set = 0;
		gctx->iv_set = 0;
		gctx->ivlen = c->cipher->iv_len;
		gctx->iv = c->iv;
		gctx->taglen = -1;
		gctx->iv_gen = 0;
		gctx->tls_aad_len = -1;
		return 1;

	case EVP_CTRL_GCM_SET_IVLEN:
		if (arg <= 0)
			return 0;
#ifdef OPENSSL_FIPS
		if (FIPS_module_mode() && !(c->flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW)
						 && arg < 12)
			return 0;
#endif
		/* Allocate memory for IV if needed */
		if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen))
			{
			if (gctx->iv != c->iv)
				OPENSSL_free(gctx->iv);
			gctx->iv = OPENSSL_malloc(arg);
			if (!gctx->iv)
				return 0;
			}
		gctx->ivlen = arg;
		return 1;

	case EVP_CTRL_GCM_SET_TAG:
		if (arg <= 0 || arg > 16 || c->encrypt)
			return 0;
		memcpy(c->buf, ptr, arg);
		gctx->taglen = arg;
		return 1;

	case EVP_CTRL_GCM_GET_TAG:
		if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0)
			return 0;
		memcpy(ptr, c->buf, arg);
		return 1;

	case EVP_CTRL_GCM_SET_IV_FIXED:
		/* Special case: -1 length restores whole IV */
		if (arg == -1)
			{
			memcpy(gctx->iv, ptr, gctx->ivlen);
			gctx->iv_gen = 1;
			return 1;
			}
		/* Fixed field must be at least 4 bytes and invocation field
		 * at least 8.
		 */
		if ((arg < 4) || (gctx->ivlen - arg) < 8)
			return 0;
		if (arg)
			memcpy(gctx->iv, ptr, arg);
		if (c->encrypt &&
			RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
			return 0;
		gctx->iv_gen = 1;
		return 1;

	case EVP_CTRL_GCM_IV_GEN:
		if (gctx->iv_gen == 0 || gctx->key_set == 0)
			return 0;
		CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
		if (arg <= 0 || arg > gctx->ivlen)
			arg = gctx->ivlen;
		memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
		/* Invocation field will be at least 8 bytes in size and
		 * so no need to check wrap around or increment more than
		 * last 8 bytes.
		 */
		ctr64_inc(gctx->iv + gctx->ivlen - 8);
		gctx->iv_set = 1;
		return 1;

	case EVP_CTRL_GCM_SET_IV_INV:
		if (gctx->iv_gen == 0 || gctx->key_set == 0 || c->encrypt)
			return 0;
		memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
		CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
		gctx->iv_set = 1;
		return 1;

	case EVP_CTRL_AEAD_TLS1_AAD:
		/* Save the AAD for later use */
		if (arg != 13)
			return 0;
		memcpy(c->buf, ptr, arg);
		gctx->tls_aad_len = arg;
			{
			unsigned int len=c->buf[arg-2]<<8|c->buf[arg-1];
			/* Correct length for explicit IV */
			len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
			/* If decrypting correct for tag too */
			if (!c->encrypt)
				len -= EVP_GCM_TLS_TAG_LEN;
                        c->buf[arg-2] = len>>8;
                        c->buf[arg-1] = len & 0xff;
			}
		/* Extra padding: tag appended to record */
		return EVP_GCM_TLS_TAG_LEN;

	case EVP_CTRL_COPY:
		{
			EVP_CIPHER_CTX *out = ptr;
			EVP_LEA_GCM_CTX *gctx_out = out->cipher_data;
			if (gctx->gcm.key)
				{
				if (gctx->gcm.key != &gctx->ks)
					return 0;
				gctx_out->gcm.key = &gctx_out->ks;
				}
			if (gctx->iv == c->iv)
				gctx_out->iv = out->iv;
			else
			{
				gctx_out->iv = OPENSSL_malloc(gctx->ivlen);
				if (!gctx_out->iv)
					return 0;
				memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
			}
			return 1;
		}

	default:
		return -1;

		}
	}

static int lea_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
	{
	EVP_LEA_GCM_CTX *gctx = ctx->cipher_data;
	if (!iv && !key)
		return 1;
	if (key)
		{ do {
		(void)0;	/* terminate potentially open 'else' */

		LEA_set_encrypt_key(key, ctx->key_len * 8, &gctx->ks);
		CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks, (block128_f)LEA_encrypt);

		gctx->ctr = NULL;

		} while (0);

		/* If we have an iv can set it directly, otherwise use
		 * saved IV.
		 */
		if (iv == NULL && gctx->iv_set)
			iv = gctx->iv;
		if (iv)
			{
			CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
			gctx->iv_set = 1;
			}
		gctx->key_set = 1;
		}
	else
		{
		/* If key set use IV, otherwise copy */
		if (gctx->key_set)
			CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
		else
			memcpy(gctx->iv, iv, gctx->ivlen);
		gctx->iv_set = 1;
		gctx->iv_gen = 0;
		}
	return 1;
	}

/* Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

static int lea_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
	{
	EVP_LEA_GCM_CTX *gctx = ctx->cipher_data;
	int rv = -1;
	/* Encrypt/decrypt must be performed in place */
	if (out != in || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN+EVP_GCM_TLS_TAG_LEN))
		return -1;
	/* Set IV from start of buffer or generate IV and write to start
	 * of buffer.
	 */
	if (EVP_CIPHER_CTX_ctrl(ctx, ctx->encrypt ?
				EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
				EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
		goto err;
	/* Use saved AAD */
	if (CRYPTO_gcm128_aad(&gctx->gcm, ctx->buf, gctx->tls_aad_len))
		goto err;
	/* Fix buffer and length to point to payload */
	in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
	out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
	len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
	if (ctx->encrypt)
		{
		/* Encrypt payload */
		if (gctx->ctr)
			{
			if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
							in, out, len,
							gctx->ctr))
				goto err;
			}
		else	{
			if (CRYPTO_lea_gcm128_encrypt(&gctx->gcm, in, out, len))
				goto err;
			}
		out += len;
		/* Finally write tag */
		CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
		rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
		}
	else
		{
		/* Decrypt */
		if (gctx->ctr)
			{
			if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
							in, out, len,
							gctx->ctr))
				goto err;
			}
		else	{
			if (CRYPTO_lea_gcm128_decrypt(&gctx->gcm, in, out, len))
				goto err;
			}
		/* Retrieve tag */
		CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf,
					EVP_GCM_TLS_TAG_LEN);
		/* If tag mismatch wipe buffer */
		if (memcmp(ctx->buf, in + len, EVP_GCM_TLS_TAG_LEN))
			{
			OPENSSL_cleanse(out, len);
			goto err;
			}
		rv = len;
		}

	err:
	gctx->iv_set = 0;
	gctx->tls_aad_len = -1;
	return rv;
	}

static int lea_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
	{
	EVP_LEA_GCM_CTX *gctx = ctx->cipher_data;
	/* If not set up, return error */
	if (!gctx->key_set)
		return -1;

	if (gctx->tls_aad_len >= 0)
		return lea_gcm_tls_cipher(ctx, out, in, len);

	if (!gctx->iv_set)
		return -1;
	if (in)
		{
		if (out == NULL)
			{
			if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
				return -1;
			}
		else if (ctx->encrypt)
			{
			if (gctx->ctr)
				{
				if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
							in, out, len,
							gctx->ctr))
					return -1;
				}
			else	{
				if (CRYPTO_lea_gcm128_encrypt(&gctx->gcm, in, out, len))
					return -1;
				}
			}
		else
			{
			if (gctx->ctr)
				{
				if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
							in, out, len,
							gctx->ctr))
					return -1;
				}
			else	{
				if (CRYPTO_lea_gcm128_decrypt(&gctx->gcm, in, out, len))
					return -1;
				}
			}
		return len;
		}
	else
		{
		if (!ctx->encrypt)
			{
			if (gctx->taglen < 0)
				return -1;
			if (CRYPTO_gcm128_finish(&gctx->gcm,
					ctx->buf, gctx->taglen) != 0)
				return -1;
			gctx->iv_set = 0;
			return 0;
			}
		CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, 16);
		gctx->taglen = 16;
		/* Don't reuse the IV */
		gctx->iv_set = 0;
		return 0;
		}

	}


BLOCK_CIPHER_custom(NID_lea,128,1,12,gcm,GCM,
		EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_AEAD_CIPHER|CUSTOM_FLAGS)
BLOCK_CIPHER_custom(NID_lea,192,1,12,gcm,GCM,
		EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_AEAD_CIPHER|CUSTOM_FLAGS)
BLOCK_CIPHER_custom(NID_lea,256,1,12,gcm,GCM,
		EVP_CIPH_FLAG_FIPS|EVP_CIPH_FLAG_AEAD_CIPHER|CUSTOM_FLAGS)

