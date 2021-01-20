#ifndef HEADER_LEA_LOCL_H
#define HEADER_LEA_LOCL_H

#include <openssl/e_os2.h>
#include <openssl/lea.h>
#ifdef OPENSSL_NO_LEA
#error LEA is disabled.
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "../modes/modes_lcl.h"
#include <openssl/modes.h> 

#if defined(__i386__) || defined(_M_IX86) || defined(_M_X64) || defined(__x86_64__)
#define ARCH_IA32
#endif

#if defined(__arm__) || defined(_M_ARM) || defined(_ARM) || defined(__arm) || defined(__aarch64__)
#define ARCH_ARM
#endif


#if defined(NO_LEA_SIMD)
//do Nothing!
#elif defined(ARCH_IA32) && !defined(I386_ONLY)

#if (defined(_MSC_VER) && _MSC_FULL_VER >= 180021114) || (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7))
#define COMPILE_AVX2
#endif

#if (defined(_MSC_VER) && _MSC_FULL_VER >= 160040219) || (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5))
#define COMPILE_XOP
#endif

#if (defined(_MSC_VER) && _MSC_FULL_VER >= 150030729) || (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4))
#define COMPILE_PCLMUL
#endif

#if (defined(_MSC_VER) && _MSC_VER >= 1250) || __GNUC__ >= 3
#define COMPILE_SSE2
#endif 

#elif defined(ARCH_NEON) /* end of ARCH_IA32 */

#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define COMPILE_NEON
#endif

#endif /* ARCH_ARM*/

# if     !defined(NO_LEA_SIMD) && !defined(I386_ONLY) &&      (  \
        ((defined(__i386)       || defined(__i386__)    || \
          defined(_M_IX86)) && defined(OPENSSL_IA32_SSE2))|| \
        defined(__x86_64)       || defined(__x86_64__)  || \
        defined(_M_AMD64)       || defined(_M_X64)      || \
        defined(__INTEL__)                              )


extern unsigned int OPENSSL_ia32cap_P[4];

#ifdef COMPILE_AVX2
#define AVX2_CAPABLE (OPENSSL_ia32cap_P[2]&(1<<5))
#endif

#ifdef COMPILE_SSE2
#ifdef OPENSSL_IA32_SSE2
#define SSE2_CAPABLE 1
#else
#define SSE2_CAPABLE 0
#endif
#endif

#ifdef COMPILE_XOP 
#define XOP_CAPABLE (OPENSSL_ia32cap_P[1]&(1<<11))
#endif

#ifdef COMPILE_PCLMUL
#define PCLMUL_CAPABLE (OPENSSL_ia32cap_P[1] & (1 << 1))
#endif

#endif

#if !defined(NO_LEA_SIMD) && defined(COMPILE_NEON)
# include "arm_arch.h"
# if __ARM_MAX_ARCH__>=7
#  define NEON_CAPABLE	(OPENSSL_armcap_P & ARMV7_NEON)
# else
#  define NEON_CAPABLE	0
# endif
#endif

#define MAXKC   (256/32)
#define MAXKB   (256/8)
#define MAXNR   32

/*		#define USE_BUILT_IN	*/
#if (USE_BUILT_IN)
#if defined(_MSC_VER)
#include <stdlib.h>
#define ROR(W,i) _lrotr(W, i)
#define ROL(W,i) _lrotl(W, i)
#else	/*	#if defined(_MSC_VER)	*/
#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))
#endif	/*	#if defined(_MSC_VER)	*/
#endif

/* This controls loop-unrolling in LEA_core.c */
#undef FULL_UNROLL

/*		#define USE_BUILT_IN	*/
#if (USE_BUILT_IN)
#if defined(_MSC_VER)
#include <stdlib.h>
#define ROR(W,i) _lrotr(W, i)
#define ROL(W,i) _lrotl(W, i)
#else	/*	#if defined(_MSC_VER)	*/
#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))
#endif	/*	#if defined(_MSC_VER)	*/
#include <string.h>
#define lea_memcpy		memcpy
#define lea_memset		memset
#define lea_memcmp		memcmp
#else	/*	#if (USE_BUILT_IN)	*/
#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))
void lea_memcpy(void *dst, void *src, int count);
void lea_memset(void *dst, int val, int count);
void lea_memcmp(void *src1, void *src2, int count);
#endif

//	endianess
#if (defined(sparc)) ||	(defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)) || defined(__BIG_ENDIAN__)
//Microblaze, SuperH, AVR32, System/360(370), ESA/390, z/Architecture, PDP-10
//	big endian
#define ctow(c, w)	(*(w) = (((c)[3] << 24) | ((c)[2] << 16) | ((c)[1] << 8) | ((c)[0])))
#define wtoc(w, c)	((c)[0] = *(w), (c)[1] = (*(w) >> 8), (c)[2] = (*(w) >> 16), (c)[3] = (*(w) >> 24))
#else
//	little endian
#define ctow(c, w)	(*(w) = *((unsigned int *)(c)))
#define wtoc(w, c)	(*((unsigned int *)(c)) = *(w))
#endif



#define lea_assert(cond)	((cond) ? 0 : (return -1;))


/*****		cryptographic functions
*****/
void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_decrypt(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key);

#if 0 //jkkim
void lea_encrypt_4block_sse2(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_decrypt_4block_sse2(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key);

void lea_encrypt_4block_xop(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_decrypt_4block_xop(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key);

void lea_encrypt_4block_neon(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_decrypt_4block_neon(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key);

void lea_encrypt_8block_avx2(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_decrypt_8block_avx2(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key);

#endif

/* XOP functions */
void lea_set_key_xop(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len);
void lea_encrypt_1blocks_xop(unsigned char *ct, const unsigned char *pt, unsigned int remainBlock, const LEA_KEY *key);
void _lea_ctr_enc_xop(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, unsigned char *ctr, const LEA_KEY *key);
void _lea_cfb128_dec_xop(unsigned char *pt, const unsigned char *ct, unsigned int ct_len, const unsigned char *iv, const LEA_KEY *key);
void _lea_ofb_enc_xop(unsigned char *ct, const unsigned char *pt, unsigned int pt_len, const unsigned char *iv, const LEA_KEY *key);
/*****		not built-in functions
*****/
void ctr128_inc_aligned(unsigned char *counter);

#if defined(_M_X64) || defined(__x86_64__)
#define XOR8x16(r, a, b)																		\
	*((unsigned long long *)(r)      ) = *((unsigned long long *)(a)      ) ^ *((unsigned long long *)(b)      ),	\
	*((unsigned long long *)(r) + 0x1) = *((unsigned long long *)(a) + 0x1) ^ *((unsigned long long *)(b) + 0x1)
#elif defined(__i386__) || defined(_M_IX86)
#define XOR8x16(r, a, b)																		\
	*((unsigned int *)(r)      ) = *((unsigned int *)(a)      ) ^ *((unsigned int *)(b)      ),	\
	*((unsigned int *)(r) + 0x1) = *((unsigned int *)(a) + 0x1) ^ *((unsigned int *)(b) + 0x1),	\
	*((unsigned int *)(r) + 0x2) = *((unsigned int *)(a) + 0x2) ^ *((unsigned int *)(b) + 0x2),	\
	*((unsigned int *)(r) + 0x3) = *((unsigned int *)(a) + 0x3) ^ *((unsigned int *)(b) + 0x3)
#else
#define XOR8x16(r, a, b)				\
	*((r)      ) = *((a)      ) ^ *((b)      ),	\
	*((r) + 0x1) = *((a) + 0x1) ^ *((b) + 0x1),	\
	*((r) + 0x2) = *((a) + 0x2) ^ *((b) + 0x2),	\
	*((r) + 0x3) = *((a) + 0x3) ^ *((b) + 0x3),	\
	*((r) + 0x4) = *((a) + 0x4) ^ *((b) + 0x4),	\
	*((r) + 0x5) = *((a) + 0x5) ^ *((b) + 0x5),	\
	*((r) + 0x6) = *((a) + 0x6) ^ *((b) + 0x6),	\
	*((r) + 0x7) = *((a) + 0x7) ^ *((b) + 0x7),	\
	*((r) + 0x8) = *((a) + 0x8) ^ *((b) + 0x8),	\
	*((r) + 0x9) = *((a) + 0x9) ^ *((b) + 0x9),	\
	*((r) + 0xa) = *((a) + 0xa) ^ *((b) + 0xa),	\
	*((r) + 0xb) = *((a) + 0xb) ^ *((b) + 0xb),	\
	*((r) + 0xc) = *((a) + 0xc) ^ *((b) + 0xc),	\
	*((r) + 0xd) = *((a) + 0xd) ^ *((b) + 0xd),	\
	*((r) + 0xe) = *((a) + 0xe) ^ *((b) + 0xe),	\
	*((r) + 0xf) = *((a) + 0xf) ^ *((b) + 0xf)
#endif

#define XOR8x64(r, a, b)				\
	XOR8x16((r)       , (a)       , (b)       ),	\
	XOR8x16((r) + 0x10, (a) + 0x10, (b) + 0x10),	\
	XOR8x16((r) + 0x20, (a) + 0x20, (b) + 0x20),	\
	XOR8x16((r) + 0x30, (a) + 0x30, (b) + 0x30)

#define XOR8x128(r, a, b)				\
	XOR8x64((r)       , (a)       , (b)       ),	\
	XOR8x64((r) + 0x40, (a) + 0x40, (b) + 0x40)

#define XOR8x16r(r, a, b)				\
	*((r) + 0xf) = *((a) + 0xf) ^ *((b) + 0xf),	\
	*((r) + 0xe) = *((a) + 0xe) ^ *((b) + 0xe),	\
	*((r) + 0xd) = *((a) + 0xd) ^ *((b) + 0xd),	\
	*((r) + 0xc) = *((a) + 0xc) ^ *((b) + 0xc),	\
	*((r) + 0xb) = *((a) + 0xb) ^ *((b) + 0xb),	\
	*((r) + 0xa) = *((a) + 0xa) ^ *((b) + 0xa),	\
	*((r) + 0x9) = *((a) + 0x9) ^ *((b) + 0x9),	\
	*((r) + 0x8) = *((a) + 0x8) ^ *((b) + 0x8),	\
	*((r) + 0x7) = *((a) + 0x7) ^ *((b) + 0x7),	\
	*((r) + 0x6) = *((a) + 0x6) ^ *((b) + 0x6),	\
	*((r) + 0x5) = *((a) + 0x5) ^ *((b) + 0x5),	\
	*((r) + 0x4) = *((a) + 0x4) ^ *((b) + 0x4),	\
	*((r) + 0x3) = *((a) + 0x3) ^ *((b) + 0x3),	\
	*((r) + 0x2) = *((a) + 0x2) ^ *((b) + 0x2),	\
	*((r) + 0x1) = *((a) + 0x1) ^ *((b) + 0x1),	\
	*((r)      ) = *((a)      ) ^ *((b)      )

#define XOR8x64r(r, a, b)				\
	XOR8x16r((r) + 0x30, (a) + 0x30, (b) + 0x30),	\
	XOR8x16r((r) + 0x20, (a) + 0x20, (b) + 0x20),	\
	XOR8x16r((r) + 0x10, (a) + 0x10, (b) + 0x10),	\
	XOR8x16r((r)       , (a)       , (b)       )

#define XOR8x128r(r, a, b)				\
	XOR8x64r((r) + 0x40, (a) + 0x40, (b) + 0x40),	\
	XOR8x64r((r)       , (a)       , (b)       )

#define	XOR32x4(d, a, b)							\
	*((d)    ) = *((a)    ) ^ *((b)    ),			\
	*((d) + 1) = *((a) + 1) ^ *((b) + 1),			\
	*((d) + 2) = *((a) + 2) ^ *((b) + 2),			\
	*((d) + 3) = *((a) + 3) ^ *((b) + 3)

#define CPY8x12(d, s)											\
	*((unsigned int *)(d)) = *((unsigned int *)(s)),			\
	*((unsigned int *)(d) + 1) = *((unsigned int *)(s) + 1),	\
	*((unsigned int *)(d) + 2) = *((unsigned int *)(s) + 2)

#define CPY8x16(d, s)											\
	*((unsigned int *)(d)) = *((unsigned int *)(s)),			\
	*((unsigned int *)(d) + 1) = *((unsigned int *)(s) + 1),	\
	*((unsigned int *)(d) + 2) = *((unsigned int *)(s) + 2),	\
	*((unsigned int *)(d) + 3) = *((unsigned int *)(s) + 3)

#define ZERO8x16(a)																				\
	(*((unsigned int *)(a)) = 0, *((unsigned int *)(a) + 1) = 0, *((unsigned int *)(a) + 2) = 0, *((unsigned int *)(a) + 3) = 0);

#define RSHIFT32x4(r, a, bit)								\
	(r)[3] = ((a)[3] >> (bit)) | ((a)[2] << (32 - (bit))),	\
	(r)[2] = ((a)[2] >> (bit)) | ((a)[1] << (32 - (bit))),	\
	(r)[1] = ((a)[1] >> (bit)) | ((a)[0] << (32 - (bit))),	\
	(r)[0] = ((a)[0] >> (bit))

#define RSHIFT8x16_1(v)								\
	(v)[15] = ((v)[15] >> 1) | ((v)[14] << 7),		\
	(v)[14] = ((v)[14] >> 1) | ((v)[13] << 7),		\
	(v)[13] = ((v)[13] >> 1) | ((v)[12] << 7),		\
	(v)[12] = ((v)[12] >> 1) | ((v)[11] << 7),		\
	(v)[11] = ((v)[11] >> 1) | ((v)[10] << 7),		\
	(v)[10] = ((v)[10] >> 1) | ((v)[ 9] << 7),		\
	(v)[ 9] = ((v)[ 9] >> 1) | ((v)[ 8] << 7),		\
	(v)[ 8] = ((v)[ 8] >> 1) | ((v)[ 7] << 7),		\
	(v)[ 7] = ((v)[ 7] >> 1) | ((v)[ 6] << 7),		\
	(v)[ 6] = ((v)[ 6] >> 1) | ((v)[ 5] << 7),		\
	(v)[ 5] = ((v)[ 5] >> 1) | ((v)[ 4] << 7),		\
	(v)[ 4] = ((v)[ 4] >> 1) | ((v)[ 3] << 7),		\
	(v)[ 3] = ((v)[ 3] >> 1) | ((v)[ 2] << 7),		\
	(v)[ 2] = ((v)[ 2] >> 1) | ((v)[ 1] << 7),		\
	(v)[ 1] = ((v)[ 1] >> 1) | ((v)[ 0] << 7),		\
	(v)[ 0] = ((v)[ 0] >> 1)

#define RSHIFT8x16_4(v)								\
	(v)[15] = ((v)[15] >> 4) | ((v)[14] << 4),		\
	(v)[14] = ((v)[14] >> 4) | ((v)[13] << 4),		\
	(v)[13] = ((v)[13] >> 4) | ((v)[12] << 4),		\
	(v)[12] = ((v)[12] >> 4) | ((v)[11] << 4),		\
	(v)[11] = ((v)[11] >> 4) | ((v)[10] << 4),		\
	(v)[10] = ((v)[10] >> 4) | ((v)[ 9] << 4),		\
	(v)[ 9] = ((v)[ 9] >> 4) | ((v)[ 8] << 4),		\
	(v)[ 8] = ((v)[ 8] >> 4) | ((v)[ 7] << 4),		\
	(v)[ 7] = ((v)[ 7] >> 4) | ((v)[ 6] << 4),		\
	(v)[ 6] = ((v)[ 6] >> 4) | ((v)[ 5] << 4),		\
	(v)[ 5] = ((v)[ 5] >> 4) | ((v)[ 4] << 4),		\
	(v)[ 4] = ((v)[ 4] >> 4) | ((v)[ 3] << 4),		\
	(v)[ 3] = ((v)[ 3] >> 4) | ((v)[ 2] << 4),		\
	(v)[ 2] = ((v)[ 2] >> 4) | ((v)[ 1] << 4),		\
	(v)[ 1] = ((v)[ 1] >> 4) | ((v)[ 0] << 4),		\
	(v)[ 0] = ((v)[ 0] >> 4)

#define RSHIFT8x16_8(v)							\
	(v)[15] = (v)[14],		\
	(v)[14] = (v)[13],		\
	(v)[13] = (v)[12],		\
	(v)[12] = (v)[11],		\
	(v)[11] = (v)[10],		\
	(v)[10] = (v)[ 9],		\
	(v)[ 9] = (v)[ 8],		\
	(v)[ 8] = (v)[ 7],		\
	(v)[ 7] = (v)[ 6],		\
	(v)[ 6] = (v)[ 5],		\
	(v)[ 5] = (v)[ 4],		\
	(v)[ 4] = (v)[ 3],		\
	(v)[ 3] = (v)[ 2],		\
	(v)[ 2] = (v)[ 1],		\
	(v)[ 1] = (v)[ 0],		\
	(v)[ 0] = 0

void CRYPTO_lea_gcm128_init(GCM128_CONTEXT *ctx,void *key,block128_f block);
GCM128_CONTEXT *CRYPTO_lea_gcm128_new(void *key, block128_f block);
void CRYPTO_lea_gcm128_release(GCM128_CONTEXT *ctx);
void CRYPTO_lea_gcm128_setiv(GCM128_CONTEXT *ctx,const unsigned char *iv,size_t len);
int CRYPTO_lea_gcm128_aad(GCM128_CONTEXT *ctx,const unsigned char *aad,size_t len);
int CRYPTO_lea_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len, ctr128_f stream);
int CRYPTO_lea_gcm128_encrypt(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len);
int CRYPTO_lea_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len,ctr128_f stream);
int CRYPTO_lea_gcm128_decrypt(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len);
void CRYPTO_lea_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
int CRYPTO_lea_gcm128_finish(GCM128_CONTEXT *ctx,const unsigned char *tag,
			size_t len);

#endif	/* !HEADER_LEA_LOCL_H */
