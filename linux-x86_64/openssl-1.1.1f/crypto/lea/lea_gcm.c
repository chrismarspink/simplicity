#define OPENSSL_FIPSAPI

//#include <openssl/crypto.h>
#include <string.h>

#include <openssl/lea.h>
#include "lea_locl.h"

#ifndef MODES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

#if defined(BSWAP4) && defined(STRICT_ALIGNMENT)
/* redefine, because alignment is ensured */
#undef	GETU32
#define	GETU32(p)	BSWAP4(*(const u32 *)(p))
#undef	PUTU32
#define	PUTU32(p,v)	*(u32 *)(p) = BSWAP4(v)
#endif

#define	PACK(s)		((size_t)(s)<<(sizeof(size_t)*8-16))
#define REDUCE1BIT(V)	do { \
	if (sizeof(size_t)==8) { \
		u64 T = U64(0xe100000000000000) & (0-(V.lo&1)); \
		V.lo  = (V.hi<<63)|(V.lo>>1); \
		V.hi  = (V.hi>>1 )^T; \
	} \
	else { \
		u32 T = 0xe1000000U & (0-(u32)(V.lo&1)); \
		V.lo  = (V.hi<<63)|(V.lo>>1); \
		V.hi  = (V.hi>>1 )^((u64)T<<32); \
	} \
} while(0)

#if	TABLE_BITS==4

static void gcm_init_4bit(u128 Htable[16], u64 H[2])
{
	u128 V;
#if defined(OPENSSL_SMALL_FOOTPRINT)
	int  i;
#endif

	Htable[0].hi = 0;
	Htable[0].lo = 0;
	V.hi = H[0];
	V.lo = H[1];

#if defined(OPENSSL_SMALL_FOOTPRINT)
	for (Htable[8]=V, i=4; i>0; i>>=1) {
		REDUCE1BIT(V);
		Htable[i] = V;
	}

	for (i=2; i<16; i<<=1) {
		u128 *Hi = Htable+i;
		int   j;
		for (V=*Hi, j=1; j<i; ++j) {
			Hi[j].hi = V.hi^Htable[j].hi;
			Hi[j].lo = V.lo^Htable[j].lo;
		}
	}
#else
	Htable[8] = V;
	REDUCE1BIT(V);
	Htable[4] = V;
	REDUCE1BIT(V);
	Htable[2] = V;
	REDUCE1BIT(V);
	Htable[1] = V;
	Htable[3].hi  = V.hi^Htable[2].hi, Htable[3].lo  = V.lo^Htable[2].lo;
	V=Htable[4];
	Htable[5].hi  = V.hi^Htable[1].hi, Htable[5].lo  = V.lo^Htable[1].lo;
	Htable[6].hi  = V.hi^Htable[2].hi, Htable[6].lo  = V.lo^Htable[2].lo;
	Htable[7].hi  = V.hi^Htable[3].hi, Htable[7].lo  = V.lo^Htable[3].lo;
	V=Htable[8];
	Htable[9].hi  = V.hi^Htable[1].hi, Htable[9].lo  = V.lo^Htable[1].lo;
	Htable[10].hi = V.hi^Htable[2].hi, Htable[10].lo = V.lo^Htable[2].lo;
	Htable[11].hi = V.hi^Htable[3].hi, Htable[11].lo = V.lo^Htable[3].lo;
	Htable[12].hi = V.hi^Htable[4].hi, Htable[12].lo = V.lo^Htable[4].lo;
	Htable[13].hi = V.hi^Htable[5].hi, Htable[13].lo = V.lo^Htable[5].lo;
	Htable[14].hi = V.hi^Htable[6].hi, Htable[14].lo = V.lo^Htable[6].lo;
	Htable[15].hi = V.hi^Htable[7].hi, Htable[15].lo = V.lo^Htable[7].lo;
#endif
#if defined(GHASH_ASM) && (defined(__arm__) || defined(__arm))
	/*
	 * ARM assembler expects specific dword order in Htable.
	 */
	{
	int j;
	const union { long one; char little; } is_endian = {1};

	if (is_endian.little)
		for (j=0;j<16;++j) {
			V = Htable[j];
			Htable[j].hi = V.lo;
			Htable[j].lo = V.hi;
		}
	else
		for (j=0;j<16;++j) {
			V = Htable[j];
			Htable[j].hi = V.lo<<32|V.lo>>32;
			Htable[j].lo = V.hi<<32|V.hi>>32;
		}
	}
#endif
}

#ifndef GHASH_ASM
static const size_t rem_4bit[16] = {
	PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460),
	PACK(0x7080), PACK(0x6CA0), PACK(0x48C0), PACK(0x54E0),
	PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
	PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0) };

static void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16])
{
	u128 Z;
	int cnt = 15;
	size_t rem, nlo, nhi;
	const union { long one; char little; } is_endian = {1};

	nlo  = ((const u8 *)Xi)[15];
	nhi  = nlo>>4;
	nlo &= 0xf;

	Z.hi = Htable[nlo].hi;
	Z.lo = Htable[nlo].lo;

	while (1) {
		rem  = (size_t)Z.lo&0xf;
		Z.lo = (Z.hi<<60)|(Z.lo>>4);
		Z.hi = (Z.hi>>4);
		if (sizeof(size_t)==8)
			Z.hi ^= rem_4bit[rem];
		else
			Z.hi ^= (u64)rem_4bit[rem]<<32;

		Z.hi ^= Htable[nhi].hi;
		Z.lo ^= Htable[nhi].lo;

		if (--cnt<0)		break;

		nlo  = ((const u8 *)Xi)[cnt];
		nhi  = nlo>>4;
		nlo &= 0xf;

		rem  = (size_t)Z.lo&0xf;
		Z.lo = (Z.hi<<60)|(Z.lo>>4);
		Z.hi = (Z.hi>>4);
		if (sizeof(size_t)==8)
			Z.hi ^= rem_4bit[rem];
		else
			Z.hi ^= (u64)rem_4bit[rem]<<32;

		Z.hi ^= Htable[nlo].hi;
		Z.lo ^= Htable[nlo].lo;
	}

	if (is_endian.little) {
#ifdef BSWAP8
		Xi[0] = BSWAP8(Z.hi);
		Xi[1] = BSWAP8(Z.lo);
#else
		u8 *p = (u8 *)Xi;
		u32 v;
		v = (u32)(Z.hi>>32);	PUTU32(p,v);
		v = (u32)(Z.hi);	PUTU32(p+4,v);
		v = (u32)(Z.lo>>32);	PUTU32(p+8,v);
		v = (u32)(Z.lo);	PUTU32(p+12,v);
#endif
	}
	else {
		Xi[0] = Z.hi;
		Xi[1] = Z.lo;
	}
}

#if !defined(OPENSSL_SMALL_FOOTPRINT)
/*
 * Streamed gcm_mult_4bit, see CRYPTO_gcm128_[en|de]crypt for
 * details... Compiler-generated code doesn't seem to give any
 * performance improvement, at least not on x86[_64]. It's here
 * mostly as reference and a placeholder for possible future
 * non-trivial optimization[s]...
 */
static void gcm_ghash_4bit(u64 Xi[2],const u128 Htable[16],
				const u8 *inp,size_t len)
{
    u128 Z;
    int cnt;
    size_t rem, nlo, nhi;
    const union { long one; char little; } is_endian = {1};

#if 1
    do {
	cnt  = 15;
	nlo  = ((const u8 *)Xi)[15];
	nlo ^= inp[15];
	nhi  = nlo>>4;
	nlo &= 0xf;

	Z.hi = Htable[nlo].hi;
	Z.lo = Htable[nlo].lo;

	while (1) {
		rem  = (size_t)Z.lo&0xf;
		Z.lo = (Z.hi<<60)|(Z.lo>>4);
		Z.hi = (Z.hi>>4);
		if (sizeof(size_t)==8)
			Z.hi ^= rem_4bit[rem];
		else
			Z.hi ^= (u64)rem_4bit[rem]<<32;

		Z.hi ^= Htable[nhi].hi;
		Z.lo ^= Htable[nhi].lo;

		if (--cnt<0)		break;

		nlo  = ((const u8 *)Xi)[cnt];
		nlo ^= inp[cnt];
		nhi  = nlo>>4;
		nlo &= 0xf;

		rem  = (size_t)Z.lo&0xf;
		Z.lo = (Z.hi<<60)|(Z.lo>>4);
		Z.hi = (Z.hi>>4);
		if (sizeof(size_t)==8)
			Z.hi ^= rem_4bit[rem];
		else
			Z.hi ^= (u64)rem_4bit[rem]<<32;

		Z.hi ^= Htable[nlo].hi;
		Z.lo ^= Htable[nlo].lo;
	}
#else
    /*
     * Extra 256+16 bytes per-key plus 512 bytes shared tables
     * [should] give ~50% improvement... One could have PACK()-ed
     * the rem_8bit even here, but the priority is to minimize
     * cache footprint...
     */ 
    u128 Hshr4[16];	/* Htable shifted right by 4 bits */
    u8   Hshl4[16];	/* Htable shifted left  by 4 bits */
    static const unsigned short rem_8bit[256] = {
	0x0000, 0x01C2, 0x0384, 0x0246, 0x0708, 0x06CA, 0x048C, 0x054E,
	0x0E10, 0x0FD2, 0x0D94, 0x0C56, 0x0918, 0x08DA, 0x0A9C, 0x0B5E,
	0x1C20, 0x1DE2, 0x1FA4, 0x1E66, 0x1B28, 0x1AEA, 0x18AC, 0x196E,
	0x1230, 0x13F2, 0x11B4, 0x1076, 0x1538, 0x14FA, 0x16BC, 0x177E,
	0x3840, 0x3982, 0x3BC4, 0x3A06, 0x3F48, 0x3E8A, 0x3CCC, 0x3D0E,
	0x3650, 0x3792, 0x35D4, 0x3416, 0x3158, 0x309A, 0x32DC, 0x331E,
	0x2460, 0x25A2, 0x27E4, 0x2626, 0x2368, 0x22AA, 0x20EC, 0x212E,
	0x2A70, 0x2BB2, 0x29F4, 0x2836, 0x2D78, 0x2CBA, 0x2EFC, 0x2F3E,
	0x7080, 0x7142, 0x7304, 0x72C6, 0x7788, 0x764A, 0x740C, 0x75CE,
	0x7E90, 0x7F52, 0x7D14, 0x7CD6, 0x7998, 0x785A, 0x7A1C, 0x7BDE,
	0x6CA0, 0x6D62, 0x6F24, 0x6EE6, 0x6BA8, 0x6A6A, 0x682C, 0x69EE,
	0x62B0, 0x6372, 0x6134, 0x60F6, 0x65B8, 0x647A, 0x663C, 0x67FE,
	0x48C0, 0x4902, 0x4B44, 0x4A86, 0x4FC8, 0x4E0A, 0x4C4C, 0x4D8E,
	0x46D0, 0x4712, 0x4554, 0x4496, 0x41D8, 0x401A, 0x425C, 0x439E,
	0x54E0, 0x5522, 0x5764, 0x56A6, 0x53E8, 0x522A, 0x506C, 0x51AE,
	0x5AF0, 0x5B32, 0x5974, 0x58B6, 0x5DF8, 0x5C3A, 0x5E7C, 0x5FBE,
	0xE100, 0xE0C2, 0xE284, 0xE346, 0xE608, 0xE7CA, 0xE58C, 0xE44E,
	0xEF10, 0xEED2, 0xEC94, 0xED56, 0xE818, 0xE9DA, 0xEB9C, 0xEA5E,
	0xFD20, 0xFCE2, 0xFEA4, 0xFF66, 0xFA28, 0xFBEA, 0xF9AC, 0xF86E,
	0xF330, 0xF2F2, 0xF0B4, 0xF176, 0xF438, 0xF5FA, 0xF7BC, 0xF67E,
	0xD940, 0xD882, 0xDAC4, 0xDB06, 0xDE48, 0xDF8A, 0xDDCC, 0xDC0E,
	0xD750, 0xD692, 0xD4D4, 0xD516, 0xD058, 0xD19A, 0xD3DC, 0xD21E,
	0xC560, 0xC4A2, 0xC6E4, 0xC726, 0xC268, 0xC3AA, 0xC1EC, 0xC02E,
	0xCB70, 0xCAB2, 0xC8F4, 0xC936, 0xCC78, 0xCDBA, 0xCFFC, 0xCE3E,
	0x9180, 0x9042, 0x9204, 0x93C6, 0x9688, 0x974A, 0x950C, 0x94CE,
	0x9F90, 0x9E52, 0x9C14, 0x9DD6, 0x9898, 0x995A, 0x9B1C, 0x9ADE,
	0x8DA0, 0x8C62, 0x8E24, 0x8FE6, 0x8AA8, 0x8B6A, 0x892C, 0x88EE,
	0x83B0, 0x8272, 0x8034, 0x81F6, 0x84B8, 0x857A, 0x873C, 0x86FE,
	0xA9C0, 0xA802, 0xAA44, 0xAB86, 0xAEC8, 0xAF0A, 0xAD4C, 0xAC8E,
	0xA7D0, 0xA612, 0xA454, 0xA596, 0xA0D8, 0xA11A, 0xA35C, 0xA29E,
	0xB5E0, 0xB422, 0xB664, 0xB7A6, 0xB2E8, 0xB32A, 0xB16C, 0xB0AE,
	0xBBF0, 0xBA32, 0xB874, 0xB9B6, 0xBCF8, 0xBD3A, 0xBF7C, 0xBEBE };
    /*
     * This pre-processing phase slows down procedure by approximately
     * same time as it makes each loop spin faster. In other words
     * single block performance is approximately same as straightforward
     * "4-bit" implementation, and then it goes only faster...
     */
    for (cnt=0; cnt<16; ++cnt) {
	Z.hi = Htable[cnt].hi;
	Z.lo = Htable[cnt].lo;
	Hshr4[cnt].lo = (Z.hi<<60)|(Z.lo>>4);
	Hshr4[cnt].hi = (Z.hi>>4);
	Hshl4[cnt]    = (u8)(Z.lo<<4);
    }

    do {
	for (Z.lo=0, Z.hi=0, cnt=15; cnt; --cnt) {
		nlo  = ((const u8 *)Xi)[cnt];
		nlo ^= inp[cnt];
		nhi  = nlo>>4;
		nlo &= 0xf;

		Z.hi ^= Htable[nlo].hi;
		Z.lo ^= Htable[nlo].lo;

		rem = (size_t)Z.lo&0xff;

		Z.lo = (Z.hi<<56)|(Z.lo>>8);
		Z.hi = (Z.hi>>8);

		Z.hi ^= Hshr4[nhi].hi;
		Z.lo ^= Hshr4[nhi].lo;
		Z.hi ^= (u64)rem_8bit[rem^Hshl4[nhi]]<<48;
	}

	nlo  = ((const u8 *)Xi)[0];
	nlo ^= inp[0];
	nhi  = nlo>>4;
	nlo &= 0xf;

	Z.hi ^= Htable[nlo].hi;
	Z.lo ^= Htable[nlo].lo;

	rem = (size_t)Z.lo&0xf;

	Z.lo = (Z.hi<<60)|(Z.lo>>4);
	Z.hi = (Z.hi>>4);

	Z.hi ^= Htable[nhi].hi;
	Z.lo ^= Htable[nhi].lo;
	Z.hi ^= ((u64)rem_8bit[rem<<4])<<48;
#endif

	if (is_endian.little) {
#ifdef BSWAP8
		Xi[0] = BSWAP8(Z.hi);
		Xi[1] = BSWAP8(Z.lo);
#else
		u8 *p = (u8 *)Xi;
		u32 v;
		v = (u32)(Z.hi>>32);	PUTU32(p,v);
		v = (u32)(Z.hi);	PUTU32(p+4,v);
		v = (u32)(Z.lo>>32);	PUTU32(p+8,v);
		v = (u32)(Z.lo);	PUTU32(p+12,v);
#endif
	}
	else {
		Xi[0] = Z.hi;
		Xi[1] = Z.lo;
	}
    } while (inp+=16, len-=16);
}
#endif
#else
void gcm_gmult_4bit(u64 Xi[2],const u128 Htable[16]);
void gcm_ghash_4bit(u64 Xi[2],const u128 Htable[16],const u8 *inp,size_t len);
#endif

#define GCM_MUL(ctx,Xi)   gcm_gmult_4bit(ctx->Xi.u,(const u128*)(ctx->Htable))
#if defined(GHASH_ASM) || !defined(OPENSSL_SMALL_FOOTPRINT)
#define GHASH(ctx,in,len) gcm_ghash_4bit((ctx)->Xi.u,(const u128*)((ctx)->Htable),in,len)
/* GHASH_CHUNK is "stride parameter" missioned to mitigate cache
 * trashing effect. In other words idea is to hash data while it's
 * still in L1 cache after encryption pass... */
#define GHASH_CHUNK       (3*1024)
#endif

#endif

#if	TABLE_BITS==4 && defined(GHASH_ASM)
# if	!defined(I386_ONLY) && \
	(defined(__i386)	|| defined(__i386__)	|| \
	 defined(__x86_64)	|| defined(__x86_64__)	|| \
	 defined(_M_IX86)	|| defined(_M_AMD64)	|| defined(_M_X64))
#  define GHASH_ASM_X86_OR_64
#  define GCM_FUNCREF_4BIT

void gcm_init_clmul(u128 Htable[16],const u64 Xi[2]);
void gcm_gmult_clmul(u64 Xi[2],const u128 Htable[16]);
void gcm_ghash_clmul(u64 Xi[2],const u128 Htable[16],const u8 *inp,size_t len);

#  if	defined(__i386) || defined(__i386__) || defined(_M_IX86)
#   define GHASH_ASM_X86
void gcm_gmult_4bit_mmx(u64 Xi[2],const u128 Htable[16]);
void gcm_ghash_4bit_mmx(u64 Xi[2],const u128 Htable[16],const u8 *inp,size_t len);

void gcm_gmult_4bit_x86(u64 Xi[2],const u128 Htable[16]);
void gcm_ghash_4bit_x86(u64 Xi[2],const u128 Htable[16],const u8 *inp,size_t len);
#  endif
# elif defined(__arm__) || defined(__arm)
#  include "arm_arch.h"
#  if __ARM_ARCH__>=7
#   define GHASH_ASM_ARM
#   define GCM_FUNCREF_4BIT
void gcm_gmult_neon(u64 Xi[2],const u128 Htable[16]);
void gcm_ghash_neon(u64 Xi[2],const u128 Htable[16],const u8 *inp,size_t len);
#  endif
# endif
#endif

#ifdef GCM_FUNCREF_4BIT
# undef  GCM_MUL
# define GCM_MUL(ctx,Xi)	(*gcm_gmult_p)(ctx->Xi.u,ctx->Htable)
# ifdef GHASH
#  undef  GHASH
#  define GHASH(ctx,in,len)	(*gcm_ghash_p)(ctx->Xi.u,ctx->Htable,in,len)
# endif
#endif

#if	TABLE_BITS!=4
int CRYPTO_lea_gcm128_encrypt(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
size_t len){
	return CRYPTO_gcm128_encrypt(ctx,in,out,len);
}

int CRYPTO_lea_gcm128_decrypt(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
size_t len){
	return CRYPTO_gcm128_decrypt(ctx,in,out,len);
}
#else
int CRYPTO_lea_gcm128_encrypt(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len)
{
	const union { long one; char little; } is_endian = {1};
	unsigned int n, ctr;
	size_t i;
	u64        mlen  = ctx->len.u[1];
	block128_f block = ctx->block;
	void      *key   = ctx->key;
#ifdef GCM_FUNCREF_4BIT
	void (*gcm_gmult_p)(u64 Xi[2],const u128 Htable[16])	= ctx->gmult;
# ifdef GHASH
	void (*gcm_ghash_p)(u64 Xi[2],const u128 Htable[16],
				const u8 *inp,size_t len)	= ctx->ghash;
# endif
#endif

#if defined(COMPILE_SSE2) || defined(COMPILE_NEON) || defined(COMPILE_XOP)
	void (*lea_encrypt_4block)(unsigned char*,const unsigned char*,const LEA_KEY*) = NULL;
#endif

#if 0
	n = (unsigned int)mlen%16; /* alternative to ctx->mres */
#endif
	mlen += len;
	if (mlen>((U64(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
		return -1;
	ctx->len.u[1] = mlen;

	if (ctx->ares) {
		/* First call to encrypt finalizes GHASH(AAD) */
		GCM_MUL(ctx,Xi);
		ctx->ares = 0;
	}

	if (is_endian.little)
#ifdef BSWAP4
		ctr = BSWAP4(ctx->Yi.d[3]);
#else
		ctr = GETU32(ctx->Yi.c+12);
#endif
	else
		ctr = ctx->Yi.d[3];

	n = ctx->mres;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
	if (16%sizeof(size_t) == 0) do {	/* always true actually */
		if (n) {
			while (n && len) {
				ctx->Xi.c[n] ^= *(out++) = *(in++)^ctx->EKi.c[n];
				--len;
				n = (n+1)%16;
			}
			if (n==0) GCM_MUL(ctx,Xi);
			else {
				ctx->mres = n;
				return 0;
			}
		}
#if defined(STRICT_ALIGNMENT)
		if (((size_t)in|(size_t)out)%sizeof(size_t) != 0)
			break;
#endif	//#if defined(STRICT_ALIGNMENT)




#if 0 //jkkim@ ----- defined(COMPILE_AVX2) && defined(GHASH)
		if(AVX2_CAPABLE){
			while (len >= 128) {
				union { u32 d[32]; u8 c[128]; } tmp;
				int h = 0;
				
				tmp.d[0x00] = tmp.d[0x04] = tmp.d[0x08] = tmp.d[0x0c] = ctx->Yi.d[0];
				tmp.d[0x10] = tmp.d[0x14] = tmp.d[0x18] = tmp.d[0x1c] = ctx->Yi.d[0];
				tmp.d[0x01] = tmp.d[0x05] = tmp.d[0x09] = tmp.d[0x0d] = ctx->Yi.d[1];
				tmp.d[0x11] = tmp.d[0x15] = tmp.d[0x19] = tmp.d[0x1d] = ctx->Yi.d[1];
				tmp.d[0x02] = tmp.d[0x06] = tmp.d[0x0a] = tmp.d[0x0e] = ctx->Yi.d[2];
				tmp.d[0x12] = tmp.d[0x16] = tmp.d[0x1a] = tmp.d[0x1e] = ctx->Yi.d[2];

				if (is_endian.little)
				{
	#ifdef BSWAP4
					tmp.d[0x03] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x07] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x0b] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x0f] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x13] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x17] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x1b] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x1f] = BSWAP4(ctr);
					ctr++;
					ctx->Yi.d[3] = BSWAP4(ctr);
	#else	//#ifdef BSWAP4
					PUTU32(tmp.c + 0x0c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x1c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x2c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x3c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x4c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x5c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x6c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x7c, ctr);
					ctr++;
					PUTU32(ctx->Yi.c+12,ctr);
	#endif	//#ifdef BSWAP4
				}
				else
				{
					tmp.d[0x03] = ctr++;
					tmp.d[0x07] = ctr++;
					tmp.d[0x0b] = ctr++;
					tmp.d[0x0f] = ctr++;
					tmp.d[0x13] = ctr++;
					tmp.d[0x17] = ctr++;
					tmp.d[0x1b] = ctr++;
					tmp.d[0x1f] = ctr++;
					ctx->Yi.d[3] = ctr;
				}
						
				lea_encrypt_8block_avx2(tmp.c, tmp.c, key);
				
				for(h = 0; h < 8; h++)
				{
				    	size_t *out_t = (size_t *)out;
				    	const size_t *in_t = (const size_t *)in;
					size_t *tmp_t = (size_t *)((unsigned char *)&tmp + (h << 4));
					
					for(i = 0; i < (16 / sizeof(size_t)); ++i)
						out_t[i] = in_t[i] ^ tmp_t[i];
					
					out += 16;
					in  += 16;
					len -= 16;
				}
				
				GHASH(ctx, out - 128, 128);
			}
		}
#endif	//#if defined(COMPILE_AVX2) && defined(GHASH)


#if 0 //jkkim@-----remark (defined(COMPILE_SSE2) || defined(COMPILE_NEON) || defined(COMPILE_XOP)) && defined(GHASH)
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
			
			if(lea_encrypt_4block != NULL){
				while (len >= 64) {
					union { u32 d[16]; u8 c[64]; } tmp;
					int h = 0;
					
					tmp.d[0x0] = tmp.d[0x4] = tmp.d[0x8] = tmp.d[0xc] = ctx->Yi.d[0];
					tmp.d[0x1] = tmp.d[0x5] = tmp.d[0x9] = tmp.d[0xd] = ctx->Yi.d[1];
					tmp.d[0x2] = tmp.d[0x6] = tmp.d[0xa] = tmp.d[0xe] = ctx->Yi.d[2];

					if (is_endian.little)
					{
		#ifdef BSWAP4
						tmp.d[0x3] = BSWAP4(ctr);
						ctr++;
						tmp.d[0x7] = BSWAP4(ctr);
						ctr++;
						tmp.d[0xb] = BSWAP4(ctr);
						ctr++;
						tmp.d[0xf] = BSWAP4(ctr);
						ctr++;
						ctx->Yi.d[3] = BSWAP4(ctr);
		#else	//#ifdef BSWAP4
						PUTU32(tmp.c + 0x0c, ctr);
						ctr++;
						PUTU32(tmp.c + 0x1c, ctr);
						ctr++;
						PUTU32(tmp.c + 0x2c, ctr);
						ctr++;
						PUTU32(tmp.c + 0x3c, ctr);
						ctr++;
						PUTU32(ctx->Yi.c+12,ctr);
		#endif	//#ifdef BSWAP4
					}
					else
					{
						tmp.d[0x3] = ctr++;
						tmp.d[0x7] = ctr++;
						tmp.d[0xb] = ctr++;
						tmp.d[0xf] = ctr++;
						ctx->Yi.d[3] = ctr;
					}
							
					lea_encrypt_4block(tmp.c, tmp.c, key);
					
					for(h = 0; h < 4; h++)
					{
					    	size_t *out_t = (size_t *)out;
					    	const size_t *in_t = (const size_t *)in;
						size_t *tmp_t = (size_t *)((unsigned char *)&tmp + (h << 4));
						
						for(i = 0; i < (16 / sizeof(size_t)); ++i)
							out_t[i] = in_t[i] ^ tmp_t[i];
						
						out += 16;
						in  += 16;
						len -= 16;
					}
					
					GHASH(ctx, out - 64, 64);
				}
			}
		}
#endif	//#if SSE2, NEON, XOP && defined(GHASH)

		while (len>=16) {
		    	size_t *out_t=(size_t *)out;
		    	const size_t *in_t=(const size_t *)in;

			(*block)(ctx->Yi.c,ctx->EKi.c,key);
			++ctr;
			if (is_endian.little)
#ifdef BSWAP4
				ctx->Yi.d[3] = BSWAP4(ctr);
#else	//#ifdef BSWAP4
				PUTU32(ctx->Yi.c+12,ctr);
#endif	//#ifdef BSWAP4
			else
				ctx->Yi.d[3] = ctr;
			for (i=0; i<16/sizeof(size_t); ++i)
				ctx->Xi.t[i] ^=
				out_t[i] = in_t[i]^ctx->EKi.t[i];
			GCM_MUL(ctx,Xi);
			out += 16;
			in  += 16;
			len -= 16;
		}

		if (len) {
			(*block)(ctx->Yi.c,ctx->EKi.c,key);
			++ctr;
			if (is_endian.little)
#ifdef BSWAP4
				ctx->Yi.d[3] = BSWAP4(ctr);
#else	//#ifdef BSWAP4
				PUTU32(ctx->Yi.c+12,ctr);
#endif	//#ifdef BSWAP4
			else
				ctx->Yi.d[3] = ctr;
			while (len--) {
				ctx->Xi.c[n] ^= out[n] = in[n]^ctx->EKi.c[n];
				++n;
			}
		}

		ctx->mres = n;
		return 0;
	} while(0);
#endif
	for (i=0;i<len;++i) {
		if (n==0) {
			(*block)(ctx->Yi.c,ctx->EKi.c,key);
			++ctr;
			if (is_endian.little)
#ifdef BSWAP4
				ctx->Yi.d[3] = BSWAP4(ctr);
#else
				PUTU32(ctx->Yi.c+12,ctr);
#endif
			else
				ctx->Yi.d[3] = ctr;
		}
		ctx->Xi.c[n] ^= out[i] = in[i]^ctx->EKi.c[n];
		n = (n+1)%16;
		if (n==0)
			GCM_MUL(ctx,Xi);
	}

	ctx->mres = n;
	return 0;
}

int CRYPTO_lea_gcm128_decrypt(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len)
{
	const union { long one; char little; } is_endian = {1};
	unsigned int n, ctr;
	size_t i;
	u64        mlen  = ctx->len.u[1];
	block128_f block = ctx->block;
	void      *key   = ctx->key;
#ifdef GCM_FUNCREF_4BIT
	void (*gcm_gmult_p)(u64 Xi[2],const u128 Htable[16])	= ctx->gmult;
# ifdef GHASH
	void (*gcm_ghash_p)(u64 Xi[2],const u128 Htable[16],
				const u8 *inp,size_t len)	= ctx->ghash;
# endif
#endif

#if defined(COMPILE_SSE2) || defined(COMPILE_NEON) || defined(COMPILE_XOP)
	void (*lea_encrypt_4block)(unsigned char*,const unsigned char*,const LEA_KEY*) = NULL;
#endif

	mlen += len;
	if (mlen>((U64(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
		return -1;
	ctx->len.u[1] = mlen;

	if (ctx->ares) {
		/* First call to decrypt finalizes GHASH(AAD) */
		GCM_MUL(ctx,Xi);
		ctx->ares = 0;
	}

	if (is_endian.little)
#ifdef BSWAP4
		ctr = BSWAP4(ctx->Yi.d[3]);
#else
		ctr = GETU32(ctx->Yi.c+12);
#endif
	else
		ctr = ctx->Yi.d[3];

	n = ctx->mres;
#if !defined(OPENSSL_SMALL_FOOTPRINT)
	if (16%sizeof(size_t) == 0) do {	/* always true actually */
		if (n) {
			while (n && len) {
				u8 c = *(in++);
				*(out++) = c^ctx->EKi.c[n];
				ctx->Xi.c[n] ^= c;
				--len;
				n = (n+1)%16;
			}
			if (n==0) GCM_MUL (ctx,Xi);
			else {
				ctx->mres = n;
				return 0;
			}
		}
#if defined(STRICT_ALIGNMENT)
		if (((size_t)in|(size_t)out)%sizeof(size_t) != 0)
			break;
#endif



#if 0 // defined(COMPILE_AVX2) && defined(GHASH)
		if(AVX2_CAPABLE){

			while (len >= 128) {
				union { u32 d[32]; u8 c[128]; } tmp;
				int h = 0;
				
				GHASH(ctx, in, 128);
				
				tmp.d[0x00] = tmp.d[0x04] = tmp.d[0x08] = tmp.d[0x0c] = ctx->Yi.d[0];
				tmp.d[0x10] = tmp.d[0x14] = tmp.d[0x18] = tmp.d[0x1c] = ctx->Yi.d[0];
				tmp.d[0x01] = tmp.d[0x05] = tmp.d[0x09] = tmp.d[0x0d] = ctx->Yi.d[1];
				tmp.d[0x11] = tmp.d[0x15] = tmp.d[0x19] = tmp.d[0x1d] = ctx->Yi.d[1];
				tmp.d[0x02] = tmp.d[0x06] = tmp.d[0x0a] = tmp.d[0x0e] = ctx->Yi.d[2];
				tmp.d[0x12] = tmp.d[0x16] = tmp.d[0x1a] = tmp.d[0x1e] = ctx->Yi.d[2];

				if (is_endian.little)
				{
	#ifdef BSWAP4
					tmp.d[0x03] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x07] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x0b] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x0f] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x13] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x17] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x1b] = BSWAP4(ctr);
					ctr++;
					tmp.d[0x1f] = BSWAP4(ctr);
					ctr++;
					ctx->Yi.d[3] = BSWAP4(ctr);
	#else	//#ifdef BSWAP4
					PUTU32(tmp.c + 0x0c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x1c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x2c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x3c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x4c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x5c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x6c, ctr);
					ctr++;
					PUTU32(tmp.c + 0x7c, ctr);
					ctr++;
					PUTU32(ctx->Yi.c+12,ctr);
	#endif	//#ifdef BSWAP4
				}
				else
				{
					tmp.d[0x03] = ctr++;
					tmp.d[0x07] = ctr++;
					tmp.d[0x0b] = ctr++;
					tmp.d[0x0f] = ctr++;
					tmp.d[0x13] = ctr++;
					tmp.d[0x17] = ctr++;
					tmp.d[0x1b] = ctr++;
					tmp.d[0x1f] = ctr++;
					ctx->Yi.d[3] = ctr;
				}
						
				lea_encrypt_8block_avx2(tmp.c, tmp.c, key);
				
				for(h = 0; h < 8; h++)
				{
				    	size_t *out_t = (size_t *)out;
				    	const size_t *in_t = (const size_t *)in;
					size_t *tmp_t = (size_t *)((unsigned char *)&tmp + (h << 4));
					
					for(i = 0; i < (16 / sizeof(size_t)); ++i)
						out_t[i] = in_t[i] ^ tmp_t[i];
					
					out += 16;
					in  += 16;
					len -= 16;
				}
			}
		}

#endif	//#if defined(COMPILE_AVX2) && defined(GHASH)


#if 0 //jkkim@----- (defined(COMPILE_SSE2) || defined(COMPILE_NEON) || defined(COMPILE_XOP)) && defined(GHASH)
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
			
			if(lea_encrypt_4block != NULL){

				while (len >= 64) {
					union { u32 d[16]; u8 c[64]; } tmp;
					int h = 0;
					
					GHASH(ctx, in, 64);
					
					tmp.d[0x0] = tmp.d[0x4] = tmp.d[0x8] = tmp.d[0xc] = ctx->Yi.d[0];
					tmp.d[0x1] = tmp.d[0x5] = tmp.d[0x9] = tmp.d[0xd] = ctx->Yi.d[1];
					tmp.d[0x2] = tmp.d[0x6] = tmp.d[0xa] = tmp.d[0xe] = ctx->Yi.d[2];

					if (is_endian.little)
					{
		#ifdef BSWAP4
						tmp.d[0x3] = BSWAP4(ctr);
						ctr++;
						tmp.d[0x7] = BSWAP4(ctr);
						ctr++;
						tmp.d[0xb] = BSWAP4(ctr);
						ctr++;
						tmp.d[0xf] = BSWAP4(ctr);
						ctr++;
						ctx->Yi.d[3] = BSWAP4(ctr);
		#else	//#ifdef BSWAP4
						PUTU32(tmp.c + 0x0c, ctr);
						ctr++;
						PUTU32(tmp.c + 0x1c, ctr);
						ctr++;
						PUTU32(tmp.c + 0x2c, ctr);
						ctr++;
						PUTU32(tmp.c + 0x3c, ctr);
						ctr++;
						PUTU32(ctx->Yi.c+12,ctr);
		#endif	//#ifdef BSWAP4
					}
					else
					{
						tmp.d[0x3] = ctr++;
						tmp.d[0x7] = ctr++;
						tmp.d[0xb] = ctr++;
						tmp.d[0xf] = ctr++;
						ctx->Yi.d[3] = ctr;
					}
							
					lea_encrypt_4block(tmp.c, tmp.c, key);
					
					for(h = 0; h < 4; h++)
					{
					    	size_t *out_t = (size_t *)out;
					    	const size_t *in_t = (const size_t *)in;
						size_t *tmp_t = (size_t *)((unsigned char *)&tmp + (h << 4));
						
						for(i = 0; i < (16 / sizeof(size_t)); ++i)
							out_t[i] = in_t[i] ^ tmp_t[i];
						
						out += 16;
						in  += 16;
						len -= 16;
					}
				}
			}
		}

#endif	//#if SSE2, XOP, NEON && defined(GHASH)



		while (len>=16) {
		    	size_t *out_t=(size_t *)out;
		    	const size_t *in_t=(const size_t *)in;

			(*block)(ctx->Yi.c,ctx->EKi.c,key);
			++ctr;
			if (is_endian.little)
#ifdef BSWAP4
				ctx->Yi.d[3] = BSWAP4(ctr);
#else	//#ifdef BSWAP4
				PUTU32(ctx->Yi.c+12,ctr);
#endif	//#ifdef BSWAP4
			else
				ctx->Yi.d[3] = ctr;
			for (i=0; i<16/sizeof(size_t); ++i) {
				size_t c = in_t[i];
				out_t[i] = c^ctx->EKi.t[i];
				ctx->Xi.t[i] ^= c;
			}
			GCM_MUL(ctx,Xi);
			out += 16;
			in  += 16;
			len -= 16;
		}

		if (len) {
			(*block)(ctx->Yi.c,ctx->EKi.c,key);
			++ctr;
			if (is_endian.little)
#ifdef BSWAP4
				ctx->Yi.d[3] = BSWAP4(ctr);
#else
				PUTU32(ctx->Yi.c+12,ctr);
#endif
			else
				ctx->Yi.d[3] = ctr;
			while (len--) {
				u8 c = in[n];
				ctx->Xi.c[n] ^= c;
				out[n] = c^ctx->EKi.c[n];
				++n;
			}
		}

		ctx->mres = n;
		return 0;
	} while(0);
#endif
	for (i=0;i<len;++i) {
		u8 c;
		if (n==0) {
			(*block)(ctx->Yi.c,ctx->EKi.c,key);
			++ctr;
			if (is_endian.little)
#ifdef BSWAP4
				ctx->Yi.d[3] = BSWAP4(ctr);
#else
				PUTU32(ctx->Yi.c+12,ctr);
#endif
			else
				ctx->Yi.d[3] = ctr;
		}
		c = in[i];
		out[i] = c^ctx->EKi.c[n];
		ctx->Xi.c[n] ^= c;
		n = (n+1)%16;
		if (n==0)
			GCM_MUL(ctx,Xi);
	}

	ctx->mres = n;
	return 0;
}

int CRYPTO_lea_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len, ctr128_f stream)
{
	const union { long one; char little; } is_endian = {1};
	unsigned int n, ctr;
	size_t i;
	u64   mlen = ctx->len.u[1];
	void *key  = ctx->key;
#ifdef GCM_FUNCREF_4BIT
	void (*gcm_gmult_p)(u64 Xi[2],const u128 Htable[16])	= ctx->gmult;
# ifdef GHASH
	void (*gcm_ghash_p)(u64 Xi[2],const u128 Htable[16],
				const u8 *inp,size_t len)	= ctx->ghash;
# endif
#endif

	mlen += len;
	if (mlen>((U64(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
		return -1;
	ctx->len.u[1] = mlen;

	if (ctx->ares) {
		/* First call to encrypt finalizes GHASH(AAD) */
		GCM_MUL(ctx,Xi);
		ctx->ares = 0;
	}

	if (is_endian.little)
#ifdef BSWAP4
		ctr = BSWAP4(ctx->Yi.d[3]);
#else
		ctr = GETU32(ctx->Yi.c+12);
#endif
	else
		ctr = ctx->Yi.d[3];

	n = ctx->mres;
	if (n) {
		while (n && len) {
			ctx->Xi.c[n] ^= *(out++) = *(in++)^ctx->EKi.c[n];
			--len;
			n = (n+1)%16;
		}
		if (n==0) GCM_MUL(ctx,Xi);
		else {
			ctx->mres = n;
			return 0;
		}
	}
#if defined(GHASH) && !defined(OPENSSL_SMALL_FOOTPRINT)
	while (len>=GHASH_CHUNK) {
		(*stream)(in,out,GHASH_CHUNK/16,key,ctx->Yi.c);
		ctr += GHASH_CHUNK/16;
		if (is_endian.little)
#ifdef BSWAP4
			ctx->Yi.d[3] = BSWAP4(ctr);
#else
			PUTU32(ctx->Yi.c+12,ctr);
#endif
		else
			ctx->Yi.d[3] = ctr;
		GHASH(ctx,out,GHASH_CHUNK);
		out += GHASH_CHUNK;
		in  += GHASH_CHUNK;
		len -= GHASH_CHUNK;
	}
#endif
	if ((i = (len&(size_t)-16))) {
		size_t j=i/16;

		(*stream)(in,out,j,key,ctx->Yi.c);
		ctr += (unsigned int)j;
		if (is_endian.little)
#ifdef BSWAP4
			ctx->Yi.d[3] = BSWAP4(ctr);
#else
			PUTU32(ctx->Yi.c+12,ctr);
#endif
		else
			ctx->Yi.d[3] = ctr;
		in  += i;
		len -= i;
#if defined(GHASH)
		GHASH(ctx,out,i);
		out += i;
#else
		while (j--) {
			for (i=0;i<16;++i) ctx->Xi.c[i] ^= out[i];
			GCM_MUL(ctx,Xi);
			out += 16;
		}
#endif
	}
	if (len) {
		(*ctx->block)(ctx->Yi.c,ctx->EKi.c,key);
		++ctr;
		if (is_endian.little)
#ifdef BSWAP4
			ctx->Yi.d[3] = BSWAP4(ctr);
#else
			PUTU32(ctx->Yi.c+12,ctr);
#endif
		else
			ctx->Yi.d[3] = ctr;
		while (len--) {
			ctx->Xi.c[n] ^= out[n] = in[n]^ctx->EKi.c[n];
			++n;
		}
	}

	ctx->mres = n;
	return 0;
}
#endif /* TABLEBIT=4 */
