#include <openssl/lea.h>
#include "lea_locl.h"


#ifdef COMPILE_NEON

#if !defined(__ARM_NEON__)
#error "turn on NEON flag for lea_neon.c"
#endif

#include <arm_neon.h>

#ifdef __ARMEL__

#define VROTL(x,i) vsriq_n_u32(vshlq_n_u32(x,i),x,32-i)
#define VROTR(x,i) vsliq_n_u32(vshrq_n_u32(x,i),x,32-i)

#define XAR3(cur, pre, tmp, rk1, rk2)																			\
	tmp = vaddq_u32(veorq_u32(pre, vdupq_n_u32(rk1)), veorq_u32(cur, vdupq_n_u32(rk2)));		\
	cur = VROTR(tmp, 3);
#define XAR5(cur, pre, tmp, rk1, rk2)																			\
	tmp = vaddq_u32(veorq_u32(pre, vdupq_n_u32(rk1)), veorq_u32(cur, vdupq_n_u32(rk2)));		\
	cur = VROTR(tmp, 5);
#define XAR9(cur, pre, tmp, rk1, rk2)																			\
	tmp = vaddq_u32(veorq_u32(pre, vdupq_n_u32(rk1)), veorq_u32(cur, vdupq_n_u32(rk2)));		\
	cur = VROTR(tmp, 23);

#define XSR9(cur, pre, rk1, rk2)																																		\
	cur = veorq_u32(vsubq_u32(VROTR(cur,9), veorq_u32(pre, vdupq_n_u32(rk1))), vdupq_n_u32(rk2));
#define XSR5(cur, pre, rk1, rk2)																																		\
	cur = veorq_u32(vsubq_u32(VROTR(cur, 27), veorq_u32(pre, vdupq_n_u32(rk1))), vdupq_n_u32(rk2));
#define XSR3(cur, pre, rk1, rk2)																																		\
	cur = veorq_u32(vsubq_u32(VROTR(cur, 29), veorq_u32(pre, vdupq_n_u32(rk1))), vdupq_n_u32(rk2));

#define x3 x.val[3]
#define x2 x.val[2]
#define x1 x.val[1]
#define x0 x.val[0]

#else

#define XAR3(cur, pre, tmp, rk1, rk2)																			\
	tmp = vaddq_u32(veorq_u32(pre, vdupq_n_u32(rk1)), veorq_u32(cur, vdupq_n_u32(rk2)));		\
	cur = veorq_u32(vshrq_n_u32(tmp, 3), vshlq_n_u32(tmp, 29));
#define XAR5(cur, pre, tmp, rk1, rk2)																			\
	tmp = vaddq_u32(veorq_u32(pre, vdupq_n_u32(rk1)), veorq_u32(cur, vdupq_n_u32(rk2)));		\
	cur = veorq_u32(vshrq_n_u32(tmp, 5), vshlq_n_u32(tmp, 27));
#define XAR9(cur, pre, tmp, rk1, rk2)																			\
	tmp = vaddq_u32(veorq_u32(pre, vdupq_n_u32(rk1)), veorq_u32(cur, vdupq_n_u32(rk2)));		\
	cur = veorq_u32(vshrq_n_u32(tmp, 23), vshlq_n_u32(tmp, 9));

#define XSR9(cur, pre, rk1, rk2)																																		\
	cur = veorq_u32(vsubq_u32(veorq_u32(vshrq_n_u32(cur, 9), vshlq_n_u32(cur, 23)), veorq_u32(pre, vdupq_n_u32(rk1))), vdupq_n_u32(rk2));
#define XSR5(cur, pre, rk1, rk2)																																		\
	cur = veorq_u32(vsubq_u32(veorq_u32(vshrq_n_u32(cur, 27), vshlq_n_u32(cur, 5)), veorq_u32(pre, vdupq_n_u32(rk1))), vdupq_n_u32(rk2));
#define XSR3(cur, pre, rk1, rk2)																																		\
	cur = veorq_u32(vsubq_u32(veorq_u32(vshrq_n_u32(cur, 29), vshlq_n_u32(cur, 3)), veorq_u32(pre, vdupq_n_u32(rk1))), vdupq_n_u32(rk2));

#define NEONtoMEM(neon, nth, mem, tmp)		\
	*(tmp) = vgetq_lane_u32(neon, nth);		\
	wtoc(tmp, mem);

#endif

void lea_encrypt_4block_neon(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key)
{
#ifdef __ARMEL__
	uint32x4x4_t x;
	uint32x4_t tmp;
	
	x = vld4q_u32((unsigned int*)pt);
#else
	uint32x4_t x0, x1, x2, x3, tmp;
	unsigned int t[4], itmp;

	ctow(pt       , t    );
	ctow(pt + 0x10, t + 1);
	ctow(pt + 0x20, t + 2);
	ctow(pt + 0x30, t + 3);
	x0 = vld1q_u32(t);

	ctow(pt + 0x04, t    );
	ctow(pt + 0x14, t + 1);
	ctow(pt + 0x24, t + 2);
	ctow(pt + 0x34, t + 3);
	x1 = vld1q_u32(t);

	ctow(pt + 0x08, t    );
	ctow(pt + 0x18, t + 1);
	ctow(pt + 0x28, t + 2);
	ctow(pt + 0x38, t + 3);
	x2 = vld1q_u32(t);

	ctow(pt + 0x0c, t    );
	ctow(pt + 0x1c, t + 1);
	ctow(pt + 0x2c, t + 2);
	ctow(pt + 0x3c, t + 3);
	x3 = vld1q_u32(t);
#endif

	XAR3(x3, x2, tmp, key->rd_key[  4], key->rd_key[  5]);
	XAR5(x2, x1, tmp, key->rd_key[  2], key->rd_key[  3]);
	XAR9(x1, x0, tmp, key->rd_key[  0], key->rd_key[  1]);
	XAR3(x0, x3, tmp, key->rd_key[ 10], key->rd_key[ 11]);
	XAR5(x3, x2, tmp, key->rd_key[  8], key->rd_key[  9]);
	XAR9(x2, x1, tmp, key->rd_key[  6], key->rd_key[  7]);
	XAR3(x1, x0, tmp, key->rd_key[ 16], key->rd_key[ 17]);
	XAR5(x0, x3, tmp, key->rd_key[ 14], key->rd_key[ 15]);
	XAR9(x3, x2, tmp, key->rd_key[ 12], key->rd_key[ 13]);
	XAR3(x2, x1, tmp, key->rd_key[ 22], key->rd_key[ 23]);
	XAR5(x1, x0, tmp, key->rd_key[ 20], key->rd_key[ 21]);
	XAR9(x0, x3, tmp, key->rd_key[ 18], key->rd_key[ 19]);

	XAR3(x3, x2, tmp, key->rd_key[ 28], key->rd_key[ 29]);
	XAR5(x2, x1, tmp, key->rd_key[ 26], key->rd_key[ 27]);
	XAR9(x1, x0, tmp, key->rd_key[ 24], key->rd_key[ 25]);
	XAR3(x0, x3, tmp, key->rd_key[ 34], key->rd_key[ 35]);
	XAR5(x3, x2, tmp, key->rd_key[ 32], key->rd_key[ 33]);
	XAR9(x2, x1, tmp, key->rd_key[ 30], key->rd_key[ 31]);
	XAR3(x1, x0, tmp, key->rd_key[ 40], key->rd_key[ 41]);
	XAR5(x0, x3, tmp, key->rd_key[ 38], key->rd_key[ 39]);
	XAR9(x3, x2, tmp, key->rd_key[ 36], key->rd_key[ 37]);
	XAR3(x2, x1, tmp, key->rd_key[ 46], key->rd_key[ 47]);
	XAR5(x1, x0, tmp, key->rd_key[ 44], key->rd_key[ 45]);
	XAR9(x0, x3, tmp, key->rd_key[ 42], key->rd_key[ 43]);

	XAR3(x3, x2, tmp, key->rd_key[ 52], key->rd_key[ 53]);
	XAR5(x2, x1, tmp, key->rd_key[ 50], key->rd_key[ 51]);
	XAR9(x1, x0, tmp, key->rd_key[ 48], key->rd_key[ 49]);
	XAR3(x0, x3, tmp, key->rd_key[ 58], key->rd_key[ 59]);
	XAR5(x3, x2, tmp, key->rd_key[ 56], key->rd_key[ 57]);
	XAR9(x2, x1, tmp, key->rd_key[ 54], key->rd_key[ 55]);
	XAR3(x1, x0, tmp, key->rd_key[ 64], key->rd_key[ 65]);
	XAR5(x0, x3, tmp, key->rd_key[ 62], key->rd_key[ 63]);
	XAR9(x3, x2, tmp, key->rd_key[ 60], key->rd_key[ 61]);
	XAR3(x2, x1, tmp, key->rd_key[ 70], key->rd_key[ 71]);
	XAR5(x1, x0, tmp, key->rd_key[ 68], key->rd_key[ 69]);
	XAR9(x0, x3, tmp, key->rd_key[ 66], key->rd_key[ 67]);

	XAR3(x3, x2, tmp, key->rd_key[ 76], key->rd_key[ 77]);
	XAR5(x2, x1, tmp, key->rd_key[ 74], key->rd_key[ 75]);
	XAR9(x1, x0, tmp, key->rd_key[ 72], key->rd_key[ 73]);
	XAR3(x0, x3, tmp, key->rd_key[ 82], key->rd_key[ 83]);
	XAR5(x3, x2, tmp, key->rd_key[ 80], key->rd_key[ 81]);
	XAR9(x2, x1, tmp, key->rd_key[ 78], key->rd_key[ 79]);
	XAR3(x1, x0, tmp, key->rd_key[ 88], key->rd_key[ 89]);
	XAR5(x0, x3, tmp, key->rd_key[ 86], key->rd_key[ 87]);
	XAR9(x3, x2, tmp, key->rd_key[ 84], key->rd_key[ 85]);
	XAR3(x2, x1, tmp, key->rd_key[ 94], key->rd_key[ 95]);
	XAR5(x1, x0, tmp, key->rd_key[ 92], key->rd_key[ 93]);
	XAR9(x0, x3, tmp, key->rd_key[ 90], key->rd_key[ 91]);

	XAR3(x3, x2, tmp, key->rd_key[100], key->rd_key[101]);
	XAR5(x2, x1, tmp, key->rd_key[ 98], key->rd_key[ 99]);
	XAR9(x1, x0, tmp, key->rd_key[ 96], key->rd_key[ 97]);
	XAR3(x0, x3, tmp, key->rd_key[106], key->rd_key[107]);
	XAR5(x3, x2, tmp, key->rd_key[104], key->rd_key[105]);
	XAR9(x2, x1, tmp, key->rd_key[102], key->rd_key[103]);
	XAR3(x1, x0, tmp, key->rd_key[112], key->rd_key[113]);
	XAR5(x0, x3, tmp, key->rd_key[110], key->rd_key[111]);
	XAR9(x3, x2, tmp, key->rd_key[108], key->rd_key[109]);
	XAR3(x2, x1, tmp, key->rd_key[118], key->rd_key[119]);
	XAR5(x1, x0, tmp, key->rd_key[116], key->rd_key[117]);
	XAR9(x0, x3, tmp, key->rd_key[114], key->rd_key[115]);

	XAR3(x3, x2, tmp, key->rd_key[124], key->rd_key[125]);
	XAR5(x2, x1, tmp, key->rd_key[122], key->rd_key[123]);
	XAR9(x1, x0, tmp, key->rd_key[120], key->rd_key[121]);
	XAR3(x0, x3, tmp, key->rd_key[130], key->rd_key[131]);
	XAR5(x3, x2, tmp, key->rd_key[128], key->rd_key[129]);
	XAR9(x2, x1, tmp, key->rd_key[126], key->rd_key[127]);
	XAR3(x1, x0, tmp, key->rd_key[136], key->rd_key[137]);
	XAR5(x0, x3, tmp, key->rd_key[134], key->rd_key[135]);
	XAR9(x3, x2, tmp, key->rd_key[132], key->rd_key[133]);
	XAR3(x2, x1, tmp, key->rd_key[142], key->rd_key[143]);
	XAR5(x1, x0, tmp, key->rd_key[140], key->rd_key[141]);
	XAR9(x0, x3, tmp, key->rd_key[138], key->rd_key[139]);

	if(key->rounds > 24)
	{
		XAR3(x3, x2, tmp, key->rd_key[148], key->rd_key[149]);
		XAR5(x2, x1, tmp, key->rd_key[146], key->rd_key[147]);
		XAR9(x1, x0, tmp, key->rd_key[144], key->rd_key[145]);
		XAR3(x0, x3, tmp, key->rd_key[154], key->rd_key[155]);
		XAR5(x3, x2, tmp, key->rd_key[152], key->rd_key[153]);
		XAR9(x2, x1, tmp, key->rd_key[150], key->rd_key[151]);
		XAR3(x1, x0, tmp, key->rd_key[160], key->rd_key[161]);
		XAR5(x0, x3, tmp, key->rd_key[158], key->rd_key[159]);
		XAR9(x3, x2, tmp, key->rd_key[156], key->rd_key[157]);
		XAR3(x2, x1, tmp, key->rd_key[166], key->rd_key[167]);
		XAR5(x1, x0, tmp, key->rd_key[164], key->rd_key[165]);
		XAR9(x0, x3, tmp, key->rd_key[162], key->rd_key[163]);
	}

	if(key->rounds > 28)
	{
		XAR3(x3, x2, tmp, key->rd_key[172], key->rd_key[173]);
		XAR5(x2, x1, tmp, key->rd_key[170], key->rd_key[171]);
		XAR9(x1, x0, tmp, key->rd_key[168], key->rd_key[169]);
		XAR3(x0, x3, tmp, key->rd_key[178], key->rd_key[179]);
		XAR5(x3, x2, tmp, key->rd_key[176], key->rd_key[177]);
		XAR9(x2, x1, tmp, key->rd_key[174], key->rd_key[175]);
		XAR3(x1, x0, tmp, key->rd_key[184], key->rd_key[185]);
		XAR5(x0, x3, tmp, key->rd_key[182], key->rd_key[183]);
		XAR9(x3, x2, tmp, key->rd_key[180], key->rd_key[181]);
		XAR3(x2, x1, tmp, key->rd_key[190], key->rd_key[191]);
		XAR5(x1, x0, tmp, key->rd_key[188], key->rd_key[189]);
		XAR9(x0, x3, tmp, key->rd_key[186], key->rd_key[187]);
	}

#ifdef __ARMEL__
	vst4q_u32((unsigned int *)ct, x);
#else
	NEONtoMEM(x0, 0, ct       , &itmp);
	NEONtoMEM(x1, 0, ct + 0x04, &itmp);
	NEONtoMEM(x2, 0, ct + 0x08, &itmp);
	NEONtoMEM(x3, 0, ct + 0x0c, &itmp);

	NEONtoMEM(x0, 1, ct + 0x10, &itmp);
	NEONtoMEM(x1, 1, ct + 0x14, &itmp);
	NEONtoMEM(x2, 1, ct + 0x18, &itmp);
	NEONtoMEM(x3, 1, ct + 0x1c, &itmp);

	NEONtoMEM(x0, 2, ct + 0x20, &itmp);
	NEONtoMEM(x1, 2, ct + 0x24, &itmp);
	NEONtoMEM(x2, 2, ct + 0x28, &itmp);
	NEONtoMEM(x3, 2, ct + 0x2c, &itmp);

	NEONtoMEM(x0, 3, ct + 0x30, &itmp);
	NEONtoMEM(x1, 3, ct + 0x34, &itmp);
	NEONtoMEM(x2, 3, ct + 0x38, &itmp);
	NEONtoMEM(x3, 3, ct + 0x3c, &itmp);
#endif
}

void lea_decrypt_4block_neon(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key)
{
#ifdef __ARMEL__
	uint32x4x4_t x;
	unsigned int t[4], itmp;

	x = vld4q_u32((unsigned int*)ct);
#else
	uint32x4_t x0, x1, x2, x3;
	unsigned int t[4], itmp;

	ctow(ct       , t    );
	ctow(ct + 0x10, t + 1);
	ctow(ct + 0x20, t + 2);
	ctow(ct + 0x30, t + 3);
	x0 = vld1q_u32(t);

	ctow(ct + 0x04, t    );
	ctow(ct + 0x14, t + 1);
	ctow(ct + 0x24, t + 2);
	ctow(ct + 0x34, t + 3);
	x1 = vld1q_u32(t);

	ctow(ct + 0x08, t    );
	ctow(ct + 0x18, t + 1);
	ctow(ct + 0x28, t + 2);
	ctow(ct + 0x38, t + 3);
	x2 = vld1q_u32(t);

	ctow(ct + 0x0c, t    );
	ctow(ct + 0x1c, t + 1);
	ctow(ct + 0x2c, t + 2);
	ctow(ct + 0x3c, t + 3);
	x3 = vld1q_u32(t);
#endif

	if(key->rounds > 28)
	{
		XSR9(x0, x3, key->rd_key[186], key->rd_key[187]);
		XSR5(x1, x0, key->rd_key[188], key->rd_key[189]);
		XSR3(x2, x1, key->rd_key[190], key->rd_key[191]);
		XSR9(x3, x2, key->rd_key[180], key->rd_key[181]);
		XSR5(x0, x3, key->rd_key[182], key->rd_key[183]);
		XSR3(x1, x0, key->rd_key[184], key->rd_key[185]);
		XSR9(x2, x1, key->rd_key[174], key->rd_key[175]);
		XSR5(x3, x2, key->rd_key[176], key->rd_key[177]);
		XSR3(x0, x3, key->rd_key[178], key->rd_key[179]);
		XSR9(x1, x0, key->rd_key[168], key->rd_key[169]);
		XSR5(x2, x1, key->rd_key[170], key->rd_key[171]);
		XSR3(x3, x2, key->rd_key[172], key->rd_key[173]);
	}

	if(key->rounds > 24)
	{
		XSR9(x0, x3, key->rd_key[162], key->rd_key[163]);
		XSR5(x1, x0, key->rd_key[164], key->rd_key[165]);
		XSR3(x2, x1, key->rd_key[166], key->rd_key[167]);
		XSR9(x3, x2, key->rd_key[156], key->rd_key[157]);
		XSR5(x0, x3, key->rd_key[158], key->rd_key[159]);
		XSR3(x1, x0, key->rd_key[160], key->rd_key[161]);
		XSR9(x2, x1, key->rd_key[150], key->rd_key[151]);
		XSR5(x3, x2, key->rd_key[152], key->rd_key[153]);
		XSR3(x0, x3, key->rd_key[154], key->rd_key[155]);
		XSR9(x1, x0, key->rd_key[144], key->rd_key[145]);
		XSR5(x2, x1, key->rd_key[146], key->rd_key[147]);
		XSR3(x3, x2, key->rd_key[148], key->rd_key[149]);
	}

	XSR9(x0, x3, key->rd_key[138], key->rd_key[139]);
	XSR5(x1, x0, key->rd_key[140], key->rd_key[141]);
	XSR3(x2, x1, key->rd_key[142], key->rd_key[143]);
	XSR9(x3, x2, key->rd_key[132], key->rd_key[133]);
	XSR5(x0, x3, key->rd_key[134], key->rd_key[135]);
	XSR3(x1, x0, key->rd_key[136], key->rd_key[137]);
	XSR9(x2, x1, key->rd_key[126], key->rd_key[127]);
	XSR5(x3, x2, key->rd_key[128], key->rd_key[129]);
	XSR3(x0, x3, key->rd_key[130], key->rd_key[131]);
	XSR9(x1, x0, key->rd_key[120], key->rd_key[121]);
	XSR5(x2, x1, key->rd_key[122], key->rd_key[123]);
	XSR3(x3, x2, key->rd_key[124], key->rd_key[125]);

	XSR9(x0, x3, key->rd_key[114], key->rd_key[115]);
	XSR5(x1, x0, key->rd_key[116], key->rd_key[117]);
	XSR3(x2, x1, key->rd_key[118], key->rd_key[119]);
	XSR9(x3, x2, key->rd_key[108], key->rd_key[109]);
	XSR5(x0, x3, key->rd_key[110], key->rd_key[111]);
	XSR3(x1, x0, key->rd_key[112], key->rd_key[113]);
	XSR9(x2, x1, key->rd_key[102], key->rd_key[103]);
	XSR5(x3, x2, key->rd_key[104], key->rd_key[105]);
	XSR3(x0, x3, key->rd_key[106], key->rd_key[107]);
	XSR9(x1, x0, key->rd_key[ 96], key->rd_key[ 97]);
	XSR5(x2, x1, key->rd_key[ 98], key->rd_key[ 99]);
	XSR3(x3, x2, key->rd_key[100], key->rd_key[101]);

	XSR9(x0, x3, key->rd_key[ 90], key->rd_key[ 91]);
	XSR5(x1, x0, key->rd_key[ 92], key->rd_key[ 93]);
	XSR3(x2, x1, key->rd_key[ 94], key->rd_key[ 95]);
	XSR9(x3, x2, key->rd_key[ 84], key->rd_key[ 85]);
	XSR5(x0, x3, key->rd_key[ 86], key->rd_key[ 87]);
	XSR3(x1, x0, key->rd_key[ 88], key->rd_key[ 89]);
	XSR9(x2, x1, key->rd_key[ 78], key->rd_key[ 79]);
	XSR5(x3, x2, key->rd_key[ 80], key->rd_key[ 81]);
	XSR3(x0, x3, key->rd_key[ 82], key->rd_key[ 83]);
	XSR9(x1, x0, key->rd_key[ 72], key->rd_key[ 73]);
	XSR5(x2, x1, key->rd_key[ 74], key->rd_key[ 75]);
	XSR3(x3, x2, key->rd_key[ 76], key->rd_key[ 77]);

	XSR9(x0, x3, key->rd_key[ 66], key->rd_key[ 67]);
	XSR5(x1, x0, key->rd_key[ 68], key->rd_key[ 69]);
	XSR3(x2, x1, key->rd_key[ 70], key->rd_key[ 71]);
	XSR9(x3, x2, key->rd_key[ 60], key->rd_key[ 61]);
	XSR5(x0, x3, key->rd_key[ 62], key->rd_key[ 63]);
	XSR3(x1, x0, key->rd_key[ 64], key->rd_key[ 65]);
	XSR9(x2, x1, key->rd_key[ 54], key->rd_key[ 55]);
	XSR5(x3, x2, key->rd_key[ 56], key->rd_key[ 57]);
	XSR3(x0, x3, key->rd_key[ 58], key->rd_key[ 59]);
	XSR9(x1, x0, key->rd_key[ 48], key->rd_key[ 49]);
	XSR5(x2, x1, key->rd_key[ 50], key->rd_key[ 51]);
	XSR3(x3, x2, key->rd_key[ 52], key->rd_key[ 53]);

	XSR9(x0, x3, key->rd_key[ 42], key->rd_key[ 43]);
	XSR5(x1, x0, key->rd_key[ 44], key->rd_key[ 45]);
	XSR3(x2, x1, key->rd_key[ 46], key->rd_key[ 47]);
	XSR9(x3, x2, key->rd_key[ 36], key->rd_key[ 37]);
	XSR5(x0, x3, key->rd_key[ 38], key->rd_key[ 39]);
	XSR3(x1, x0, key->rd_key[ 40], key->rd_key[ 41]);
	XSR9(x2, x1, key->rd_key[ 30], key->rd_key[ 31]);
	XSR5(x3, x2, key->rd_key[ 32], key->rd_key[ 33]);
	XSR3(x0, x3, key->rd_key[ 34], key->rd_key[ 35]);
	XSR9(x1, x0, key->rd_key[ 24], key->rd_key[ 25]);
	XSR5(x2, x1, key->rd_key[ 26], key->rd_key[ 27]);
	XSR3(x3, x2, key->rd_key[ 28], key->rd_key[ 29]);

	XSR9(x0, x3, key->rd_key[ 18], key->rd_key[ 19]);
	XSR5(x1, x0, key->rd_key[ 20], key->rd_key[ 21]);
	XSR3(x2, x1, key->rd_key[ 22], key->rd_key[ 23]);
	XSR9(x3, x2, key->rd_key[ 12], key->rd_key[ 13]);
	XSR5(x0, x3, key->rd_key[ 14], key->rd_key[ 15]);
	XSR3(x1, x0, key->rd_key[ 16], key->rd_key[ 17]);
	XSR9(x2, x1, key->rd_key[  6], key->rd_key[  7]);
	XSR5(x3, x2, key->rd_key[  8], key->rd_key[  9]);
	XSR3(x0, x3, key->rd_key[ 10], key->rd_key[ 11]);
	XSR9(x1, x0, key->rd_key[  0], key->rd_key[  1]);
	XSR5(x2, x1, key->rd_key[  2], key->rd_key[  3]);
	XSR3(x3, x2, key->rd_key[  4], key->rd_key[  5]);

#ifdef __ARMEL__
	vst4q_u32((unsigned int *)pt, x);
#else
	NEONtoMEM(x0, 0, pt       , &itmp);
	NEONtoMEM(x1, 0, pt + 0x04, &itmp);
	NEONtoMEM(x2, 0, pt + 0x08, &itmp);
	NEONtoMEM(x3, 0, pt + 0x0c, &itmp);

	NEONtoMEM(x0, 1, pt + 0x10, &itmp);
	NEONtoMEM(x1, 1, pt + 0x14, &itmp);
	NEONtoMEM(x2, 1, pt + 0x18, &itmp);
	NEONtoMEM(x3, 1, pt + 0x1c, &itmp);

	NEONtoMEM(x0, 2, pt + 0x20, &itmp);
	NEONtoMEM(x1, 2, pt + 0x24, &itmp);
	NEONtoMEM(x2, 2, pt + 0x28, &itmp);
	NEONtoMEM(x3, 2, pt + 0x2c, &itmp);

	NEONtoMEM(x0, 3, pt + 0x30, &itmp);
	NEONtoMEM(x1, 3, pt + 0x34, &itmp);
	NEONtoMEM(x2, 3, pt + 0x38, &itmp);
	NEONtoMEM(x3, 3, pt + 0x3c, &itmp);
#endif
}

#undef x0
#undef x1
#undef x2
#undef x3

#endif	//	#if defined(__ARM_NEON__)
