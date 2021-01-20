#ifndef LEA_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

#include <stdlib.h>
#include <openssl/lea.h>
#include "lea_locl.h"

static const unsigned int delta[8][36] = {
	{0xc3efe9db, 0x87dfd3b7, 0x0fbfa76f, 0x1f7f4ede, 0x3efe9dbc, 0x7dfd3b78, 0xfbfa76f0, 0xf7f4ede1,
	0xefe9dbc3, 0xdfd3b787, 0xbfa76f0f, 0x7f4ede1f, 0xfe9dbc3e, 0xfd3b787d, 0xfa76f0fb, 0xf4ede1f7,
	0xe9dbc3ef, 0xd3b787df, 0xa76f0fbf, 0x4ede1f7f, 0x9dbc3efe, 0x3b787dfd, 0x76f0fbfa, 0xede1f7f4,
	0xdbc3efe9, 0xb787dfd3, 0x6f0fbfa7, 0xde1f7f4e, 0xbc3efe9d, 0x787dfd3b, 0xf0fbfa76, 0xe1f7f4eD,
	0xc3efe9db,	0x87dfd3b7, 0x0fbfa76f, 0x1f7f4ede},
	{0x44626b02, 0x88c4d604, 0x1189ac09, 0x23135812, 0x4626b024, 0x8c4d6048, 0x189ac091, 0x31358122,
	0x626b0244, 0xc4d60488, 0x89ac0911, 0x13581223, 0x26b02446, 0x4d60488c, 0x9ac09118, 0x35812231,
	0x6b024462, 0xd60488c4, 0xac091189, 0x58122313, 0xb0244626, 0x60488c4d, 0xc091189a, 0x81223135,
	0x0244626b, 0x0488c4d6, 0x091189ac, 0x12231358, 0x244626b0, 0x488c4d60, 0x91189ac0, 0x22313581,
	0x44626b02, 0x88c4d604, 0x1189ac09, 0x23135812},
	{0x79e27c8a, 0xf3c4f914, 0xe789f229, 0xcf13e453, 0x9e27c8a7, 0x3c4f914f, 0x789f229e, 0xf13e453c,
	0xe27c8a79, 0xc4f914f3, 0x89f229e7, 0x13e453cf, 0x27c8a79e, 0x4f914f3c, 0x9f229e78, 0x3e453cf1,
	0x7c8a79e2, 0xf914f3c4, 0xf229e789, 0xe453cf13, 0xc8a79e27, 0x914f3c4f, 0x229e789f, 0x453cf13e,
	0x8a79e27c, 0x14f3c4f9, 0x29e789f2, 0x53cf13e4, 0xa79e27c8, 0x4f3c4f91, 0x9e789f22, 0x3cf13e45,
	0x79e27c8a, 0xf3c4f914, 0xe789f229, 0xcf13e453},
	{0x78df30ec, 0xf1be61d8, 0xe37cc3b1, 0xc6f98763, 0x8df30ec7, 0x1be61d8f, 0x37cc3b1e, 0x6f98763c,
	0xdf30ec78, 0xbe61d8f1, 0x7cc3b1e3, 0xf98763c6, 0xf30ec78d, 0xe61d8f1b, 0xcc3b1e37, 0x98763c6f,
	0x30ec78df, 0x61d8f1be, 0xc3b1e37c, 0x8763c6f9, 0x0ec78df3, 0x1d8f1be6, 0x3b1e37cc, 0x763c6f98,
	0xec78df30, 0xd8f1be61, 0xb1e37cc3, 0x63c6f987, 0xc78df30e, 0x8f1be61d, 0x1e37cc3b, 0x3c6f9876,
	0x78df30ec,	0xf1be61d8, 0xe37cc3b1, 0xc6f98763},
	{0x715ea49e, 0xe2bd493c, 0xc57a9279, 0x8af524f3, 0x15ea49e7, 0x2bd493ce, 0x57a9279c, 0xaf524f38,
	0x5ea49e71, 0xbd493ce2, 0x7a9279c5, 0xf524f38a, 0xea49e715, 0xd493ce2b, 0xa9279c57, 0x524f38af,
	0xa49e715e, 0x493ce2bd, 0x9279c57a, 0x24f38af5, 0x49e715ea, 0x93ce2bd4, 0x279c57a9, 0x4f38af52,
	0x9e715ea4, 0x3ce2bd49, 0x79c57a92, 0xf38af524, 0xe715ea49, 0xce2bd493, 0x9c57a927, 0x38af524f,
	0x715ea49e,	0xe2bd493c, 0xc57a9279, 0x8af524f3},
	{0xc785da0a, 0x8f0bb415, 0x1e17682b, 0x3c2ed056, 0x785da0ac, 0xf0bb4158, 0xe17682b1, 0xc2ed0563,
	0x85da0ac7, 0x0bb4158f, 0x17682b1e, 0x2ed0563c, 0x5da0ac78, 0xbb4158f0, 0x7682b1e1, 0xed0563c2,
	0xda0ac785, 0xb4158f0b, 0x682b1e17, 0xd0563c2e, 0xa0ac785d, 0x4158f0bb, 0x82b1e176, 0x0563c2ed,
	0x0ac785da, 0x158f0bb4, 0x2b1e1768, 0x563c2ed0, 0xac785da0, 0x58f0bb41, 0xb1e17682, 0x63c2ed05,
	0xc785da0a, 0x8f0bb415, 0x1e17682b, 0x3c2ed056},
	{0xe04ef22a, 0xc09de455, 0x813bc8ab, 0x02779157, 0x04ef22ae, 0x09de455c, 0x13bc8ab8, 0x27791570,
	0x4ef22ae0, 0x9de455c0, 0x3bc8ab81, 0x77915702, 0xef22ae04, 0xde455c09, 0xbc8ab813, 0x79157027,
	0xf22ae04e, 0xe455c09d, 0xc8ab813b, 0x91570277, 0x22ae04ef, 0x455c09de, 0x8ab813bc, 0x15702779,
	0x2ae04ef2, 0x55c09de4, 0xab813bc8, 0x57027791, 0xae04ef22, 0x5c09de45, 0xb813bc8a, 0x70277915,
	0xe04ef22a,	0xc09de455, 0x813bc8ab, 0x02779157},
	{0xe5c40957, 0xcb8812af, 0x9710255f, 0x2e204abf, 0x5c40957e, 0xb8812afc, 0x710255f9, 0xe204abf2,
	0xc40957e5, 0x8812afcb, 0x10255f97, 0x204abf2e, 0x40957e5c, 0x812afcb8, 0x0255f971, 0x04abf2e2,
	0x0957e5c4, 0x12afcb88, 0x255f9710, 0x4abf2e20, 0x957e5c40, 0x2afcb881, 0x55f97102, 0xabf2e204,
	0x57e5c409, 0xafcb8812, 0x5f971025, 0xbf2e204a, 0x7e5c4095, 0xfcb8812a, 0xf9710255, 0xf2e204ab,
	0xe5c40957,	0xcb8812af, 0x9710255f, 0x2e204abf}
};

int private_LEA_set_encrypt_key(const unsigned char *userKey, const int bits,
			LEA_KEY *key) {
	unsigned int tmp;
	if (!userKey || !key)
		return -1;
	if (bits != 128 && bits != 192 && bits != 256)
		return -2;
	
#ifdef ARCH_IA32
#if 0 //jkkim@ def COMPILE_XOP
	if (XOP_CAPABLE){
		lea_set_key_xop(key, userKey, bits);
		return 0;
	}
#endif
#endif

	switch(bits)
	{
	case 128:
		ctow(userKey, &tmp);
		key->rd_key[  0] = ROL(tmp + delta[0][ 0], 1);
		key->rd_key[  6] = ROL(key->rd_key[  0] + delta[1][ 1], 1);
		key->rd_key[ 12] = ROL(key->rd_key[  6] + delta[2][ 2], 1);
		key->rd_key[ 18] = ROL(key->rd_key[ 12] + delta[3][ 3], 1);
		key->rd_key[ 24] = ROL(key->rd_key[ 18] + delta[0][ 4], 1);
		key->rd_key[ 30] = ROL(key->rd_key[ 24] + delta[1][ 5], 1);
		key->rd_key[ 36] = ROL(key->rd_key[ 30] + delta[2][ 6], 1);
		key->rd_key[ 42] = ROL(key->rd_key[ 36] + delta[3][ 7], 1);
		key->rd_key[ 48] = ROL(key->rd_key[ 42] + delta[0][ 8], 1);
		key->rd_key[ 54] = ROL(key->rd_key[ 48] + delta[1][ 9], 1);
		key->rd_key[ 60] = ROL(key->rd_key[ 54] + delta[2][10], 1);
		key->rd_key[ 66] = ROL(key->rd_key[ 60] + delta[3][11], 1);
		key->rd_key[ 72] = ROL(key->rd_key[ 66] + delta[0][12], 1);
		key->rd_key[ 78] = ROL(key->rd_key[ 72] + delta[1][13], 1);
		key->rd_key[ 84] = ROL(key->rd_key[ 78] + delta[2][14], 1);
		key->rd_key[ 90] = ROL(key->rd_key[ 84] + delta[3][15], 1);
		key->rd_key[ 96] = ROL(key->rd_key[ 90] + delta[0][16], 1);
		key->rd_key[102] = ROL(key->rd_key[ 96] + delta[1][17], 1);
		key->rd_key[108] = ROL(key->rd_key[102] + delta[2][18], 1);
		key->rd_key[114] = ROL(key->rd_key[108] + delta[3][19], 1);
		key->rd_key[120] = ROL(key->rd_key[114] + delta[0][20], 1);
		key->rd_key[126] = ROL(key->rd_key[120] + delta[1][21], 1);
		key->rd_key[132] = ROL(key->rd_key[126] + delta[2][22], 1);
		key->rd_key[138] = ROL(key->rd_key[132] + delta[3][23], 1);

		ctow(userKey + 4, &tmp);
		key->rd_key[  1] = key->rd_key[  3] = key->rd_key[  5] = ROL(tmp + delta[0][ 1], 3);
		key->rd_key[  7] = key->rd_key[  9] = key->rd_key[ 11] = ROL(key->rd_key[  1] + delta[1][ 2], 3);
		key->rd_key[ 13] = key->rd_key[ 15] = key->rd_key[ 17] = ROL(key->rd_key[  7] + delta[2][ 3], 3);
		key->rd_key[ 19] = key->rd_key[ 21] = key->rd_key[ 23] = ROL(key->rd_key[ 13] + delta[3][ 4], 3);
		key->rd_key[ 25] = key->rd_key[ 27] = key->rd_key[ 29] = ROL(key->rd_key[ 19] + delta[0][ 5], 3);
		key->rd_key[ 31] = key->rd_key[ 33] = key->rd_key[ 35] = ROL(key->rd_key[ 25] + delta[1][ 6], 3);
		key->rd_key[ 37] = key->rd_key[ 39] = key->rd_key[ 41] = ROL(key->rd_key[ 31] + delta[2][ 7], 3);
		key->rd_key[ 43] = key->rd_key[ 45] = key->rd_key[ 47] = ROL(key->rd_key[ 37] + delta[3][ 8], 3);
		key->rd_key[ 49] = key->rd_key[ 51] = key->rd_key[ 53] = ROL(key->rd_key[ 43] + delta[0][ 9], 3);
		key->rd_key[ 55] = key->rd_key[ 57] = key->rd_key[ 59] = ROL(key->rd_key[ 49] + delta[1][10], 3);
		key->rd_key[ 61] = key->rd_key[ 63] = key->rd_key[ 65] = ROL(key->rd_key[ 55] + delta[2][11], 3);
		key->rd_key[ 67] = key->rd_key[ 69] = key->rd_key[ 71] = ROL(key->rd_key[ 61] + delta[3][12], 3);
		key->rd_key[ 73] = key->rd_key[ 75] = key->rd_key[ 77] = ROL(key->rd_key[ 67] + delta[0][13], 3);
		key->rd_key[ 79] = key->rd_key[ 81] = key->rd_key[ 83] = ROL(key->rd_key[ 73] + delta[1][14], 3);
		key->rd_key[ 85] = key->rd_key[ 87] = key->rd_key[ 89] = ROL(key->rd_key[ 79] + delta[2][15], 3);
		key->rd_key[ 91] = key->rd_key[ 93] = key->rd_key[ 95] = ROL(key->rd_key[ 85] + delta[3][16], 3);
		key->rd_key[ 97] = key->rd_key[ 99] = key->rd_key[101] = ROL(key->rd_key[ 91] + delta[0][17], 3);
		key->rd_key[103] = key->rd_key[105] = key->rd_key[107] = ROL(key->rd_key[ 97] + delta[1][18], 3);
		key->rd_key[109] = key->rd_key[111] = key->rd_key[113] = ROL(key->rd_key[103] + delta[2][19], 3);
		key->rd_key[115] = key->rd_key[117] = key->rd_key[119] = ROL(key->rd_key[109] + delta[3][20], 3);
		key->rd_key[121] = key->rd_key[123] = key->rd_key[125] = ROL(key->rd_key[115] + delta[0][21], 3);
		key->rd_key[127] = key->rd_key[129] = key->rd_key[131] = ROL(key->rd_key[121] + delta[1][22], 3);
		key->rd_key[133] = key->rd_key[135] = key->rd_key[137] = ROL(key->rd_key[127] + delta[2][23], 3);
		key->rd_key[139] = key->rd_key[141] = key->rd_key[143] = ROL(key->rd_key[133] + delta[3][24], 3);

		ctow(userKey + 8, &tmp);
		key->rd_key[  2] = ROL(tmp + delta[0][ 2], 6);
		key->rd_key[  8] = ROL(key->rd_key[  2] + delta[1][ 3], 6);
		key->rd_key[ 14] = ROL(key->rd_key[  8] + delta[2][ 4], 6);
		key->rd_key[ 20] = ROL(key->rd_key[ 14] + delta[3][ 5], 6);
		key->rd_key[ 26] = ROL(key->rd_key[ 20] + delta[0][ 6], 6);
		key->rd_key[ 32] = ROL(key->rd_key[ 26] + delta[1][ 7], 6);
		key->rd_key[ 38] = ROL(key->rd_key[ 32] + delta[2][ 8], 6);
		key->rd_key[ 44] = ROL(key->rd_key[ 38] + delta[3][ 9], 6);
		key->rd_key[ 50] = ROL(key->rd_key[ 44] + delta[0][10], 6);
		key->rd_key[ 56] = ROL(key->rd_key[ 50] + delta[1][11], 6);
		key->rd_key[ 62] = ROL(key->rd_key[ 56] + delta[2][12], 6);
		key->rd_key[ 68] = ROL(key->rd_key[ 62] + delta[3][13], 6);
		key->rd_key[ 74] = ROL(key->rd_key[ 68] + delta[0][14], 6);
		key->rd_key[ 80] = ROL(key->rd_key[ 74] + delta[1][15], 6);
		key->rd_key[ 86] = ROL(key->rd_key[ 80] + delta[2][16], 6);
		key->rd_key[ 92] = ROL(key->rd_key[ 86] + delta[3][17], 6);
		key->rd_key[ 98] = ROL(key->rd_key[ 92] + delta[0][18], 6);
		key->rd_key[104] = ROL(key->rd_key[ 98] + delta[1][19], 6);
		key->rd_key[110] = ROL(key->rd_key[104] + delta[2][20], 6);
		key->rd_key[116] = ROL(key->rd_key[110] + delta[3][21], 6);
		key->rd_key[122] = ROL(key->rd_key[116] + delta[0][22], 6);
		key->rd_key[128] = ROL(key->rd_key[122] + delta[1][23], 6);
		key->rd_key[134] = ROL(key->rd_key[128] + delta[2][24], 6);
		key->rd_key[140] = ROL(key->rd_key[134] + delta[3][25], 6);

		ctow(userKey + 12, &tmp);
		key->rd_key[  4] = ROL(tmp + delta[0][ 3], 11);
		key->rd_key[ 10] = ROL(key->rd_key[  4] + delta[1][ 4], 11);
		key->rd_key[ 16] = ROL(key->rd_key[ 10] + delta[2][ 5], 11);
		key->rd_key[ 22] = ROL(key->rd_key[ 16] + delta[3][ 6], 11);
		key->rd_key[ 28] = ROL(key->rd_key[ 22] + delta[0][ 7], 11);
		key->rd_key[ 34] = ROL(key->rd_key[ 28] + delta[1][ 8], 11);
		key->rd_key[ 40] = ROL(key->rd_key[ 34] + delta[2][ 9], 11);
		key->rd_key[ 46] = ROL(key->rd_key[ 40] + delta[3][10], 11);
		key->rd_key[ 52] = ROL(key->rd_key[ 46] + delta[0][11], 11);
		key->rd_key[ 58] = ROL(key->rd_key[ 52] + delta[1][12], 11);
		key->rd_key[ 64] = ROL(key->rd_key[ 58] + delta[2][13], 11);
		key->rd_key[ 70] = ROL(key->rd_key[ 64] + delta[3][14], 11);
		key->rd_key[ 76] = ROL(key->rd_key[ 70] + delta[0][15], 11);
		key->rd_key[ 82] = ROL(key->rd_key[ 76] + delta[1][16], 11);
		key->rd_key[ 88] = ROL(key->rd_key[ 82] + delta[2][17], 11);
		key->rd_key[ 94] = ROL(key->rd_key[ 88] + delta[3][18], 11);
		key->rd_key[100] = ROL(key->rd_key[ 94] + delta[0][19], 11);
		key->rd_key[106] = ROL(key->rd_key[100] + delta[1][20], 11);
		key->rd_key[112] = ROL(key->rd_key[106] + delta[2][21], 11);
		key->rd_key[118] = ROL(key->rd_key[112] + delta[3][22], 11);
		key->rd_key[124] = ROL(key->rd_key[118] + delta[0][23], 11);
		key->rd_key[130] = ROL(key->rd_key[124] + delta[1][24], 11);
		key->rd_key[136] = ROL(key->rd_key[130] + delta[2][25], 11);
		key->rd_key[142] = ROL(key->rd_key[136] + delta[3][26], 11);
		break;

	case 192:
		ctow(userKey, &tmp);
		key->rd_key[  0] = ROL(tmp + delta[0][ 0], 1);
		key->rd_key[  6] = ROL(key->rd_key[  0] + delta[1][ 1], 1);
		key->rd_key[ 12] = ROL(key->rd_key[  6] + delta[2][ 2], 1);
		key->rd_key[ 18] = ROL(key->rd_key[ 12] + delta[3][ 3], 1);
		key->rd_key[ 24] = ROL(key->rd_key[ 18] + delta[4][ 4], 1);
		key->rd_key[ 30] = ROL(key->rd_key[ 24] + delta[5][ 5], 1);
		key->rd_key[ 36] = ROL(key->rd_key[ 30] + delta[0][ 6], 1);
		key->rd_key[ 42] = ROL(key->rd_key[ 36] + delta[1][ 7], 1);
		key->rd_key[ 48] = ROL(key->rd_key[ 42] + delta[2][ 8], 1);
		key->rd_key[ 54] = ROL(key->rd_key[ 48] + delta[3][ 9], 1);
		key->rd_key[ 60] = ROL(key->rd_key[ 54] + delta[4][10], 1);
		key->rd_key[ 66] = ROL(key->rd_key[ 60] + delta[5][11], 1);
		key->rd_key[ 72] = ROL(key->rd_key[ 66] + delta[0][12], 1);
		key->rd_key[ 78] = ROL(key->rd_key[ 72] + delta[1][13], 1);
		key->rd_key[ 84] = ROL(key->rd_key[ 78] + delta[2][14], 1);
		key->rd_key[ 90] = ROL(key->rd_key[ 84] + delta[3][15], 1);
		key->rd_key[ 96] = ROL(key->rd_key[ 90] + delta[4][16], 1);
		key->rd_key[102] = ROL(key->rd_key[ 96] + delta[5][17], 1);
		key->rd_key[108] = ROL(key->rd_key[102] + delta[0][18], 1);
		key->rd_key[114] = ROL(key->rd_key[108] + delta[1][19], 1);
		key->rd_key[120] = ROL(key->rd_key[114] + delta[2][20], 1);
		key->rd_key[126] = ROL(key->rd_key[120] + delta[3][21], 1);
		key->rd_key[132] = ROL(key->rd_key[126] + delta[4][22], 1);
		key->rd_key[138] = ROL(key->rd_key[132] + delta[5][23], 1);
		key->rd_key[144] = ROL(key->rd_key[138] + delta[0][24], 1);
		key->rd_key[150] = ROL(key->rd_key[144] + delta[1][25], 1);
		key->rd_key[156] = ROL(key->rd_key[150] + delta[2][26], 1);
		key->rd_key[162] = ROL(key->rd_key[156] + delta[3][27], 1);

		ctow(userKey + 4, &tmp);
		key->rd_key[  1] = ROL(tmp + delta[0][ 1], 3);
		key->rd_key[  7] = ROL(key->rd_key[  1] + delta[1][ 2], 3);
		key->rd_key[ 13] = ROL(key->rd_key[  7] + delta[2][ 3], 3);
		key->rd_key[ 19] = ROL(key->rd_key[ 13] + delta[3][ 4], 3);
		key->rd_key[ 25] = ROL(key->rd_key[ 19] + delta[4][ 5], 3);
		key->rd_key[ 31] = ROL(key->rd_key[ 25] + delta[5][ 6], 3);
		key->rd_key[ 37] = ROL(key->rd_key[ 31] + delta[0][ 7], 3);
		key->rd_key[ 43] = ROL(key->rd_key[ 37] + delta[1][ 8], 3);
		key->rd_key[ 49] = ROL(key->rd_key[ 43] + delta[2][ 9], 3);
		key->rd_key[ 55] = ROL(key->rd_key[ 49] + delta[3][10], 3);
		key->rd_key[ 61] = ROL(key->rd_key[ 55] + delta[4][11], 3);
		key->rd_key[ 67] = ROL(key->rd_key[ 61] + delta[5][12], 3);
		key->rd_key[ 73] = ROL(key->rd_key[ 67] + delta[0][13], 3);
		key->rd_key[ 79] = ROL(key->rd_key[ 73] + delta[1][14], 3);
		key->rd_key[ 85] = ROL(key->rd_key[ 79] + delta[2][15], 3);
		key->rd_key[ 91] = ROL(key->rd_key[ 85] + delta[3][16], 3);
		key->rd_key[ 97] = ROL(key->rd_key[ 91] + delta[4][17], 3);
		key->rd_key[103] = ROL(key->rd_key[ 97] + delta[5][18], 3);
		key->rd_key[109] = ROL(key->rd_key[103] + delta[0][19], 3);
		key->rd_key[115] = ROL(key->rd_key[109] + delta[1][20], 3);
		key->rd_key[121] = ROL(key->rd_key[115] + delta[2][21], 3);
		key->rd_key[127] = ROL(key->rd_key[121] + delta[3][22], 3);
		key->rd_key[133] = ROL(key->rd_key[127] + delta[4][23], 3);
		key->rd_key[139] = ROL(key->rd_key[133] + delta[5][24], 3);
		key->rd_key[145] = ROL(key->rd_key[139] + delta[0][25], 3);
		key->rd_key[151] = ROL(key->rd_key[145] + delta[1][26], 3);
		key->rd_key[157] = ROL(key->rd_key[151] + delta[2][27], 3);
		key->rd_key[163] = ROL(key->rd_key[157] + delta[3][28], 3);

		ctow(userKey + 8, &tmp);
		key->rd_key[  2] = ROL(tmp + delta[0][ 2], 6);
		key->rd_key[  8] = ROL(key->rd_key[  2] + delta[1][ 3], 6);
		key->rd_key[ 14] = ROL(key->rd_key[  8] + delta[2][ 4], 6);
		key->rd_key[ 20] = ROL(key->rd_key[ 14] + delta[3][ 5], 6);
		key->rd_key[ 26] = ROL(key->rd_key[ 20] + delta[4][ 6], 6);
		key->rd_key[ 32] = ROL(key->rd_key[ 26] + delta[5][ 7], 6);
		key->rd_key[ 38] = ROL(key->rd_key[ 32] + delta[0][ 8], 6);
		key->rd_key[ 44] = ROL(key->rd_key[ 38] + delta[1][ 9], 6);
		key->rd_key[ 50] = ROL(key->rd_key[ 44] + delta[2][10], 6);
		key->rd_key[ 56] = ROL(key->rd_key[ 50] + delta[3][11], 6);
		key->rd_key[ 62] = ROL(key->rd_key[ 56] + delta[4][12], 6);
		key->rd_key[ 68] = ROL(key->rd_key[ 62] + delta[5][13], 6);
		key->rd_key[ 74] = ROL(key->rd_key[ 68] + delta[0][14], 6);
		key->rd_key[ 80] = ROL(key->rd_key[ 74] + delta[1][15], 6);
		key->rd_key[ 86] = ROL(key->rd_key[ 80] + delta[2][16], 6);
		key->rd_key[ 92] = ROL(key->rd_key[ 86] + delta[3][17], 6);
		key->rd_key[ 98] = ROL(key->rd_key[ 92] + delta[4][18], 6);
		key->rd_key[104] = ROL(key->rd_key[ 98] + delta[5][19], 6);
		key->rd_key[110] = ROL(key->rd_key[104] + delta[0][20], 6);
		key->rd_key[116] = ROL(key->rd_key[110] + delta[1][21], 6);
		key->rd_key[122] = ROL(key->rd_key[116] + delta[2][22], 6);
		key->rd_key[128] = ROL(key->rd_key[122] + delta[3][23], 6);
		key->rd_key[134] = ROL(key->rd_key[128] + delta[4][24], 6);
		key->rd_key[140] = ROL(key->rd_key[134] + delta[5][25], 6);
		key->rd_key[146] = ROL(key->rd_key[140] + delta[0][26], 6);
		key->rd_key[152] = ROL(key->rd_key[146] + delta[1][27], 6);
		key->rd_key[158] = ROL(key->rd_key[152] + delta[2][28], 6);
		key->rd_key[164] = ROL(key->rd_key[158] + delta[3][29], 6);

		ctow(userKey + 12, &tmp);
		key->rd_key[  3] = ROL(tmp + delta[0][ 3], 11);
		key->rd_key[  9] = ROL(key->rd_key[  3] + delta[1][ 4], 11);
		key->rd_key[ 15] = ROL(key->rd_key[  9] + delta[2][ 5], 11);
		key->rd_key[ 21] = ROL(key->rd_key[ 15] + delta[3][ 6], 11);
		key->rd_key[ 27] = ROL(key->rd_key[ 21] + delta[4][ 7], 11);
		key->rd_key[ 33] = ROL(key->rd_key[ 27] + delta[5][ 8], 11);
		key->rd_key[ 39] = ROL(key->rd_key[ 33] + delta[0][ 9], 11);
		key->rd_key[ 45] = ROL(key->rd_key[ 39] + delta[1][10], 11);
		key->rd_key[ 51] = ROL(key->rd_key[ 45] + delta[2][11], 11);
		key->rd_key[ 57] = ROL(key->rd_key[ 51] + delta[3][12], 11);
		key->rd_key[ 63] = ROL(key->rd_key[ 57] + delta[4][13], 11);
		key->rd_key[ 69] = ROL(key->rd_key[ 63] + delta[5][14], 11);
		key->rd_key[ 75] = ROL(key->rd_key[ 69] + delta[0][15], 11);
		key->rd_key[ 81] = ROL(key->rd_key[ 75] + delta[1][16], 11);
		key->rd_key[ 87] = ROL(key->rd_key[ 81] + delta[2][17], 11);
		key->rd_key[ 93] = ROL(key->rd_key[ 87] + delta[3][18], 11);
		key->rd_key[ 99] = ROL(key->rd_key[ 93] + delta[4][19], 11);
		key->rd_key[105] = ROL(key->rd_key[ 99] + delta[5][20], 11);
		key->rd_key[111] = ROL(key->rd_key[105] + delta[0][21], 11);
		key->rd_key[117] = ROL(key->rd_key[111] + delta[1][22], 11);
		key->rd_key[123] = ROL(key->rd_key[117] + delta[2][23], 11);
		key->rd_key[129] = ROL(key->rd_key[123] + delta[3][24], 11);
		key->rd_key[135] = ROL(key->rd_key[129] + delta[4][25], 11);
		key->rd_key[141] = ROL(key->rd_key[135] + delta[5][26], 11);
		key->rd_key[147] = ROL(key->rd_key[141] + delta[0][27], 11);
		key->rd_key[153] = ROL(key->rd_key[147] + delta[1][28], 11);
		key->rd_key[159] = ROL(key->rd_key[153] + delta[2][29], 11);
		key->rd_key[165] = ROL(key->rd_key[159] + delta[3][30], 11);

		ctow(userKey + 16, &tmp);
		key->rd_key[  4] = ROL(tmp + delta[0][ 4], 13);
		key->rd_key[ 10] = ROL(key->rd_key[  4] + delta[1][ 5], 13);
		key->rd_key[ 16] = ROL(key->rd_key[ 10] + delta[2][ 6], 13);
		key->rd_key[ 22] = ROL(key->rd_key[ 16] + delta[3][ 7], 13);
		key->rd_key[ 28] = ROL(key->rd_key[ 22] + delta[4][ 8], 13);
		key->rd_key[ 34] = ROL(key->rd_key[ 28] + delta[5][ 9], 13);
		key->rd_key[ 40] = ROL(key->rd_key[ 34] + delta[0][10], 13);
		key->rd_key[ 46] = ROL(key->rd_key[ 40] + delta[1][11], 13);
		key->rd_key[ 52] = ROL(key->rd_key[ 46] + delta[2][12], 13);
		key->rd_key[ 58] = ROL(key->rd_key[ 52] + delta[3][13], 13);
		key->rd_key[ 64] = ROL(key->rd_key[ 58] + delta[4][14], 13);
		key->rd_key[ 70] = ROL(key->rd_key[ 64] + delta[5][15], 13);
		key->rd_key[ 76] = ROL(key->rd_key[ 70] + delta[0][16], 13);
		key->rd_key[ 82] = ROL(key->rd_key[ 76] + delta[1][17], 13);
		key->rd_key[ 88] = ROL(key->rd_key[ 82] + delta[2][18], 13);
		key->rd_key[ 94] = ROL(key->rd_key[ 88] + delta[3][19], 13);
		key->rd_key[100] = ROL(key->rd_key[ 94] + delta[4][20], 13);
		key->rd_key[106] = ROL(key->rd_key[100] + delta[5][21], 13);
		key->rd_key[112] = ROL(key->rd_key[106] + delta[0][22], 13);
		key->rd_key[118] = ROL(key->rd_key[112] + delta[1][23], 13);
		key->rd_key[124] = ROL(key->rd_key[118] + delta[2][24], 13);
		key->rd_key[130] = ROL(key->rd_key[124] + delta[3][25], 13);
		key->rd_key[136] = ROL(key->rd_key[130] + delta[4][26], 13);
		key->rd_key[142] = ROL(key->rd_key[136] + delta[5][27], 13);
		key->rd_key[148] = ROL(key->rd_key[142] + delta[0][28], 13);
		key->rd_key[154] = ROL(key->rd_key[148] + delta[1][29], 13);
		key->rd_key[160] = ROL(key->rd_key[154] + delta[2][30], 13);
		key->rd_key[166] = ROL(key->rd_key[160] + delta[3][31], 13);

		ctow(userKey + 20, &tmp);
		key->rd_key[  5] = ROL(tmp + delta[0][ 5], 17);
		key->rd_key[ 11] = ROL(key->rd_key[  5] + delta[1][ 6], 17);
		key->rd_key[ 17] = ROL(key->rd_key[ 11] + delta[2][ 7], 17);
		key->rd_key[ 23] = ROL(key->rd_key[ 17] + delta[3][ 8], 17);
		key->rd_key[ 29] = ROL(key->rd_key[ 23] + delta[4][ 9], 17);
		key->rd_key[ 35] = ROL(key->rd_key[ 29] + delta[5][10], 17);
		key->rd_key[ 41] = ROL(key->rd_key[ 35] + delta[0][11], 17);
		key->rd_key[ 47] = ROL(key->rd_key[ 41] + delta[1][12], 17);
		key->rd_key[ 53] = ROL(key->rd_key[ 47] + delta[2][13], 17);
		key->rd_key[ 59] = ROL(key->rd_key[ 53] + delta[3][14], 17);
		key->rd_key[ 65] = ROL(key->rd_key[ 59] + delta[4][15], 17);
		key->rd_key[ 71] = ROL(key->rd_key[ 65] + delta[5][16], 17);
		key->rd_key[ 77] = ROL(key->rd_key[ 71] + delta[0][17], 17);
		key->rd_key[ 83] = ROL(key->rd_key[ 77] + delta[1][18], 17);
		key->rd_key[ 89] = ROL(key->rd_key[ 83] + delta[2][19], 17);
		key->rd_key[ 95] = ROL(key->rd_key[ 89] + delta[3][20], 17);
		key->rd_key[101] = ROL(key->rd_key[ 95] + delta[4][21], 17);
		key->rd_key[107] = ROL(key->rd_key[101] + delta[5][22], 17);
		key->rd_key[113] = ROL(key->rd_key[107] + delta[0][23], 17);
		key->rd_key[119] = ROL(key->rd_key[113] + delta[1][24], 17);
		key->rd_key[125] = ROL(key->rd_key[119] + delta[2][25], 17);
		key->rd_key[131] = ROL(key->rd_key[125] + delta[3][26], 17);
		key->rd_key[137] = ROL(key->rd_key[131] + delta[4][27], 17);
		key->rd_key[143] = ROL(key->rd_key[137] + delta[5][28], 17);
		key->rd_key[149] = ROL(key->rd_key[143] + delta[0][29], 17);
		key->rd_key[155] = ROL(key->rd_key[149] + delta[1][30], 17);
		key->rd_key[161] = ROL(key->rd_key[155] + delta[2][31], 17);
		key->rd_key[167] = ROL(key->rd_key[161] + delta[3][ 0], 17);
		break;

	case 256:
		ctow(userKey, &tmp);
		key->rd_key[  0] = ROL(tmp + delta[0][ 0],  1);
		key->rd_key[  8] = ROL(key->rd_key[  0] + delta[1][ 3],  6);
		key->rd_key[ 16] = ROL(key->rd_key[  8] + delta[2][ 6], 13);
		key->rd_key[ 24] = ROL(key->rd_key[ 16] + delta[4][ 4],  1);
		key->rd_key[ 32] = ROL(key->rd_key[ 24] + delta[5][ 7],  6);
		key->rd_key[ 40] = ROL(key->rd_key[ 32] + delta[6][10], 13);
		key->rd_key[ 48] = ROL(key->rd_key[ 40] + delta[0][ 8],  1);
		key->rd_key[ 56] = ROL(key->rd_key[ 48] + delta[1][11],  6);
		key->rd_key[ 64] = ROL(key->rd_key[ 56] + delta[2][14], 13);
		key->rd_key[ 72] = ROL(key->rd_key[ 64] + delta[4][12],  1);
		key->rd_key[ 80] = ROL(key->rd_key[ 72] + delta[5][15],  6);
		key->rd_key[ 88] = ROL(key->rd_key[ 80] + delta[6][18], 13);
		key->rd_key[ 96] = ROL(key->rd_key[ 88] + delta[0][16],  1);
		key->rd_key[104] = ROL(key->rd_key[ 96] + delta[1][19],  6);
		key->rd_key[112] = ROL(key->rd_key[104] + delta[2][22], 13);
		key->rd_key[120] = ROL(key->rd_key[112] + delta[4][20],  1);
		key->rd_key[128] = ROL(key->rd_key[120] + delta[5][23],  6);
		key->rd_key[136] = ROL(key->rd_key[128] + delta[6][26], 13);
		key->rd_key[144] = ROL(key->rd_key[136] + delta[0][24],  1);
		key->rd_key[152] = ROL(key->rd_key[144] + delta[1][27],  6);
		key->rd_key[160] = ROL(key->rd_key[152] + delta[2][30], 13);
		key->rd_key[168] = ROL(key->rd_key[160] + delta[4][28],  1);
		key->rd_key[176] = ROL(key->rd_key[168] + delta[5][31],  6);
		key->rd_key[184] = ROL(key->rd_key[176] + delta[6][ 2], 13);

		ctow(userKey + 4, &tmp);
		key->rd_key[  1] = ROL(tmp + delta[0][ 1],  3);
		key->rd_key[  9] = ROL(key->rd_key[  1] + delta[1][ 4], 11);
		key->rd_key[ 17] = ROL(key->rd_key[  9] + delta[2][ 7], 17);
		key->rd_key[ 25] = ROL(key->rd_key[ 17] + delta[4][ 5],  3);
		key->rd_key[ 33] = ROL(key->rd_key[ 25] + delta[5][ 8], 11);
		key->rd_key[ 41] = ROL(key->rd_key[ 33] + delta[6][11], 17);
		key->rd_key[ 49] = ROL(key->rd_key[ 41] + delta[0][ 9],  3);
		key->rd_key[ 57] = ROL(key->rd_key[ 49] + delta[1][12], 11);
		key->rd_key[ 65] = ROL(key->rd_key[ 57] + delta[2][15], 17);
		key->rd_key[ 73] = ROL(key->rd_key[ 65] + delta[4][13],  3);
		key->rd_key[ 81] = ROL(key->rd_key[ 73] + delta[5][16], 11);
		key->rd_key[ 89] = ROL(key->rd_key[ 81] + delta[6][19], 17);
		key->rd_key[ 97] = ROL(key->rd_key[ 89] + delta[0][17],  3);
		key->rd_key[105] = ROL(key->rd_key[ 97] + delta[1][20], 11);
		key->rd_key[113] = ROL(key->rd_key[105] + delta[2][23], 17);
		key->rd_key[121] = ROL(key->rd_key[113] + delta[4][21],  3);
		key->rd_key[129] = ROL(key->rd_key[121] + delta[5][24], 11);
		key->rd_key[137] = ROL(key->rd_key[129] + delta[6][27], 17);
		key->rd_key[145] = ROL(key->rd_key[137] + delta[0][25],  3);
		key->rd_key[153] = ROL(key->rd_key[145] + delta[1][28], 11);
		key->rd_key[161] = ROL(key->rd_key[153] + delta[2][31], 17);
		key->rd_key[169] = ROL(key->rd_key[161] + delta[4][29],  3);
		key->rd_key[177] = ROL(key->rd_key[169] + delta[5][ 0], 11);
		key->rd_key[185] = ROL(key->rd_key[177] + delta[6][ 3], 17);

		ctow(userKey + 8, &tmp);
		key->rd_key[  2] = ROL(tmp + delta[0][ 2],  6);
		key->rd_key[ 10] = ROL(key->rd_key[  2] + delta[1][ 5], 13);
		key->rd_key[ 18] = ROL(key->rd_key[ 10] + delta[3][ 3],  1);
		key->rd_key[ 26] = ROL(key->rd_key[ 18] + delta[4][ 6],  6);
		key->rd_key[ 34] = ROL(key->rd_key[ 26] + delta[5][ 9], 13);
		key->rd_key[ 42] = ROL(key->rd_key[ 34] + delta[7][ 7],  1);
		key->rd_key[ 50] = ROL(key->rd_key[ 42] + delta[0][10],  6);
		key->rd_key[ 58] = ROL(key->rd_key[ 50] + delta[1][13], 13);
		key->rd_key[ 66] = ROL(key->rd_key[ 58] + delta[3][11],  1);
		key->rd_key[ 74] = ROL(key->rd_key[ 66] + delta[4][14],  6);
		key->rd_key[ 82] = ROL(key->rd_key[ 74] + delta[5][17], 13);
		key->rd_key[ 90] = ROL(key->rd_key[ 82] + delta[7][15],  1);
		key->rd_key[ 98] = ROL(key->rd_key[ 90] + delta[0][18],  6);
		key->rd_key[106] = ROL(key->rd_key[ 98] + delta[1][21], 13);
		key->rd_key[114] = ROL(key->rd_key[106] + delta[3][19],  1);
		key->rd_key[122] = ROL(key->rd_key[114] + delta[4][22],  6);
		key->rd_key[130] = ROL(key->rd_key[122] + delta[5][25], 13);
		key->rd_key[138] = ROL(key->rd_key[130] + delta[7][23],  1);
		key->rd_key[146] = ROL(key->rd_key[138] + delta[0][26],  6);
		key->rd_key[154] = ROL(key->rd_key[146] + delta[1][29], 13);
		key->rd_key[162] = ROL(key->rd_key[154] + delta[3][27],  1);
		key->rd_key[170] = ROL(key->rd_key[162] + delta[4][30],  6);
		key->rd_key[178] = ROL(key->rd_key[170] + delta[5][ 1], 13);
		key->rd_key[186] = ROL(key->rd_key[178] + delta[7][31],  1);

		ctow(userKey + 12, &tmp);
		key->rd_key[  3] = ROL(tmp + delta[0][ 3], 11);
		key->rd_key[ 11] = ROL(key->rd_key[  3] + delta[1][ 6], 17);
		key->rd_key[ 19] = ROL(key->rd_key[ 11] + delta[3][ 4],  3);
		key->rd_key[ 27] = ROL(key->rd_key[ 19] + delta[4][ 7], 11);
		key->rd_key[ 35] = ROL(key->rd_key[ 27] + delta[5][10], 17);
		key->rd_key[ 43] = ROL(key->rd_key[ 35] + delta[7][ 8],  3);
		key->rd_key[ 51] = ROL(key->rd_key[ 43] + delta[0][11], 11);
		key->rd_key[ 59] = ROL(key->rd_key[ 51] + delta[1][14], 17);
		key->rd_key[ 67] = ROL(key->rd_key[ 59] + delta[3][12],  3);
		key->rd_key[ 75] = ROL(key->rd_key[ 67] + delta[4][15], 11);
		key->rd_key[ 83] = ROL(key->rd_key[ 75] + delta[5][18], 17);
		key->rd_key[ 91] = ROL(key->rd_key[ 83] + delta[7][16],  3);
		key->rd_key[ 99] = ROL(key->rd_key[ 91] + delta[0][19], 11);
		key->rd_key[107] = ROL(key->rd_key[ 99] + delta[1][22], 17);
		key->rd_key[115] = ROL(key->rd_key[107] + delta[3][20],  3);
		key->rd_key[123] = ROL(key->rd_key[115] + delta[4][23], 11);
		key->rd_key[131] = ROL(key->rd_key[123] + delta[5][26], 17);
		key->rd_key[139] = ROL(key->rd_key[131] + delta[7][24],  3);
		key->rd_key[147] = ROL(key->rd_key[139] + delta[0][27], 11);
		key->rd_key[155] = ROL(key->rd_key[147] + delta[1][30], 17);
		key->rd_key[163] = ROL(key->rd_key[155] + delta[3][28],  3);
		key->rd_key[171] = ROL(key->rd_key[163] + delta[4][31], 11);
		key->rd_key[179] = ROL(key->rd_key[171] + delta[5][ 2], 17);
		key->rd_key[187] = ROL(key->rd_key[179] + delta[7][ 0],  3);

		ctow(userKey + 16, &tmp);
		key->rd_key[  4] = ROL(tmp + delta[0][ 4], 13);
		key->rd_key[ 12] = ROL(key->rd_key[  4] + delta[2][ 2],  1);
		key->rd_key[ 20] = ROL(key->rd_key[ 12] + delta[3][ 5],  6);
		key->rd_key[ 28] = ROL(key->rd_key[ 20] + delta[4][ 8], 13);
		key->rd_key[ 36] = ROL(key->rd_key[ 28] + delta[6][ 6],  1);
		key->rd_key[ 44] = ROL(key->rd_key[ 36] + delta[7][ 9],  6);
		key->rd_key[ 52] = ROL(key->rd_key[ 44] + delta[0][12], 13);
		key->rd_key[ 60] = ROL(key->rd_key[ 52] + delta[2][10],  1);
		key->rd_key[ 68] = ROL(key->rd_key[ 60] + delta[3][13],  6);
		key->rd_key[ 76] = ROL(key->rd_key[ 68] + delta[4][16], 13);
		key->rd_key[ 84] = ROL(key->rd_key[ 76] + delta[6][14],  1);
		key->rd_key[ 92] = ROL(key->rd_key[ 84] + delta[7][17],  6);
		key->rd_key[100] = ROL(key->rd_key[ 92] + delta[0][20], 13);
		key->rd_key[108] = ROL(key->rd_key[100] + delta[2][18],  1);
		key->rd_key[116] = ROL(key->rd_key[108] + delta[3][21],  6);
		key->rd_key[124] = ROL(key->rd_key[116] + delta[4][24], 13);
		key->rd_key[132] = ROL(key->rd_key[124] + delta[6][22],  1);
		key->rd_key[140] = ROL(key->rd_key[132] + delta[7][25],  6);
		key->rd_key[148] = ROL(key->rd_key[140] + delta[0][28], 13);
		key->rd_key[156] = ROL(key->rd_key[148] + delta[2][26],  1);
		key->rd_key[164] = ROL(key->rd_key[156] + delta[3][29],  6);
		key->rd_key[172] = ROL(key->rd_key[164] + delta[4][ 0], 13);
		key->rd_key[180] = ROL(key->rd_key[172] + delta[6][30],  1);
		key->rd_key[188] = ROL(key->rd_key[180] + delta[7][ 1],  6);

		ctow(userKey + 20, &tmp);
		key->rd_key[  5] = ROL(tmp + delta[0][ 5], 17);
		key->rd_key[ 13] = ROL(key->rd_key[  5] + delta[2][ 3],  3);
		key->rd_key[ 21] = ROL(key->rd_key[ 13] + delta[3][ 6], 11);
		key->rd_key[ 29] = ROL(key->rd_key[ 21] + delta[4][ 9], 17);
		key->rd_key[ 37] = ROL(key->rd_key[ 29] + delta[6][ 7],  3);
		key->rd_key[ 45] = ROL(key->rd_key[ 37] + delta[7][10], 11);
		key->rd_key[ 53] = ROL(key->rd_key[ 45] + delta[0][13], 17);
		key->rd_key[ 61] = ROL(key->rd_key[ 53] + delta[2][11],  3);
		key->rd_key[ 69] = ROL(key->rd_key[ 61] + delta[3][14], 11);
		key->rd_key[ 77] = ROL(key->rd_key[ 69] + delta[4][17], 17);
		key->rd_key[ 85] = ROL(key->rd_key[ 77] + delta[6][15],  3);
		key->rd_key[ 93] = ROL(key->rd_key[ 85] + delta[7][18], 11);
		key->rd_key[101] = ROL(key->rd_key[ 93] + delta[0][21], 17);
		key->rd_key[109] = ROL(key->rd_key[101] + delta[2][19],  3);
		key->rd_key[117] = ROL(key->rd_key[109] + delta[3][22], 11);
		key->rd_key[125] = ROL(key->rd_key[117] + delta[4][25], 17);
		key->rd_key[133] = ROL(key->rd_key[125] + delta[6][23],  3);
		key->rd_key[141] = ROL(key->rd_key[133] + delta[7][26], 11);
		key->rd_key[149] = ROL(key->rd_key[141] + delta[0][29], 17);
		key->rd_key[157] = ROL(key->rd_key[149] + delta[2][27],  3);
		key->rd_key[165] = ROL(key->rd_key[157] + delta[3][30], 11);
		key->rd_key[173] = ROL(key->rd_key[165] + delta[4][ 1], 17);
		key->rd_key[181] = ROL(key->rd_key[173] + delta[6][31],  3);
		key->rd_key[189] = ROL(key->rd_key[181] + delta[7][ 2], 11);

		ctow(userKey + 24, &tmp);
		key->rd_key[  6] = ROL(tmp + delta[1][ 1],  1);
		key->rd_key[ 14] = ROL(key->rd_key[  6] + delta[2][ 4],  6);
		key->rd_key[ 22] = ROL(key->rd_key[ 14] + delta[3][ 7], 13);
		key->rd_key[ 30] = ROL(key->rd_key[ 22] + delta[5][ 5],  1);
		key->rd_key[ 38] = ROL(key->rd_key[ 30] + delta[6][ 8],  6);
		key->rd_key[ 46] = ROL(key->rd_key[ 38] + delta[7][11], 13);
		key->rd_key[ 54] = ROL(key->rd_key[ 46] + delta[1][ 9],  1);
		key->rd_key[ 62] = ROL(key->rd_key[ 54] + delta[2][12],  6);
		key->rd_key[ 70] = ROL(key->rd_key[ 62] + delta[3][15], 13);
		key->rd_key[ 78] = ROL(key->rd_key[ 70] + delta[5][13],  1);
		key->rd_key[ 86] = ROL(key->rd_key[ 78] + delta[6][16],  6);
		key->rd_key[ 94] = ROL(key->rd_key[ 86] + delta[7][19], 13);
		key->rd_key[102] = ROL(key->rd_key[ 94] + delta[1][17],  1);
		key->rd_key[110] = ROL(key->rd_key[102] + delta[2][20],  6);
		key->rd_key[118] = ROL(key->rd_key[110] + delta[3][23], 13);
		key->rd_key[126] = ROL(key->rd_key[118] + delta[5][21],  1);
		key->rd_key[134] = ROL(key->rd_key[126] + delta[6][24],  6);
		key->rd_key[142] = ROL(key->rd_key[134] + delta[7][27], 13);
		key->rd_key[150] = ROL(key->rd_key[142] + delta[1][25],  1);
		key->rd_key[158] = ROL(key->rd_key[150] + delta[2][28],  6);
		key->rd_key[166] = ROL(key->rd_key[158] + delta[3][31], 13);
		key->rd_key[174] = ROL(key->rd_key[166] + delta[5][29],  1);
		key->rd_key[182] = ROL(key->rd_key[174] + delta[6][ 0],  6);
		key->rd_key[190] = ROL(key->rd_key[182] + delta[7][ 3], 13);

		ctow(userKey + 28, &tmp);
		key->rd_key[  7] = ROL(tmp + delta[1][ 2],  3);
		key->rd_key[ 15] = ROL(key->rd_key[  7] + delta[2][ 5], 11);
		key->rd_key[ 23] = ROL(key->rd_key[ 15] + delta[3][ 8], 17);
		key->rd_key[ 31] = ROL(key->rd_key[ 23] + delta[5][ 6],  3);
		key->rd_key[ 39] = ROL(key->rd_key[ 31] + delta[6][ 9], 11);
		key->rd_key[ 47] = ROL(key->rd_key[ 39] + delta[7][12], 17);
		key->rd_key[ 55] = ROL(key->rd_key[ 47] + delta[1][10],  3);
		key->rd_key[ 63] = ROL(key->rd_key[ 55] + delta[2][13], 11);
		key->rd_key[ 71] = ROL(key->rd_key[ 63] + delta[3][16], 17);
		key->rd_key[ 79] = ROL(key->rd_key[ 71] + delta[5][14],  3);
		key->rd_key[ 87] = ROL(key->rd_key[ 79] + delta[6][17], 11);
		key->rd_key[ 95] = ROL(key->rd_key[ 87] + delta[7][20], 17);
		key->rd_key[103] = ROL(key->rd_key[ 95] + delta[1][18],  3);
		key->rd_key[111] = ROL(key->rd_key[103] + delta[2][21], 11);
		key->rd_key[119] = ROL(key->rd_key[111] + delta[3][24], 17);
		key->rd_key[127] = ROL(key->rd_key[119] + delta[5][22],  3);
		key->rd_key[135] = ROL(key->rd_key[127] + delta[6][25], 11);
		key->rd_key[143] = ROL(key->rd_key[135] + delta[7][28], 17);
		key->rd_key[151] = ROL(key->rd_key[143] + delta[1][26],  3);
		key->rd_key[159] = ROL(key->rd_key[151] + delta[2][29], 11);
		key->rd_key[167] = ROL(key->rd_key[159] + delta[3][ 0], 17);
		key->rd_key[175] = ROL(key->rd_key[167] + delta[5][30],  3);
		key->rd_key[183] = ROL(key->rd_key[175] + delta[6][ 1], 11);
		key->rd_key[191] = ROL(key->rd_key[183] + delta[7][ 4], 17);

		break;
	}

	key->rounds = (bits >> 4) + 16;
	
	return 0;
}

int private_LEA_set_decrypt_key(const unsigned char *userKey, const int bits,
			 LEA_KEY *key) {

	return private_LEA_set_encrypt_key(userKey, bits, key);
}

void LEA_encrypt(const unsigned char *in, unsigned char *out,
		 const LEA_KEY *key) {
		 	 
	unsigned int X0,X1,X2,X3;

	ctow(in     , &X0);
	ctow(in +  4, &X1);
	ctow(in +  8, &X2);
	ctow(in + 12, &X3);

	X3 = ROR((X2 ^ key->rd_key[  4]) + (X3 ^ key->rd_key[  5]), 3);
	X2 = ROR((X1 ^ key->rd_key[  2]) + (X2 ^ key->rd_key[  3]), 5);
	X1 = ROL((X0 ^ key->rd_key[  0]) + (X1 ^ key->rd_key[  1]), 9);
	X0 = ROR((X3 ^ key->rd_key[ 10]) + (X0 ^ key->rd_key[ 11]), 3);
	X3 = ROR((X2 ^ key->rd_key[  8]) + (X3 ^ key->rd_key[  9]), 5);
	X2 = ROL((X1 ^ key->rd_key[  6]) + (X2 ^ key->rd_key[  7]), 9);
	X1 = ROR((X0 ^ key->rd_key[ 16]) + (X1 ^ key->rd_key[ 17]), 3);
	X0 = ROR((X3 ^ key->rd_key[ 14]) + (X0 ^ key->rd_key[ 15]), 5);
	X3 = ROL((X2 ^ key->rd_key[ 12]) + (X3 ^ key->rd_key[ 13]), 9);
	X2 = ROR((X1 ^ key->rd_key[ 22]) + (X2 ^ key->rd_key[ 23]), 3);
	X1 = ROR((X0 ^ key->rd_key[ 20]) + (X1 ^ key->rd_key[ 21]), 5);
	X0 = ROL((X3 ^ key->rd_key[ 18]) + (X0 ^ key->rd_key[ 19]), 9);

	X3 = ROR((X2 ^ key->rd_key[ 28]) + (X3 ^ key->rd_key[ 29]), 3);
	X2 = ROR((X1 ^ key->rd_key[ 26]) + (X2 ^ key->rd_key[ 27]), 5);
	X1 = ROL((X0 ^ key->rd_key[ 24]) + (X1 ^ key->rd_key[ 25]), 9);
	X0 = ROR((X3 ^ key->rd_key[ 34]) + (X0 ^ key->rd_key[ 35]), 3);
	X3 = ROR((X2 ^ key->rd_key[ 32]) + (X3 ^ key->rd_key[ 33]), 5);
	X2 = ROL((X1 ^ key->rd_key[ 30]) + (X2 ^ key->rd_key[ 31]), 9);
	X1 = ROR((X0 ^ key->rd_key[ 40]) + (X1 ^ key->rd_key[ 41]), 3);
	X0 = ROR((X3 ^ key->rd_key[ 38]) + (X0 ^ key->rd_key[ 39]), 5);
	X3 = ROL((X2 ^ key->rd_key[ 36]) + (X3 ^ key->rd_key[ 37]), 9);
	X2 = ROR((X1 ^ key->rd_key[ 46]) + (X2 ^ key->rd_key[ 47]), 3);
	X1 = ROR((X0 ^ key->rd_key[ 44]) + (X1 ^ key->rd_key[ 45]), 5);
	X0 = ROL((X3 ^ key->rd_key[ 42]) + (X0 ^ key->rd_key[ 43]), 9);

	X3 = ROR((X2 ^ key->rd_key[ 52]) + (X3 ^ key->rd_key[ 53]), 3);
	X2 = ROR((X1 ^ key->rd_key[ 50]) + (X2 ^ key->rd_key[ 51]), 5);
	X1 = ROL((X0 ^ key->rd_key[ 48]) + (X1 ^ key->rd_key[ 49]), 9);
	X0 = ROR((X3 ^ key->rd_key[ 58]) + (X0 ^ key->rd_key[ 59]), 3);
	X3 = ROR((X2 ^ key->rd_key[ 56]) + (X3 ^ key->rd_key[ 57]), 5);
	X2 = ROL((X1 ^ key->rd_key[ 54]) + (X2 ^ key->rd_key[ 55]), 9);
	X1 = ROR((X0 ^ key->rd_key[ 64]) + (X1 ^ key->rd_key[ 65]), 3);
	X0 = ROR((X3 ^ key->rd_key[ 62]) + (X0 ^ key->rd_key[ 63]), 5);
	X3 = ROL((X2 ^ key->rd_key[ 60]) + (X3 ^ key->rd_key[ 61]), 9);
	X2 = ROR((X1 ^ key->rd_key[ 70]) + (X2 ^ key->rd_key[ 71]), 3);
	X1 = ROR((X0 ^ key->rd_key[ 68]) + (X1 ^ key->rd_key[ 69]), 5);
	X0 = ROL((X3 ^ key->rd_key[ 66]) + (X0 ^ key->rd_key[ 67]), 9);

	X3 = ROR((X2 ^ key->rd_key[ 76]) + (X3 ^ key->rd_key[ 77]), 3);
	X2 = ROR((X1 ^ key->rd_key[ 74]) + (X2 ^ key->rd_key[ 75]), 5);
	X1 = ROL((X0 ^ key->rd_key[ 72]) + (X1 ^ key->rd_key[ 73]), 9);
	X0 = ROR((X3 ^ key->rd_key[ 82]) + (X0 ^ key->rd_key[ 83]), 3);
	X3 = ROR((X2 ^ key->rd_key[ 80]) + (X3 ^ key->rd_key[ 81]), 5);
	X2 = ROL((X1 ^ key->rd_key[ 78]) + (X2 ^ key->rd_key[ 79]), 9);
	X1 = ROR((X0 ^ key->rd_key[ 88]) + (X1 ^ key->rd_key[ 89]), 3);
	X0 = ROR((X3 ^ key->rd_key[ 86]) + (X0 ^ key->rd_key[ 87]), 5);
	X3 = ROL((X2 ^ key->rd_key[ 84]) + (X3 ^ key->rd_key[ 85]), 9);
	X2 = ROR((X1 ^ key->rd_key[ 94]) + (X2 ^ key->rd_key[ 95]), 3);
	X1 = ROR((X0 ^ key->rd_key[ 92]) + (X1 ^ key->rd_key[ 93]), 5);
	X0 = ROL((X3 ^ key->rd_key[ 90]) + (X0 ^ key->rd_key[ 91]), 9);

	X3 = ROR((X2 ^ key->rd_key[100]) + (X3 ^ key->rd_key[101]), 3);
	X2 = ROR((X1 ^ key->rd_key[ 98]) + (X2 ^ key->rd_key[ 99]), 5);
	X1 = ROL((X0 ^ key->rd_key[ 96]) + (X1 ^ key->rd_key[ 97]), 9);
	X0 = ROR((X3 ^ key->rd_key[106]) + (X0 ^ key->rd_key[107]), 3);
	X3 = ROR((X2 ^ key->rd_key[104]) + (X3 ^ key->rd_key[105]), 5);
	X2 = ROL((X1 ^ key->rd_key[102]) + (X2 ^ key->rd_key[103]), 9);
	X1 = ROR((X0 ^ key->rd_key[112]) + (X1 ^ key->rd_key[113]), 3);
	X0 = ROR((X3 ^ key->rd_key[110]) + (X0 ^ key->rd_key[111]), 5);
	X3 = ROL((X2 ^ key->rd_key[108]) + (X3 ^ key->rd_key[109]), 9);
	X2 = ROR((X1 ^ key->rd_key[118]) + (X2 ^ key->rd_key[119]), 3);
	X1 = ROR((X0 ^ key->rd_key[116]) + (X1 ^ key->rd_key[117]), 5);
	X0 = ROL((X3 ^ key->rd_key[114]) + (X0 ^ key->rd_key[115]), 9);

	X3 = ROR((X2 ^ key->rd_key[124]) + (X3 ^ key->rd_key[125]), 3);
	X2 = ROR((X1 ^ key->rd_key[122]) + (X2 ^ key->rd_key[123]), 5);
	X1 = ROL((X0 ^ key->rd_key[120]) + (X1 ^ key->rd_key[121]), 9);
	X0 = ROR((X3 ^ key->rd_key[130]) + (X0 ^ key->rd_key[131]), 3);
	X3 = ROR((X2 ^ key->rd_key[128]) + (X3 ^ key->rd_key[129]), 5);
	X2 = ROL((X1 ^ key->rd_key[126]) + (X2 ^ key->rd_key[127]), 9);
	X1 = ROR((X0 ^ key->rd_key[136]) + (X1 ^ key->rd_key[137]), 3);
	X0 = ROR((X3 ^ key->rd_key[134]) + (X0 ^ key->rd_key[135]), 5);
	X3 = ROL((X2 ^ key->rd_key[132]) + (X3 ^ key->rd_key[133]), 9);
	X2 = ROR((X1 ^ key->rd_key[142]) + (X2 ^ key->rd_key[143]), 3);
	X1 = ROR((X0 ^ key->rd_key[140]) + (X1 ^ key->rd_key[141]), 5);
	X0 = ROL((X3 ^ key->rd_key[138]) + (X0 ^ key->rd_key[139]), 9);

	if(key->rounds > 24)
	{
		X3 = ROR((X2 ^ key->rd_key[148]) + (X3 ^ key->rd_key[149]), 3);
		X2 = ROR((X1 ^ key->rd_key[146]) + (X2 ^ key->rd_key[147]), 5);
		X1 = ROL((X0 ^ key->rd_key[144]) + (X1 ^ key->rd_key[145]), 9);
		X0 = ROR((X3 ^ key->rd_key[154]) + (X0 ^ key->rd_key[155]), 3);
		X3 = ROR((X2 ^ key->rd_key[152]) + (X3 ^ key->rd_key[153]), 5);
		X2 = ROL((X1 ^ key->rd_key[150]) + (X2 ^ key->rd_key[151]), 9);
		X1 = ROR((X0 ^ key->rd_key[160]) + (X1 ^ key->rd_key[161]), 3);
		X0 = ROR((X3 ^ key->rd_key[158]) + (X0 ^ key->rd_key[159]), 5);
		X3 = ROL((X2 ^ key->rd_key[156]) + (X3 ^ key->rd_key[157]), 9);
		X2 = ROR((X1 ^ key->rd_key[166]) + (X2 ^ key->rd_key[167]), 3);
		X1 = ROR((X0 ^ key->rd_key[164]) + (X1 ^ key->rd_key[165]), 5);
		X0 = ROL((X3 ^ key->rd_key[162]) + (X0 ^ key->rd_key[163]), 9);
	}

	if(key->rounds > 28)
	{
		X3 = ROR((X2 ^ key->rd_key[172]) + (X3 ^ key->rd_key[173]), 3);
		X2 = ROR((X1 ^ key->rd_key[170]) + (X2 ^ key->rd_key[171]), 5);
		X1 = ROL((X0 ^ key->rd_key[168]) + (X1 ^ key->rd_key[169]), 9);
		X0 = ROR((X3 ^ key->rd_key[178]) + (X0 ^ key->rd_key[179]), 3);
		X3 = ROR((X2 ^ key->rd_key[176]) + (X3 ^ key->rd_key[177]), 5);
		X2 = ROL((X1 ^ key->rd_key[174]) + (X2 ^ key->rd_key[175]), 9);
		X1 = ROR((X0 ^ key->rd_key[184]) + (X1 ^ key->rd_key[185]), 3);
		X0 = ROR((X3 ^ key->rd_key[182]) + (X0 ^ key->rd_key[183]), 5);
		X3 = ROL((X2 ^ key->rd_key[180]) + (X3 ^ key->rd_key[181]), 9);
		X2 = ROR((X1 ^ key->rd_key[190]) + (X2 ^ key->rd_key[191]), 3);
		X1 = ROR((X0 ^ key->rd_key[188]) + (X1 ^ key->rd_key[189]), 5);
		X0 = ROL((X3 ^ key->rd_key[186]) + (X0 ^ key->rd_key[187]), 9);
	}

	wtoc(&X0, out     );
	wtoc(&X1, out +  4);
	wtoc(&X2, out +  8);
	wtoc(&X3, out + 12);
}

void LEA_decrypt(const unsigned char *in, unsigned char *out,
		 const LEA_KEY *key) {

	unsigned int X0,X1,X2,X3;

	ctow(in     , &X0);
	ctow(in +  4, &X1);
	ctow(in +  8, &X2);
	ctow(in + 12, &X3);

	if(key->rounds > 28)
	{
		X0 = (ROR(X0, 9) - (X3 ^ key->rd_key[186])) ^ key->rd_key[187];
		X1 = (ROL(X1, 5) - (X0 ^ key->rd_key[188])) ^ key->rd_key[189];
		X2 = (ROL(X2, 3) - (X1 ^ key->rd_key[190])) ^ key->rd_key[191];
		X3 = (ROR(X3, 9) - (X2 ^ key->rd_key[180])) ^ key->rd_key[181];
		X0 = (ROL(X0, 5) - (X3 ^ key->rd_key[182])) ^ key->rd_key[183];
		X1 = (ROL(X1, 3) - (X0 ^ key->rd_key[184])) ^ key->rd_key[185];
		X2 = (ROR(X2, 9) - (X1 ^ key->rd_key[174])) ^ key->rd_key[175];
		X3 = (ROL(X3, 5) - (X2 ^ key->rd_key[176])) ^ key->rd_key[177];
		X0 = (ROL(X0, 3) - (X3 ^ key->rd_key[178])) ^ key->rd_key[179];
		X1 = (ROR(X1, 9) - (X0 ^ key->rd_key[168])) ^ key->rd_key[169];
		X2 = (ROL(X2, 5) - (X1 ^ key->rd_key[170])) ^ key->rd_key[171];
		X3 = (ROL(X3, 3) - (X2 ^ key->rd_key[172])) ^ key->rd_key[173];
	}

	if(key->rounds > 24)
	{
		X0 = (ROR(X0, 9) - (X3 ^ key->rd_key[162])) ^ key->rd_key[163];
		X1 = (ROL(X1, 5) - (X0 ^ key->rd_key[164])) ^ key->rd_key[165];
		X2 = (ROL(X2, 3) - (X1 ^ key->rd_key[166])) ^ key->rd_key[167];
		X3 = (ROR(X3, 9) - (X2 ^ key->rd_key[156])) ^ key->rd_key[157];
		X0 = (ROL(X0, 5) - (X3 ^ key->rd_key[158])) ^ key->rd_key[159];
		X1 = (ROL(X1, 3) - (X0 ^ key->rd_key[160])) ^ key->rd_key[161];
		X2 = (ROR(X2, 9) - (X1 ^ key->rd_key[150])) ^ key->rd_key[151];
		X3 = (ROL(X3, 5) - (X2 ^ key->rd_key[152])) ^ key->rd_key[153];
		X0 = (ROL(X0, 3) - (X3 ^ key->rd_key[154])) ^ key->rd_key[155];
		X1 = (ROR(X1, 9) - (X0 ^ key->rd_key[144])) ^ key->rd_key[145];
		X2 = (ROL(X2, 5) - (X1 ^ key->rd_key[146])) ^ key->rd_key[147];
		X3 = (ROL(X3, 3) - (X2 ^ key->rd_key[148])) ^ key->rd_key[149];
	}

	X0 = (ROR(X0, 9) - (X3 ^ key->rd_key[138])) ^ key->rd_key[139];
	X1 = (ROL(X1, 5) - (X0 ^ key->rd_key[140])) ^ key->rd_key[141];
	X2 = (ROL(X2, 3) - (X1 ^ key->rd_key[142])) ^ key->rd_key[143];
	X3 = (ROR(X3, 9) - (X2 ^ key->rd_key[132])) ^ key->rd_key[133];
	X0 = (ROL(X0, 5) - (X3 ^ key->rd_key[134])) ^ key->rd_key[135];
	X1 = (ROL(X1, 3) - (X0 ^ key->rd_key[136])) ^ key->rd_key[137];
	X2 = (ROR(X2, 9) - (X1 ^ key->rd_key[126])) ^ key->rd_key[127];
	X3 = (ROL(X3, 5) - (X2 ^ key->rd_key[128])) ^ key->rd_key[129];
	X0 = (ROL(X0, 3) - (X3 ^ key->rd_key[130])) ^ key->rd_key[131];
	X1 = (ROR(X1, 9) - (X0 ^ key->rd_key[120])) ^ key->rd_key[121];
	X2 = (ROL(X2, 5) - (X1 ^ key->rd_key[122])) ^ key->rd_key[123];
	X3 = (ROL(X3, 3) - (X2 ^ key->rd_key[124])) ^ key->rd_key[125];

	X0 = (ROR(X0, 9) - (X3 ^ key->rd_key[114])) ^ key->rd_key[115];
	X1 = (ROL(X1, 5) - (X0 ^ key->rd_key[116])) ^ key->rd_key[117];
	X2 = (ROL(X2, 3) - (X1 ^ key->rd_key[118])) ^ key->rd_key[119];
	X3 = (ROR(X3, 9) - (X2 ^ key->rd_key[108])) ^ key->rd_key[109];
	X0 = (ROL(X0, 5) - (X3 ^ key->rd_key[110])) ^ key->rd_key[111];
	X1 = (ROL(X1, 3) - (X0 ^ key->rd_key[112])) ^ key->rd_key[113];
	X2 = (ROR(X2, 9) - (X1 ^ key->rd_key[102])) ^ key->rd_key[103];
	X3 = (ROL(X3, 5) - (X2 ^ key->rd_key[104])) ^ key->rd_key[105];
	X0 = (ROL(X0, 3) - (X3 ^ key->rd_key[106])) ^ key->rd_key[107];
	X1 = (ROR(X1, 9) - (X0 ^ key->rd_key[ 96])) ^ key->rd_key[ 97];
	X2 = (ROL(X2, 5) - (X1 ^ key->rd_key[ 98])) ^ key->rd_key[ 99];
	X3 = (ROL(X3, 3) - (X2 ^ key->rd_key[100])) ^ key->rd_key[101];

	X0 = (ROR(X0, 9) - (X3 ^ key->rd_key[ 90])) ^ key->rd_key[ 91];
	X1 = (ROL(X1, 5) - (X0 ^ key->rd_key[ 92])) ^ key->rd_key[ 93];
	X2 = (ROL(X2, 3) - (X1 ^ key->rd_key[ 94])) ^ key->rd_key[ 95];
	X3 = (ROR(X3, 9) - (X2 ^ key->rd_key[ 84])) ^ key->rd_key[ 85];
	X0 = (ROL(X0, 5) - (X3 ^ key->rd_key[ 86])) ^ key->rd_key[ 87];
	X1 = (ROL(X1, 3) - (X0 ^ key->rd_key[ 88])) ^ key->rd_key[ 89];
	X2 = (ROR(X2, 9) - (X1 ^ key->rd_key[ 78])) ^ key->rd_key[ 79];
	X3 = (ROL(X3, 5) - (X2 ^ key->rd_key[ 80])) ^ key->rd_key[ 81];
	X0 = (ROL(X0, 3) - (X3 ^ key->rd_key[ 82])) ^ key->rd_key[ 83];
	X1 = (ROR(X1, 9) - (X0 ^ key->rd_key[ 72])) ^ key->rd_key[ 73];
	X2 = (ROL(X2, 5) - (X1 ^ key->rd_key[ 74])) ^ key->rd_key[ 75];
	X3 = (ROL(X3, 3) - (X2 ^ key->rd_key[ 76])) ^ key->rd_key[ 77];

	X0 = (ROR(X0, 9) - (X3 ^ key->rd_key[ 66])) ^ key->rd_key[ 67];
	X1 = (ROL(X1, 5) - (X0 ^ key->rd_key[ 68])) ^ key->rd_key[ 69];
	X2 = (ROL(X2, 3) - (X1 ^ key->rd_key[ 70])) ^ key->rd_key[ 71];
	X3 = (ROR(X3, 9) - (X2 ^ key->rd_key[ 60])) ^ key->rd_key[ 61];
	X0 = (ROL(X0, 5) - (X3 ^ key->rd_key[ 62])) ^ key->rd_key[ 63];
	X1 = (ROL(X1, 3) - (X0 ^ key->rd_key[ 64])) ^ key->rd_key[ 65];
	X2 = (ROR(X2, 9) - (X1 ^ key->rd_key[ 54])) ^ key->rd_key[ 55];
	X3 = (ROL(X3, 5) - (X2 ^ key->rd_key[ 56])) ^ key->rd_key[ 57];
	X0 = (ROL(X0, 3) - (X3 ^ key->rd_key[ 58])) ^ key->rd_key[ 59];
	X1 = (ROR(X1, 9) - (X0 ^ key->rd_key[ 48])) ^ key->rd_key[ 49];
	X2 = (ROL(X2, 5) - (X1 ^ key->rd_key[ 50])) ^ key->rd_key[ 51];
	X3 = (ROL(X3, 3) - (X2 ^ key->rd_key[ 52])) ^ key->rd_key[ 53];

	X0 = (ROR(X0, 9) - (X3 ^ key->rd_key[ 42])) ^ key->rd_key[ 43];
	X1 = (ROL(X1, 5) - (X0 ^ key->rd_key[ 44])) ^ key->rd_key[ 45];
	X2 = (ROL(X2, 3) - (X1 ^ key->rd_key[ 46])) ^ key->rd_key[ 47];
	X3 = (ROR(X3, 9) - (X2 ^ key->rd_key[ 36])) ^ key->rd_key[ 37];
	X0 = (ROL(X0, 5) - (X3 ^ key->rd_key[ 38])) ^ key->rd_key[ 39];
	X1 = (ROL(X1, 3) - (X0 ^ key->rd_key[ 40])) ^ key->rd_key[ 41];
	X2 = (ROR(X2, 9) - (X1 ^ key->rd_key[ 30])) ^ key->rd_key[ 31];
	X3 = (ROL(X3, 5) - (X2 ^ key->rd_key[ 32])) ^ key->rd_key[ 33];
	X0 = (ROL(X0, 3) - (X3 ^ key->rd_key[ 34])) ^ key->rd_key[ 35];
	X1 = (ROR(X1, 9) - (X0 ^ key->rd_key[ 24])) ^ key->rd_key[ 25];
	X2 = (ROL(X2, 5) - (X1 ^ key->rd_key[ 26])) ^ key->rd_key[ 27];
	X3 = (ROL(X3, 3) - (X2 ^ key->rd_key[ 28])) ^ key->rd_key[ 29];

	X0 = (ROR(X0, 9) - (X3 ^ key->rd_key[ 18])) ^ key->rd_key[ 19];
	X1 = (ROL(X1, 5) - (X0 ^ key->rd_key[ 20])) ^ key->rd_key[ 21];
	X2 = (ROL(X2, 3) - (X1 ^ key->rd_key[ 22])) ^ key->rd_key[ 23];
	X3 = (ROR(X3, 9) - (X2 ^ key->rd_key[ 12])) ^ key->rd_key[ 13];
	X0 = (ROL(X0, 5) - (X3 ^ key->rd_key[ 14])) ^ key->rd_key[ 15];
	X1 = (ROL(X1, 3) - (X0 ^ key->rd_key[ 16])) ^ key->rd_key[ 17];
	X2 = (ROR(X2, 9) - (X1 ^ key->rd_key[  6])) ^ key->rd_key[  7];
	X3 = (ROL(X3, 5) - (X2 ^ key->rd_key[  8])) ^ key->rd_key[  9];
	X0 = (ROL(X0, 3) - (X3 ^ key->rd_key[ 10])) ^ key->rd_key[ 11];
	X1 = (ROR(X1, 9) - (X0 ^ key->rd_key[  0])) ^ key->rd_key[  1];
	X2 = (ROL(X2, 5) - (X1 ^ key->rd_key[  2])) ^ key->rd_key[  3];
	X3 = (ROL(X3, 3) - (X2 ^ key->rd_key[  4])) ^ key->rd_key[  5];


	wtoc(&X0, out     );
	wtoc(&X1, out +  4);
	wtoc(&X2, out +  8);
	wtoc(&X3, out + 12);
}