#
# crypto/lea/Makefile
#

DIR=	lea
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

LEA_ENC=lea_core.o lea_cbc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
#TEST=leatest.c
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=lea_misc.c lea_ecb.c lea_cbc.c lea_cfb.c lea_ofb.c lea_ctr.c lea_gcm.c lea_core.c e_lea.c
LIBOBJ=lea_misc.o lea_ecb.o lea_cfb.o $(LEA_ENC) lea_ofb.o lea_ctr.o lea_gcm.o e_lea.o

SRC= $(LIBSRC)

EXHEADER= lea.h
HEADER= lea_locl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

LEA_SIMD_AVX2=
LEA_SIMD_SSE2=
LEA_SIMD_XOP=
LEA_SIMD_NEON=

ifneq ($(findstring cl,$(CC)),)
	LEA_CC=vc
else 
ifneq ($(findstring gcc,$(CC)),)
	LEA_CC=gcc
else
ifneq ($(shell $(CC) -v 3>&1 2>&1 1>&2 | grep gcc version),)
	LEA_CC=gcc
else
	LEA_CC=generic
endif #cc
endif #gcc
endif #cl

ifeq (mem_clr.o, $(CPUID_OBJ))
	LEA_PLATFORM=generic
else
ifeq (x86_64cpuid.o,$(CPUID_OBJ))
	LEA_PLATFORM=IA32
else
ifeq (x86cpuid.o,$(CPUID_OBJ))
	LEA_PLATFORM=IA32
else
ifneq ($(findstring armv4cpuid.o,$(CPUID_OBJ)),)
	LEA_PLATFORM=armv4
else
ifneq ($(findstring arm64cpuid.o,$(CPUID_OBJ)),)
	LEA_PLATFORM=arm64
else
	LEA_PLATFORM=generic
endif #arm64
endif #armv4
endif #x86
endif #x86_64
endif #mem_clr.o

#OPENSSL DOESN'T SUPPORT INTRINSIC COMPILE OPTIONS WITHOUT SSE2, AESNI, SHA
ifeq (generic, $(LEA_PLATFORM))
CFLAGS += -DNO_LEA_SIMD
else 
ifeq ($(LEA_PLATFORM),IA32)
	ifeq ($(LEA_CC),gcc)
		#intel_gcc

		ifneq ($(shell $(CC) --target-help 3>&1 2>&1 1>&2 | grep avx2),)
			ifeq ($(LEA_SIMD_AVX2),)
				LEA_SIMD_AVX2 = -mavx2
			endif
			LIBOBJ += lea_avx2.o
			LIBSRC += lea_avx2.c
		endif

		ifneq ($(shell $(CC) --target-help 3>&1 2>&1 1>&2 | grep sse2),)
			ifeq ($(LEA_SIMD_SSE2),)
				LEA_SIMD_SSE2 = -msse2
			endif
			LIBOBJ += lea_sse.o
			LIBSRC += lea_sse.c
		endif

		ifneq ($(shell $(CC) --target-help 3>&1 2>&1 1>&2 | grep xop),)
			ifeq ($(LEA_SIMD_XOP),)
				LEA_SIMD_XOP = -mxop
			endif
			LIBOBJ += lea_xop.o
			LIBSRC += lea_xop.c
		endif

	else 
		ifeq ($(LEA_CC),vc)

			#intel_VC just ADD! VC will 'deal with them' properly
			ifeq ($(LEA_SIMD_AVX2),)
				LEA_SIMD_AVX2 = /arch:AVX2
			endif
			ifeq ($(LEA_SIMD_SSE2),)
				LEA_SIMD_SSE2 = /arch:SSE2
			endif
			ifeq ($(LEA_SIMD_XOP),)
				LEA_SIMD_XOP = /arch:SSE2
			endif
			LIBOBJ += lea_avx2.o lea_sse2.o lea_xop.o #lea_gcm_pclmul.o
			LIBSRC += lea_avx2.c lea_sse2.c lea_xop.c #lea_gcm_pclmul.c
		endif
	endif

else 
ifeq ($(LEA_PLATFORM),armv4)

	ifeq ($(LEA_CC),gcc)
		#armv4_gcc
		ifneq ($(shell $(CC) --target-help 3>&1 2>&1 1>&2 | grep neon),)
			ifneq ($(LEA_SIMD_NEON),)
				ifeq ($(findstring neon,$(CFLAG)),)

					ifeq ($(findstring mfloat-abi,$(CFLAG)),)
						LEA_SIMD_NEON = -mfloat-abi=softfp -mfpu=neon
					else
						LEA_SIMD_NEON = -fpu=neon
					endif

				endif #endof neon, cflag
			endif

			LIBOBJ += lea_neon.o
			LIBSRC += lea_neon.c
		endif
	endif

else 
ifeq ($(LEA_PLATFORM),arm64)

	ifeq ($(LEA_CC),gcc)

		#arm64_gcc just add
		LIBOBJ += lea_neon.o
		LIBSRC += lea_neon.c
	endif

endif #arm64
endif #armv4
endif #ia32
endif #generic

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

lea_avx2.o:	lea_avx2.c
	$(CC) $(CFLAGS) $(LEA_SIMD_AVX2) -c -o $@ lea_avx2.c

lea_sse.o:	lea_sse.c
	$(CC) $(CFLAGS) $(LEA_SIMD_SSE2) -c -o $@ lea_sse.c

lea_xop.o:	lea_xop.c
	$(CC) $(CFLAGS) $(LEA_SIMD_XOP) -c -o $@ lea_xop.c

lea_gcm_pclmul.o:	lea_gcm_pclmul.c
	$(CC) $(CFLAGS) $(LEA_SIMD_PCLMUL) -c -o $@ lea_gcm_pclmul.c

lea_neon.o:	lea_neon.c
	$(CC) $(CFLAGS) $(LEA_SIMD_NEON) -c -o $@ lea_neon.c

# GNU make "catch all"

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) $(LEA_SIMD_AVX2) $(LEA_SIMD_SSE2) $(LEA_SIMD_XOP) $(LEA_SIMD_PCLMUL) $(LEA_SIMD_NEON) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

e_lea.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
e_lea.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
e_lea.o: ../../include/openssl/err.h ../../include/openssl/evp.h
e_lea.o: ../../include/openssl/lea.h ../../include/openssl/lhash.h
e_lea.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
e_lea.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
e_lea.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
e_lea.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
e_lea.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
e_lea.o: ../evp/evp_locl.h ../modes/modes_lcl.h
e_lea.o: e_lea.c lea_locl.h
lea_avx2.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_avx2.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_avx2.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_avx2.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_avx2.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_avx2.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_avx2.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_avx2.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_avx2.o: lea_avx2.c lea_locl.h
lea_neon.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_neon.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_neon.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_neon.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_neon.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_neon.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_neon.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_neon.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_neon.o: lea_neon.c lea_locl.h
lea_cbc.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_cbc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_cbc.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_cbc.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_cbc.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_cbc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_cbc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_cbc.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_cbc.o: lea_cbc.c lea_locl.h
lea_cfb.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_cfb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_cfb.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_cfb.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_cfb.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_cfb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_cfb.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_cfb.o: ../../include/openssl/symhacks.h
lea_cfb.o: lea_cfb.c lea_locl.h
lea_core.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_core.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_core.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_core.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_core.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_core.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_core.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_core.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_core.o: lea_core.c lea_locl.h
lea_ctr.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_ctr.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_ctr.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_ctr.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_ctr.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_ctr.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_ctr.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_ctr.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_ctr.o: lea_ctr.c lea_locl.h
lea_ecb.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_ecb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_ecb.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_ecb.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_ecb.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_ecb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_ecb.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_ecb.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h 
lea_ecb.o: lea_ecb.c lea_locl.h
lea_gcm.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_gcm.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_gcm.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_gcm.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_gcm.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_gcm.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_gcm.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_gcm.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_gcm.o: lea_gcm.c lea_locl.h
lea_misc.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_misc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_misc.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_misc.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_misc.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_misc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_misc.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_misc.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_misc.o: lea_misc.c lea_locl.h
lea_ofb.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_ofb.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_ofb.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_ofb.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_ofb.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_ofb.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_ofb.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_ofb.o: ../../include/openssl/symhacks.h
lea_sse.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_sse.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_sse.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_sse.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_sse.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_sse.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_sse.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_sse.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_sse.o: lea_sse.c lea_locl.h
lea_xop.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
lea_xop.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
lea_xop.o: ../../include/openssl/evp.h ../../include/openssl/lea.h
lea_xop.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
lea_xop.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
lea_xop.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
lea_xop.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
lea_xop.o: ../../include/openssl/symhacks.h ../modes/modes_lcl.h
lea_xop.o: lea_xop.c lea_locl.h
