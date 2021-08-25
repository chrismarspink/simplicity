#ifndef _GZPKI_ENC_H_
#define _GZPKI_ENC_H_



#if 1
# include <openssl/crypto.h>
# include <openssl/x509_vfy.h>
# include <openssl/x509v3.h>
# include <openssl/cms.h>
# include <openssl/evp.h>
# include <openssl/ui.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/pkcs12.h>
# include <openssl/rand.h>
# include <openssl/txt_db.h>
# include <openssl/lhash.h>
# include <openssl/ocsp.h>
# include <openssl/sha.h>
# include <openssl/ripemd.h>

# include <sys/types.h>
# include <openssl/conf.h>
# include <openssl/objects.h>
#endif

#undef SIZE
#undef BSIZE
#define SIZE    (512)
#define BSIZE   (8*1024)



int GZPKI_do_ENC(GZPKI_CTX *ctx);


void encrypt(char *infile, char *outfile);
void decrypt(char *infile, char *outfile);

#endif