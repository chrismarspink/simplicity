# ifndef _GZPKI_X509_H_
# define _GZPKI_X509_H_

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <time.h>
# include <assert.h>


//TODO: REMOVE
#if 0
# include <openssl/crypto.h>
# include <openssl/pem.h>
# include <openssl/err.h>
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
#endif


# include "gzpki_types.h"


int GZPKI_do_X509(GZPKI_CTX *ctx);


#endif /* _GZPKI_X509_H_ */
