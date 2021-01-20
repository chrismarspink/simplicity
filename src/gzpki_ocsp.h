# ifndef _GZPKI_OCSP_H_
# define _GZPKI_OCSP_H_

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

# include "gzpki_common.h"
# include "gzpki_types.h"


#define GZPKI_set_VAfile GZPKI_set_ocsp_verify_certfile
#define GZPKI_get_VAfile GZPKI_get_ocsp_verify_certfile

int GZPKI_do_OCSP(GZPKI_CTX *ctx);


#endif /* _GZPKI_OCSP_H_ */
