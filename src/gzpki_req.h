#ifndef _GZPKI_REQ_H_
#define _GZPKI_REQ_H_


#include <stdio.h>
#include <string.h>

# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include <assert.h>


# include "gzpki_types.h"

int GZPKI_do_REQ(GZPKI_CTX *ctx);
int GZPKI_send_REQ(GZPKI_CTX *ctx);

#endif /* _GZPKI_REQ_H_ */
