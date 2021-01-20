#ifndef _GZPKI_COMMON_H_
#define _GZPKI_COMMON_H_

#define DEBUG_MODE 1

# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include <assert.h>
# include <fcntl.h>
# include <unistd.h>

# ifndef OPENSSL_NO_POSIX_IO
#  include <sys/stat.h>
#  include <fcntl.h>
# endif

 
#include "gzpki_types.h"

#define GZPKI_VERSION "2.0.0"
char *GZPKI_lib_get_version();
/* Maximum leeway in validity period: default 5 minutes */
# define MAX_VALIDITY_PERIOD    (5 * 60)

//static char *save_rand_file;
char *save_rand_file;

//for X.509
#undef POSTFIX
#define POSTFIX    ".srl"
#define DEF_DAYS   30

# define DECLARE_GZPKI_SET_FN(name) int GZPKI_set_##name (GZPKI_CTX *, int);
# define IMPLEMENT_GZPKI_SET_FN(name) \
        int GZPKI_set_##name (GZPKI_CTX *ctx, int name) { \
                ctx->name = name;\
                return CMS_RET_OK; }

# define DECLARE_GZPKI_SET_CHAR_FN(name) int GZPKI_set_##name (GZPKI_CTX *, char *);
# define IMPLEMENT_GZPKI_SET_CHAR_FN(name) \
        int GZPKI_set_##name (GZPKI_CTX *ctx, char *name) { \
                ctx->name = GZPKI_strdup(name);\
                return CMS_RET_OK; }


# define DECLARE_GZPKI_GET_FN(name) int GZPKI_get_##name (GZPKI_CTX *);
# define IMPLEMENT_GZPKI_GET_FN(name) \
        int GZPKI_get_##name (GZPKI_CTX *ctx) { \
                return ctx->name; }

# define DECLARE_GZPKI_GET_CHAR_FN(name) char* GZPKI_get_##name (GZPKI_CTX *);
# define IMPLEMENT_GZPKI_GET_CHAR_FN(name) \
        char* GZPKI_get_##name (GZPKI_CTX *ctx) { \
                return ctx->name; }


# define DECLARE_GZPKI_SET_FN2(name)    DECLARE_GZPKI_SET_FN(name) \
                                        DECLARE_GZPKI_GET_FN(name) 
# define IMPLEMENT_GZPKI_SET_FN2(name)  IMPLEMENT_GZPKI_SET_FN(name) \
                                        IMPLEMENT_GZPKI_GET_FN(name) 
# define DECLARE_GZPKI_SET_CHAR_FN2(name)   DECLARE_GZPKI_SET_CHAR_FN(name) \
                                            DECLARE_GZPKI_GET_CHAR_FN(name) 
# define IMPLEMENT_GZPKI_SET_CHAR_FN2(name) IMPLEMENT_GZPKI_SET_CHAR_FN(name) \
                                            IMPLEMENT_GZPKI_GET_CHAR_FN(name) 


#define  GZPKI_set_req_challenge_password(A, B)     \
    GZPKI_set_challengePassword_default(A, B)
    //GZPKI_set_challengePassword(A, "challengePassword:"); 


#define  GZPKI_set_req_content_type(A,B)    \
    GZPKI_set_contentType_default(A, B)
    //GZPKI_set_contentType(A, "contentType:"); 


#define  GZPKI_set_req_unstructured_name(A, B) \
    GZPKI_set_unstructuredName_default(A, B)
    //GZPKI_set_unstructuredName(A, "unstructuredName:"); 
    //GZPKI_set_unstructuredName_default(A, B)
//----------
// callback_password 용, 가급적 삭제
// password는 OpenSSL의 방법을 따르지 않고 set 함수 제공
//----------
typedef struct ui_method_st UI_METHOD;

void gzpki_lib_init();

extern char *default_config_file ;

 BIO *bio_in;
 BIO *bio_out;
 BIO *bio_err;

struct alg_def {
    int index;
    const char *name;
};    

struct ecparam_def {
    int index;
    const char *name;
    const char *comment;
};    


static const struct ecparam_def ecparam_list[] = {
    {1 ,"secp112r1", "SECG/WTLS curve over a 112 bit prime field"},
    {2 ,"secp112r2", "SECG curve over a 112 bit prime field"},
    {3 ,"secp128r1", "SECG curve over a 128 bit prime field"},
    {4 ,"secp128r2", "SECG curve over a 128 bit prime field"},
    {5 ,"secp160k1", "SECG curve over a 160 bit prime field"},
    {6 ,"secp160r1", "SECG curve over a 160 bit prime field"},
    {7 ,"secp160r2", "SECG/WTLS curve over a 160 bit prime field"},
    {8 ,"secp192k1 ", "SECG curve over a 192 bit prime field"},
    {9 ,"secp224k1 ", "SECG curve over a 224 bit prime field"},
    {10 ,"secp224r1 ", "NIST/SECG curve over a 224 bit prime field"},
    {11 ,"secp256k1 ", "SECG curve over a 256 bit prime field"},
    {12 ,"secp384r1 ", "NIST/SECG curve over a 384 bit prime field"},
    {13 ,"secp521r1 ", "NIST/SECG curve over a 521 bit prime field"},
    {14 ,"prime192v1", "NIST/X9.62/SECG curve over a 192 bit prime field"},
    {15 ,"prime192v2", "X9.62 curve over a 192 bit prime field"},
    {16 ,"prime192v3", "X9.62 curve over a 192 bit prime field"},
    {17 ,"prime239v1", "X9.62 curve over a 239 bit prime field"},
    {18 ,"prime239v2", "X9.62 curve over a 239 bit prime field"},
    {19 ,"prime239v3", "X9.62 curve over a 239 bit prime field"},
    {20 ,"prime256v1", "X9.62/SECG curve over a 256 bit prime field"},
    {21 ,"sect113r1 ", "SECG curve over a 113 bit binary field"},
    {22 ,"sect113r2 ", "SECG curve over a 113 bit binary field"},
    {23 ,"sect131r1 ", "SECG/WTLS curve over a 131 bit binary field"},
    {24 ,"sect131r2 ", "SECG curve over a 131 bit binary field"},
    {25 ,"sect163k1 ", "NIST/SECG/WTLS curve over a 163 bit binary field"},
    {26 ,"sect163r1 ", "SECG curve over a 163 bit binary field"},
    {27 ,"sect163r1 ", "SECG curve over a 163 bit binary field"},
    {28 ,"sect163r1 ", "SECG curve over a 163 bit binary field"},
    {29 ,"sect163r1 ", "SECG curve over a 163 bit binary field"},
    {30 ,"sect163r2 ", "NIST/SECG curve over a 163 bit binary field"},
    {31 ,"sect193r1 ", "SECG curve over a 193 bit binary field"},
    {32 ,"sect193r2 ", "SECG curve over a 193 bit binary field"},
    {33 ,"sect233k1 ", "NIST/SECG/WTLS curve over a 233 bit binary field"},
    {34 ,"sect233r1 ", "NIST/SECG/WTLS curve over a 233 bit binary field"},
    {35 ,"sect239k1 ", "SECG curve over a 239 bit binary field"},
    {36 ,"sect283k1 ", "NIST/SECG curve over a 283 bit binary field"},
    {37 ,"sect283r1 ", "NIST/SECG curve over a 283 bit binary field"},
    {38 ,"sect409k1 ", "NIST/SECG curve over a 409 bit binary field"},
    {39 ,"sect409r1 ", "NIST/SECG curve over a 409 bit binary field"},
    {40 ,"sect571k1 ", "NIST/SECG curve over a 571 bit binary field"},
    {41 ,"sect571r1 ", "NIST/SECG curve over a 571 bit binary field"},
    {42 ,"c2pnb163v1", "X9.62 curve over a 163 bit binary field"},
    {43 ,"c2pnb163v2", "X9.62 curve over a 163 bit binary field"},
    {44 ,"c2pnb163v3", "X9.62 curve over a 163 bit binary field"},
    {45 ,"c2pnb176v1", "X9.62 curve over a 176 bit binary field"},
    {46 ,"c2tnb191v1", "X9.62 curve over a 191 bit binary field"},
    {47 ,"c2tnb191v2", "X9.62 curve over a 191 bit binary field"},
    {48 ,"c2tnb191v3", "X9.62 curve over a 191 bit binary field"},
    {49 ,"c2pnb208w1", "X9.62 curve over a 208 bit binary field"},
    {50 ,"c2tnb239v1", "X9.62 curve over a 239 bit binary field"},
    {51 ,"c2tnb239v2", "X9.62 curve over a 239 bit binary field"},
    {52 ,"c2tnb239v3", "X9.62 curve over a 239 bit binary field"},
    {53 ,"c2pnb272w1", "X9.62 curve over a 272 bit binary field"},
    {54 ,"c2pnb304w1", "X9.62 curve over a 304 bit binary field"},
    {55 ,"c2tnb359v1", "X9.62 curve over a 359 bit binary field"},
    {56 ,"c2pnb368w1", "X9.62 curve over a 368 bit binary field"},
    {57 ,"c2tnb431r1", "X9.62 curve over a 431 bit binary field"},
    {58 ,"wap-wsg-idm-ecid-wtls1", "WTLS curve over a 113 bit binary field"},
    {59 ,"wap-wsg-idm-ecid-wtls3", "NIST/SECG/WTLS curve over a 163 bit binary field"},
    {60 ,"wap-wsg-idm-ecid-wtls4", "SECG curve over a 113 bit binary field"},
    {61 ,"wap-wsg-idm-ecid-wtls5", "X9.62 curve over a 163 bit binary field"},
    {62 ,"wap-wsg-idm-ecid-wtls6", "SECG/WTLS curve over a 112 bit prime field"},
    {63 ,"wap-wsg-idm-ecid-wtls7", "SECG/WTLS curve over a 160 bit prime field"},
    {64 ,"wap-wsg-idm-ecid-wtls8", "WTLS curve over a 112 bit prime field"},
    {65 ,"wap-wsg-idm-ecid-wtls9", "WTLS curve over a 160 bit prime field"},
    {66 ,"wap-wsg-idm-ecid-wtls10", "NIST/SECG/WTLS curve over a 233 bit binary field"},
    {67 ,"wap-wsg-idm-ecid-wtls11", "NIST/SECG/WTLS curve over a 233 bit binary field"},
    {68 ,"wap-wsg-idm-ecid-wtls12", "WTLS curve over a 224 bit prime field"},
    {69 ,"brainpoolP160r1", "RFC 5639 curve over a 160 bit prime field"},
    {70 ,"brainpoolP160t1", "RFC 5639 curve over a 160 bit prime field"},
    {71 ,"brainpoolP192r1", "RFC 5639 curve over a 192 bit prime field"},
    {72 ,"brainpoolP192t1", "RFC 5639 curve over a 192 bit prime field"},
    {73 ,"brainpoolP224r1", "RFC 5639 curve over a 224 bit prime field"},
    {74 ,"brainpoolP224t1", "RFC 5639 curve over a 224 bit prime field"},
    {75 ,"brainpoolP256r1", "RFC 5639 curve over a 256 bit prime field"},
    {76 ,"brainpoolP256t1", "RFC 5639 curve over a 256 bit prime field"},
    {77 ,"brainpoolP320r1", "RFC 5639 curve over a 320 bit prime field"},
    {78 ,"brainpoolP320t1", "RFC 5639 curve over a 320 bit prime field"},
    {79 ,"brainpoolP384r1", "RFC 5639 curve over a 384 bit prime field"},
    {80 ,"brainpoolP384t1", "RFC 5639 curve over a 384 bit prime field"},
    {81 ,"brainpoolP512r1", "RFC 5639 curve over a 512 bit prime field"},
    {82 ,"brainpoolP512t1", "RFC 5639 curve over a 512 bit prime field"},
    {83 ,"SM2", "SM2 curve over a 256 bit prime field"},
    {84 , NULL, NULL}
};

static const struct alg_def md_alg_list[] = {
    {1, "sha256"},
    {2, "sha384"},
    {3, "sha512"},
    {4, "sha224"},
    {5, "sha512-224"},
    {6, "sha512-256"},
    {7, "sha3-224"},
    {8, "sha3-384"},
    {9, "sha3-256"},
    {10, "sha3-512"},
    {11, "shake128"},
    {12, "shake256"},
    {13, NULL},
};

#if 1
static const struct alg_def cipher_alg_list[] = {
    {1    ,"aes128"},                    
    {2    ,"aes192"},                   
    {3    ,"aes256"},
    {4    ,"aria128"},                   
    {5    ,"aria192"},                   
    {6    ,"aria256"},                  
    {7    ,"lea128"}, 
    {8    ,"lea192"}, 
    {9    ,"lea256"},
    {10   ,"seed"},
    {11  ,NULL}
};
#else
static const struct alg_def cipher_alg_list[] = {
    {1    ,"aes-128-cbc"},               
    {2    ,"aes-128-cfb"},            
    {3    ,"aes-128-cfb1"},             
    {4    ,"aes-128-cfb8"},              
    {5    ,"aes-128-ctr"},               
    {6    ,"aes-128-ecb"},              
    {7    ,"aes-128-ofb"},               
    {8    ,"aes-192-cbc"},               
    {9    ,"aes-192-cfb"},              
    {10   ,"aes-192-cfb1"},              
    {11   ,"aes-192-cfb8"},              
    {12   ,"aes-192-ctr"},              
    {13   ,"aes-192-ecb"},               
    {14   ,"aes-192-ofb"},               
    {15   ,"aes-256-cbc"},              
    {16   ,"aes-256-cfb"},               
    {17   ,"aes-256-cfb1"},              
    {18   ,"aes-256-cfb8"},             
    {19   ,"aes-256-ctr"},               
    {20   ,"aes-256-ecb"},               
    {21   ,"aes-256-ofb"},              
    {22   ,"aes128"},                    
    {23   ,"aes192"},                   
    {24   ,"aes256"},
    {25   ,"aria-128-cbc"},
    {26   ,"aria-128-cfb"},
    {27   ,"aria-128-cfb1"},
    {28   ,"aria-128-cfb8"},
    {29   ,"aria-128-ctr"},              
    {30   ,"aria-128-ecb"},             
    {31   ,"aria-128-ofb"},              
    {32   ,"aria-192-cbc"},              
    {33   ,"aria-192-cfb"},             
    {34   ,"aria-192-cfb1"},
    {35   ,"aria-192-cfb8"},
    {36   ,"aria-192-ctr"},             
    {37   ,"aria-192-ecb"},              
    {38   ,"aria-192-ofb"},              
    {39   ,"aria-256-cbc"},             
    {40   ,"aria-256-cfb"},              
    {41   ,"aria-256-cfb1"},             
    {42   ,"aria-256-cfb8"},            
    {43   ,"aria-256-ctr"},              
    {44   ,"aria-256-ecb"},              
    {45   ,"aria-256-ofb"},             
    {46   ,"aria128"},                   
    {47   ,"aria192"},                   
    {48   ,"aria256"},                  
    {49   ,"bf"},                        
    {50   ,"bf-cbc"},                    
    {51   ,"bf-cfb"},                   
    {52   ,"bf-ecb"},                    
    {53   ,"bf-ofb"},                    
    {54   ,"blowfish"},                 
    {55   ,"camellia-128-cbc"},
    {56   ,"camellia-128-cfb"},
    {57   ,"camellia-128-cfb1"},
    {58   ,"camellia-128-cfb8"},
    {59   ,"camellia-128-ctr"},          
    {60   ,"camellia-128-ecb"},         
    {61   ,"camellia-128-ofb"},          
    {62   ,"camellia-192-cbc"},          
    {63   ,"camellia-192-cfb"},         
    {64   ,"camellia-192-cfb1"},         
    {65   ,"camellia-192-cfb8"},         
    {66   ,"camellia-192-ctr"},         
    {67   ,"camellia-192-ecb"},          
    {68   ,"camellia-192-ofb"},          
    {69   ,"camellia-256-cbc"},         
    {70   ,"camellia-256-cfb"},          
    {71   ,"camellia-256-cfb1"},         
    {72   ,"camellia-256-cfb8"},        
    {73   ,"camellia-256-ctr"},          
    {74   ,"camellia-256-ecb"},          
    {75   ,"camellia-256-ofb"},         
    {76   ,"camellia128"},               
    {77   ,"camellia192"},               
    {78   ,"camellia256"},              
    {79   ,"cast"},
    {80   ,"cast-cbc"},
    {81   ,"cast5-cbc"},                
    {82   ,"cast5-cfb"},                 
    {83   ,"cast5-ecb"},                 
    {84   ,"cast5-ofb"},                
    {85   ,"idea"},
    {86   ,"idea-cbc"},
    {87   ,"idea-cfb"},
    {88   ,"idea-ecb"},
    {89   ,"idea-ofb"},
    {90   ,"lea-128-cbc"},
    {91   ,"lea-128-ccm"},
    {92   ,"lea-128-cfb"},
    {93   ,"lea-128-cfb1"},
    {94   ,"lea-128-cfb8"},
    {95   ,"lea-128-ctr"},
    {96   ,"lea-128-ecb"},
    {97   ,"lea-128-ofb"},
    {98   ,"lea-192-cbc"},
    {99   ,"lea-192-ccm"},
    {100  ,"lea-192-cfb"},
    {101  ,"lea-192-cfb1"},
    {102  ,"lea-192-cfb8"},
    {103  ,"lea-192-ctr"},
    {104  ,"lea-192-ecb"},
    {105  ,"lea-192-ofb"},
    {106  ,"lea-256-cbc"},
    {107  ,"lea-256-ccm"},
    {108  ,"lea-256-cfb"},
    {109  ,"lea-256-cfb1"}, 
    {110  ,"lea-256-cfb8"},
    {111  ,"lea-256-ctr"}, 
    {112  ,"lea-256-ecb"}, 
    {113  ,"lea-256-ofb"},
    {114  ,"lea128"}, 
    {115  ,"lea192"}, 
    {116  ,"lea256"},
    {117  ,"rc2"},
    {118  ,"rc2-128"},
    {119  ,"rc2-40"},
    {120  ,"rc2-40-cbc"},
    {121  ,"rc2-64"},
    {122  ,"rc2-64-cbc"},
    {123  ,"rc2-cbc"},
    {124  ,"rc2-cfb"},
    {125  ,"rc2-ecb"},
    {126  ,"rc2-ofb"},
    {127  ,"rc4"},
    {128  ,"rc4-40"},
    {129  ,"seed"},
    {130  ,"seed-cbc"},
    {131  ,"seed-cfb"},
    {132  ,"seed-ecb"},
    {133  ,"seed-ofb"},
    {134  ,"sm4"},
    {135  ,"sm4-cbc"},                 
    {136  ,"sm4-cfb"},                 
    {137  ,"sm4-ctr"},                
    {138  ,"sm4-ecb"},                 
    {139  ,"sm4-ofb"},
    {140  ,NULL}
};
#endif 

#define GZPKI_strdup OPENSSL_strdup
#define GZPKI_free   free



void GZPKI_lib_set_debug_mode(int mode);

/*static*/ char *app_get_pass(const char *arg, int keepbio);
int  istext(int format);
void* app_malloc(int sz, const char *what);
int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2);

BIO *bio_open_default_(const char *filename, char mode, int format, int quiet);
BIO *bio_open_default(const char *filename, char mode, int format);
BIO *bio_open_default_quiet(const char *filename, char mode, int format);

BIO_METHOD *apps_bf_prefix(void);

BIO *dup_bio_in(int format);
BIO *dup_bio_out(int format);
BIO *dup_bio_err(int format);

int file_exist(char *fname);

const char *modestr(char mode, int format);

unsigned char *GZPKI_gen_random_pass(int nbytes);

typedef struct prefix_ctx_st {
    char *prefix;
    int linestart;               /* flag to indicate we're at the line start */
} PREFIX_CTX;


X509 *load_cert(const char *file, int format, const char *cert_descrip);
int load_certs(const char *file, STACK_OF(X509) **certs, int format, const char *pass, const char *desc);
X509_CRL *load_crl(const char *infile, int format);
EVP_PKEY *load_key_buffer(const char *buffer, int len, int format,  const char *pass);
EVP_PKEY *load_key(const char *file, int format, int maybe_stdin, const char *pass, ENGINE *e, const char *key_descrip);
EVP_PKEY *load_pubkey(const char *file, int format, int maybe_stdin,const char *pass, ENGINE *e, const char *key_descrip);
/*static*/ int load_certs_crls(const char *file, int format, const char *pass, const char *desc, STACK_OF(X509) **pcerts, STACK_OF(X509_CRL) **pcrls);
int load_certs(const char *file, STACK_OF(X509) **certs, int format, const char *pass, const char *desc);
int load_crls(const char *file, STACK_OF(X509_CRL) **crls, int format, const char *pass, const char *desc);
/*static*/ int load_pkcs12(BIO *in, const char *desc, pem_password_cb *pem_cb, void *cb_data, EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
void print_name(BIO *out, const char *title, X509_NAME *nm, unsigned long lflags);

void unbuffer(FILE *fp);

# define PW_MIN_LENGTH 4

typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;

int password_callback_noprompt(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp);
int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp);

X509_STORE *setup_verify(const char *CAfile, const char *CApath, int noCAfile, int noCApath);

int gzpki_common_context_init(GZPKI_CTX *ctx);
int gzpki_common_context_free(GZPKI_CTX *ctx);

#define GZPKI_init_ctx gzpki_common_context_init
#define GZPKI_free_ctx gzpki_common_context_free

BIO *GZPKI_set_in_BIO(int intype, char *infile, char *inbuffer, int inbuffer_size, int informat);
BIO *GZPKI_set_out_BIO(int outtype, char *outfile, int outformat);

int GZPKI_set_infile(GZPKI_CTX *ctx, char *infile, char *inbuffer, int inbuffer_size, int informat);
int GZPKI_set_outfile(GZPKI_CTX *ctx, char *outfile, int outformat);

char *GZPKI_get_mem(GZPKI_CTX *ctx) ;
int GZPKI_get_mem_length(GZPKI_CTX *ctx) ;
int GZPKI_set_sign_md(GZPKI_CTX *ctx, char *sign_md);

#define GZPKI_set_md_alg GZPKI_set_sign_md

# define SERIAL_RAND_BITS        159

# define TM_START        0
# define TM_STOP         1

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value);
int app_access(const char* name, int flag);
int app_isdir(const char *name);
int fileno_stdin(void);
int fileno_stdout(void);
int raw_write_stdout(const void *buf, int siz);

void store_setup_crl_download(X509_STORE *st);
double app_tminterval(int stop, int usertime);

char * print_name_str(X509_NAME *nm, unsigned long lflags);
void print_name(BIO *out, const char *title, X509_NAME *nm, unsigned long lflags);


#if defined(_WIN32) && defined(STD_INPUT_HANDLE)
    int raw_read_stdin(void *buf, int siz);
#elif defined(__VMS)
    # include <sys/socket.h>
    int raw_read_stdin(void *buf, int siz);
#else
    int raw_read_stdin(void *buf, int siz);
#endif


int set_nameopt(const char *arg);
int set_nameopt_v(unsigned long arg);
unsigned long get_nameopt(void) ;
int set_name_ex(unsigned long *flags, const char *arg);
CONF *gzpki_load_config(const char *inbuffer);
CONF *app_load_config(const char *filename);
CONF *app_load_config_bio(BIO *in, const char *filename);
int app_load_modules(const CONF *config);
CONF *app_load_config_quiet(const char *filename) ;
int add_oid_section(CONF *conf);
void app_RAND_load_conf(CONF *c, const char *section);

int GZPKI_set_operation(GZPKI_CTX *ctx, int operation);
int GZPKI_set_encerts(GZPKI_CTX *ctx, char *certfile );
int GZPKI_set_key_buffer(GZPKI_CTX *ctx, char *buffer, char *passin, int load_flag);
int GZPKI_set_keyfile(GZPKI_CTX *ctx, char *keyfile, char *passin, int load_flag);
int GZPKI_get_flags_str(GZPKI_CTX *ctx);

char *GZPKI_get_sign_md_name(GZPKI_CTX *ctx);
char *get_md_alg_string_by_type(int type);

int set_cert_times(X509 *x, const char *startdate, const char *enddate, int days);
int GZPKI_set_cipher(GZPKI_CTX *ctx, char *cipher_name);
int GZPKI_set_signer(GZPKI_CTX *ctx, char *pSignerFile, char *pKeyFile, char *passin);

void print_operation_str(int operation);
#if 0//DEL
char *get_operation_str(int operation);
char *GZPKI_get_operation_str(GZPKI_CTX *ctx);
#endif

int GZPKI_reset_outfile(GZPKI_CTX *ctx, char *outfile, int outformat);
int asprintf(char **, const char *, ...);
int vasprintf(char **, const char *, va_list);
#include <stdio.h>
int str_append(char **json, const char *format, ...);
char *GZPKI_get_format_str(int f);
int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);

//static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);
int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai);
void corrupt_signature(const ASN1_STRING *signature);
void print_array(BIO *out, const char* title, int len, const unsigned char* d);
void print_cert_checks(BIO *bio, X509 *x, const char *checkhost, const char *checkemail, const char *checkip);
BIGNUM *load_serial(const char *serialfile, int create, ASN1_INTEGER **retai);
int save_serial(const char *serialfile, const char *suffix, const BIGNUM *serial, ASN1_INTEGER **retai);


//OCSP
OCSP_RESPONSE *process_responder(OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 STACK_OF(CONF_VALUE) *headers,
                                 int req_timeout);
//--------------------------------------------------
// CA DATABASE
//--------------------------------------------------


//#include "mysql.h"

#ifndef HEADER_NELEM_H
# define HEADER_NELEM_H

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#endif

#define NUM_REASONS OSSL_NELEM(crl_reasons)

/* Functions defined in ca.c and also used in ocsp.c */
int unpack_revinfo(ASN1_TIME **prevtm, int *preason, ASN1_OBJECT **phold,
                   ASN1_GENERALIZEDTIME **pinvtm, const char *str);

# define DB_type         0
# define DB_exp_date     1
# define DB_rev_date     2
# define DB_serial       3      /* index - unique */
# define DB_file         4
# define DB_name         5      /* index - unique when active and not disabled */
# define DB_NUMBER       6

# define DB_TYPE_REV     'R'    /* Revoked  */
# define DB_TYPE_EXP     'E'    /* Expired  */
# define DB_TYPE_VAL     'V'    /* Valid ; inserted with: ca ... -valid */
# define DB_TYPE_SUSP    'S'    /* Suspended  */

typedef struct db_attr_st {
    int unique_subject;
} DB_ATTR;

typedef struct ca_db_st {
    DB_ATTR attributes;
    TXT_DB *db;
    char *dbfname;
# ifndef OPENSSL_NO_POSIX_IO
    struct stat dbst;
# endif

    //MYSQL myql ;
    //MYSQL_RES *res;
    //MYSQL_ROW row;
    //int fields, cnt;
} CA_DB;
//

CA_DB *load_index(const char *dbfile, DB_ATTR *db_attr);
int index_index(CA_DB *db);
int save_index(const char *dbfile, const char *suffix, CA_DB *db);
int rotate_index(const char *dbfile, const char *new_suffix, const char *old_suffix);
void free_index(CA_DB *db);
int parse_yesno(const char *str, int def);

#define X509_FLAG_CA (X509_FLAG_NO_ISSUER | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION)

int set_cert_ex(unsigned long *flags, const char *arg);
int set_ext_copy(int *copy_type, const char *arg);
void make_uppercase(char *string);
int rotate_serial(const char *serialfile, const char *new_suffix, const char *old_suffix); 
int do_X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);
X509_NAME *parse_name(const char *cp, long chtype, int canmulti);
int copy_extensions(X509 *x, X509_REQ *req, int copy_type);

int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b);

# define index_name_cmp_noconst(a, b) \
        index_name_cmp((const OPENSSL_CSTRING *)CHECKED_PTR_OF(OPENSSL_STRING, a), \
        (const OPENSSL_CSTRING *)CHECKED_PTR_OF(OPENSSL_STRING, b))


DECLARE_GZPKI_SET_FN2(informat)
DECLARE_GZPKI_SET_FN2(outformat)
DECLARE_GZPKI_SET_FN2(keyformat)
DECLARE_GZPKI_SET_FN2(CAformat)
DECLARE_GZPKI_SET_FN2(intype)
DECLARE_GZPKI_SET_FN2(outtype)
DECLARE_GZPKI_SET_FN2(text)
DECLARE_GZPKI_SET_FN2(genkey)
DECLARE_GZPKI_SET_FN2(print)

DECLARE_GZPKI_SET_FN2(new_form)
DECLARE_GZPKI_SET_FN2(new_asn1_flag)
DECLARE_GZPKI_SET_FN2(noout)
DECLARE_GZPKI_SET_FN2(param_out)
DECLARE_GZPKI_SET_FN2(pubin)
DECLARE_GZPKI_SET_FN2(pubout)
DECLARE_GZPKI_SET_FN2(subject_out)

DECLARE_GZPKI_SET_CHAR_FN2(passin)
DECLARE_GZPKI_SET_CHAR_FN2(passout)
DECLARE_GZPKI_SET_CHAR_FN2(passinarg)
DECLARE_GZPKI_SET_CHAR_FN2(passoutarg)
//CHECK & REMOVE
DECLARE_GZPKI_SET_CHAR_FN2(passargin)
DECLARE_GZPKI_SET_CHAR_FN2(passargout)
DECLARE_GZPKI_SET_CHAR_FN2(keyalg)


DECLARE_GZPKI_SET_CHAR_FN2(name)
DECLARE_GZPKI_SET_CHAR_FN2(keyoutfile)
DECLARE_GZPKI_SET_CHAR_FN2(inserial)
DECLARE_GZPKI_SET_CHAR_FN2(subj)
DECLARE_GZPKI_SET_CHAR_FN2(extensions)
DECLARE_GZPKI_SET_CHAR_FN2(req_exts)

DECLARE_GZPKI_SET_CHAR_FN2(default_config_file)
//DECLARE_GZPKI_GET_CHAR_FN(default_config_file)

DECLARE_GZPKI_SET_CHAR_FN2(certfile)
DECLARE_GZPKI_SET_CHAR_FN2(crlfile)
DECLARE_GZPKI_SET_CHAR_FN2(cipher_name)

DECLARE_GZPKI_SET_FN2(newreq)   //REQ
DECLARE_GZPKI_SET_FN2(keyform)  //REQ
DECLARE_GZPKI_SET_FN2(batch)    //REQ
DECLARE_GZPKI_SET_FN2(newhdr)   //REQ
DECLARE_GZPKI_SET_FN2(verify)   //REQ
DECLARE_GZPKI_SET_FN2(verbose)  //REQ
DECLARE_GZPKI_SET_FN2(modulus)  //REQ
DECLARE_GZPKI_SET_FN2(chtype)   //REQ
DECLARE_GZPKI_SET_FN2(pubkey)   //REQ
DECLARE_GZPKI_SET_FN2(x509)     //REQ
DECLARE_GZPKI_SET_FN2(days)     //REQ
DECLARE_GZPKI_SET_FN2(multirdn)
DECLARE_GZPKI_SET_FN2(precert)
DECLARE_GZPKI_GET_CHAR_FN(outfile)
DECLARE_GZPKI_SET_CHAR_FN2(default_md)
DECLARE_GZPKI_SET_CHAR_FN2(authorityKeyIdentifier)

DECLARE_GZPKI_SET_CHAR_FN2(default_bits)
DECLARE_GZPKI_SET_CHAR_FN2(default_keyfile)
DECLARE_GZPKI_SET_CHAR_FN2(string_mask)
DECLARE_GZPKI_SET_CHAR_FN2(countryName)
DECLARE_GZPKI_SET_CHAR_FN2(stateOrProvinceName)
DECLARE_GZPKI_SET_CHAR_FN2(localityName)
DECLARE_GZPKI_SET_CHAR_FN2(organizationName)
DECLARE_GZPKI_SET_CHAR_FN2(organizationUnitName)
DECLARE_GZPKI_SET_CHAR_FN2(commonName)
DECLARE_GZPKI_SET_CHAR_FN2(emailAddress)

DECLARE_GZPKI_SET_CHAR_FN2(countryName_default)
DECLARE_GZPKI_SET_CHAR_FN2(stateOrProvinceName_default)
DECLARE_GZPKI_SET_CHAR_FN2(localityName_default)
DECLARE_GZPKI_SET_CHAR_FN2(organizationName_default)
DECLARE_GZPKI_SET_CHAR_FN2(organizationUnitName_default)
DECLARE_GZPKI_SET_CHAR_FN2(commonName_default)
DECLARE_GZPKI_SET_CHAR_FN2(emailAddress_default)

DECLARE_GZPKI_SET_CHAR_FN2(subjectKeyIdentifier)
DECLARE_GZPKI_SET_CHAR_FN2(issuerKeyIdentifier)
DECLARE_GZPKI_SET_CHAR_FN2(basicConstraints)
DECLARE_GZPKI_SET_CHAR_FN2(subjectAltName)
DECLARE_GZPKI_SET_CHAR_FN2(nsComment)
DECLARE_GZPKI_SET_CHAR_FN2(extendedKeyUsage)
DECLARE_GZPKI_SET_CHAR_FN2(DNS1)
DECLARE_GZPKI_SET_CHAR_FN2(DNS2)
DECLARE_GZPKI_SET_CHAR_FN2(DNS3)
DECLARE_GZPKI_SET_CHAR_FN2(DNS4)
DECLARE_GZPKI_SET_CHAR_FN2(DNS5)
DECLARE_GZPKI_SET_CHAR_FN2(DNS6)
DECLARE_GZPKI_SET_CHAR_FN2(DNS7)
DECLARE_GZPKI_SET_CHAR_FN2(DNS8)
DECLARE_GZPKI_SET_CHAR_FN2(utf8)

DECLARE_GZPKI_SET_CHAR_FN2(challengePassword)
DECLARE_GZPKI_SET_CHAR_FN2(challengePassword_default)
DECLARE_GZPKI_SET_CHAR_FN2(contentType)
DECLARE_GZPKI_SET_CHAR_FN2(contentType_default)
DECLARE_GZPKI_SET_CHAR_FN2(unstructuredName)
DECLARE_GZPKI_SET_CHAR_FN2(unstructuredName_default)

DECLARE_GZPKI_SET_CHAR_FN2(reqSubjectDN)
DECLARE_GZPKI_SET_CHAR_FN2(reqAlgorithName)
DECLARE_GZPKI_SET_CHAR_FN2(reqErrstr)

DECLARE_GZPKI_SET_FN2(reqVersion)
DECLARE_GZPKI_SET_FN2(reqErrcode)
DECLARE_GZPKI_SET_FN2(reqKeyBits)

DECLARE_GZPKI_SET_CHAR_FN2(signerfile)

DECLARE_GZPKI_SET_CHAR_FN2(extfile)
DECLARE_GZPKI_SET_CHAR_FN2(extsect)
DECLARE_GZPKI_SET_CHAR_FN2(CAfile)

DECLARE_GZPKI_SET_FN2(CA_flag) //X509
DECLARE_GZPKI_SET_FN2(sign_flag) //X509

DECLARE_GZPKI_SET_CHAR_FN2(CAkeyfile)

DECLARE_GZPKI_SET_CHAR_FN2(fkeyfile)
DECLARE_GZPKI_SET_CHAR_FN2(addtrust)
DECLARE_GZPKI_SET_CHAR_FN2(addreject)
DECLARE_GZPKI_SET_CHAR_FN2(alias)
DECLARE_GZPKI_SET_CHAR_FN2(CAserial)

DECLARE_GZPKI_SET_CHAR_FN2(checkhost) //X509
DECLARE_GZPKI_SET_CHAR_FN2(checkip) //X509
DECLARE_GZPKI_SET_CHAR_FN2(randfile) //X509



DECLARE_GZPKI_SET_FN2(certflag)             //X509
DECLARE_GZPKI_SET_FN2(opt_email)            //X509
DECLARE_GZPKI_SET_FN2(opt_ocsp_uri)         //X509
DECLARE_GZPKI_SET_FN2(opt_serial)           //X509
DECLARE_GZPKI_SET_FN2(opt_next_serial)      //X509
DECLARE_GZPKI_SET_FN2(opt_modulus)          //X509
DECLARE_GZPKI_SET_FN2(opt_pubkey)           //X509
DECLARE_GZPKI_SET_FN2(opt_x509req)          //X509
DECLARE_GZPKI_SET_FN2(opt_text)             //X509
DECLARE_GZPKI_SET_FN2(opt_subject)          //X509
DECLARE_GZPKI_SET_FN2(opt_issuer)           //X509
DECLARE_GZPKI_SET_FN2(opt_fingerprint)      //X509
DECLARE_GZPKI_SET_FN2(opt_subject_hash)     //X509
DECLARE_GZPKI_SET_FN2(opt_subject_hash_old) //X509
DECLARE_GZPKI_SET_FN2(opt_issuer_hash)      //X509
DECLARE_GZPKI_SET_FN2(opt_issuer_hash_old)  //X509
DECLARE_GZPKI_SET_FN2(opt_pprint)           //X509
DECLARE_GZPKI_SET_FN2(opt_startdate)        //X509
DECLARE_GZPKI_SET_FN2(opt_enddate)          //X509

DECLARE_GZPKI_SET_FN2(opt_noout)            //X509
DECLARE_GZPKI_SET_FN2(opt_ext)              //X509
DECLARE_GZPKI_SET_FN2(opt_nocert)           //X509
DECLARE_GZPKI_SET_FN2(opt_trustout)         //X509
DECLARE_GZPKI_SET_FN2(opt_clrtrust)         //X509
DECLARE_GZPKI_SET_FN2(opt_clrreject)        //X509
DECLARE_GZPKI_SET_FN2(opt_CA_createserial)  //X509
DECLARE_GZPKI_SET_FN2(opt_clrext)           //X509
DECLARE_GZPKI_SET_FN2(opt_ocspid)           //X509
DECLARE_GZPKI_SET_FN2(opt_badsig)           //X509
DECLARE_GZPKI_SET_FN2(opt_checkend)         //X509
DECLARE_GZPKI_SET_FN2(opt_preserve_dates)   //X509
DECLARE_GZPKI_SET_FN2(opt_reqfile)          //X509


DECLARE_GZPKI_SET_CHAR_FN2(x509_field_email)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_ocsp_uri)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_serial)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_next_serial)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_modulus)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_pubkey)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_x509req)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_text)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_subject)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_issuer)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_fingerprint)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_subject_hash)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_subject_hash_old)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_issuer_hash)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_issuer_hash_old)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_pprint)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_startdate)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_enddate)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_noout)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_ext)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_clrtrust)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_clrreject)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_aliasout)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_CA_createserial)
DECLARE_GZPKI_SET_CHAR_FN2(x509_field_ocspid)

DECLARE_GZPKI_SET_CHAR_FN2(req_field_subject)

DECLARE_GZPKI_SET_FN2(opt_get_field_all)


//--------------------------------------------------
// OCSP
//--------------------------------------------------
DECLARE_GZPKI_SET_FN2(req_timeout)
DECLARE_GZPKI_SET_FN2(ocsp_port)
DECLARE_GZPKI_SET_FN2(ocsp_opt_ignore_err)
DECLARE_GZPKI_SET_FN2(ocsp_opt_noverify)
DECLARE_GZPKI_SET_FN2(ocsp_opt_add_nonce)
DECLARE_GZPKI_SET_FN2(ocsp_opt_resp_no_certs)
DECLARE_GZPKI_SET_FN2(ocsp_opt_resp_key_id)
DECLARE_GZPKI_SET_FN2(ocsp_opt_no_certs)
DECLARE_GZPKI_SET_FN2(ocsp_opt_no_signature_verify)
DECLARE_GZPKI_SET_FN2(ocsp_opt_no_cert_verify)
DECLARE_GZPKI_SET_FN2(ocsp_opt_no_chain)
DECLARE_GZPKI_SET_FN2(ocsp_opt_no_cert_checks)
DECLARE_GZPKI_SET_FN2(ocsp_opt_no_explicit)
DECLARE_GZPKI_SET_FN2(ocsp_opt_trust_other)
DECLARE_GZPKI_SET_FN2(ocsp_opt_no_intern)
DECLARE_GZPKI_SET_FN2(ocsp_opt_badsig)
DECLARE_GZPKI_SET_FN2(ocsp_opt_req_text)
DECLARE_GZPKI_SET_FN2(ocsp_opt_resp_text)
DECLARE_GZPKI_SET_FN2(ocsp_valididy_period)
DECLARE_GZPKI_SET_FN2(ocsp_status_age)
DECLARE_GZPKI_SET_FN2(ocsp_accept_count)
DECLARE_GZPKI_SET_FN2(ocsp_ndays)
DECLARE_GZPKI_SET_FN2(ocsp_next_minutes)
DECLARE_GZPKI_SET_FN2(ocsp_multi)

DECLARE_GZPKI_SET_CHAR_FN2(ocsp_url)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_host)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_reqin)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_respin)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_signerfile)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_verify_certfile)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_sign_certfile)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_reqout)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_respout)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_path)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_issuer_certfile)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_certfile)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_serial)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_index_filename)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_ca_filename)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_resp_signfile)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_resp_keyfile)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_resp_other_certfile)
//DECLARE_GZPKI_SET_CHAR_FN2(ocsp_resp_sign_md)

DECLARE_GZPKI_SET_FN2(ocsp_verify_result)
DECLARE_GZPKI_SET_CHAR_FN2(ocsp_verify_result_str)

DECLARE_GZPKI_SET_CHAR_FN2(configfile)
DECLARE_GZPKI_SET_CHAR_FN2(section_name)
DECLARE_GZPKI_SET_CHAR_FN2(subjec_str)
DECLARE_GZPKI_SET_CHAR_FN2(startdate)
DECLARE_GZPKI_SET_CHAR_FN2(enddate)
DECLARE_GZPKI_SET_CHAR_FN2(ca_policy)
DECLARE_GZPKI_SET_CHAR_FN2(sign_md_alg)
DECLARE_GZPKI_SET_CHAR_FN2(ca_outdir)

DECLARE_GZPKI_SET_FN2(opt_ca_rand_serial)
DECLARE_GZPKI_SET_FN2(opt_ca_create_serial)
DECLARE_GZPKI_SET_FN2(opt_ca_multivalue_rdn)
DECLARE_GZPKI_SET_FN2(certificate_days)
DECLARE_GZPKI_SET_FN2(opt_ca_selfsign)
DECLARE_GZPKI_SET_FN2(opt_ca_no_text)

DECLARE_GZPKI_SET_CHAR_FN2(ca_signature_parameters)

DECLARE_GZPKI_SET_FN2(opt_preserve_dn)
DECLARE_GZPKI_SET_FN2(opt_ca_email_dn)
DECLARE_GZPKI_SET_FN2(opt_ca_msie_hack)
DECLARE_GZPKI_SET_FN2(opt_ca_generate_crl)
DECLARE_GZPKI_SET_FN2(crl_crldays)
DECLARE_GZPKI_SET_FN2(crl_crlhours)
DECLARE_GZPKI_SET_FN2(crl_crlsec)
DECLARE_GZPKI_SET_FN2(opt_ca_reqinfile)
DECLARE_GZPKI_SET_FN2(opt_ca_reqin)
DECLARE_GZPKI_SET_FN2(opt_ca_do_revoke)
DECLARE_GZPKI_SET_FN2(opt_ca_update_database)
//DECLARE_GZPKI_SET_FN2(crl_revoke_type)


DECLARE_GZPKI_SET_CHAR_FN2(ca_selfsigned_certificate)
DECLARE_GZPKI_SET_CHAR_FN2(spkac_file)
DECLARE_GZPKI_SET_CHAR_FN2(caconf_entensions_section_name)
DECLARE_GZPKI_SET_CHAR_FN2(caconf_crl_entensions_section_name)
DECLARE_GZPKI_SET_CHAR_FN2(ca_status_serial)
DECLARE_GZPKI_SET_CHAR_FN2(caconf_entensions_file_name)
DECLARE_GZPKI_SET_CHAR_FN2(crl_revoke_reason)

//CA DATABASE OPTION
DECLARE_GZPKI_SET_FN2(use_sqldb)
DECLARE_GZPKI_SET_FN2(use_txtdb)
DECLARE_GZPKI_SET_CHAR_FN2(ca_name)

DECLARE_GZPKI_SET_FN2(opt_req_verify)
DECLARE_GZPKI_SET_FN2(req_verify_result)

DECLARE_GZPKI_SET_FN2(opt_verify_trusted)
DECLARE_GZPKI_SET_FN2(opt_verify_crl_download)
DECLARE_GZPKI_SET_FN2(opt_verify_show_chain)


DECLARE_GZPKI_SET_CHAR_FN2(trusted_certfile)
DECLARE_GZPKI_SET_CHAR_FN2(untrusted_certfile)
DECLARE_GZPKI_SET_CHAR_FN2(verify_opts)

DECLARE_GZPKI_SET_CHAR_FN2(key_pem)
DECLARE_GZPKI_SET_CHAR_FN2(csr_pem)
DECLARE_GZPKI_SET_CHAR_FN2(key_pass)
DECLARE_GZPKI_SET_CHAR_FN2(template_id)



int GZPKI_set_crl_revoke_type(GZPKI_CTX *ctx, REVINFO_TYPE name);
REVINFO_TYPE GZPKI_get_crl_revoke_type(GZPKI_CTX *ctx);

DECLARE_GZPKI_SET_FN2(ca_request_file_cnt)


char *ltrim(char *s);
char *rtrim(char *s);
char *trim(char *s);

void GZPKI_print_errors(GZPKI_CTX *ctx);
void GZPKI_print_errors_std();

int GZPKI_add_flags(GZPKI_CTX *ctx, int opt);
int GZPKI_set_flags(GZPKI_CTX *ctx, int opt);
int GZPKI_remove_flags(GZPKI_CTX *ctx, int opt);


//function
int is_valid_cipher(char *name);
int is_file_exists( char *filename );

void show_ecparam();
int is_valid_ecparam(char *name);

#define OSSL_ERR_RET(n)  ret = n; \
                    GZPKI_print_errors(ctx); \
                    goto end

#define ERR_RET(n)  ret = n; \
                    goto end                    

#if 0
    #define GZPKI_set_CN(c,x) {GZPKI_set_commonName_default(c, x);  GZPKI_set_commonName(c, x);}
    #define GZPKI_set_E(c,x)  {GZPKI_set_emailAddress_default(c, x);  GZPKI_set_emailAddress_default(c, x);}
    #define GZPKI_set_OU(c,x) {GZPKI_set_organizationUnitName_default(c, x);  GZPKI_set_organizationUnitName_default(c, x);}
    #define GZPKI_set_O(c,x)  {GZPKI_set_organizationName_default(c, x);  GZPKI_set_organizationName_default(c, x);}
    #define GZPKI_set_L(c,x)  {GZPKI_set_localityName_default(c, x);  GZPKI_set_localityName_default(c, x);}
    #define GZPKI_set_ST(c,x) {GZPKI_set_stateOrProvinceName_default(c, x);  GZPKI_set_stateOrProvinceName_default(c, x);}
    #define GZPKI_set_C(c,x)  {GZPKI_set_countryName_default(c, x);  GZPKI_set_countryName_default(c, x);}
#endif

#define GZPKI_set_CN    GZPKI_set_commonName
#define GZPKI_set_E     GZPKI_set_emailAddress
#define GZPKI_set_OU    GZPKI_set_organizationUnitName
#define GZPKI_set_O     GZPKI_set_organizationName
#define GZPKI_set_L     GZPKI_set_localityName
#define GZPKI_set_ST    GZPKI_set_stateOrProvinceName
#define GZPKI_set_C     GZPKI_set_countryName


int GZPKI_check_valid_certificate(char *file, int format);

int GZPKI_generate_device_password(GZPKI_CTX *ctx, char *mac_addr_str, char *filename);

//unsigned char *GZPKI_keypass_genpass(char *dbfile, char *id, char *master_pass, int nbytes, int type);
int GZPKI_sha256_hash(char *string, char *sha256_string);
int GZPKI_keypass_init(char *dbfile, char *master);
int GZPKI_do_RAND(GZPKI_CTX *ctx);
int GZPKI_do_ENC(GZPKI_CTX *ctx) ;
char *GZPKI_ripemd160_hash(unsigned char *string, int len);


int generate_dirctory(char *path, mode_t mode);

#define FILE_OK 0
#define FILE_NOT_EXIST 1
#define FILE_TO_LARGE 2
#define FILE_READ_ERROR 3

//#define DUMP_FILE_SIZE_LIMIT 1073741824 //1GB
#define DUMP_FILE_SIZE_LIMIT 1048576  //1MB, (1073741824/1024)

char * dump_file_content(const char * f_name, int * err, size_t * f_size) ;

char *repl_str(const char *str, const char *from, const char *to);

// the code for UNICODE string 
int mystrstr(wchar_t *txt1,wchar_t *txt2);
void StringReplace(wchar_t *buff,wchar_t *txt1,wchar_t *txt2);

char* GZPKI_generate_PRIKEY(char *curve_name, char *pwd, char *encrypt_algo,  int *len, char *file);
char* GZPKI_generate_CSR(char *key_pem, char *keyfile, char *pwd, char *configfile, char *dn_str, char *csrfile, char *req_section, char *req_exts,
                char *dn_c, char *dn_st, char *dn_l, char *dn_o, char *dn_ou, char *dn_cn, char *dn_e, int format);


int copy_file(const char *to, const char *from);

//get csv field
const char* getfield(char* line, int num);
int csvgetline(FILE *fin);
char *unquote(char *p);

int GZPKI_gzcmm_database_init(char *dbfile);
int reqdb_status_comp(char *file, char *userid, char *stat);
int reqdb_status_update(char *file, char *userid, char *status);
int get_request_userid(char *file, char *sql);

char *base64(unsigned char *data,int input_length);
char *decode64(unsigned char *data, int input_length);

int add_file_to_dirctory(char *path, char *file, char *data, char *fmode);


#define SECRET_CREATE_NEW       0
#define SECRET_IMPORT_KE        1
#define SECRET_CREATE_EXPORT    2


char *bin2hex(const unsigned char *bin, size_t len);

int GZPKI_init_token(TOKEN_CTX *tk, char *token_dir);
int GZPKI_free_token(TOKEN_CTX *tk);
int GZPKI_get_token(TOKEN_CTX *tk, int loadcert, int loadkey);
int GZPKI_get_token_load_key(TOKEN_CTX *tk, int flag_load_key, char *pass);
char * GZPKI_get_token_device_password(TOKEN_CTX *tk);



#endif /* _GZPKI_COMMON_H_ */


