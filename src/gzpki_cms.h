
#include <stdio.h>
#include <string.h>



# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include <assert.h>


struct gzcms_ctx_st {
    
    ASN1_OBJECT *econtent_type;

    BIO *in;
    BIO *out;
    BIO *indata;
    BIO *rctin;
    
    BIO *bio_in ;
    BIO *bio_out;
    BIO *bio_err ;

    CMS_ContentInfo *cms;
    CMS_ContentInfo *rcms;
    CMS_ReceiptRequest *rr;
    ENGINE *e;
    EVP_PKEY *key;
    const EVP_CIPHER *cipher;
    const EVP_CIPHER *wrap_cipher;
    EVP_MD *sign_md;
    STACK_OF(OPENSSL_STRING) *rr_to;
    STACK_OF(OPENSSL_STRING) *rr_from;
    STACK_OF(OPENSSL_STRING) *sksigners;
    STACK_OF(OPENSSL_STRING) *skkeys;
    STACK_OF(OPENSSL_STRING) *skpassins;
    STACK_OF(X509) *encerts;
    STACK_OF(X509) *other;
    X509 *cert;
    X509 *recip;
    X509 *signer;
    X509_STORE *store;
    X509_VERIFY_PARAM *vpm;
    char *certfile;
    char *keyfile;
    char *contfile;
    char *CAfile;
    char *CApath;
    int  cafileformat;
    char *certsoutfile;
    int noCAfile;
    int noCApath;
    char *infile;
    char *outfile;
    char *rctfile;
    char *passinarg;
    char *passin;
    char *signerfile;
    char *recipfile;
    char *to;
    char *from;
    char *subject;
    char *prog;

    //cms_key_param *key_first;
    //cms_key_param *key_param;

    int flags; // CMS_DETACHED
    int noout; // 0
    int print; //0
    int keyidx; // -1
    int vpmtouched; // 0

    int informat; //FORMAT_SMIME
    int outformat; //FORMAT_SMIME;
    
    int operation; // 0
    int ret; // 1
    int rr_print; // 0
    int rr_allorfirst; // -1;
    
    int verify_retcode; // 0
    int rctformat; // FORMAT_SMIME
    int keyform; // FORMAT_PEM
    
    size_t secret_keylen; // 0
    size_t secret_keyidlen; // 0;
    unsigned char *pwri_pass; //NULL
    unsigned char *pwri_tmp; // NULL;
    unsigned char *secret_key; //NULL
    unsigned char *secret_keyid; //NULL;
    //DELETE long ltmp;
    const char *mime_eol; // "\n";
    int debug;
    int verify_result;
    int digest_verify_result;

    unsigned char *inbuffer;
    int inbuffer_size;
    unsigned char *outbuffer;
    int outbuffer_size;

    int errcode;
    char errstr[4096];

    int intype ;
    int outtype ;

    BUF_MEM *bptr;

    char *outdata;
    int outdata_length;
};

typedef struct gzcms_ctx_st GZCMS_CTX;

int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2);

//----------------------------------------
//cms.c: DECLARATION
int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value);

void gzcms_print_operation_str(int op);
char *gzcms_get_format_str(int f);

void release_engine(ENGINE *e);

void policies_print(X509_STORE_CTX *ctx);

int GZPKI_set_recipfile(GZPKI_CTX *ctx, char *recipfile);
int gzcms_load_recip_certificate(GZCMS_CTX *ctx, char *recipfile, int format);

EVP_PKEY *load_key(const char *file, int format, int maybe_stdin, const char *pass, ENGINE *e, const char *key_descrip);
ENGINE *setup_engine(const char *engine, int debug);

int GZPKI_do_CMS(GZPKI_CTX *ctx);

#define init_cms_context_op(__CTX__, __OP__) init_cms_context(__CTX__); \
    set_cms_operation(__CTX__, __OP__)

int asprintf(char **, const char *, ...);
int vasprintf(char **, const char *, va_list);
#include <stdio.h>
int str_append(char **json, const char *format, ...);


# define TM_START        0
# define TM_STOP         1

void print_name(BIO *out, const char *title, X509_NAME *nm, unsigned long lflags);
void* app_malloc(int sz, const char *what);







