

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef OPENSSL_NO_POSIX_IO
# include <sys/stat.h>
# include <fcntl.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#include <openssl/bn.h>
#include <openssl/ssl.h>


# include <openssl/e_os2.h>
# include <openssl/ossl_typ.h>
# include <openssl/bio.h>
# include <openssl/x509.h>
# include <openssl/conf.h>
# include <openssl/txt_db.h>
# include <openssl/engine.h>
# include <openssl/ocsp.h>
# include <openssl/lhash.h>
# include <signal.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <wchar.h>

#ifndef W_OK
# if !defined(OPENSSL_SYS_VXWORKS) && !defined(OPENSSL_SYS_WINDOWS)
#  include <sys/file.h>
# endif
#endif

#include "gzpki_common.h"

static unsigned long nmflag = 0;
static char nmflag_set = 0;


static UI_METHOD *ui_method = NULL;
static const UI_METHOD *ui_fallback_method = NULL;
static BIO_METHOD *prefix_method = NULL;


static int prefix_write(BIO *b, const char *out, size_t outl, size_t *numwritten);
static int prefix_read(BIO *b, char *buf, size_t size, size_t *numread);
static int prefix_puts(BIO *b, const char *str);
static int prefix_gets(BIO *b, char *str, int size);
static long prefix_ctrl(BIO *b, int cmd, long arg1, void *arg2);
static int prefix_create(BIO *b);
static int prefix_destroy(BIO *b);
static long prefix_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);

extern int GZPKI_do_REQ(GZPKI_CTX *ctx);
extern int GZPKI_do_ECPARAM(GZPKI_CTX *ctx);

char errstr[1024];
int errcode;

/// @brief CRL revocation reason strings 
static const char *crl_reasons[] = {
    "unspecified", 
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    "holdInstruction", /* Additional pseudo reasons : OpenSSL*/
    "keyTime",
    "CAkeyTime"
};

void gzpki_lib_init() {
    memset(errstr, 0, sizeof(errstr));
    errcode = 0;
    return;
}


int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp);

char *default_config_file = NULL;
BIO *bio_in = NULL;
BIO *bio_out = NULL;
BIO *bio_err = NULL;

typedef struct {
    const char *name;
    unsigned long flag;
    unsigned long mask;
} NAME_EX_TBL;


void* app_malloc(int sz, const char *what)
{
    void *vp = OPENSSL_malloc(sz);

    if (vp == NULL) {
        printf("app-malloc(): Could not allocate %d bytes for %s\n", sz, what);
        exit(1);
    }
    return vp;
}


int istext(int format) {    
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

int app_passwd(const char *arg1, const char *arg2, char **pass1, char **pass2)
{
    int same;
    if (arg2 == NULL || arg1 == NULL || strcmp(arg1, arg2))
        same = 0;
    else
        same = 1;
    if (arg1 != NULL) {
        *pass1 = app_get_pass(arg1, same);
        if (*pass1 == NULL)
            return 0;
    } else if (pass1 != NULL) {
        *pass1 = NULL;
    }
    if (arg2 != NULL) {
        *pass2 = app_get_pass(arg2, same ? 2 : 0);
        if (*pass2 == NULL)
            return 0;
    } else if (pass2 != NULL) {
        *pass2 = NULL;
    }
    return 1;
}

char *app_get_pass(const char *arg, int keepbio)
{
    char *tmp, tpass[APP_PASS_LEN];
    static BIO *pwdbio = NULL;
    int i;

    if (strncmp(arg, "keyid:", 6) == 0)
        return GZPKI_strdup(arg + 5);
    if (strncmp(arg, "pass:", 5) == 0)
        return GZPKI_strdup(arg + 5);
    if (strncmp(arg, "env:", 4) == 0) {
        tmp = getenv(arg + 4);
        if (tmp == NULL) {
            fprintf(stderr, "Can't read environment variable %s\n", arg + 4);
            return NULL;
        }
        return GZPKI_strdup(tmp);
    }
    if (!keepbio || pwdbio == NULL) {
        if (strncmp(arg, "file:", 5) == 0) {
            pwdbio = BIO_new_file(arg + 5, "r");
            if (pwdbio == NULL) {
                //BIO_printf(bio_err, "Can't open file %s\n", arg + 5);
                printf("Can't open file %s\n", arg + 5);
                return NULL;
            }
#if !defined(_WIN32)
            // Under _WIN32, which covers even Win64 and CE, file descriptors referenced by BIO_s_fd are not inherited by child process and therefore below is not an option.
            // It could have been an option if bss_fd.c was operating on real Windows descriptors, such as those obtained with CreateFile.
        } else if (strncmp(arg, "fd:", 3) == 0) {
            BIO *btmp;
            i = atoi(arg + 3);
            if (i >= 0)
                pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
            if ((i < 0) || !pwdbio) {
                printf("Can't access file descriptor %s\n", arg + 3);
                return NULL;
            }
            // Can't do BIO_gets on an fd BIO so add a buffering BIO
            btmp = BIO_new(BIO_f_buffer());
            pwdbio = BIO_push(btmp, pwdbio);
#endif
        } else if (strcmp(arg, "stdin") == 0) {
            pwdbio = dup_bio_in(FORMAT_TEXT);
            if (!pwdbio) {
                //BIO_printf(bio_err, "Can't open BIO for stdin\n");
                printf("Can't open BIO for stdin\n");
                return NULL;
            }
        } else {
            fprintf(stderr, "Invalid password argument \"%s\"\n", arg);
            return NULL;
        }
    }
    i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
    if (keepbio != 1) {
        BIO_free_all(pwdbio);
        pwdbio = NULL;
    }
    if (i <= 0) {
        fprintf(stderr, "Error reading password from BIO\n");
        return NULL;
    }
    tmp = strchr(tpass, '\n');
    if (tmp != NULL)
        *tmp = 0;
    return GZPKI_strdup(tpass);
}

static const char *modeverb(char mode)
{
    switch (mode) {
    case 'a':
        return "appending";
    case 'r':
        return "reading";
    case 'w':
        return "writing";
    }
    return "(doing something)";
}

const char *modestr(char mode, int format) {
    OPENSSL_assert(mode == 'a' || mode == 'r' || mode == 'w');

    switch (mode) {
    case 'a':
        return istext(format) ? "a" : "ab";
    case 'r':
        return istext(format) ? "r" : "rb";
    case 'w':
        return istext(format) ? "w" : "wb";
    }
    /* The assert above should make sure we never reach this point */
    return NULL;
}


BIO *bio_open_default_(const char *filename, char mode, int format, int quiet) {
    BIO *ret;

    if (filename == NULL || strcmp(filename, "-") == 0) {
        ret = mode == 'r' ? dup_bio_in(format) : dup_bio_out(format);
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        
        fprintf(stderr, "error:open:%s:%s\n", mode == 'r' ? "stdin" : "stdout", strerror(errno));
    } else {
        ret = BIO_new_file(filename, modestr(mode, format));
        if (quiet) {
            ERR_clear_error();
            return ret;
        }
        if (ret != NULL)
            return ret;
        fprintf(stderr, "error:open:%s for %s, %s\n", filename, modeverb(mode), strerror(errno));
    }
    return NULL;
}

BIO *bio_open_default(const char *filename, char mode, int format) {
    return bio_open_default_(filename, mode, format, 0);
}

BIO *bio_open_default_quiet(const char *filename, char mode, int format) {
    return bio_open_default_(filename, mode, format, 1);
}

static BIO_METHOD *prefix_meth = NULL;

BIO_METHOD *apps_bf_prefix(void) {
    if (prefix_meth == NULL) {
        if ((prefix_meth =
             BIO_meth_new(BIO_TYPE_FILTER, "Prefix filter")) == NULL
            || !BIO_meth_set_create(prefix_meth, prefix_create)
            || !BIO_meth_set_destroy(prefix_meth, prefix_destroy)
            || !BIO_meth_set_write_ex(prefix_meth, prefix_write)
            || !BIO_meth_set_read_ex(prefix_meth, prefix_read)
            || !BIO_meth_set_puts(prefix_meth, prefix_puts)
            || !BIO_meth_set_gets(prefix_meth, prefix_gets)
            || !BIO_meth_set_ctrl(prefix_meth, prefix_ctrl)
            || !BIO_meth_set_callback_ctrl(prefix_meth, prefix_callback_ctrl)) {
            BIO_meth_free(prefix_meth);
            prefix_meth = NULL;
        }
    }
    return prefix_meth;
}

static int prefix_create(BIO *b) {
    PREFIX_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->prefix = NULL;
    ctx->linestart = 1;
    BIO_set_data(b, ctx);
    BIO_set_init(b, 1);
    return 1;
}

static int prefix_destroy(BIO *b) {
    PREFIX_CTX *ctx = BIO_get_data(b);
    OPENSSL_free(ctx->prefix);
    OPENSSL_free(ctx);
    return 1;
}

static int prefix_read(BIO *b, char *in, size_t size, size_t *numread) {
    return BIO_read_ex(BIO_next(b), in, size, numread);
}

static int prefix_write(BIO *b, const char *out, size_t outl, size_t *numwritten) {
    PREFIX_CTX *ctx = BIO_get_data(b);

    if (ctx == NULL)
        return 0;

    /* If no prefix is set or if it's empty, we've got nothing to do here */
    if (ctx->prefix == NULL || *ctx->prefix == '\0') {
        /* We do note if what comes next will be a new line, though */
        if (outl > 0)
            ctx->linestart = (out[outl-1] == '\n');
        return BIO_write_ex(BIO_next(b), out, outl, numwritten);
    }

    *numwritten = 0;

    while (outl > 0) {
        size_t i;
        char c;

        // If we know that we're at the start of the line, output the prefix 
        if (ctx->linestart) {
            size_t dontcare;

            if (!BIO_write_ex(BIO_next(b), ctx->prefix, strlen(ctx->prefix),
                              &dontcare))
                return 0;
            ctx->linestart = 0;
        }

        // Now, go look for the next LF, or the end of the string
        for (i = 0, c = '\0'; i < outl && (c = out[i]) != '\n'; i++)
            continue;
        if (c == '\n')
            i++;

        // Output what we found so far 
        while (i > 0) {
            size_t num = 0;

            if (!BIO_write_ex(BIO_next(b), out, i, &num))
                return 0;
            out += num;
            outl -= num;
            *numwritten += num;
            i -= num;
        }

        // If we found a LF, what follows is a new line, so take note 
        if (c == '\n')
            ctx->linestart = 1;
    }

    return 1;
}

static long prefix_ctrl(BIO *b, int cmd, long num, void *ptr) {
    long ret = 0;

    switch (cmd) {
    case PREFIX_CTRL_SET_PREFIX:
        {
            PREFIX_CTX *ctx = BIO_get_data(b);

            if (ctx == NULL)
                break;

            OPENSSL_free(ctx->prefix);
            ctx->prefix = GZPKI_strdup((const char *)ptr);
            ret = ctx->prefix != NULL;
        }
        break;
    default:
        if (BIO_next(b) != NULL)
            ret = BIO_ctrl(BIO_next(b), cmd, num, ptr);
        break;
    }
    return ret;
}

static long prefix_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp) {
    return BIO_callback_ctrl(BIO_next(b), cmd, fp);
}

static int prefix_gets(BIO *b, char *buf, int size) {
    return BIO_gets(BIO_next(b), buf, size);
}

static int prefix_puts(BIO *b, const char *str) {
    return BIO_write(b, str, strlen(str));
}


BIO *dup_bio_in(int format) {
    return BIO_new_fp(stdin, BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
}

BIO *dup_bio_out(int format) {
    BIO *b = BIO_new_fp(stdout, BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
    void *prefix = NULL;

    if (istext(format) && (prefix = getenv("HARNESS_OSSL_PREFIX")) != NULL) {
        if (prefix_method == NULL)
            prefix_method = apps_bf_prefix();
        b = BIO_push(BIO_new(prefix_method), b);
        BIO_ctrl(b, PREFIX_CTRL_SET_PREFIX, 0, prefix);
    }

    return b;
}

BIO *dup_bio_err(int format) {
    BIO *b = BIO_new_fp(stderr, BIO_NOCLOSE | (istext(format) ? BIO_FP_TEXT : 0));
    return b;
}


int file_exist(char *fname) {
    if( access( fname, F_OK ) != -1 ) {
        return CMS_RET_OK;
    } 
    else {
        return CMS_RET_FAIL;
    }
    return CMS_RET_ERROR;
}

/*static*/ 
int load_pkcs12(BIO *in, const char *desc,
                       pem_password_cb *pem_cb, void *cb_data,
                       EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *pass;
    char tpass[PEM_BUFSIZE];
    int len, ret = 0;
    PKCS12 *p12;
    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        BIO_printf(bio_err, "Error loading PKCS12 file for %s\n", desc);
        goto die;
    }
    // See if an empty password will do 
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0)) {
        pass = "";
    } else {
        if (!pem_cb)
            pem_cb = (pem_password_cb *)password_callback;
        len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
        if (len < 0) {
            BIO_printf(bio_err, "Passphrase callback error for %s\n", desc);
            goto die;
        }
        if (len < PEM_BUFSIZE)
            tpass[len] = 0;
        if (!PKCS12_verify_mac(p12, tpass, len)) {
            BIO_printf(bio_err, "Mac verify error (wrong password?) in PKCS12 file for %s\n", desc);
            goto die;
        }
        pass = tpass;
    }
    ret = PKCS12_parse(p12, pass, pkey, cert, ca);
 die:
    PKCS12_free(p12);
    return ret;
}

int GZPKI_check_valid_certificate(char *file, int format) {
    X509 *tmp = load_cert((const char *)file, format, "X.509 Certificate");
    if(tmp)
        return CMS_RET_OK;

    return CMS_RET_FAIL;
}

X509 *load_cert(const char *file, int format, const char *cert_descrip)
{
    X509 *x = NULL;
    BIO *cert;

    if (format == FORMAT_HTTP) {
    #if 0 // !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        load_cert_crl_http(file, &x, NULL);
    #endif
        return x;
    }

    if (file == NULL) {
        unbuffer(stdin);
        cert = dup_bio_in(format);
    } else {
        cert = bio_open_default(file, 'r', format);
    }
    if (cert == NULL)
        goto end;

    if (format == FORMAT_ASN1) {
        x = d2i_X509_bio(cert, NULL);
    } else if (format == FORMAT_PEM) {
        x = PEM_read_bio_X509_AUX(cert, NULL, (pem_password_cb *)password_callback, NULL);
    } else if (format == FORMAT_PKCS12) {
        if (!load_pkcs12(cert, cert_descrip, NULL, NULL, NULL, &x, NULL))
            goto end;
    } else {
        fprintf(stderr, "bad input format specified for %s\n", cert_descrip);
        goto end;
    }
 end:
    if (x == NULL) {
        fprintf(stderr, "unable to load certificate\n");
        //ERR_print_errors(bio_err);
    }
    BIO_free(cert);
    return x;
}

X509_CRL *load_crl(const char *infile, int format)
{
    X509_CRL *x = NULL;
    BIO *in = NULL;

    if (format == FORMAT_HTTP) {
    
    #if 0// !defined(OPENSSL_NO_OCSP) && !defined(OPENSSL_NO_SOCK)
        load_cert_crl_http(infile, NULL, &x);
    #endif
        return x;
    }

    in = bio_open_default(infile, 'r', format);
    if (in == NULL)
        goto end;
    if (format == FORMAT_ASN1) {
        x = d2i_X509_CRL_bio(in, NULL);
    } else if (format == FORMAT_PEM) {
        x = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    } else {
        BIO_printf(bio_err, "bad input format specified for input crl\n");
        goto end;
    }
    if (x == NULL) {
        BIO_printf(bio_err, "unable to load CRL\n");
        ERR_print_errors(bio_err);
        goto end;
    }

 end:
    BIO_free(in);
    return x;
}


EVP_PKEY *load_key_buffer(const char *buffer, int len, int format,  const char *pass)
{
    BIO *biokey = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = NULL;

    biokey = BIO_new(BIO_s_mem());

    //informat = FORMAT_PEM(=FORMAT_SMIME)으로 고정
    biokey = BIO_new_mem_buf(buffer, -1);
        
    //if(informat == FORMAT_ASN1) biokey = BIO_new_mem_buf(buffer, buffer_size);

    if (biokey == NULL) {
        printf("error: fail to set mem buf.\n");
        goto end;
    }

    //if (format == FORMAT_ASN1) pkey = d2i_PrivateKey_bio(biokey, NULL);
    //if (format == FORMAT_PEM)
    if(pass == NULL)
        pkey = PEM_read_bio_PrivateKey(biokey, NULL, (pem_password_cb *)password_callback, &cb_data);
    else
        pkey = PEM_read_bio_PrivateKey(biokey, NULL, (pem_password_cb *)password_callback_noprompt, &cb_data);
    
 end:
    BIO_free(biokey);
    if (pkey == NULL) {
        BIO_printf(bio_err, "error:unable to load\n");
    }

    return pkey;
}


EVP_PKEY *load_key(const char *file, int format, int maybe_stdin, const char *pass, ENGINE *e, const char *key_descrip)
{
    BIO *biokey = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    //cb_data.password = GZPKI_strdup(pass);
    cb_data.password = pass;
    cb_data.prompt_info = NULL;

    if (file == NULL && maybe_stdin) {
        unbuffer(stdin);
        biokey = dup_bio_in(format);
    } else {
        biokey = bio_open_default(file, 'r', format);
    }
    if (biokey == NULL)
    {
        printf("load_key: null key!\n");
        goto end;
    }

    if (format == FORMAT_ASN1)
    {
        pkey = d2i_PrivateKey_bio(biokey, NULL);
    } 
    else if (format == FORMAT_PEM)
    {
        if (pass == NULL) {
            IF_VERBOSE fprintf(stderr, "gzpki_common():load_key():read private key with password.\n");
            pkey = PEM_read_bio_PrivateKey(biokey, NULL, (pem_password_cb *)password_callback, &cb_data);
        }
        else {
            IF_VERBOSE fprintf(stderr, "gzpki_common():load_key():read private key with no password.\n");
            pkey = PEM_read_bio_PrivateKey(biokey, NULL, (pem_password_cb *)password_callback_noprompt, &cb_data);
        }

        if (pkey == NULL) {
            IF_VERBOSE fprintf(stderr, "gzpki_common():load_key():null private key.\n");
            //IF_VERBOSE GZPKI_print_errors_std();
        }
    } 
    else if (format == FORMAT_PKCS12)
    {
        if (!load_pkcs12(biokey, key_descrip, (pem_password_cb *)password_callback, &cb_data, &pkey, NULL, NULL))
            goto end;
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA) && !defined (OPENSSL_NO_RC4)
    } else if (format == FORMAT_MSBLOB) {
        pkey = b2i_PrivateKey_bio(biokey);
#endif
    } else {
        BIO_printf(bio_err, "bad input format specified for key file\n");
        goto end;
    }
 end:
    BIO_free(biokey);
    if (pkey == NULL) {
        BIO_printf(bio_err, "unable to load %s\n", key_descrip);
        //ERR_print_errors(bio_err);
        //GZPKI_print_errors_std();
    }

    return pkey;
}

EVP_PKEY *load_pubkey(const char *file, int format, int maybe_stdin,
                      const char *pass, ENGINE *e, const char *key_descrip)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE)) {
        BIO_printf(bio_err, "no keyfile specified\n");
        fprintf(stderr, "no keyfile specified\n");
        goto end;
    }
    if (format == FORMAT_ENGINE) {
        if (e == NULL) {
            BIO_printf(bio_err, "no engine specified\n");
        } else {
#if 0 //ndef OPENSSL_NO_ENGINE
            pkey = ENGINE_load_public_key(e, file, ui_method, &cb_data);
            if (pkey == NULL) {
                BIO_printf(bio_err, "cannot load %s from engine\n", key_descrip);
                ERR_print_errors(bio_err);
            }
#else
            BIO_printf(bio_err, "engines not supported\n");
#endif
        }
        goto end;
    }
    if (file == NULL && maybe_stdin) {
        unbuffer(stdin);
        key = dup_bio_in(format);
    } else {
        key = bio_open_default(file, 'r', format);
    }
    if (key == NULL) {
        fprintf(stderr, "key is null.\n");
        goto end;
    }
    if (format == FORMAT_ASN1) {
        pkey = d2i_PUBKEY_bio(key, NULL);
    } else if (format == FORMAT_ASN1RSA) {
#ifndef OPENSSL_NO_RSA
        RSA *rsa;
        rsa = d2i_RSAPublicKey_bio(key, NULL);
        if (rsa) {
            pkey = EVP_PKEY_new();
            if (pkey != NULL)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        } else
#else
        BIO_printf(bio_err, "RSA keys not supported\n");
#endif
            pkey = NULL;
    } else if (format == FORMAT_PEMRSA) {
#ifndef OPENSSL_NO_RSA
        RSA *rsa;
        rsa = PEM_read_bio_RSAPublicKey(key, NULL, (pem_password_cb *)password_callback, &cb_data);
        if (rsa != NULL) {
            pkey = EVP_PKEY_new();
            if (pkey != NULL)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        } else
#else
        BIO_printf(bio_err, "RSA keys not supported\n");
#endif
            pkey = NULL;
    } else if (format == FORMAT_PEM) {
        pkey = PEM_read_bio_PUBKEY(key, NULL, (pem_password_cb *)password_callback, &cb_data);
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA)
    } else if (format == FORMAT_MSBLOB) {
        pkey = b2i_PublicKey_bio(key);
#endif
    }
 end:
    BIO_free(key);
    if (pkey == NULL)
        BIO_printf(bio_err, "unable to load %s\n", key_descrip);
    return pkey;
}

/*static*/ int load_certs_crls(const char *file, int format,
                           const char *pass, const char *desc,
                           STACK_OF(X509) **pcerts,
                           STACK_OF(X509_CRL) **pcrls)
{
    int i;
    BIO *bio;
    STACK_OF(X509_INFO) *xis = NULL;
    X509_INFO *xi;
    PW_CB_DATA cb_data;
    int rv = 0;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (format != FORMAT_PEM) {
        BIO_printf(bio_err, "bad input format specified for %s\n", desc);
        return 0;
    }

    bio = bio_open_default(file, 'r', FORMAT_PEM);
    if (bio == NULL)
        return 0;

    xis = PEM_X509_INFO_read_bio(bio, NULL, (pem_password_cb *)password_callback, &cb_data);

    BIO_free(bio);

    if (pcerts != NULL && *pcerts == NULL) {
        *pcerts = sk_X509_new_null();
        if (*pcerts == NULL)
            goto end;
    }

    if (pcrls != NULL && *pcrls == NULL) {
        *pcrls = sk_X509_CRL_new_null();
        if (*pcrls == NULL)
            goto end;
    }

    for (i = 0; i < sk_X509_INFO_num(xis); i++) {
        xi = sk_X509_INFO_value(xis, i);
        if (xi->x509 != NULL && pcerts != NULL) {
            if (!sk_X509_push(*pcerts, xi->x509))
                goto end;
            xi->x509 = NULL;
        }
        if (xi->crl != NULL && pcrls != NULL) {
            if (!sk_X509_CRL_push(*pcrls, xi->crl))
                goto end;
            xi->crl = NULL;
        }
    }

    if (pcerts != NULL && sk_X509_num(*pcerts) > 0)
        rv = 1;

    if (pcrls != NULL && sk_X509_CRL_num(*pcrls) > 0)
        rv = 1;

 end:

    sk_X509_INFO_pop_free(xis, X509_INFO_free);

    if (rv == 0) {
        if (pcerts != NULL) {
            sk_X509_pop_free(*pcerts, X509_free);
            *pcerts = NULL;
        }
        if (pcrls != NULL) {
            sk_X509_CRL_pop_free(*pcrls, X509_CRL_free);
            *pcrls = NULL;
        }
        BIO_printf(bio_err, "unable to load %s\n", pcerts ? "certificates" : "CRLs");
        ERR_print_errors(bio_err);
    }
    return rv;
}


/*
 * Initialize or extend, if *certs != NULL, a certificate stack.
 */
int load_certs(const char *file, STACK_OF(X509) **certs, int format, const char *pass, const char *desc) {
    return load_certs_crls(file, format, pass, desc, certs, NULL);
}

/*
 * Initialize or extend, if *crls != NULL, a certificate stack.
 */
int load_crls(const char *file, STACK_OF(X509_CRL) **crls, int format, const char *pass, const char *desc) {
    return load_certs_crls(file, format, pass, desc, NULL, crls);
}

void print_name(BIO *out, const char *title, X509_NAME *nm, unsigned long lflags);


char * print_name_str(X509_NAME *nm, unsigned long lflags)
{
    char *buf;
    char mline = 0;
    int indent = 0;
    BIO *out = NULL;
    BUF_MEM *bptr;
    char *ret = NULL;


    out = BIO_new(BIO_s_mem());

    if ((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        printf("DEBUG:print_name_str:lflags = XN_FLAG_SEP_MULTILINE!\n");
        mline = 1;
        indent = 4;
    }
    if (lflags == XN_FLAG_COMPAT) {
        printf("DEBUG:print_name_str:lflags = XN_FLAG_COMPAT!\n");
        buf = X509_NAME_oneline(nm, 0, 0);
        BIO_puts(out, buf);
        //BIO_puts(out, "\n");
        OPENSSL_free(buf);
    } else {
        if (mline)
            BIO_puts(out, "\n");
        X509_NAME_print_ex(out, nm, indent, lflags);
        //BIO_puts(out, "\n");
    }

    BIO_get_mem_ptr( out, &bptr);    

    printf("DEBUG:print_name_str: [%s]\n", bptr->data);
    ret =  GZPKI_strdup(bptr->data);

    ret[bptr->length] = 0;

    return ret;

}




void print_name(BIO *out, const char *title, X509_NAME *nm, unsigned long lflags)
{
    char *buf;
    char mline = 0;
    int indent = 0;
    

    if (title)
        BIO_puts(out, title);
    if ((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mline = 1;
        indent = 4;
    }
    if (lflags == XN_FLAG_COMPAT) {
        buf = X509_NAME_oneline(nm, 0, 0);
        BIO_puts(out, buf);
        BIO_puts(out, "\n");
        OPENSSL_free(buf);
    } else {
        if (mline)
            BIO_puts(out, "\n");
        X509_NAME_print_ex(out, nm, indent, lflags);
        BIO_puts(out, "\n");
    }
}


void unbuffer(FILE *fp)
{
/*
 * On VMS, setbuf() will only take 32-bit pointers, and a compilation
 * with /POINTER_SIZE=64 will give off a MAYLOSEDATA2 warning here.
 * However, we trust that the C RTL will never give us a FILE pointer
 * above the first 4 GB of memory, so we simply turn off the warning
 * temporarily.
 */
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma environment save
# pragma message disable maylosedata2
#endif
    setbuf(fp, NULL);
#if defined(OPENSSL_SYS_VMS) && defined(__DECC)
# pragma environment restore
#endif
}


int password_callback_noprompt(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp)
{
    int res = 0;
    //del: UI *ui = NULL;
    PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;
    int size = 0;
    
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"password_callback(noprompt): pwd=[%s]\n", (char *)cb_data->password);
    if(cb_data->password)
    {
        size = strlen(cb_data->password);
        strncpy(buf, (char *)cb_data->password, size);

        buf[size] = '\0';

        IF_VERBOSE {
            fprintf(stderr, "password_callback(noprompt): buf=[%s], len=[%ld]\n", buf, strlen(buf));
        }

        res = strlen(buf);
    }

    return res;
}


int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp)
{
    int res = 0;
    UI *ui = NULL;
    PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

    ui = UI_new_method(ui_method);
    if (ui) {
        int ok = 0;
        char *buff = NULL;
        int ui_flags = 0;
        const char *prompt_info = NULL;
        char *prompt;

        if (cb_data != NULL && cb_data->prompt_info != NULL)
            prompt_info = cb_data->prompt_info;
        prompt = UI_construct_prompt(ui, "pass phrase", prompt_info);
        if (!prompt) {
            BIO_printf(bio_err, "Out of memory\n");
            UI_free(ui);
            return 0;
        }

        ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
        UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

        /* We know that there is no previous user data to return to us */
        (void)UI_add_user_data(ui, cb_data);

        ok = UI_add_input_string(ui, prompt, ui_flags, buf,
                                 PW_MIN_LENGTH, bufsiz - 1);

        if (ok >= 0 && verify) {
            buff = app_malloc(bufsiz, "password buffer");
            ok = UI_add_verify_string(ui, prompt, ui_flags, buff,
                                      PW_MIN_LENGTH, bufsiz - 1, buf);
        }
        if (ok >= 0)
            do {
                ok = UI_process(ui);
            } while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

        OPENSSL_clear_free(buff, (unsigned int)bufsiz);

        if (ok >= 0)
            res = strlen(buf);
        if (ok == -1) {
            BIO_printf(bio_err, "User interface error\n");
            ERR_print_errors(bio_err);
            OPENSSL_cleanse(buf, (unsigned int)bufsiz);
            res = 0;
        }
        if (ok == -2) {
            BIO_printf(bio_err, "aborted!\n");
            OPENSSL_cleanse(buf, (unsigned int)bufsiz);
            res = 0;
        }
        UI_free(ui);
        OPENSSL_free(prompt);
    }
    return res;
}


X509_STORE *setup_verify(const char *CAfile, const char *CApath, int noCAfile, int noCApath)
{
    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup;

    if (store == NULL)
        goto end;

    if (CAfile != NULL || !noCAfile) {
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (lookup == NULL)
            goto end;
        if (CAfile) {
            if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
                BIO_printf(bio_err, "Error loading file %s\n", CAfile);
                goto end;
            }
        } else {
            X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }

    if (CApath != NULL || !noCApath) {
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        if (lookup == NULL)
            goto end;
        if (CApath) {
            if (!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM)) {
                BIO_printf(bio_err, "Error loading directory %s\n", CApath);
                goto end;
            }
        } else {
            X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }

    ERR_clear_error();
    return store;
 end:
    X509_STORE_free(store);
    return NULL;
}

int gzpki_common_context_init(GZPKI_CTX *ctx);

#define FREE_STR(X)  if(ctx->X && ctx->X != NULL) { \
                free(ctx->X); \
                ctx->X= NULL; \
            }

int gzpki_common_context_free(GZPKI_CTX *ctx)
{
    //==================================================
    // COMMON
    //================================================== 
    if(ctx->in) BIO_free(ctx->in);
    if(ctx->out) BIO_free_all(ctx->out);
   
    FREE_STR(infile);
    FREE_STR(outfile);
    
    //==================================================
    // FREE CMS CTX
    //==================================================
    BN_free(ctx->ec_p);
    BN_free(ctx->ec_a);
    BN_free(ctx->ec_b);
    BN_free(ctx->ec_gen);
    BN_free(ctx->ec_order);
    BN_free(ctx->ec_cofactor);

    //==================================================
    // FREE CMS CTX
    //==================================================
    if(ctx->encerts)
        sk_X509_pop_free(ctx->encerts, X509_free);
    if(ctx->other)
        sk_X509_pop_free(ctx->other, X509_free);

    X509_VERIFY_PARAM_free(ctx->vpm);
    sk_OPENSSL_STRING_free(ctx->sksigners);
    sk_OPENSSL_STRING_free(ctx->skkeys);
    OPENSSL_free(ctx->secret_key);
    OPENSSL_free(ctx->secret_keyid);
    OPENSSL_free(ctx->pwri_tmp);
    ASN1_OBJECT_free(ctx->econtent_type);
    CMS_ReceiptRequest_free(ctx->rr);
    sk_OPENSSL_STRING_free(ctx->rr_to);
    sk_OPENSSL_STRING_free(ctx->rr_from);
    
    X509_STORE_free(ctx->store);
    X509_free(ctx->cert);
    X509_free(ctx->recip);
    X509_free(ctx->signer);
    EVP_PKEY_free(ctx->key);
    CMS_ContentInfo_free(ctx->cms);
    CMS_ContentInfo_free(ctx->rcms);
    
    //release_engine(ctx->e);
    BIO_free(ctx->rctin);
    BIO_free(ctx->indata);
    /*OPENSSL_free(ctx->passin);*/

    if(ctx->req_conf)
        NCONF_free(ctx->req_conf);
    if(ctx->addext_conf)
        NCONF_free(ctx->addext_conf);

    FREE_STR(req_conf_str);
    FREE_STR(passphrase);
    FREE_STR(cipher_name);
    //FREE_STR(passin);
    FREE_STR(passout);
    FREE_STR(subj);
    FREE_STR(req_exts);

    FREE_STR(countryName);
    FREE_STR(stateOrProvinceName);
    FREE_STR(localityName);
    FREE_STR(organizationName);
    FREE_STR(organizationUnitName);
    FREE_STR(commonName);
    FREE_STR(emailAddress);
    FREE_STR(crl_revoke_reason);

    FREE_STR(configfile);
    FREE_STR(req_section);
    FREE_STR(db_file);
        
    //CA: 인증서 생성 후 반환값
    //FREE_STR(caIssuerDN);

    return 0;
}


static unsigned long index_serial_hash(const OPENSSL_CSTRING *a) {
    const char *n;
    n = a[DB_serial];
    while (*n == '0')
        n++;
    return OPENSSL_LH_strhash(n);
}

static int index_serial_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b) {
    const char *aa, *bb;

    for (aa = a[DB_serial]; *aa == '0'; aa++) ;
    for (bb = b[DB_serial]; *bb == '0'; bb++) ;
    return strcmp(aa, bb);
}

static int index_name_qual(char **a) {
    return (a[0][0] == 'V');
}

static unsigned long index_name_hash(const OPENSSL_CSTRING *a) {
    return OPENSSL_LH_strhash(a[DB_name]);
}

int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b) {
    return strcmp(a[DB_name], b[DB_name]);
}

static IMPLEMENT_LHASH_HASH_FN(index_serial, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_COMP_FN(index_serial, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_HASH_FN(index_name, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_COMP_FN(index_name, OPENSSL_CSTRING)


#undef SIZE
#undef BSIZE
#define SIZE    (512)
#define BSIZE   (8*1024)

int parse_yesno(const char *str, int def)
{
    if (str) {
        switch (*str) {
        case 'f':              /* false */
        case 'F':              /* FALSE */
        case 'n':              /* no */
        case 'N':              /* NO */
        case '0':              /* 0 */
            return 0;
        case 't':              /* true */
        case 'T':              /* TRUE */
        case 'y':              /* yes */
        case 'Y':              /* YES */
        case '1':              /* 1 */
            return 1;
        }
    }
    return def;
}


CA_DB *load_index(const char *dbfile, DB_ATTR *db_attr)
{
    CA_DB *retdb = NULL;
    TXT_DB *tmpdb = NULL;
    BIO *in;
    CONF *dbattr_conf = NULL;
    char buf[BSIZE];
#ifndef OPENSSL_NO_POSIX_IO
    FILE *dbfp;
    struct stat dbst;
#endif

    in = BIO_new_file(dbfile, "r");
    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }

#ifndef OPENSSL_NO_POSIX_IO
    BIO_get_fp(in, &dbfp);
    if (fstat(fileno(dbfp), &dbst) == -1) {
        SYSerr(SYS_F_FSTAT, errno);
        ERR_add_error_data(3, "fstat('", dbfile, "')");
        ERR_print_errors(bio_err);
        goto err;
    }
#endif

    if ((tmpdb = TXT_DB_read(in, DB_NUMBER)) == NULL)
        goto err;

#ifndef OPENSSL_SYS_VMS
    BIO_snprintf(buf, sizeof(buf), "%s.attr", dbfile);
#else
    BIO_snprintf(buf, sizeof(buf), "%s-attr", dbfile);
#endif
    dbattr_conf = app_load_config(buf);

    retdb = app_malloc(sizeof(*retdb), "new DB");
    retdb->db = tmpdb;
    tmpdb = NULL;
    if (db_attr)
        retdb->attributes = *db_attr;
    else {
        retdb->attributes.unique_subject = 1;
    }

    if (dbattr_conf) {
        char *p = NCONF_get_string(dbattr_conf, NULL, "unique_subject");
        if (p) {
            retdb->attributes.unique_subject = parse_yesno(p, 1);
        }
    }

    retdb->dbfname = OPENSSL_strdup(dbfile);
#ifndef OPENSSL_NO_POSIX_IO
    retdb->dbst = dbst;
#endif

 err:
    NCONF_free(dbattr_conf);
    TXT_DB_free(tmpdb);
    BIO_free_all(in);
    return retdb;
}



/*
 * Returns > 0 on success, <= 0 on error
 */
int index_index(CA_DB *db)
{
    if (!TXT_DB_create_index(db->db, DB_serial, NULL,
                             LHASH_HASH_FN(index_serial),
                             LHASH_COMP_FN(index_serial))) {
        BIO_printf(bio_err, "error creating serial number index:(%ld,%ld,%ld)\n", db->db->error, db->db->arg1, db->db->arg2);
        fprintf(stderr, "error creating serial number index:(%ld,%ld,%ld)\n", db->db->error, db->db->arg1, db->db->arg2);
        return 0;
    }

    if (db->attributes.unique_subject
        && !TXT_DB_create_index(db->db, DB_name, index_name_qual,
                                LHASH_HASH_FN(index_name),
                                LHASH_COMP_FN(index_name))) {
        BIO_printf(bio_err, "error creating name index:(%ld,%ld,%ld)\n", db->db->error, db->db->arg1, db->db->arg2);
        fprintf(stderr, "error creating name index:(%ld,%ld,%ld)\n", db->db->error, db->db->arg1, db->db->arg2);
        return 0;
    }
    return 1;
}

int save_index(const char *dbfile, const char *suffix, CA_DB *db)
{
    char buf[3][BSIZE];
    BIO *out;
    int j;

    j = strlen(dbfile) + strlen(suffix);
    if (j + 6 >= BSIZE) {
        BIO_printf(bio_err, "file name too long\n");
        goto err;
    }
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[2], sizeof(buf[2]), "%s.attr", dbfile);
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "%s.attr.%s", dbfile, suffix);
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "%s.%s", dbfile, suffix);
#else
    j = BIO_snprintf(buf[2], sizeof(buf[2]), "%s-attr", dbfile);
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "%s-attr-%s", dbfile, suffix);
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "%s-%s", dbfile, suffix);
#endif
    out = BIO_new_file(buf[0], "w");
    if (out == NULL) {
        perror(dbfile);
        BIO_printf(bio_err, "unable to open '%s'\n", dbfile);
        goto err;
    }
    j = TXT_DB_write(out, db->db);
    BIO_free(out);
    if (j <= 0)
        goto err;

    out = BIO_new_file(buf[1], "w");
    if (out == NULL) {
        perror(buf[2]);
        BIO_printf(bio_err, "unable to open '%s'\n", buf[2]);
        goto err;
    }
    BIO_printf(out, "unique_subject = %s\n",
               db->attributes.unique_subject ? "yes" : "no");
    BIO_free(out);

    return 1;
 err:
    return 0;
}

int rotate_index(const char *dbfile, const char *new_suffix, const char *old_suffix)
{
    char buf[5][BSIZE];
    int i, j;

    i = strlen(dbfile) + strlen(old_suffix);
    j = strlen(dbfile) + strlen(new_suffix);
    if (i > j)
        j = i;
    if (j + 6 >= BSIZE) {
        BIO_printf(bio_err, "file name too long\n");
        goto err;
    }
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[4], sizeof(buf[4]), "%s.attr", dbfile);
    j = BIO_snprintf(buf[3], sizeof(buf[3]), "%s.attr.%s", dbfile, old_suffix);
    j = BIO_snprintf(buf[2], sizeof(buf[2]), "%s.attr.%s", dbfile, new_suffix);
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "%s.%s", dbfile, old_suffix);
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "%s.%s", dbfile, new_suffix);
#else
    j = BIO_snprintf(buf[4], sizeof(buf[4]), "%s-attr", dbfile);
    j = BIO_snprintf(buf[3], sizeof(buf[3]), "%s-attr-%s", dbfile, old_suffix);
    j = BIO_snprintf(buf[2], sizeof(buf[2]), "%s-attr-%s", dbfile, new_suffix);
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "%s-%s", dbfile, old_suffix);
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "%s-%s", dbfile, new_suffix);
#endif
    if (rename(dbfile, buf[1]) < 0 && errno != ENOENT
#ifdef ENOTDIR
        && errno != ENOTDIR
#endif
        ) {
        BIO_printf(bio_err, "unable to rename %s to %s\n", dbfile, buf[1]);
        perror("reason");
        goto err;
    }
    if (rename(buf[0], dbfile) < 0) {
        BIO_printf(bio_err, "unable to rename %s to %s\n", buf[0], dbfile);
        perror("reason");
        rename(buf[1], dbfile);
        goto err;
    }
    if (rename(buf[4], buf[3]) < 0 && errno != ENOENT
#ifdef ENOTDIR
        && errno != ENOTDIR
#endif
        ) {
        BIO_printf(bio_err, "unable to rename %s to %s\n", buf[4], buf[3]);
        perror("reason");
        rename(dbfile, buf[0]);
        rename(buf[1], dbfile);
        goto err;
    }
    if (rename(buf[2], buf[4]) < 0) {
        BIO_printf(bio_err, "unable to rename %s to %s\n", buf[2], buf[4]);
        perror("reason");
        rename(buf[3], buf[4]);
        rename(dbfile, buf[0]);
        rename(buf[1], dbfile);
        goto err;
    }
    return 1;
 err:
    return 0;
}

void free_index(CA_DB *db)
{
    if (db) {
        TXT_DB_free(db->db);
        OPENSSL_free(db->dbfname);
        OPENSSL_free(db);
    }
}

BIO *GZPKI_set_in_BIO(int intype, char *infile, char *inbuffer, int inbuffer_size, int informat)
{
    BIO *in = NULL;
    if(intype == FORMAT_FILE) {
        if(infile == NULL) {
            printf("error: null file name\n");
            return NULL;
        }
        if(CMS_RET_OK != file_exist(infile)){
            printf("error:GZPKI_set_in_BIO():no input file:%s\n", infile);
            return NULL;
        }
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL) {
            printf("error: fail to open file: %s\n", infile);
            return NULL;
        }
    } else if(intype == FORMAT_MEM) {

        in = BIO_new(BIO_s_mem());
        if(informat == FORMAT_SMIME || informat == FORMAT_PEM) {
            in = BIO_new_mem_buf(inbuffer, -1);
        }
        else if(informat == FORMAT_ASN1) {
            in = BIO_new_mem_buf(inbuffer, inbuffer_size);
        }
        if (in == NULL) {
            printf("error: fail to set mem buf.\n");
            return NULL;
        }

    }
    return in;
}

//-----------------------------------------------------------------
BIO *GZPKI_set_out_BIO(int outtype, char *outfile, int outformat)
{
    BIO *out = NULL;
    if(outfile == NULL || outtype == FORMAT_MEM) {
        out = BIO_new(BIO_s_mem());
    }
    else {
        out = bio_open_default(outfile, 'w', outformat);
        if (out == NULL)  {
            return NULL;
        }
    }
    return out;
}


int GZPKI_set_infile(GZPKI_CTX *ctx, char *infile, char *inbuffer, int inbuffer_size, int informat) {
    
    int intype = -1;
    if(infile == NULL && inbuffer == NULL) {
        sprintf(ctx->errstr, "invalid infile and inbuffer");
        return CMS_RET_ERROR;
    }
    
    ctx->informat = informat;
    intype = infile == NULL ?  FORMAT_MEM : FORMAT_FILE;
    ctx->intype = intype;

    ctx->infile = GZPKI_strdup(infile);

    if(infile != NULL )
        ctx->intype = FORMAT_FILE;
    else if(inbuffer != NULL && inbuffer_size>0)
        ctx->intype = FORMAT_MEM;
    else
        CMS_RET_ERROR;


    ctx->in = GZPKI_set_in_BIO(intype, infile, inbuffer, inbuffer_size, informat);
    if(ctx->in == NULL)
        return CMS_RET_ERROR;

    return CMS_RET_OK;
}

int GZPKI_set_outfile(GZPKI_CTX *ctx, char *outfile, int outformat) {
    ctx->outfile = GZPKI_strdup(outfile);
    ctx->outformat = outformat;
    ctx->outtype = outfile == NULL ?  FORMAT_MEM : FORMAT_FILE;
    
    ctx->out  = GZPKI_set_out_BIO(ctx->outtype, ctx->outfile, ctx->outformat);

    if(ctx->out == NULL)
        return CMS_RET_ERROR;

    return CMS_RET_OK;
}


int GZPKI_reset_outfile(GZPKI_CTX *ctx, char *outfile, int outformat) {
    
    if(ctx->out) BIO_free_all(ctx->out);
    
    ctx->outfile = GZPKI_strdup(outfile);
    ctx->outformat = outformat;
    ctx->outtype = outfile == NULL ?  FORMAT_MEM : FORMAT_FILE;
    
    ctx->out  = GZPKI_set_out_BIO(ctx->outtype, ctx->outfile, ctx->outformat);

    if(ctx->out == NULL)
        return CMS_RET_ERROR;

    return CMS_RET_OK;
}

char *GZPKI_get_mem(GZPKI_CTX *ctx) {
    BIO_get_mem_ptr( ctx->out, &ctx->bptr);    
    return ctx->bptr->data;
}

int GZPKI_get_mem_length(GZPKI_CTX *ctx) {
    BIO_get_mem_ptr( ctx->out, &ctx->bptr);
    return ctx->bptr->length;
}

int GZPKI_set_sign_md(GZPKI_CTX *ctx, char *sign_md) {
    #if 0
        1) sha256, sha384, sha512, sha224, 
        2) sha512-224, sha512-256, 
        3) sha3-224, sha3-384, sha3-256, sha3-512
        4) shake128, shake256
    #endif

    ctx->sign_md =  (EVP_MD *)EVP_get_digestbyname(sign_md);
    if(ctx->sign_md == NULL) {
        memset(ctx->errstr, 0, sizeof(ctx->errstr));
        sprintf(ctx->errstr, "fail to set message digest algorithm: %s", sign_md);
        return CMS_RET_ERROR;
    }
    return CMS_RET_OK;
}



int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;
    stmp = OPENSSL_strdup(value);
    if (!stmp)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}

static void nodes_print(const char *name, STACK_OF(X509_POLICY_NODE) *nodes)
{
    X509_POLICY_NODE *node;
    int i;

    BIO_printf(bio_err, "%s Policies:", name);
    if (nodes) {
        BIO_puts(bio_err, "\n");
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(bio_err, node, 2);
        }
    } else {
        BIO_puts(bio_err, " <empty>\n");
    }
}

void policies_print(X509_STORE_CTX *ctx)
{
    X509_POLICY_TREE *tree;
    int explicit_policy;
    tree = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(bio_err, "Require explicit Policy: %s\n",
               explicit_policy ? "True" : "False");

    nodes_print("Authority", X509_policy_tree_get0_policies(tree));
    nodes_print("User", X509_policy_tree_get0_user_policies(tree));
}

/*-
 * next_protos_parse parses a comma separated list of strings into a string
 * in a format suitable for passing to SSL_CTX_set_next_protos_advertised.
 *   outlen: (output) set to the length of the resulting buffer on success.
 *   err: (maybe NULL) on failure, an error message line is written to this BIO.
 *   in: a NUL terminated string like "abc,def,ghi"
 *
 *   returns: a malloc'd buffer or NULL on failure.
 */
unsigned char *next_protos_parse(size_t *outlen, const char *in)
{
    size_t len;
    unsigned char *out;
    size_t i, start = 0;

    len = strlen(in);
    if (len >= 65535)
        return NULL;

    out = app_malloc(strlen(in) + 1, "NPN buffer");
    for (i = 0; i <= len; ++i) {
        if (i == len || in[i] == ',') {
            if (i - start > 255) {
                OPENSSL_free(out);
                return NULL;
            }
            out[start] = (unsigned char)(i - start);
            start = i + 1;
        } else {
            out[i + 1] = in[i];
        }
    }

    *outlen = len + 1;
    return out;
}

void print_cert_checks(BIO *bio, X509 *x,
                       const char *checkhost,
                       const char *checkemail, const char *checkip)
{
    if (x == NULL)
        return;
    if (checkhost) {
        BIO_printf(bio, "Hostname %s does%s match certificate\n", 
                   checkhost,
                   X509_check_host(x, checkhost, 0, 0, NULL) == 1
                       ? "" : " NOT");
    }

    if (checkemail) {
        BIO_printf(bio, "Email %s does%s match certificate\n",
                   checkemail, X509_check_email(x, checkemail, 0, 0)
                   ? "" : " NOT");
    }

    if (checkip) {
        BIO_printf(bio, "IP %s does%s match certificate\n",
                   checkip, X509_check_ip_asc(x, checkip, 0) ? "" : " NOT");
    }
}

/* Get first http URL from a DIST_POINT structure */

static const char *get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            const char *uptr = (const char *)ASN1_STRING_get0_data(uri);
            if (strncmp(uptr, "http://", 7) == 0)
                return uptr;
        }
    }
    return NULL;
}

/*
 * Look through a CRLDP structure and attempt to find an http URL to
 * downloads a CRL from.
 */

static X509_CRL *load_crl_crldp(STACK_OF(DIST_POINT) *crldp)
{
    int i;
    const char *urlptr = NULL;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = get_dp_url(dp);
        if (urlptr)
            return load_crl(urlptr, FORMAT_HTTP);
    }
    return NULL;
}

/*
 * Example of downloading CRLs from CRLDP: not usable for real world as it
 * always downloads, doesn't support non-blocking I/O and doesn't cache
 * anything.
 */

static STACK_OF(X509_CRL) *crls_http_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;

    crls = sk_X509_CRL_new_null();
    if (!crls)
        return NULL;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl) {
        sk_X509_CRL_free(crls);
        return NULL;
    }
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

void store_setup_crl_download(X509_STORE *st)
{
    X509_STORE_set_lookup_crls_cb(st, crls_http_cb);
}

/*
 * Platform-specific sections
 */
#if defined(_WIN32)
# ifdef fileno
#  undef fileno
#  define fileno(a) (int)_fileno(a)
# endif

# include <windows.h>
# include <tchar.h>

static int WIN32_rename(const char *from, const char *to)
{
    TCHAR *tfrom = NULL, *tto;
    DWORD err;
    int ret = 0;

    if (sizeof(TCHAR) == 1) {
        tfrom = (TCHAR *)from;
        tto = (TCHAR *)to;
    } else {                    /* UNICODE path */

        size_t i, flen = strlen(from) + 1, tlen = strlen(to) + 1;
        tfrom = malloc(sizeof(*tfrom) * (flen + tlen));
        if (tfrom == NULL)
            goto err;
        tto = tfrom + flen;
# if !defined(_WIN32_WCE) || _WIN32_WCE>=101
        if (!MultiByteToWideChar(CP_ACP, 0, from, flen, (WCHAR *)tfrom, flen))
# endif
            for (i = 0; i < flen; i++)
                tfrom[i] = (TCHAR)from[i];
# if !defined(_WIN32_WCE) || _WIN32_WCE>=101
        if (!MultiByteToWideChar(CP_ACP, 0, to, tlen, (WCHAR *)tto, tlen))
# endif
            for (i = 0; i < tlen; i++)
                tto[i] = (TCHAR)to[i];
    }

    if (MoveFile(tfrom, tto))
        goto ok;
    err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS) {
        if (DeleteFile(tto) && MoveFile(tfrom, tto))
            goto ok;
        err = GetLastError();
    }
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
        errno = ENOENT;
    else if (err == ERROR_ACCESS_DENIED)
        errno = EACCES;
    else
        errno = EINVAL;         /* we could map more codes... */
 err:
    ret = -1;
 ok:
    if (tfrom != NULL && tfrom != (TCHAR *)from)
        free(tfrom);
    return ret;
}
#endif

/* app_tminterval section */
#if defined(_WIN32)
double app_tminterval(int stop, int usertime)
{
    FILETIME now;
    double ret = 0;
    static ULARGE_INTEGER tmstart;
    static int warning = 1;
# ifdef _WIN32_WINNT
    static HANDLE proc = NULL;

    if (proc == NULL) {
        if (check_winnt())
            proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,
                               GetCurrentProcessId());
        if (proc == NULL)
            proc = (HANDLE) - 1;
    }

    if (usertime && proc != (HANDLE) - 1) {
        FILETIME junk;
        GetProcessTimes(proc, &junk, &junk, &junk, &now);
    } else
# endif
    {
        SYSTEMTIME systime;

        if (usertime && warning) {
            BIO_printf(bio_err, "To get meaningful results, run this program on idle system.\n");
            warning = 0;
        }
        GetSystemTime(&systime);
        SystemTimeToFileTime(&systime, &now);
    }

    if (stop == TM_START) {
        tmstart.u.LowPart = now.dwLowDateTime;
        tmstart.u.HighPart = now.dwHighDateTime;
    } else {
        ULARGE_INTEGER tmstop;

        tmstop.u.LowPart = now.dwLowDateTime;
        tmstop.u.HighPart = now.dwHighDateTime;

        ret = (__int64)(tmstop.QuadPart - tmstart.QuadPart) * 1e-7;
    }

    return ret;
}
#elif defined(OPENSSL_SYSTEM_VXWORKS)
# include <time.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
# ifdef CLOCK_REALTIME
    static struct timespec tmstart;
    struct timespec now;
# else
    static unsigned long tmstart;
    unsigned long now;
# endif
    static int warning = 1;

    if (usertime && warning) {
        BIO_printf(bio_err, "To get meaningful results, run this program on idle system.\n");
        warning = 0;
    }
# ifdef CLOCK_REALTIME
    clock_gettime(CLOCK_REALTIME, &now);
    if (stop == TM_START)
        tmstart = now;
    else
        ret = ((now.tv_sec + now.tv_nsec * 1e-9)
               - (tmstart.tv_sec + tmstart.tv_nsec * 1e-9));
# else
    now = tickGet();
    if (stop == TM_START)
        tmstart = now;
    else
        ret = (now - tmstart) / (double)sysClkRateGet();
# endif
    return ret;
}

#elif defined(OPENSSL_SYSTEM_VMS)
# include <time.h>
# include <times.h>

double app_tminterval(int stop, int usertime)
{
    static clock_t tmstart;
    double ret = 0;
    clock_t now;
# ifdef __TMS
    struct tms rus;

    now = times(&rus);
    if (usertime)
        now = rus.tms_utime;
# else
    if (usertime)
        now = clock();          /* sum of user and kernel times */
    else {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        now = (clock_t)((unsigned long long)tv.tv_sec * CLK_TCK +
                        (unsigned long long)tv.tv_usec * (1000000 / CLK_TCK)
            );
    }
# endif
    if (stop == TM_START)
        tmstart = now;
    else
        ret = (now - tmstart) / (double)(CLK_TCK);

    return ret;
}

#elif defined(_SC_CLK_TCK)      /* by means of unistd.h */
# include <sys/times.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct tms rus;
    clock_t now = times(&rus);
    static clock_t tmstart;

    if (usertime)
        now = rus.tms_utime;

    if (stop == TM_START) {
        tmstart = now;
    } else {
        long int tck = sysconf(_SC_CLK_TCK);
        ret = (now - tmstart) / (double)tck;
    }

    return ret;
}

#else
# include <sys/time.h>
# include <sys/resource.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct rusage rus;
    struct timeval now;
    static struct timeval tmstart;

    if (usertime)
        getrusage(RUSAGE_SELF, &rus), now = rus.ru_utime;
    else
        gettimeofday(&now, NULL);

    if (stop == TM_START)
        tmstart = now;
    else
        ret = ((now.tv_sec + now.tv_usec * 1e-6)
               - (tmstart.tv_sec + tmstart.tv_usec * 1e-6));

    return ret;
}
#endif

int app_access(const char* name, int flag)
{
#ifdef _WIN32
    return _access(name, flag);
#else
    return access(name, flag);
#endif
}

/* app_isdir section */
#ifdef _WIN32
int app_isdir(const char *name)
{
    DWORD attr;
# if defined(UNICODE) || defined(_UNICODE)
    size_t i, len_0 = strlen(name) + 1;
    WCHAR tempname[MAX_PATH];

    if (len_0 > MAX_PATH)
        return -1;

#  if !defined(_WIN32_WCE) || _WIN32_WCE>=101
    if (!MultiByteToWideChar(CP_ACP, 0, name, len_0, tempname, MAX_PATH))
#  endif
        for (i = 0; i < len_0; i++)
            tempname[i] = (WCHAR)name[i];

    attr = GetFileAttributes(tempname);
# else
    attr = GetFileAttributes(name);
# endif
    if (attr == INVALID_FILE_ATTRIBUTES)
        return -1;
    return ((attr & FILE_ATTRIBUTE_DIRECTORY) != 0);
}
#else
# include <sys/stat.h>
# ifndef S_ISDIR
#  if defined(_S_IFMT) && defined(_S_IFDIR)
#   define S_ISDIR(a)   (((a) & _S_IFMT) == _S_IFDIR)
#  else
#   define S_ISDIR(a)   (((a) & S_IFMT) == S_IFDIR)
#  endif
# endif

int app_isdir(const char *name)
{
# if defined(S_ISDIR)
    struct stat st;

    if (stat(name, &st) == 0)
        return S_ISDIR(st.st_mode);
    else
        return -1;
# else
    return -1;
# endif
}
#endif

/* raw_read|write section */
int fileno_stdin(void) {
    return fileno(stdin);
}

int fileno_stdout(void) {
    return fileno(stdout);
}

#if defined(_WIN32) && defined(STD_INPUT_HANDLE)
    int raw_read_stdin(void *buf, int siz) {
        DWORD n;
        if (ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, siz, &n, NULL))
            return n;
        else
            return -1;
    }
#else
    int raw_read_stdin(void *buf, int siz) {
        return read(fileno_stdin(), buf, siz);
    }
#endif

#if defined(_WIN32) && defined(STD_OUTPUT_HANDLE)
int raw_write_stdout(const void *buf, int siz)
{
    DWORD n;
    if (WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, siz, &n, NULL))
        return n;
    else
        return -1;
}
#else
int raw_write_stdout(const void *buf, int siz)
{
    return write(fileno_stdout(), buf, siz);
}
#endif

int set_nameopt(const char *arg) {
    int ret = set_name_ex(&nmflag, arg);
    if (ret) nmflag_set = 1;
    return ret;
}

int set_nameopt_v(unsigned long value) {
#if 0    
    nmflag =  value;
#else
    nmflag =  XN_FLAG_RFC2253_GZ;
#endif
    nmflag_set = 1;
    return 1;
}

unsigned long get_nameopt(void) {
    return (nmflag_set) ? nmflag : XN_FLAG_ONELINE;
}

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);
static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);



int set_name_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL ex_tbl[] = {
        {"esc_2253", ASN1_STRFLGS_ESC_2253, 0},
        {"esc_2254", ASN1_STRFLGS_ESC_2254, 0},
        {"esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0},
        {"esc_msb", ASN1_STRFLGS_ESC_MSB, 0},
        {"use_quote", ASN1_STRFLGS_ESC_QUOTE, 0},
        {"utf8", ASN1_STRFLGS_UTF8_CONVERT, 0},
        {"ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0},
        {"show_type", ASN1_STRFLGS_SHOW_TYPE, 0},
        {"dump_all", ASN1_STRFLGS_DUMP_ALL, 0},
        {"dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
        {"dump_der", ASN1_STRFLGS_DUMP_DER, 0},
        {"compat", XN_FLAG_COMPAT, 0xffffffffL},
        {"sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
        {"sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
        {"sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
        {"sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
        {"dn_rev", XN_FLAG_DN_REV, 0},
        {"nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
        {"sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
        {"lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
        {"align", XN_FLAG_FN_ALIGN, 0},
        {"oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
        {"space_eq", XN_FLAG_SPC_EQ, 0},
        {"dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
        {"RFC2253", XN_FLAG_RFC2253, 0xffffffffL},
        {"oneline", XN_FLAG_ONELINE, 0xffffffffL},
        {"multiline", XN_FLAG_MULTILINE, 0xffffffffL},
        {"ca_default", XN_FLAG_MULTILINE, 0xffffffffL},
        {NULL, 0, 0}
    };
    if (set_multi_opts(flags, arg, ex_tbl) == 0)
        return 0;
    if (*flags != XN_FLAG_COMPAT
        && (*flags & XN_FLAG_SEP_MASK) == 0)
        *flags |= XN_FLAG_SEP_CPLUS_SPC;
    return 1;
}


static int set_multi_opts(unsigned long *flags, const char *arg, const NAME_EX_TBL * in_tbl) {
    STACK_OF(CONF_VALUE) *vals;
    CONF_VALUE *val;
    int i, ret = 1;
    if (!arg)
        return 0;
    vals = X509V3_parse_list(arg);
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        val = sk_CONF_VALUE_value(vals, i);
        if (!set_table_opts(flags, val->name, in_tbl))
            ret = 0;
    }
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return ret;
}

static int set_table_opts(unsigned long *flags, const char *arg, const NAME_EX_TBL * in_tbl) {
    char c;
    const NAME_EX_TBL *ptbl;
    c = arg[0];

    if (c == '-') {
        c = 0;
        arg++;
    } else if (c == '+') {
        c = 1;
        arg++;
    } else {
        c = 1;
    }

    for (ptbl = in_tbl; ptbl->name; ptbl++) {
        if (strcasecmp(arg, ptbl->name) == 0) {
            *flags &= ~ptbl->mask;
            if (c)
                *flags |= ptbl->flag;
            else
                *flags &= ~ptbl->flag;
            return 1;
        }
    }
    return 0;
}


CONF *gzpki_load_config(const char *inbuffer) {
    BIO *in;
    CONF *conf;

    in = BIO_new_mem_buf(inbuffer, -1);

    if (in == NULL)
        return NULL;

    conf = app_load_config_bio(in, NULL);
    BIO_free(in);
    return conf;
}

CONF *app_load_config(const char *filename) {
    BIO *in;
    CONF *conf;

    in = bio_open_default(filename, 'r', FORMAT_TEXT);
    if (in == NULL)
        return NULL;

    conf = app_load_config_bio(in, filename);
    BIO_free(in);
    return conf;
}

CONF *app_load_config_bio(BIO *in, const char *filename){
    long errorline = -1;
    CONF *conf;
    int i;

    conf = NCONF_new(NULL);
    i = NCONF_load_bio(conf, in, &errorline);
    if (i > 0)
        return conf;

    if (errorline <= 0) {
        BIO_printf(bio_err, "error: Can't load ");
    } else {
        BIO_printf(bio_err, "error: Error on line %ld of ", errorline);
    }
    if (filename != NULL)
        BIO_printf(bio_err, "config file \"%s\"\n", filename);
    else
        BIO_printf(bio_err, "config input");

    NCONF_free(conf);
    return NULL;
}

CONF *app_load_config_quiet(const char *filename) {
    BIO *in;
    CONF *conf;

    in = bio_open_default_quiet(filename, 'r', FORMAT_TEXT);
    if (in == NULL)
        return NULL;

    conf = app_load_config_bio(in, filename);
    BIO_free(in);
    return conf;
}

int add_oid_section(CONF *conf)
{
    char *p;
    STACK_OF(CONF_VALUE) *sktmp;
    CONF_VALUE *cnf;
    int i;

    if ((p = NCONF_get_string(conf, NULL, "oid_section")) == NULL) {
        ERR_clear_error();
        return 1;
    }
    if ((sktmp = NCONF_get_section(conf, p)) == NULL) {
        BIO_printf(bio_err, "problem loading oid section %s\n", p);
        return 0;
    }
    for (i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
        cnf = sk_CONF_VALUE_value(sktmp, i);
        if (OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
            BIO_printf(bio_err, "problem creating object %s=%s\n",
                       cnf->name, cnf->value);
            return 0;
        }
    }
    return 1;
}

void app_RAND_load_conf(CONF *c, const char *section) {
    const char *randfile = NCONF_get_string(c, section, "RANDFILE");

    if (randfile == NULL) {
        ERR_clear_error();
        return;
    }
    if (RAND_load_file(randfile, -1) < 0) {
        BIO_printf(bio_err, "Can't load %s into RNG\n", randfile);
        ERR_print_errors(bio_err);
    }
    if (save_rand_file == NULL)
        save_rand_file = OPENSSL_strdup(randfile);
}

int app_load_modules(const CONF *config) {
    CONF *to_free = NULL;

    if (config == NULL)
        config = to_free = app_load_config_quiet(default_config_file);
    if (config == NULL)
        return 1;

    if (CONF_modules_load(config, NULL, 0) <= 0) {
        BIO_printf(bio_err, "Error configuring OpenSSL modules\n");
        ERR_print_errors(bio_err);
        NCONF_free(to_free);
        return 0;
    }
    NCONF_free(to_free);
    return 1;
}


int GZPKI_set_operation(GZPKI_CTX *ctx, int operation) {
    ctx->operation = operation;
    return CMS_RET_OK;
}

/// @brief set certificate for CMS encryption
/// @return CMS_RET_OK/CMS_RET_ERROR
int GZPKI_set_encerts(GZPKI_CTX *ctx, char *certfile ) 
{
    X509 *cert = NULL; //TODO: remove ctx->cert ?
    memset(ctx->errstr, 0, sizeof(ctx->errstr));
    
    if (ctx->encerts == NULL && (ctx->encerts = sk_X509_new_null()) == NULL) {
        sprintf(ctx->errstr, "fail to create encerts structure");
        return CMS_RET_ERROR; 
    }
    cert = load_cert(certfile, FORMAT_PEM, "recipient certificate file");
    if (cert == NULL) {
        sprintf(ctx->errstr, "fail to load certificate: %s", certfile);
        return CMS_RET_ERROR; 
    }
    sk_X509_push(ctx->encerts, cert);

    cert = NULL;
    return CMS_RET_OK;
}


int GZPKI_set_keyfile(GZPKI_CTX *ctx, char *keyfile, char *passin, int load_flag) {
    ctx->keyfile = GZPKI_strdup(keyfile);
    
    if(passin)
        ctx->passin = GZPKI_strdup(passin);
    else 
        ctx->passin =  NULL;

    if(load_flag == 1 && ctx->keyfile != NULL)
    {
        ctx->key = load_key(ctx->keyfile, ctx->keyform, 0, passin, NULL, keyfile);
        if (ctx->key == NULL)
        {
            snprintf(ctx->errstr, sizeof(ctx->errstr),  "unable to load %s", ctx->keyfile);
            return CMS_RET_ERROR;
        }
    }
    return CMS_RET_OK;
}

int GZPKI_set_key_buffer(GZPKI_CTX *ctx, char *buffer, char *passin, int load_flag) {
    
    int len = strlen(buffer);
    
    if(passin)
        ctx->passin = GZPKI_strdup(passin);
    else 
        ctx->passin =  NULL;

    if(load_flag == 1)
    {

        ctx->key = load_key_buffer(buffer, len, FORMAT_PEM,  passin);
        //ctx->key = load_key(ctx->keyfile, ctx->keyform, 0, passin, NULL, keyfile);
        if (ctx->key == NULL)
        {
            snprintf(ctx->errstr, sizeof(ctx->errstr),  "unable to load: len=%d", len);
            return CMS_RET_ERROR;
        }
    }
    return CMS_RET_OK;
}

int GZPKI_get_flags_str(GZPKI_CTX *ctx)
{
    int flags = ctx->flags;
    printf("GZPKI_get_flags_str:flags=[" color_red_b "0x%02x" color_reset "]\n", flags);

    printf(color_red);
    if(flags & CMS_TEXT)        printf("CMS_TEXT\n");
    if(flags & CMS_NOCERTS)     printf("CMS_NOCERTS\n");
    if(flags & CMS_NOSIGS)      printf("CMS_NOSIGS\n");
    if(flags & CMS_NOINTERN)    printf("CMS_NOINTERN\n");
    if(flags & CMS_NOVERIFY)    printf("CMS_NOVERIFY\n");
    if(flags & CMS_DETACHED)    printf("CMS_DETACHED\n");
    if(flags & CMS_BINARY)      printf("CMS_BINARY\n");
    if(flags & CMS_NOATTR)      printf("CMS_NOATTR\n");
    if(flags & CMS_NOSMIMECAP)  printf("CMS_NOSMIMECAP\n");
    if(flags & CMS_CRLFEOL)     printf("CMS_CRLFEOL\n");
    if(flags & CMS_STREAM)      printf("CMS_STREAM\n");
    if(flags & CMS_NOCRL)       printf("CMS_NOCRL\n");
    if(flags & CMS_PARTIAL)     printf("CMS_PARTIAL\n");
    if(flags & CMS_USE_KEYID)   printf("CMS_USE_KEYID\n");
    if(flags & CMS_KEY_PARAM)   printf("CMS_KEY_PARAM\n");
    if(flags & CMS_ASCIICRLF)   printf("CMS_ASCIICRLF\n");
    if(flags & CMS_NO_SIGNER_CERT_VERIFY)   printf("CMS_NO_SIGNER_CERT_VERIFY\n");
    if(flags & CMS_NOOLDMIMETYPE)           printf("CMS_NOOLDMIMETYPE\n");
    if(flags & CMS_REUSE_DIGEST)            printf("CMS_REUSE_DIGEST\n");
    if(flags & CMS_DEBUG_DECRYPT)           printf("CMS_DEBUG_DECRYPT\n");
    if(flags & CMS_NO_CONTENT_VERIFY)       printf("CMS_NO_CONTENT_VERIFY\n");
    if(flags & CMS_NO_ATTR_VERIFY)          printf("CMS_NO_ATTR_VERIFY\n");
    printf(color_reset);

    return 0;    
}

char *GZPKI_get_sign_md_name(GZPKI_CTX *ctx) {
    return get_md_alg_string_by_type(ctx->sign_md->type);
}


char *get_md_alg_string_by_type(int type) {
    char *hashalgs = NULL;
    switch(type) {
        case NID_sha256:     hashalgs = GZPKI_strdup(LN_sha256);     break;
        case NID_sha384:     hashalgs = GZPKI_strdup(LN_sha384);     break;
        case NID_sha512:     hashalgs = GZPKI_strdup(LN_sha512);     break;
        case NID_sha224:     hashalgs = GZPKI_strdup(LN_sha224);     break;
        
        case NID_sha512_224: hashalgs = GZPKI_strdup(LN_sha512_224); break;
        case NID_sha512_256: hashalgs = GZPKI_strdup(LN_sha512_256); break;
        
        case NID_sha3_224:   hashalgs = GZPKI_strdup(LN_sha3_224);   break;
        case NID_sha3_256:   hashalgs = GZPKI_strdup(LN_sha3_256);   break;
        case NID_sha3_384:   hashalgs = GZPKI_strdup(LN_sha3_384);   break;
        case NID_sha3_512:   hashalgs = GZPKI_strdup(LN_sha3_512);   break;

        case NID_shake128:   hashalgs = GZPKI_strdup(LN_shake128);   break;
        case NID_shake256:   hashalgs = GZPKI_strdup(LN_shake256);   break;

        case NID_hmac_sha3_224: hashalgs = GZPKI_strdup(LN_hmac_sha3_224);  break;
        case NID_hmac_sha3_256: hashalgs = GZPKI_strdup(LN_hmac_sha3_256);  break;
        case NID_hmac_sha3_384: hashalgs = GZPKI_strdup(LN_hmac_sha3_384);  break;
        case NID_hmac_sha3_512: hashalgs = GZPKI_strdup(LN_hmac_sha3_512);  break;

        case NID_dsa_with_SHA224: hashalgs = GZPKI_strdup(SN_dsa_with_SHA224);  break;
        case NID_dsa_with_SHA256: hashalgs = GZPKI_strdup(SN_dsa_with_SHA256);  break;
        default: 
            hashalgs = GZPKI_strdup("unkonwn algorithm");  break;
    }
    return hashalgs;
}



/// @brief  set cipher algorithm for CMS envelopment data
/// @return CMS_RET_OK/CMS_RET_ERROR
int GZPKI_set_cipher(GZPKI_CTX *ctx, char *cipher_name) {
    if(cipher_name == NULL) {
        sprintf(ctx->errstr, "Null ciphers");
        return CMS_RET_ERROR;
    }
    
    ctx->cipher = EVP_get_cipherbyname((const char *)cipher_name);
    if (ctx->cipher == NULL) {
        sprintf(ctx->errstr, "Invalid cipher name %s", cipher_name);
        return CMS_RET_ERROR;
    }
    else
        sprintf(ctx->errstr, "set cipher %s", cipher_name);

    ctx->cipher_name = GZPKI_strdup(cipher_name);
    return CMS_RET_OK;
}


/// @brief  set cipher algorithm for CMS envelopment data
/// @return CMS_RET_OK/CMS_RET_ERROR
int GZPKI_set_signer(GZPKI_CTX *ctx, char *pSignerFile, char *pKeyFile, char *passin) {
    int r = CMS_RET_ERROR; 
    char *keyfile = NULL;
    
    if (pSignerFile != NULL) {
        if (ctx->sksigners == NULL && (ctx->sksigners = sk_OPENSSL_STRING_new_null()) == NULL) {
            r = CMS_RET_ERROR;
            goto end;
        }
        
        sk_OPENSSL_STRING_push(ctx->sksigners, pSignerFile);
        
        if (pKeyFile == NULL){
            keyfile = GZPKI_strdup(pSignerFile);
        }
        else {
            keyfile = GZPKI_strdup(pKeyFile);
        }

        if (ctx->skkeys == NULL && (ctx->skkeys = sk_OPENSSL_STRING_new_null()) == NULL) {
            sprintf(ctx->errstr, "fail to create private key stack");
            r = CMS_RET_ERROR;
            goto end;
        }
        
        sk_OPENSSL_STRING_push(ctx->skkeys, keyfile);
        keyfile = NULL;

        if (ctx->skpassins == NULL && (ctx->skpassins = sk_OPENSSL_STRING_new_null()) == NULL) {
            sprintf(ctx->errstr, "fail to create password stack");
            r = CMS_RET_ERROR;
            goto end;
        }

        if(passin != NULL) {
            sk_OPENSSL_STRING_push(ctx->skpassins, passin);
        }

    }
    else {
        sprintf(ctx->errstr, "null signer file");
        r = CMS_RET_ERROR;
        return r;
    }

    sprintf(ctx->errstr, "GZPKI_set_signer(%s,%s)\n", pSignerFile, pKeyFile);
    return CMS_RET_OK;
end:
    return r;
}

void print_operation_str(int operation) {
    switch(operation)
    {
        case SMIME_SIGN: printf("SMIME_SIGN"); break;
        case SMIME_VERIFY: printf("SMIME_VERIFY"); break;
        case SMIME_ENCRYPT: printf("SMIME_ENCRYPT"); break;
        case SMIME_DECRYPT: printf("SMIME_DECRYPT"); break;
        case ECCP2_ENCRYPT: printf("ECCP2_ENCRYPT"); break;
        case ECCP2_DECRYPT: printf("ECCP2_DECRYPT"); break;
        case ECCP2_GENERATE_SECRET: printf("ECCP2_GENERATE_SECRET"); break;
        default: printf("UNKNOWN"); break;
    }   
    return;    
}

#if 0 //DEL
char *get_operation_str(int operation) {
    char *op_str=NULL;
    
    switch(operation)
    {
        case SMIME_SIGN: op_str = GZPKI_strdup("SMIME_SIGN"); break;
        case SMIME_VERIFY: op_str = GZPKI_strdup("SMIME_VERIFY"); break;
        case SMIME_RESIGN: op_str = GZPKI_strdup("SMIME_RESIGN"); break;

        case SMIME_ENCRYPT: op_str = GZPKI_strdup("SMIME_ENCRYPT"); break;
        case SMIME_DECRYPT: op_str = GZPKI_strdup("SMIME_DECRYPT"); break;
        
        case SMIME_SIGN_RECEIPT: op_str = GZPKI_strdup("SMIME_SIGN_RECEIPT"); break;
        case SMIME_VERIFY_RECEIPT: op_str = GZPKI_strdup("SMIME_VERIFY_RECEIPT"); break;

        case SMIME_CMSOUT: op_str = GZPKI_strdup("SMIME_CMSOUT"); break;

        case SMIME_DATAOUT: op_str = GZPKI_strdup("SMIME_DATAOUT"); break;
        case SMIME_DATA_CREATE: op_str = GZPKI_strdup("SMIME_DATA_CREATE"); break;

        case SMIME_DIGEST_VERIFY: op_str = GZPKI_strdup("SMIME_DIGEST_VERIFY"); break;
        case SMIME_DIGEST_CREATE: op_str = GZPKI_strdup("SMIME_DIGEST_CREATE"); break;

        case SMIME_UNCOMPRESS: op_str = GZPKI_strdup("SMIME_UNCOMPRESS"); break;
        case SMIME_COMPRESS: op_str = GZPKI_strdup("SMIME_COMPRESS"); break;

        case SMIME_ENCRYPTED_DECRYPT: op_str = GZPKI_strdup("SMIME_ENCRYPTED_DECRYPT"); break;
        case SMIME_ENCRYPTED_ENCRYPT: op_str = GZPKI_strdup("SMIME_ENCRYPTED_ENCRYPT"); break;
        
        default: op_str = GZPKI_strdup("UNKNOWN"); break;
        
    }
    return op_str;
}

char *GZPKI_get_operation_str(GZPKI_CTX *ctx) {
    return get_operation_str(ctx->operation);
}
#endif 

int str_append(char **json, const char *format, ...)
{
    char *str = NULL;
    char *old_json = NULL, *new_json = NULL;

    va_list arg_ptr;
    va_start(arg_ptr, format);
    vasprintf(&str, format, arg_ptr);

    // save old json
    asprintf(&old_json, "%s", (*json == NULL ? "" : *json));

    // calloc new json memory
    new_json = (char *)calloc(strlen(old_json) + strlen(str) + 1, sizeof(char));

    strcat(new_json, old_json);
    strcat(new_json, str);

    if (*json) free(*json);
    *json = new_json;

    free(old_json);
    free(str);

    return 0;
}



char *GZPKI_get_format_str(int f)
{
    char *fmstr = NULL;
    fmstr = (char *)malloc(32);
    if(f == FORMAT_UNDEF)       sprintf(fmstr, "%s", "FORMAT_UNDEF");
    else if(f == FORMAT_TEXT)   sprintf(fmstr, "%s", "FORMAT_TEXT");        
    else if(f == FORMAT_BINARY) sprintf(fmstr, "%s", "FORMAT_BINARY");        
    else if(f == FORMAT_BASE64) sprintf(fmstr, "%s", "FORMAT_BASE64");        
    else if(f == FORMAT_ASN1)   sprintf(fmstr, "%s", "FORMAT_ASN1");        
    else if(f == FORMAT_PEM)    sprintf(fmstr, "%s", "FORMAT_PEM");        
    else if(f == FORMAT_PKCS12) sprintf(fmstr, "%s", "FORMAT_PKCS12");        
    else if(f == FORMAT_SMIME)  sprintf(fmstr, "%s", "FORMAT_SMIME");                        
    else if(f == FORMAT_ENGINE) sprintf(fmstr, "%s", "FORMAT_ENGINE");        
    else if(f == FORMAT_PEMRSA) sprintf(fmstr, "%s", "FORMAT_PEMRSA");        
    else if(f == FORMAT_ASN1RSA) 
                                sprintf(fmstr, "%s", "FORMAT_ASN1RSA");        
    else if(f == FORMAT_MSBLOB) sprintf(fmstr, "%s", "FORMAT_MSBLOB");        
    else if(f == FORMAT_PVK)    sprintf(fmstr, "%s", "FORMAT_PVK");        
    else if(f == FORMAT_HTTP)   sprintf(fmstr, "%s", "FORMAT_HTTP");        
    else if(f == FORMAT_NSS)    sprintf(fmstr, "%s", "FORMAT_NSS");                                
    else                        sprintf(fmstr, "%s", "ERROR_FAIL_TO_GET_FORMAT");
    return fmstr;
}

int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}


int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;

    btmp = b == NULL ? BN_new() : b;
    if (btmp == NULL)
        return 0;

    if (!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

 error:

    if (btmp != b)
        BN_free(btmp);

    return ret;
}

void corrupt_signature(const ASN1_STRING *signature) {
        unsigned char *s = signature->data;
        s[signature->length - 1] ^= 0x1;
}

void print_array(BIO *out, const char* title, int len, const unsigned char* d) {
    int i;

    BIO_printf(out, "unsigned char %s[%d] = {", title, len);
    for (i = 0; i < len; i++) {
        if ((i % 10) == 0)
            BIO_printf(out, "\n    ");
        if (i < len - 1)
            BIO_printf(out, "0x%02X, ", d[i]);
        else
            BIO_printf(out, "0x%02X", d[i]);
    }
    BIO_printf(out, "\n};\n");
}


/*static*/ int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    EVP_PKEY_CTX *pkctx = NULL;
    int i, def_nid;

    if (ctx == NULL)
        return 0;

    /* EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2 && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }

    if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
        return 0;
    
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", sigopt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }
    return 1;
}



int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_REQ_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}

//static IMPLEMENT_LHASH_HASH_FN(index_serial, OPENSSL_CSTRING)
//static IMPLEMENT_LHASH_COMP_FN(index_serial, OPENSSL_CSTRING)
//static IMPLEMENT_LHASH_HASH_FN(index_name, OPENSSL_CSTRING)
//static IMPLEMENT_LHASH_COMP_FN(index_name, OPENSSL_CSTRING)
#undef BSIZE
#define BSIZE 256
BIGNUM *load_serial(const char *serialfile, int create, ASN1_INTEGER **retai)
{
    BIO *in = NULL;
    BIGNUM *ret = NULL;
    char buf[1024];
    ASN1_INTEGER *ai = NULL;

    ai = ASN1_INTEGER_new();
    if (ai == NULL)
        goto err;

    in = BIO_new_file(serialfile, "r");
    if (in == NULL) {
        if (!create) {
            perror(serialfile);
            goto err;
        }
        ERR_clear_error();
        ret = BN_new();
        if (ret == NULL || !rand_serial(ret, ai))
            BIO_printf(bio_err, "Out of memory\n");
    } else {
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            BIO_printf(bio_err, "unable to load number from %s\n",
                       serialfile);
            goto err;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            BIO_printf(bio_err,
                       "error converting number from bin to BIGNUM\n");
            goto err;
        }
    }

    if (ret && retai) {
        *retai = ai;
        ai = NULL;
    }
 err:
    BIO_free(in);
    ASN1_INTEGER_free(ai);
    return ret;
}




int save_serial(const char *serialfile, const char *suffix, const BIGNUM *serial,
                ASN1_INTEGER **retai)
{
    char buf[1][BSIZE];
    BIO *out = NULL;
    int ret = 0;
    ASN1_INTEGER *ai = NULL;
    int j;

    if (suffix == NULL)
        j = strlen(serialfile);
    else
        j = strlen(serialfile) + strlen(suffix) + 1;
    if (j >= BSIZE) {
        BIO_printf(bio_err, "file name too long\n");
        goto err;
    }

    if (suffix == NULL)
        OPENSSL_strlcpy(buf[0], serialfile, BSIZE);
    else {
#ifndef OPENSSL_SYS_VMS
        j = BIO_snprintf(buf[0], sizeof(buf[0]), "%s.%s", serialfile, suffix);
#else
        j = BIO_snprintf(buf[0], sizeof(buf[0]), "%s-%s", serialfile, suffix);
#endif
    }
    out = BIO_new_file(buf[0], "w");
    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }

    if ((ai = BN_to_ASN1_INTEGER(serial, NULL)) == NULL) {
        BIO_printf(bio_err, "error converting serial to ASN.1 format\n");
        goto err;
    }
    i2a_ASN1_INTEGER(out, ai);
    BIO_puts(out, "\n");
    ret = 1;
    if (retai) {
        *retai = ai;
        ai = NULL;
    }
 err:
    BIO_free_all(out);
    ASN1_INTEGER_free(ai);
    return ret;
}

int unpack_revinfo(ASN1_TIME **prevtm, int *preason, ASN1_OBJECT **phold, ASN1_GENERALIZEDTIME **pinvtm, const char *str) {
    char *tmp;
    char *rtime_str, *reason_str = NULL, *arg_str = NULL, *p;
    int reason_code = -1;
    int ret = 0;
    unsigned int i;
    ASN1_OBJECT *hold = NULL;
    ASN1_GENERALIZEDTIME *comp_time = NULL;

    tmp = OPENSSL_strdup(str);
    if (!tmp) {
        BIO_printf(bio_err, "memory allocation failure\n");
        goto end;
    }

    p = strchr(tmp, ',');

    rtime_str = tmp;

    if (p) {
        *p = '\0';
        p++;
        reason_str = p;
        p = strchr(p, ',');
        if (p) {
            *p = '\0';
            arg_str = p + 1;
        }
    }

    if (prevtm) {
        *prevtm = ASN1_UTCTIME_new();
        if (*prevtm == NULL) {
            BIO_printf(bio_err, "memory allocation failure\n");
            goto end;
        }
        if (!ASN1_UTCTIME_set_string(*prevtm, rtime_str)) {
            BIO_printf(bio_err, "invalid revocation date %s\n", rtime_str);
            goto end;
        }
    }
    if (reason_str) {
        for (i = 0; i < NUM_REASONS; i++) {
            if (strcasecmp(reason_str, crl_reasons[i]) == 0) {
                reason_code = i;
                break;
            }
        }
        if (reason_code == OCSP_REVOKED_STATUS_NOSTATUS) {
            BIO_printf(bio_err, "invalid reason code %s\n", reason_str);
            goto end;
        }

        if (reason_code == 7) {
            reason_code = OCSP_REVOKED_STATUS_REMOVEFROMCRL;
        } else if (reason_code == 8) { /* Hold instruction */
            if (!arg_str) {
                BIO_printf(bio_err, "missing hold instruction\n");
                goto end;
            }
            reason_code = OCSP_REVOKED_STATUS_CERTIFICATEHOLD;
            hold = OBJ_txt2obj(arg_str, 0);

            if (!hold) {
                BIO_printf(bio_err, "invalid object identifier %s\n", arg_str);
                goto end;
            }
            if (phold)
                *phold = hold;
            else
                ASN1_OBJECT_free(hold);
        } else if ((reason_code == 9) || (reason_code == 10)) {
            if (!arg_str) {
                BIO_printf(bio_err, "missing compromised time\n");
                goto end;
            }
            comp_time = ASN1_GENERALIZEDTIME_new();
            if (comp_time == NULL) {
                BIO_printf(bio_err, "memory allocation failure\n");
                goto end;
            }
            if (!ASN1_GENERALIZEDTIME_set_string(comp_time, arg_str)) {
                BIO_printf(bio_err, "invalid compromised time %s\n", arg_str);
                goto end;
            }
            if (reason_code == 9)
                reason_code = OCSP_REVOKED_STATUS_KEYCOMPROMISE;
            else
                reason_code = OCSP_REVOKED_STATUS_CACOMPROMISE;
        }
    }

    if (preason)
        *preason = reason_code;
    if (pinvtm) {
        *pinvtm = comp_time;
        comp_time = NULL;
    }

    ret = 1;

 end:

    OPENSSL_free(tmp);
    ASN1_GENERALIZEDTIME_free(comp_time);

    return ret;
}

int set_cert_ex(unsigned long *flags, const char *arg) {
    static const NAME_EX_TBL cert_tbl[] = {
        {"compatible", X509_FLAG_COMPAT, 0xffffffffl},
        {"ca_default", X509_FLAG_CA, 0xffffffffl},
        {"no_header", X509_FLAG_NO_HEADER, 0},
        {"no_version", X509_FLAG_NO_VERSION, 0},
        {"no_serial", X509_FLAG_NO_SERIAL, 0},
        {"no_signame", X509_FLAG_NO_SIGNAME, 0},
        {"no_validity", X509_FLAG_NO_VALIDITY, 0},
        {"no_subject", X509_FLAG_NO_SUBJECT, 0},
        {"no_issuer", X509_FLAG_NO_ISSUER, 0},
        {"no_pubkey", X509_FLAG_NO_PUBKEY, 0},
        {"no_extensions", X509_FLAG_NO_EXTENSIONS, 0},
        {"no_sigdump", X509_FLAG_NO_SIGDUMP, 0},
        {"no_aux", X509_FLAG_NO_AUX, 0},
        {"no_attributes", X509_FLAG_NO_ATTRIBUTES, 0},
        {"ext_default", X509V3_EXT_DEFAULT, X509V3_EXT_UNKNOWN_MASK},
        {"ext_error", X509V3_EXT_ERROR_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {"ext_parse", X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {"ext_dump", X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {NULL, 0, 0}
    };
    return set_multi_opts(flags, arg, cert_tbl);
}

int set_ext_copy(int *copy_type, const char *arg) {
    if (strcasecmp(arg, "none") == 0)
        *copy_type = EXT_COPY_NONE;
    else if (strcasecmp(arg, "copy") == 0)
        *copy_type = EXT_COPY_ADD;
    else if (strcasecmp(arg, "copyall") == 0)
        *copy_type = EXT_COPY_ALL;
    else
        return 0;
    return 1;
}

int GZPKI_set_crl_revoke_type(GZPKI_CTX *ctx, REVINFO_TYPE crl_revoke_type) { 
    ctx->crl_revoke_type = crl_revoke_type;
    return CMS_RET_OK; 
}

REVINFO_TYPE GZPKI_get_crl_revoke_type(GZPKI_CTX *ctx) { 
    return ctx->crl_revoke_type; 
}


int rotate_serial(const char *serialfile, const char *new_suffix, const char *old_suffix)
{
    char buf[2][BSIZE];
    int i, j;

    i = strlen(serialfile) + strlen(old_suffix);
    j = strlen(serialfile) + strlen(new_suffix);
    if (i > j)
        j = i;
    if (j + 1 >= BSIZE) {
        BIO_printf(bio_err, "file name too long\n");
        goto err;
    }
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "%s.%s", serialfile, new_suffix);
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "%s.%s", serialfile, old_suffix);
#else
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "%s-%s", serialfile, new_suffix);
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "%s-%s", serialfile, old_suffix);
#endif
    if (rename(serialfile, buf[1]) < 0 && errno != ENOENT
#ifdef ENOTDIR
        && errno != ENOTDIR
#endif
        ) {
        BIO_printf(bio_err,
                   "unable to rename %s to %s\n", serialfile, buf[1]);
        perror("reason");
        goto err;
    }
    if (rename(buf[0], serialfile) < 0) {
        BIO_printf(bio_err,
                   "unable to rename %s to %s\n", buf[0], serialfile);
        perror("reason");
        rename(buf[1], serialfile);
        goto err;
    }
    return 1;
 err:
    return 0;
}


int do_X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md,
                     STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_CRL_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}


/*
 * name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
X509_NAME *parse_name(const char *cp, long chtype, int canmulti)
{
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/') {
        BIO_printf(bio_err,
                   "name is expected to be in the format "
                   "/type0=value0/type1=value1/type2=... where characters may "
                   "be escaped by \\. This name is not in that format: '%s'\n",
                   --cp);
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL)
        return NULL;
    work = OPENSSL_strdup(cp);
    if (work == NULL)
        goto err;

    while (*cp) {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp && *cp != '=')
            *bp++ = *cp++;
        if (*cp == '\0') {
            BIO_printf(bio_err,
                    "libgzpki: Hit end of string before finding the equals.\n");
            goto err;
        }
        *bp++ = '\0';
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp && *cp != '/'; *bp++ = *cp++) {
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                BIO_printf(bio_err, "lilbgzpki: escape character at end of string\n");
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp)
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            BIO_printf(bio_err, "lilbgzpki: Skipping unknown attribute \"%s\"\n", typestr);
            continue;
        }
        if (*valstr == '\0') {
            BIO_printf(bio_err,
                       "lilbgzpki: No value provided for Subject Attribute %s, skipped\n", typestr);
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0))
            goto err;
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}

//DUPLICATED
#if 0
int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b) {
    return strcmp(a[DB_name], b[DB_name]);
}
#endif

void make_uppercase(char *string)
{
    int i;

    for (i = 0; string[i] != '\0'; i++)
        string[i] = toupper((unsigned char)string[i]);
}



int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509_EXTENSION *ext, *tmpext;
    ASN1_OBJECT *obj;
    int i, idx, ret = 0;
    if (!x || !req || (copy_type == EXT_COPY_NONE))
        return 1;
    exts = X509_REQ_get_extensions(req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        idx = X509_get_ext_by_OBJ(x, obj, -1);
        /* Does extension exist? */
        if (idx != -1) {
            /* If normal copy don't override existing extension */
            if (copy_type == EXT_COPY_ADD)
                continue;
            /* Delete all extensions of same type */
            do {
                tmpext = X509_get_ext(x, idx);
                X509_delete_ext(x, idx);
                X509_EXTENSION_free(tmpext);
                idx = X509_get_ext_by_OBJ(x, obj, -1);
            } while (idx != -1);
        }
        if (!X509_add_ext(x, ext, -1))
            goto end;
    }

    ret = 1;

 end:

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    return ret;
}


IMPLEMENT_GZPKI_SET_FN2(informat)
IMPLEMENT_GZPKI_SET_FN2(outformat)
IMPLEMENT_GZPKI_SET_FN2(keyformat)
IMPLEMENT_GZPKI_SET_FN2(CAformat)
IMPLEMENT_GZPKI_SET_FN2(CAkeyformat)
IMPLEMENT_GZPKI_SET_FN2(intype)
IMPLEMENT_GZPKI_SET_FN2(outtype)
IMPLEMENT_GZPKI_SET_FN2(text)
IMPLEMENT_GZPKI_SET_FN2(genkey)
IMPLEMENT_GZPKI_SET_FN2(print)

IMPLEMENT_GZPKI_SET_FN2(new_form)
IMPLEMENT_GZPKI_SET_FN2(new_asn1_flag)
IMPLEMENT_GZPKI_SET_FN2(noout)
IMPLEMENT_GZPKI_SET_FN2(param_out)
IMPLEMENT_GZPKI_SET_FN2(pubin)
IMPLEMENT_GZPKI_SET_FN2(pubout)
IMPLEMENT_GZPKI_SET_FN2(subject_out)

IMPLEMENT_GZPKI_SET_CHAR_FN2(passin)
IMPLEMENT_GZPKI_SET_CHAR_FN2(passout)
IMPLEMENT_GZPKI_SET_CHAR_FN2(passinarg)
IMPLEMENT_GZPKI_SET_CHAR_FN2(passoutarg)
//CHECK & REMOVE
IMPLEMENT_GZPKI_SET_CHAR_FN2(passargin)
IMPLEMENT_GZPKI_SET_CHAR_FN2(passargout)
IMPLEMENT_GZPKI_SET_CHAR_FN2(keyalg)

IMPLEMENT_GZPKI_SET_CHAR_FN2(name)
IMPLEMENT_GZPKI_SET_CHAR_FN2(keyoutfile)
//IMPLEMENT_GZPKI_SET_CHAR_FN2(inserial) //X509 REQ
IMPLEMENT_GZPKI_SET_CHAR_FN2(subj)
IMPLEMENT_GZPKI_SET_CHAR_FN2(extensions)
IMPLEMENT_GZPKI_SET_CHAR_FN2(req_exts)

IMPLEMENT_GZPKI_SET_CHAR_FN2(default_config_file)

IMPLEMENT_GZPKI_SET_CHAR_FN2(certfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(crlfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(cipher_name)

IMPLEMENT_GZPKI_SET_FN2(newreq)
IMPLEMENT_GZPKI_SET_FN2(keyform)
IMPLEMENT_GZPKI_SET_FN2(batch)
IMPLEMENT_GZPKI_SET_FN2(newhdr)
IMPLEMENT_GZPKI_SET_FN2(verify)
IMPLEMENT_GZPKI_SET_FN2(verbose)
IMPLEMENT_GZPKI_SET_FN2(modulus)
IMPLEMENT_GZPKI_SET_FN2(chtype)
IMPLEMENT_GZPKI_SET_FN2(pubkey)
IMPLEMENT_GZPKI_SET_FN2(x509)
IMPLEMENT_GZPKI_SET_FN2(days)
//IMPLEMENT_GZPKI_SET_FN2(subject)
IMPLEMENT_GZPKI_SET_FN2(multirdn)
IMPLEMENT_GZPKI_SET_FN2(precert)

/*GET*/
IMPLEMENT_GZPKI_GET_CHAR_FN(outfile)
/*GET INT*/
//IMPLEMENT_GZPKI_GET_FN(intype)
//IMPLEMENT_GZPKI_GET_FN(outtype)


IMPLEMENT_GZPKI_SET_CHAR_FN2(default_md)
IMPLEMENT_GZPKI_SET_CHAR_FN2(authorityKeyIdentifier)

IMPLEMENT_GZPKI_SET_CHAR_FN2(default_bits)
IMPLEMENT_GZPKI_SET_CHAR_FN2(default_keyfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(string_mask)
IMPLEMENT_GZPKI_SET_CHAR_FN2(countryName)
IMPLEMENT_GZPKI_SET_CHAR_FN2(stateOrProvinceName)
IMPLEMENT_GZPKI_SET_CHAR_FN2(localityName)
IMPLEMENT_GZPKI_SET_CHAR_FN2(organizationName)
IMPLEMENT_GZPKI_SET_CHAR_FN2(organizationUnitName)
IMPLEMENT_GZPKI_SET_CHAR_FN2(commonName)
IMPLEMENT_GZPKI_SET_CHAR_FN2(emailAddress)
IMPLEMENT_GZPKI_SET_CHAR_FN2(countryName_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(stateOrProvinceName_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(localityName_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(organizationName_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(organizationUnitName_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(commonName_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(emailAddress_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(subjectKeyIdentifier)
IMPLEMENT_GZPKI_SET_CHAR_FN2(issuerKeyIdentifier)
IMPLEMENT_GZPKI_SET_CHAR_FN2(basicConstraints)
IMPLEMENT_GZPKI_SET_CHAR_FN2(subjectAltName)
IMPLEMENT_GZPKI_SET_CHAR_FN2(nsComment)
IMPLEMENT_GZPKI_SET_CHAR_FN2(extendedKeyUsage)
IMPLEMENT_GZPKI_SET_CHAR_FN2(DNS1)
IMPLEMENT_GZPKI_SET_CHAR_FN2(DNS2)
IMPLEMENT_GZPKI_SET_CHAR_FN2(DNS3)
IMPLEMENT_GZPKI_SET_CHAR_FN2(DNS4)
IMPLEMENT_GZPKI_SET_CHAR_FN2(DNS5)
IMPLEMENT_GZPKI_SET_CHAR_FN2(DNS6)
IMPLEMENT_GZPKI_SET_CHAR_FN2(DNS7)
IMPLEMENT_GZPKI_SET_CHAR_FN2(DNS8)
IMPLEMENT_GZPKI_SET_CHAR_FN2(utf8)

IMPLEMENT_GZPKI_SET_CHAR_FN2(challengePassword)
IMPLEMENT_GZPKI_SET_CHAR_FN2(challengePassword_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(contentType)
IMPLEMENT_GZPKI_SET_CHAR_FN2(contentType_default)
IMPLEMENT_GZPKI_SET_CHAR_FN2(unstructuredName)
IMPLEMENT_GZPKI_SET_CHAR_FN2(unstructuredName_default)


IMPLEMENT_GZPKI_SET_CHAR_FN2(signerfile)
//IMPLEMENT_GZPKI_SET_CHAR_FN2(CAfile)
//IMPLEMENT_GZPKI_SET_CHAR_FN2(keyfile)

IMPLEMENT_GZPKI_SET_CHAR_FN2(extfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(extsect)
IMPLEMENT_GZPKI_SET_CHAR_FN2(CAfile)

IMPLEMENT_GZPKI_SET_FN2(opt_CA_flag) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_sign_flag) //X509

IMPLEMENT_GZPKI_SET_CHAR_FN2(CAkeyfile)
//IMPLEMENT_GZPKI_SET_CHAR_FN2(CAserial)
//IMPLEMENT_GZPKI_SET_CHAR_FN2(randfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(inserial)
IMPLEMENT_GZPKI_SET_CHAR_FN2(fkeyfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(addtrust)
IMPLEMENT_GZPKI_SET_CHAR_FN2(addreject)
IMPLEMENT_GZPKI_SET_CHAR_FN2(alias)
IMPLEMENT_GZPKI_SET_CHAR_FN2(CAserial)
IMPLEMENT_GZPKI_SET_CHAR_FN2(randfile)

IMPLEMENT_GZPKI_SET_CHAR_FN2(checkhost) //X509
IMPLEMENT_GZPKI_SET_CHAR_FN2(checkip) //X509

IMPLEMENT_GZPKI_SET_FN2(certflag) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_email) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_ocsp_uri) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_serial) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_next_serial) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_modulus) //X509
//IMPLEMENT_GZPKI_SET_FN2(opt_pubkey) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_pubkey) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_x509req) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_text) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_subject) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_issuer) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_fingerprint) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_subject_hash) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_subject_hash_old) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_issuer_hash) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_issuer_hash_old) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_pprint) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_startdate) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_enddate) //X509


IMPLEMENT_GZPKI_SET_FN2(opt_noout) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_ext) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_nocert) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_trustout) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_clrtrust) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_clrreject) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_CA_createserial) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_clrext) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_ocspid) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_badsig) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_checkend) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_preserve_dates) //X509
IMPLEMENT_GZPKI_SET_FN2(opt_reqfile) //X509


IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_email)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_ocsp_uri)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_serial)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_next_serial)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_modulus)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_pubkey)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_x509req)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_text)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_subject)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_issuer)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_fingerprint)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_subject_hash)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_subject_hash_old)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_issuer_hash)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_issuer_hash_old)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_pprint)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_startdate)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_enddate)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_noout)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_ext)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_clrtrust)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_clrreject)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_aliasout)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_CA_createserial)
IMPLEMENT_GZPKI_SET_CHAR_FN2(x509_field_ocspid)

IMPLEMENT_GZPKI_SET_CHAR_FN2(req_field_subject)

IMPLEMENT_GZPKI_SET_FN2(opt_get_field_all)

//OCSP
IMPLEMENT_GZPKI_SET_FN2(req_timeout)
IMPLEMENT_GZPKI_SET_FN2(ocsp_port)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_ignore_err)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_noverify)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_add_nonce)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_resp_no_certs)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_resp_key_id)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_no_certs)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_no_signature_verify)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_no_cert_verify)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_no_chain)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_no_cert_checks)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_no_explicit)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_trust_other)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_no_intern)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_badsig)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_req_text)
IMPLEMENT_GZPKI_SET_FN2(ocsp_opt_resp_text)
IMPLEMENT_GZPKI_SET_FN2(ocsp_valididy_period)
IMPLEMENT_GZPKI_SET_FN2(ocsp_status_age)
IMPLEMENT_GZPKI_SET_FN2(ocsp_accept_count)
IMPLEMENT_GZPKI_SET_FN2(ocsp_ndays)
IMPLEMENT_GZPKI_SET_FN2(ocsp_next_minutes)
IMPLEMENT_GZPKI_SET_FN2(ocsp_multi)

IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_url)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_host)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_reqin)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_respin)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_signerfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_verify_certfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_sign_certfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_reqout)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_respout)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_path)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_issuer_certfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_certfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_serial)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_index_filename)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_ca_filename)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_resp_signfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_resp_keyfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_resp_other_certfile)
//IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_resp_sign_md)

IMPLEMENT_GZPKI_SET_FN2(ocsp_verify_result)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ocsp_verify_result_str)


IMPLEMENT_GZPKI_SET_CHAR_FN2(configfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(section_name)
IMPLEMENT_GZPKI_SET_CHAR_FN2(subjec_str)
IMPLEMENT_GZPKI_SET_CHAR_FN2(startdate)
IMPLEMENT_GZPKI_SET_CHAR_FN2(enddate)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ca_policy)
IMPLEMENT_GZPKI_SET_CHAR_FN2(sign_md_alg)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ca_outdir)

IMPLEMENT_GZPKI_SET_FN2(opt_ca_rand_serial)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_create_serial)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_multivalue_rdn)
IMPLEMENT_GZPKI_SET_FN2(certificate_days)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_selfsign)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_no_text)

IMPLEMENT_GZPKI_SET_FN2(opt_preserve_dn)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_email_dn)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_msie_hack)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_generate_crl)
IMPLEMENT_GZPKI_SET_FN2(crl_crldays)
IMPLEMENT_GZPKI_SET_FN2(crl_crlhours)
IMPLEMENT_GZPKI_SET_FN2(crl_crlsec)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_reqinfile)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_reqin)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_do_revoke)
IMPLEMENT_GZPKI_SET_FN2(opt_ca_update_database)

IMPLEMENT_GZPKI_SET_CHAR_FN2(ca_selfsigned_certificate)
IMPLEMENT_GZPKI_SET_CHAR_FN2(spkac_file)
IMPLEMENT_GZPKI_SET_CHAR_FN2(caconf_entensions_section_name)
IMPLEMENT_GZPKI_SET_CHAR_FN2(caconf_crl_entensions_section_name)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ca_status_serial)

IMPLEMENT_GZPKI_SET_CHAR_FN2(ca_signature_parameters)
IMPLEMENT_GZPKI_SET_CHAR_FN2(caconf_entensions_file_name)
IMPLEMENT_GZPKI_SET_CHAR_FN2(crl_revoke_reason)

IMPLEMENT_GZPKI_SET_FN2(ca_request_file_cnt)

IMPLEMENT_GZPKI_SET_FN2(use_sqldb)
IMPLEMENT_GZPKI_SET_FN2(use_txtdb)
IMPLEMENT_GZPKI_SET_CHAR_FN2(ca_name)

IMPLEMENT_GZPKI_SET_FN2(opt_req_verify)
IMPLEMENT_GZPKI_SET_FN2(req_verify_result)

IMPLEMENT_GZPKI_SET_FN2(opt_verify_trusted)
IMPLEMENT_GZPKI_SET_FN2(opt_verify_crl_download)
IMPLEMENT_GZPKI_SET_FN2(opt_verify_show_chain)


IMPLEMENT_GZPKI_SET_CHAR_FN2(trusted_certfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(untrusted_certfile)
IMPLEMENT_GZPKI_SET_CHAR_FN2(verify_opts)

IMPLEMENT_GZPKI_SET_CHAR_FN2(key_pem)
IMPLEMENT_GZPKI_SET_CHAR_FN2(csr_pem)
IMPLEMENT_GZPKI_SET_CHAR_FN2(key_pass)
IMPLEMENT_GZPKI_SET_CHAR_FN2(template_id)

int _G_DEBUG_MODE_ = 0;
int _G_VERBOSE_MODE_ = 0;
void GZPKI_lib_set_debug_mode(int mode) {
    _G_DEBUG_MODE_ = mode;
    //printf("GZPKI_lib_set_debug_mode(%d): %d\n", mode,  _G_DEBUG_MODE_);
}

char *GZPKI_lib_get_version() {
    return (char *)GZPKI_VERSION;
}

int gzpki_common_context_init(GZPKI_CTX *ctx)
{

#ifdef DEBUG_MODE    
    //fprintf(stderr, "gzpki:common:context init.\n");
#endif 

    ctx->debug_mode = 1;
    ctx->operation = 0;
    ctx->device_password = NULL;
    //--------------------------------------------------
    //CA
    //--------------------------------------------------
        ctx->db_ip = NULL;
        ctx->db_port = 0;
        ctx->db_file = NULL;
        ctx->db_user = NULL;
        ctx->db_name = NULL;
        ctx->db_pwd = NULL;

        ctx->use_sqldb = 1;
        ctx->use_txtdb = 1;
        ctx->ca_name = NULL;
        ctx->opt_ca_reqin = 0; //openssl ca -in
        ctx->configfile = NULL; 
        ctx->section_name = NULL;
        ctx->subjec_str = NULL;
        ctx->opt_ca_rand_serial = 0;
        ctx->opt_ca_create_serial = 0;
        ctx->opt_ca_multivalue_rdn = 0;
        ctx->startdate = NULL;
        ctx->enddate = NULL;
        ctx->certificate_days = 0;
        ctx->ca_policy = NULL;
        ctx->sign_md_alg = NULL;
        ctx->opt_ca_selfsign = 0;
        ctx->ca_outdir = NULL;
        ctx->ca_signature_parameters = NULL;
        ctx->opt_ca_no_text = 0;
        ctx->opt_ca_load_private_key = 1;

        ctx->opt_preserve_dn = 0;
        ctx->opt_ca_email_dn = 1;
        ctx->opt_ca_msie_hack = 0;
        ctx->opt_ca_generate_crl = 0;
        ctx->crl_crldays = 0;
        ctx->crl_crlhours = 0;
        ctx->crl_crlsec = 0;
        //ctx->ca_opt_reqinfile = 0;
        ctx->opt_ca_reqinfile = 0;
        ctx->ca_selfsigned_certificate = NULL;
        ctx->opt_ca_do_revoke = 0;
        ctx->opt_ca_update_database = 0;

        ctx->spkac_file = NULL;
        ctx->caconf_entensions_section_name = NULL;
        ctx->caconf_crl_entensions_section_name = NULL;
        ctx->ca_status_serial = NULL;
        ctx->caconf_entensions_file_name = NULL;
        ctx->crl_revoke_reason = NULL;
        ctx->crl_revoke_type = REV_NONE;
        ctx->ca_request_file_cnt = 1;

        ctx->crlfile = NULL;

        //todo : add init function key_pem/csr_pem, key_pass
        ctx->key_pem = NULL;
        ctx->csr_pem = NULL;
        ctx->key_pass = NULL;
        ctx->template_id = NULL;

    //VERIFY
    
        ctx->opt_verify_trusted = 0;
        ctx->opt_verify_crl_download = 0;
        ctx->opt_verify_show_chain = 0;
        ctx->trusted_certfile = NULL;
        ctx->untrusted_certfile = NULL;
        ctx->verify_opts = NULL;

        ctx->verify_add_policy = NULL; //"adds policy to the acceptable policy set"
        ctx->verify_purpose = NULL;
        
        ctx->verify_name = NULL;
        ctx->verify_depth = 0;
        ctx->verify_auth_level = 0;
        ctx->verify_epoch_time = NULL;
        ctx->verify_host_name = NULL;
        ctx->verify_email = NULL;
        ctx->verify_ip = NULL;
    //IN
        ctx->intype = ctx->outtype = FORMAT_FILE; //FORMAT_MEM;
        ctx->in = ctx->out = NULL; 
        ctx->infile = ctx->outfile = NULL;
        ctx->informat = ctx->outformat = FORMAT_PEM;
        ctx->keyformat = FORMAT_PEM;
        ctx->CAformat = FORMAT_PEM;
        ctx->CAkeyformat = FORMAT_PEM;

        ctx->e = NULL;
        ctx->bptr = NULL;

        ctx->key = NULL;
        
        ctx->passinarg = NULL;
        ctx->passoutarg = NULL;
        ctx->passin = NULL;
        ctx->passout = NULL;

        ctx->bio_in = dup_bio_in(FORMAT_TEXT);
        ctx->bio_out = dup_bio_out(FORMAT_TEXT);
        ctx->bio_err = dup_bio_err(FORMAT_TEXT);
    
        ctx->debug = _G_DEBUG_MODE_;

    //ECPARAM
        ctx->form  = POINT_CONVERSION_UNCOMPRESSED; //ECC + ECPARAM
        ctx->asn1_flag = OPENSSL_EC_NAMED_CURVE;
        ctx->new_asn1_flag = 0;
        ctx->noout = 0;
        //DEL ctx->C = 0;
        ctx->new_asn1_flag = 0;
        ctx->ret = 1;
        ctx->private = CMS_OPT_OFF; //ecc + ecparam
        ctx->no_seed = CMS_OPT_OFF;
        ctx->check = CMS_OPT_OFF; //ecc + ecparam
        ctx->new_form = CMS_OPT_OFF; //ecc + ecparam
        ctx->text = CMS_OPT_OFF;
        ctx->genkey = 0;
        ctx->curve_name = NULL;
        ctx->ec_gen = ctx->ec_order = ctx->ec_cofactor = NULL;
        ctx->ec_p = ctx->ec_a = ctx->ec_b = NULL;
    //ECC
        
        ctx->param_out = CMS_OPT_OFF;
        ctx->pubin = CMS_OPT_OFF;
        ctx->pubout = CMS_OPT_OFF;
        ctx->no_public = CMS_OPT_OFF;
        ctx->name = (char *)"aes128";
        ctx->enc = EVP_get_cipherbyname(ctx->name); 
        ctx->asn1_flag = OPENSSL_EC_NAMED_CURVE;
        ctx->new_asn1_flag = CMS_OPT_OFF;
        ctx->name = (char *)"aes128";
        ctx->enc = EVP_get_cipherbyname(ctx->name); 

    //REQ VALUE RETURNED by text option
    //함수는 나중에...
        ctx->reqVersion = 0;
        ctx->reqSubjectDN = NULL;
        ctx->reqAlgorithmName = NULL;
        ctx->reqErrcode = 0;
        ctx->reqErrstr = NULL;       
        ctx->reqChallengePassword = NULL;
        ctx->reqContentType = NULL;
        ctx->reqUnstructuredName = NULL;
        ctx->reqRole = NULL;
        ctx->reqSubjectKeyIdentifier = NULL;

        ctx->reqCN = NULL;
        ctx->reqEmail = NULL;
        ctx->reqUUID = NULL;
        ctx->reqData = NULL;
        ctx->reqDate = NULL;
        ctx->reqFilename = NULL;
        ctx->reqKeyBits = 0;

        ctx->opt_req_verify = 0;

    //REQ
        ctx->newreq = CMS_OPT_OFF;
        ctx->keyout = NULL; 
        ctx->keyoutfile = NULL;
        ctx->keyalg = NULL; //디폴트 알고리즘 미리 설정해둔다. 
        ctx->batch = 1; //req_mein에서 global/static int batch = 0;
        ctx->newhdr = CMS_OPT_OFF;
        ctx->verify = CMS_OPT_OFF;
        ctx->verbose = CMS_OPT_OFF;
        ctx->modulus = CMS_OPT_OFF;
        ctx->chtype = MBSTRING_UTF8;
        ctx->pubkey = CMS_OPT_OFF;
        ctx->x509 = CMS_OPT_OFF;
        ctx->days = 0;
        ctx->serial = NULL;
        ctx->subject_out = CMS_OPT_OFF;
        ctx->subj = NULL;
        ctx->multirdn = CMS_OPT_OFF;
        ctx->extensions = NULL;
        ctx->req_exts = NULL;
        ctx->precert = CMS_OPT_OFF;
        ctx->default_config_file = NULL;
        ctx->req = NULL;
        ctx->serial = NULL;
        ctx->pkey = NULL;
        ctx->genctx = NULL;
        ctx->pkeyopts = NULL;
        ctx->sigopts = NULL;
        ctx->addexts = NULL;
        ctx->x509ss = NULL;
        ctx->md_alg = NULL;
        ctx->digest = NULL;

    //REQ_CONF
        ctx->req_conf = NULL;
        ctx->addext_conf = NULL;
        ctx->req_section = NULL;

        ctx->distinguished_name = (char *)"subject"; //섹션명, 설정하지 않음(고정값)
        ctx->req_extensions     = (char *)"req_ext";
        ctx->x509_extensions    = (char *)"x509_ext";

        //[req]
        ctx->default_bits       = (char *)"2048";  
        ctx->default_keyfile    = (char *)"req.key";
        ctx->string_mask        = (char *)"utf8only";
        ctx->default_md         = (char *)"sha256";

        //[subject]
#if 0        
        ctx->countryName = "Country Name";
        ctx->countryName_default = "KR";
        ctx->stateOrProvinceName = "State or Province";
        ctx->stateOrProvinceName_default = NULL;
        ctx->localityName = "Locality";
        ctx->localityName_default = NULL;
        ctx->organizationName = "Organization";
        ctx->organizationName_default = NULL;
        ctx->organizationUnitName = "Organization Unit";
        ctx->organizationUnitName_default = NULL;
        ctx->commonName = "Common Name";
        ctx->commonName_default = NULL;
        ctx->emailAddress = "Email Address";
        ctx->emailAddress_default = NULL;
#else
        ctx->countryName = NULL;
        ctx->countryName_default = NULL;
        ctx->stateOrProvinceName = NULL;
        ctx->stateOrProvinceName_default = NULL;
        ctx->localityName = NULL;
        ctx->localityName_default = NULL;
        ctx->organizationName = NULL;
        ctx->organizationName_default = NULL;
        ctx->organizationUnitName = NULL;
        ctx->organizationUnitName_default = NULL;
        ctx->commonName = NULL;
        ctx->commonName_default = NULL;
        ctx->emailAddress = NULL;
        ctx->emailAddress_default = NULL;        
#endif        

        //[x509_ext]
        ctx->subjectKeyIdentifier = (char *)"hash";
        ctx->authorityKeyIdentifier = (char *)"keyid,issuer";
        ctx->basicConstraints = (char *)"CA:FALSE";
        //ctx->keyUsage = "digitalSignature, keyEncipherment";
        ctx->keyUsage = (char *)"digitalSignature, keyEncipherment, nonRepudiation, dataEncipherment, keyAgreement";//, encipherOnly, decipherOnly
        ctx->subjectAltName = (char *)"@alternate_names";
        ctx->nsComment = (char *)"Copyright © 2018 - Green Zone Security Co., Ltd. All rights reserved.";
        ctx->extendedKeyUsage = (char *)"serverAuth, clientAuth";

        //REQ req_attributes
        //ctx->challengePassword = NULL;
        ctx->challengePassword = (char *)"revoke password";
        ctx->challengePassword_default = NULL;
        ctx->contentType = NULL;
        ctx->contentType_default = NULL;
        ctx->unstructuredName = NULL;
        ctx->unstructuredName_default = NULL;

        //[req_ext]
        //ctx->subjectKeyIdentifier = "hash";
        //ctx->basicConstraints = "CA:FALSE";
        //ctx->keyUsage = "digitalSignature, keyEncipherment, nonRepudiation, dataEncipherment, keyAgreement";//, encipherOnly, decipherOnly
        
        ctx->DNS1 = NULL;
        ctx->DNS2 = NULL;
        ctx->DNS3 = NULL;
        ctx->DNS4 = NULL;
        ctx->DNS5 = NULL;
        ctx->DNS6 = NULL;
        ctx->DNS7 = NULL;
        ctx->DNS8 = NULL;
        
        ctx->req_conf_str = NULL;

    //X509
        ctx->randfile= NULL;
        ctx->extfile = NULL;
        ctx->extsect = NULL;
        //ctx->CAfile = NULL; //CMS, X509
        ctx->opt_CA_flag = 0;
        ctx->opt_sign_flag = 0;

        ////
        ctx->CAkeyfile = NULL;
        ctx->CAserial  = NULL;
        ctx->randfile  = NULL;
        ctx->inserial  = NULL; //X509, REQ
        ctx->fkeyfile  = NULL;
        ctx->addtrust  = NULL;
        ctx->addreject = NULL;
        ctx->alias     = NULL;
        ctx->checkhost = NULL;
        ctx->checkip   = NULL;
    
        ctx->certflag    = 0; //int //set_cert_ex 참조 설정함수를 만든다. GZPKI_set_certflag() 외부 call
        ctx->opt_email   = 0;
        ctx->opt_ocsp_uri  = 0;
        ctx->opt_serial    = 0;
        ctx->opt_next_serial = 0;
        ctx->opt_modulus = 0;
        ctx->opt_pubkey  = 0;
        ctx->opt_x509req = 0;
        ctx->opt_text    = 0;
        ctx->opt_subject = 0;
        ctx->opt_issuer  = 0;
        ctx->opt_fingerprint = 0;
        ctx->opt_subject_hash= 0;
        ctx->opt_subject_hash_old    = 0;
        ctx->opt_issuer_hash = 0;
        ctx->opt_issuer_hash_old     = 0;
        ctx->opt_pprint  = 0;
        ctx->opt_startdate   = 0;
        ctx->opt_enddate     = 0;
        ctx->opt_noout       = 0;
        ctx->opt_ext         = 0;
        ctx->opt_nocert      = 0;
        ctx->opt_trustout    = 0;
        ctx->opt_clrtrust    = 0;
        ctx->opt_clrreject   = 0;
        ctx->opt_aliasout    = 0;
        ctx->opt_CA_createserial  = 0;
        ctx->opt_clrext      = 0;
        ctx->opt_ocspid      = 0;
        ctx->opt_badsig      = 0;
        ctx->opt_checkend    = 0;
        ctx->opt_preserve_dates  = 0;
        ctx->opt_reqfile     = 0;


        ctx->x509_field_email = NULL; 
        ctx->x509_field_ocsp_uri = NULL; 
        ctx->x509_field_serial = NULL;
        ctx->x509_field_next_serial = NULL; 
        ctx->x509_field_modulus = NULL; 
        ctx->x509_field_pubkey = NULL; 
        ctx->x509_field_x509req = NULL; 
        ctx->x509_field_text = NULL; 
        ctx->x509_field_subject = NULL; 
        ctx->x509_field_issuer = NULL; 
        ctx->x509_field_fingerprint = NULL; 
        ctx->x509_field_subject_hash = NULL; 
        ctx->x509_field_subject_hash_old = NULL; 
        ctx->x509_field_issuer_hash = NULL; 
        ctx->x509_field_issuer_hash_old = NULL; 
        ctx->x509_field_pprint = NULL; 
        ctx->x509_field_startdate = NULL; 
        ctx->x509_field_enddate = NULL; 
        ctx->x509_field_noout = NULL; 
        ctx->x509_field_ext = NULL; 
        ctx->x509_field_clrtrust = NULL; 
        ctx->x509_field_clrreject = NULL; 
        ctx->x509_field_aliasout = NULL; 
        ctx->x509_field_CA_createserial = NULL; 
        ctx->x509_field_ocspid = NULL; 

        ctx->req_field_subject = NULL; 

        ctx->opt_get_field_all = 0;
        ctx->opt_req_verify = 0;
        ctx->req_verify_result = 0;

    //--------------------------------------------------
    // OCSP
    //--------------------------------------------------
        ctx->req_timeout = -1;
        ctx->ocsp_port = 0;
        ctx->ocsp_opt_ignore_err = 0;
        ctx->ocsp_opt_noverify = 0;
        ctx->ocsp_opt_add_nonce =  -1;      //add_nonce:2, no_nonce: 0
        ctx->ocsp_opt_resp_no_certs = 0;
        ctx->ocsp_opt_resp_key_id = 0;      //OCSP_RESPID_KEY
        ctx->ocsp_opt_no_certs = 0;         //OCSP_NOCERTS
        ctx->ocsp_opt_no_signature_verify=0;//OCSP_NOSIGS
        ctx->ocsp_opt_no_cert_verify = 0;   //OCSP_NOVERIFY
        ctx->ocsp_opt_no_chain = 0;         //OCSP_NOCHAIN
        ctx->ocsp_opt_no_cert_checks = 0;   //OCSP_NOCHECKS
        ctx->ocsp_opt_no_explicit = 0;      //OCSP_NOEXPLICIT
        ctx->ocsp_opt_trust_other = 0;      //OCSP_TRUSTOTHER
        ctx->ocsp_opt_no_intern = 0;        //OCSP_NOINTERN
        ctx->ocsp_opt_badsig = 0;
        ctx->ocsp_opt_req_text = 0;
        ctx->ocsp_opt_resp_text = 0;
        ctx->ocsp_valididy_period = MAX_VALIDITY_PERIOD;
        ctx->ocsp_status_age = -1; //maxage
        ctx->ocsp_accept_count = -1;
        ctx->ocsp_ndays = 0;
        ctx->ocsp_next_minutes = -1;
        ctx->ocsp_multi = 0;

        ctx->ocsp_url = NULL;
        ctx->ocsp_host = NULL;
        ctx->ocsp_reqin = NULL;
        ctx->ocsp_respin = NULL;
        ctx->ocsp_signerfile = NULL;
        ctx->ocsp_verify_certfile = NULL;
        ctx->ocsp_sign_certfile = NULL;
        ctx->ocsp_reqout = NULL;
        ctx->ocsp_respout = NULL;
        ctx->ocsp_path = (char *)"/";
        ctx->ocsp_issuer_certfile = NULL;
        ctx->ocsp_certfile = NULL;
        ctx->ocsp_serial = NULL;
        ctx->ocsp_index_filename = NULL;
        ctx->ocsp_ca_filename = NULL;
        ctx->ocsp_resp_signfile = NULL;
        ctx->ocsp_resp_keyfile = NULL;
        ctx->ocsp_resp_other_certfile = NULL;
        ctx->ocsp_resp_sign_md = NULL;

        ctx->ocsp_verify_result = 0;
        ctx->ocsp_verify_result_str = NULL;
    //--------------------------------------------------
    //CMS
    //--------------------------------------------------
        ctx->cipher_name = NULL;
        ctx->econtent_type = NULL;
        ctx->indata = ctx->rctin = NULL;
        ctx->cms = ctx->rcms = NULL;
        ctx->rr = NULL;
        ctx->cipher = ctx->wrap_cipher = NULL;
        ctx->sign_md = NULL;
        ctx->rr_to = ctx->rr_from = NULL;
        ctx->sksigners = ctx->skkeys = ctx->skpassins = NULL;
        ctx->encerts = ctx->other = NULL;
        ctx->cert = ctx->recip = ctx->signer = NULL;
        ctx->store = NULL;
        ctx->vpm = NULL;
        ctx->certfile = ctx->keyfile = ctx->contfile = NULL;
        ctx->CAfile = ctx->CApath = NULL;
        ctx->cafileformat = FORMAT_PEM;
        ctx->certsoutfile = NULL;
        ctx->noCApath = ctx->noCAfile = CMS_OPT_OFF;
        ctx->rctfile = NULL;
        ctx->signerfile = ctx->recipfile = NULL;
        ctx->to = ctx->from = ctx->subject = NULL;
        ctx->flags = CMS_DETACHED;//= CMS_DETACHED;
        ctx->noout = CMS_OPT_OFF;
        ctx->print = CMS_OPT_OFF;
        ctx->keyidx = CMS_OPT_UNDEF;
        ctx->vpmtouched = CMS_OPT_OFF;
        
    
        ctx->ret = 1;
        ctx->rr_print = CMS_OPT_OFF; //0 fixed
        ctx->rr_allorfirst = -1; //-1 fixed

        ctx->verify_retcode = 0;
        ctx->rctformat = FORMAT_SMIME;
        ctx->keyform = FORMAT_PEM;
        ctx->secret_keylen = 0;
        ctx->secret_keyidlen = 0;
        ctx->pwri_pass = ctx->pwri_tmp = NULL;
        ctx->secret_key = ctx->secret_keyid = NULL;
        ctx->mime_eol = "\n";

        ctx->verify_result = -1;
        ctx->digest_verify_result = -1;

        ctx->inbuffer = NULL;
        ctx->inbuffer_size = 0;

        ctx->outbuffer = NULL;
        ctx->outbuffer_size = 0;

        ctx->outdata = NULL;
        ctx->outdata_length = -1;

    //name option
        ctx->opt_req_nameopt = XN_FLAG_RFC2253_GZ;
        ctx->opt_cert_nameopt = XN_FLAG_RFC2253_GZ;
        ctx->opt_nameopt = XN_FLAG_RFC2253_GZ;

        ctx->opt_ca_index_db_sync = 0;

        //ctx->req_uuid = NULL;
        ctx->reqUUID = NULL;

    //ENC
        ctx->base64 = 0;
        ctx->olb64 = 0;
        ctx->cipher_list = 0;
        ctx->printkey = 0;
        ctx->nopad = 0;
        ctx->nosalt = 0;
        ctx->pbkdf2 = 0; //0
        ctx->iter = 0;
        ctx->passphrase = NULL;
        ctx->passphrase_file = NULL;
        ctx->rawkey_hex = NULL;
        ctx->salt_hex = NULL;
        ctx->iv_hex = NULL;
        ctx->dgst_name = NULL;

    //=========================
    // Initialize Code
    //=========================
    //----------------------------------------
    //openssl init process 
    //----------------------------------------
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    
#if 1//check    
    if (ctx->vpm == NULL && (ctx->vpm = X509_VERIFY_PARAM_new()) == NULL) {
        return CMS_RET_ERROR;
    }
#endif    

    ctx->errcode = 0;
    memset(ctx->errstr, 0, sizeof(ctx->errstr));

    


    return CMS_RET_OK;
}



char *ltrim(char *s) {
    while(isspace(*s)) s++;
    return s;
}

char *rtrim(char *s) {
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}

 char *trim(char *s) {
    return rtrim(ltrim(s)); 
}

void GZPKI_print_errors(GZPKI_CTX *ctx) {
    unsigned long l;
    char buf[256];
    //unused: char buf2[4096];
    const char *file, *data;
    int line, flags;
    /* We don't know what kind of thing CRYPTO_THREAD_ID is. 
     * Here is our best attempt to convert it into something we can print. 
     */
    union {
        CRYPTO_THREAD_ID tid;
        unsigned long ltid;
    } tid;

    tid.ltid = 0;
    tid.tid = CRYPTO_THREAD_get_current_id();

    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        ERR_error_string_n(l, buf, sizeof(buf));
        //snprintf(ctx->errstr, sizeof(ctx->errstr), "%lu:%s:%s:%d:%s\n", tid.ltid, buf, file, line, (flags & ERR_TXT_STRING) ? data : "");
        snprintf(ctx->errstr, sizeof(ctx->errstr), "%s\n", (flags & ERR_TXT_STRING) ? data : "");
    }
}

void GZPKI_print_errors_std() {
    unsigned long l;
    char buf[256];
    //unused char buf2[4096];
    const char *file, *data;
    int line, flags;
    /* We don't know what kind of thing CRYPTO_THREAD_ID is. Here is our best
     * attempt to convert it into something we can print. */
    union {
        CRYPTO_THREAD_ID tid;
        unsigned long ltid;
    } tid;

    tid.ltid = 0;
    tid.tid = CRYPTO_THREAD_get_current_id();

    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        ERR_error_string_n(l, buf, sizeof(buf));
        printf("%lu:%s:%s:%d:%s\n", tid.ltid, buf, file, line, (flags & ERR_TXT_STRING) ? data : "");
        //snprintf(ctx->errstr, sizeof(ctx->errstr), "%s\n", (flags & ERR_TXT_STRING) ? data : "");
    }
}

int GZPKI_add_flags(GZPKI_CTX *ctx, int opt)
{
    ctx->flags |= opt;
    return ctx->flags;
}

int GZPKI_set_flags(GZPKI_CTX *ctx, int opt)
{
    ctx->flags = opt;
    return ctx->flags;
}

int GZPKI_remove_flags(GZPKI_CTX *ctx, int opt)
{
    ctx->flags &= ~opt;
    return ctx->flags;

}


int is_valid_ecparam(char *name)
{
    int i = 0;
    //unused char *L = NULL;
    //unused: char *tmp_ecparam = NULL;

    for (i=0; ecparam_list[i].name != NULL; i++ ) {
        if(0 == strcmp(name, ecparam_list[i].name))
            return 1;
    }

    return 0;
}

void show_ecparam()
{
    int i = 0;

    for (i=0; ecparam_list[i].name != NULL; i++ ) {
        printf("%s\n",ecparam_list[i].name );
    }

    return ;
}


int is_valid_cipher(char *name)
{
    int i=0;
    if(!name) 
        return 0;

    for (i=0; cipher_alg_list[i].name != NULL; i++ ) {
        if(0 == strcmp(name, cipher_alg_list[i].name)) {
            IF_VERBOSE fprintf(stderr, DEBUG_TAG"valid cipher: %s(in list: %s)\n", name, cipher_alg_list[i].name );
            return 1;
         }
    }
    //printf("NOT MATCH: %s VS %s\n", name, cipher_alg_list[i].name );
    return 0;
}

int is_file_exists( char *filename )
{
    return access( filename, 0 ) == 0;
}

//============================== from gzpki_cms

static int ui_open(UI *ui)
{
    int (*opener)(UI *ui) = UI_method_get_opener(ui_fallback_method);

    if (opener)
        return opener(ui);
    return 1;
}

static int ui_read(UI *ui, UI_STRING *uis)
{
    int (*reader)(UI *ui, UI_STRING *uis) = NULL;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
                if (password && password[0] != '\0') {
                    UI_set_result(ui, uis, password);
                    return 1;
                }
            }
            break;
        case UIT_NONE:
        case UIT_BOOLEAN:
        case UIT_INFO:
        case UIT_ERROR:
            break;
        }
    }

    reader = UI_method_get_reader(ui_fallback_method);
    if (reader)
        return reader(ui, uis);
    return 1;
}

static int ui_write(UI *ui, UI_STRING *uis)
{
    int (*writer)(UI *ui, UI_STRING *uis) = NULL;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
                if (password && password[0] != '\0')
                    return 1;
            }
            break;
        case UIT_NONE:
        case UIT_BOOLEAN:
        case UIT_INFO:
        case UIT_ERROR:
            break;
        }
    }

    writer = UI_method_get_writer(ui_fallback_method);
    if (writer)
        return writer(ui, uis);
    return 1;
}

static int ui_close(UI *ui)
{
    int (*closer)(UI *ui) = UI_method_get_closer(ui_fallback_method);

    if (closer)
        return closer(ui);
    return 1;
}

int setup_ui_method(void)
{
    ui_fallback_method = UI_null();
#ifndef OPENSSL_NO_UI_CONSOLE
    ui_fallback_method = UI_OpenSSL();
#endif
    ui_method = UI_create_method("OpenSSL application user interface");
    UI_method_set_opener(ui_method, ui_open);
    UI_method_set_reader(ui_method, ui_read);
    UI_method_set_writer(ui_method, ui_write);
    UI_method_set_closer(ui_method, ui_close);
    return 0;
}

void destroy_ui_method(void)
{
    if (ui_method) {
        UI_destroy_method(ui_method);
        ui_method = NULL;
    }
}

const UI_METHOD *get_ui_method(void)
{
    return ui_method;
}


//====

void destroy_prefix_method(void)
{
    BIO_meth_free(prefix_method);
    prefix_method = NULL;
}




void convrt_mac(const char *data, char *cvrt_str, int sz)
{
     char buf[128] = {0,};
     char t_buf[8];
     char *stp = strtok( (char *)data , ":" );
     int temp=0;
     do
     {
        memset( t_buf, 0, sizeof(t_buf) );
        sscanf( stp, "%x", &temp );
        snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
        strncat( buf, t_buf, sizeof(buf)-1 );
        strncat( buf, ":", sizeof(buf)-1 );
     } while( (stp = strtok( NULL , ":" )) != NULL );
     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}


char *g_NIC = NULL;
char g_MAC[256];
char g_RH_DIGEST[41];

int get_NIC_name() //eth0와 같은 NIC을 가져온다.
{
	int sock;
	struct ifconf ifconf;
	struct ifreq ifr[50];
	int ifs;
	int i;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	ifconf.ifc_buf = (char *) ifr;
	ifconf.ifc_len = sizeof ifr;

	if (ioctl(sock, SIOCGIFCONF, &ifconf) == -1) {
		perror("ioctl");
		return 0;
	}

	ifs = ifconf.ifc_len / sizeof(ifr[0]);

	for (i = 0; i < ifs; i++) {
		if(strcmp(ifr[i].ifr_name, "lo") != 0) //'lo'를 제외한 나머지 NIC을 가져온다.
		{
            g_NIC = GZPKI_strdup(ifr[i].ifr_name);
			break;
		}
	}

	close(sock);
	return 1;
}


int get_MAC_address(char *nic) {
    int sock;
    struct ifreq ifr;
    char mac_adr[18] = {0,};

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        return 0;
    }

    //strcpy(ifr.ifr_name, "eth0");
    if(nic)
        strcpy(ifr.ifr_name, nic);
    else if(g_NIC != NULL)
        strcpy(ifr.ifr_name, g_NIC);
    else {
        close(sock);
        return 0;
    }

    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		perror("ioctl():get_MAC_address()");
		close(sock);
		return 0;
	}

    convrt_mac( ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );
    memset(g_MAC, 0, sizeof(g_MAC));
	strcpy(g_MAC, mac_adr);
    
	close(sock);
	return 1;
}


int sha256_ripemd160_hash(char *string) {
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, string, strlen(string));
    SHA256_Final(sha256_digest, &ctx);

    char sha256_string[SHA256_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&sha256_string[i*2], "%02x", (unsigned int)sha256_digest[i]);

    IF_VERBOSE fprintf(stderr, DEBUG_TAG"sha256_ripemd160_hash:SHA256 digest: [%s]\n", sha256_string);

    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160,  sha256_string , strlen(sha256_string));
    RIPEMD160_Final(hash, &ripemd160);
    
    
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        sprintf(&g_RH_DIGEST[i*2], "%02x", hash[i]);
    }
    
    g_RH_DIGEST[40] = 0;
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"sha256_ripemd160_hash:RIPEMD160 digest: ["color_green_b"%s"color_reset"]\n", (char *)g_RH_DIGEST);
    return 0;
}



char *GZPKI_ripemd160_hash(unsigned char *string, int len) {

    char DGST[RIPEMD160_DIGEST_LENGTH*2+1];
    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160,  string , len);
    RIPEMD160_Final(hash, &ripemd160);
    
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        sprintf(&DGST[i*2], "%02x", hash[i]);
    }
    
    char *p = NULL;
    p = GZPKI_strdup(DGST);
    return p;
}

unsigned char *generate_certificate_hash(char *file, int format, char *name) {
    unsigned int n;
    int j=0;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned char *certhash = NULL;//[];
    const EVP_MD *fdig = NULL;
    //char *R = NULL;

    certhash = (unsigned char *)malloc(EVP_MAX_MD_SIZE);

    IF_VERBOSE fprintf(stderr, DEBUG_TAG"generate certificate hash()...\n");
    X509 *cert = load_cert((const char *)file, format, "X.509 Certificate");
    if(!cert) {
        fprintf(stderr, "error:fail to load:%s\n", file);
        return NULL;
    }

    fdig = EVP_get_digestbyname(name);
    if(fdig == NULL)
        fdig = EVP_ripemd160();
        //fdig = EVP_sha1();

    if (!X509_digest(cert, fdig, md, &n)) {
        fprintf(stderr, "out of memory\n");
        return NULL;;
    }
    
    for (j = 0; j < (int)n; j++) {
        sprintf( &certhash[j*2], "%02x", md[j]);
    }
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"%s Fingerprint(%s)=", file, OBJ_nid2sn(EVP_MD_type(fdig)));
    IF_VERBOSE fprintf(stderr, "["color_yellow_b"%s"color_reset"]\n", certhash);
    //char *p = GZPKI_strdup(certhash);
    return certhash;

}

//char *GZPKI_generate_device_password(GZPKI_CTX *ctx, char *MAC_ADDR_STR, char *filename) {

char *generate_device_password(char *MAC_ADDR_STR, char *filename) {
    
    unsigned char *fingerprint = NULL;
    if(filename) {
        fingerprint = generate_certificate_hash(filename, FORMAT_PEM, (char *)"ripemd160");
    }
    char inbuf[512];
    memset(inbuf, 0, sizeof(inbuf));
    
    //on-site
    if(MAC_ADDR_STR == NULL) {
        get_NIC_name();
        D_printf(DEBUG_TAG"NIC: %s\n", g_NIC);

        get_MAC_address(NULL);
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"MAC: %s\n", g_MAC);

        //unused: char outputBuffer[41];

        IF_VERBOSE fprintf(stderr, DEBUG_TAG"SEED: "color_yellow_b"%s"color_reset, g_MAC);
        IF_VERBOSE fprintf(stderr, color_cyan_b"%s"color_reset"\n", fingerprint);
        sprintf(inbuf, "%s%s", g_MAC, fingerprint);
    }
    //on server side
    else {
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"SEED: "color_yellow_b"%s"color_reset, MAC_ADDR_STR);
        IF_VERBOSE fprintf(stderr, color_cyan_b"%s"color_reset"\n", fingerprint);
        sprintf(inbuf, "%s%s", MAC_ADDR_STR, fingerprint);
    }

    sha256_ripemd160_hash( (char *)inbuf);
    
    /*if(ctx->device_password)
        free(ctx->device_password);

    ctx->device_password = GZPKI_strdup(g_RH_DIGEST);
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"RIPEMD160(SHA256(%s)) = ["color_red_b"%s"color_reset"]\n", inbuf, ctx->device_password);
    */

    return GZPKI_strdup(g_RH_DIGEST);

}

#if 1
int GZPKI_generate_device_password(GZPKI_CTX *ctx, char *MAC_ADDR_STR, char *filename) {
    
     if(ctx->device_password)
        free(ctx->device_password);

    ctx->device_password = generate_device_password(MAC_ADDR_STR, filename);
    D_printf("GZPKI_generate_device_password: [%s]\n", ctx->device_password);

    return 0;

}
#else
int GZPKI_generate_device_password(GZPKI_CTX *ctx, char *MAC_ADDR_STR, char *filename) {
    
    unsigned char *fingerprint = NULL;
    if(filename) {
        fingerprint = generate_certificate_hash(filename, FORMAT_PEM, (char *)"ripemd160");
        //fprintf(stdout, "%s", fingerprint);
    }
    char inbuf[512];
    memset(inbuf, 0, sizeof(inbuf));
    
    //on-site
    if(MAC_ADDR_STR == NULL) {
        get_NIC_name();
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"NIC: %s\n", g_NIC);

        get_MAC_address(NULL);
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"MAC: %s\n", g_MAC);

        char outputBuffer[41];

        IF_VERBOSE fprintf(stderr, DEBUG_TAG"SEED: "color_yellow_b"%s"color_reset, g_MAC);
        IF_VERBOSE fprintf(stderr, color_cyan_b"%s"color_reset"\n", fingerprint);
        sprintf(inbuf, "%s%s", g_MAC, fingerprint);
    }
    //on server side
    else {
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"SEED: "color_yellow_b"%s"color_reset, MAC_ADDR_STR);
        IF_VERBOSE fprintf(stderr, color_cyan_b"%s"color_reset"\n", fingerprint);
        sprintf(inbuf, "%s%s", MAC_ADDR_STR, fingerprint);
    }

    sha256_ripemd160_hash( (char *)inbuf);
    //g_PASSWORD = (char *)g_RH_DIGEST;
    if(ctx->device_password)
        free(ctx->device_password);

    ctx->device_password = GZPKI_strdup(g_RH_DIGEST);
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"RIPEMD160(SHA256(%s)) = ["color_red_b"%s"color_reset"]\n", inbuf, ctx->device_password/*g_RH_DIGEST*/);

    return 0;
}
#endif


//--------------------------------------------------
// key pass DB file generate.
//--------------------------------------------------

int GZPKI_sha256_hash(char *string, char *sha256_string) {
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];


    //IF_VERBOSE fprintf(stderr, "GZPKI_sha256_hash: len=%d\n", strlen(string));
    //IF_VERBOSE fprintf(stderr, "GZPKI_sha256_hash: %s\n", string);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, string, strlen(string));
    SHA256_Final(sha256_digest, &ctx);

    //char sha256_string[SHA256_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&sha256_string[i*2], "%02x", (unsigned int)sha256_digest[i]);

    IF_VERBOSE fprintf(stderr, DEBUG_TAG"SHA256: [%s]\n", sha256_string);
    
    return CMS_RET_OK;
}


int generate_dirctory(char *path, mode_t mode)
{
	//int r = 0;
    if(NULL==path)
        return -1;
	struct stat st = {0};

    if (stat(path, &st) == -1) {
        //mkdir("/some/directory", 0700);
        int r = mkdir( path, mode );
        if( r == 0 ) {
            fprintf(stdout, "genreate: %s\n", path);
        }
        else if( r == -1 ) {
            //perror( "error:directory already exist or invalid directory.\n" );
            fprintf(stderr, "error:%d:%s", errno, strerror(errno) );
            return -1;
        }
    }
    else {
        IF_VERBOSE fprintf(stderr, "directory already exist: %s\n", path);
        return -1;
    }
	return 0;
}

//PATH
//FILE
//CONTENT
//MODE

int add_file_to_dirctory(char *path, char *file, char *data, char *fmode)
{
	int r = 0;
    FILE *fp = NULL;
    char *mode =  (char *)"w";
    char filename[512];
    if(!path)
        return -1;
	struct stat st = {0};

    fprintf(stderr, "add_file_to_dirctory: path=[%s], file=[%s], data=[%s], mode=[%s]\n", path, file, data, fmode);

    if (stat(path, &st) == -1) {
        fprintf(stderr, "error:%d:%s", errno, strerror(errno) );
        return -1;
    }

    memset(filename, 0, sizeof(filename));
    sprintf(filename, "%s/%s", path, file);
    if (stat(filename, &st) != -1) {
        fprintf(stderr, "error:%d:%s", errno, strerror(errno) );
        return -1;
    }

    //fprintf(stderr, "filename: %s\n", filename);

    if(fmode != NULL)
        mode = fmode;
    
    fp = fopen(filename, "w");
    //for ecc aem data saving
    //fp = fopen(filename, "wb+");
    if( fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:mkfopendir:%s, %s\n", filename, strerror(errno));
        return -1;
    } 
    else {
        fprintf(fp, "%s", data);
        //fwrite(data,sizeof(data),1,fp);
    }

    fclose(fp);
    
    fprintf(stdout, "generate: %s\n", filename);

	return 0;
}


char *repl_str(const char *str, const char *from, const char *to) {

	/* Adjust each of the below values to suit your needs. */

	/* Increment positions cache size initially by this number. */
	size_t cache_sz_inc = 16;
	/* Thereafter, each time capacity needs to be increased,
	 * multiply the increment by this factor. */
	const size_t cache_sz_inc_factor = 3;
	/* But never increment capacity by more than this number. */
	const size_t cache_sz_inc_max = 1048576;

	char *pret, *ret = NULL;
	const char *pstr2, *pstr = str;
	size_t i, count = 0;
	#if (__STDC_VERSION__ >= 199901L)
	uintptr_t *pos_cache_tmp, *pos_cache = NULL;
	#else
	ptrdiff_t *pos_cache_tmp, *pos_cache = NULL;
	#endif
	size_t cache_sz = 0;
	size_t cpylen, orglen, retlen, tolen, fromlen = strlen(from);

	/* Find all matches and cache their positions. */
	while ((pstr2 = strstr(pstr, from)) != NULL) {
		count++;

		/* Increase the cache size when necessary. */
		if (cache_sz < count) {
			cache_sz += cache_sz_inc;
			pos_cache_tmp = realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
			if (pos_cache_tmp == NULL) {
				goto end_repl_str;
			} else pos_cache = pos_cache_tmp;
			cache_sz_inc *= cache_sz_inc_factor;
			if (cache_sz_inc > cache_sz_inc_max) {
				cache_sz_inc = cache_sz_inc_max;
			}
		}

		pos_cache[count-1] = pstr2 - str;
		pstr = pstr2 + fromlen;
	}

	orglen = pstr - str + strlen(pstr);

	/* Allocate memory for the post-replacement string. */
	if (count > 0) {
		tolen = strlen(to);
		retlen = orglen + (tolen - fromlen) * count;
	} else	retlen = orglen;
	ret = malloc(retlen + 1);
	if (ret == NULL) {
		goto end_repl_str;
	}

	if (count == 0) {
		/* If no matches, then just duplicate the string. */
		strcpy(ret, str);
	} else {
		/* Otherwise, duplicate the string whilst performing
		 * the replacements using the position cache. */
		pret = ret;
		memcpy(pret, str, pos_cache[0]);
		pret += pos_cache[0];
		for (i = 0; i < count; i++) {
			memcpy(pret, to, tolen);
			pret += tolen;
			pstr = str + pos_cache[i] + fromlen;
			cpylen = (i == count-1 ? orglen : pos_cache[i+1]) - pos_cache[i] - fromlen;
			memcpy(pret, pstr, cpylen);
			pret += cpylen;
		}
		ret[retlen] = '\0';
	}

end_repl_str:
	/* Free the cache and return the post-replacement string,
	 * which will be NULL in the event of an error. */
	free(pos_cache);
	return ret;
}



// Here is the code for unicode strings!
int mystrstr(wchar_t *txt1,wchar_t *txt2)
{
    wchar_t *posstr=wcsstr(txt1,txt2);
    if(posstr!=NULL)
    {
        return (posstr-txt1);
    }else
    {
        return -1;
    }
}

// assume: supplied buff is enough to hold generated text
void StringReplace(wchar_t *buff,wchar_t *txt1,wchar_t *txt2)
{
    wchar_t *tmp;
    wchar_t *nextStr;
    int pos;

    tmp=wcsdup(buff);

    pos=mystrstr(tmp,txt1);
    if(pos!=-1) {
        buff[0]=0;
        wcsncpy(buff,tmp,pos);
        buff[pos]=0;

        wcscat(buff,txt2);
        nextStr=tmp+pos+wcslen(txt1);

        while(wcslen(nextStr)!=0) {
            pos=mystrstr(nextStr,txt1);
            if(pos==-1) {
                wcscat(buff,nextStr);
                break;
            }

            wcsncat(buff,nextStr,pos);
            wcscat(buff,txt2);

            nextStr=nextStr+pos+wcslen(txt1);   
        }
    }

    free(tmp);
}

char * dump_file_content(const char * f_name, int * err, size_t * f_size) {
    char * buffer;
    size_t length;
    FILE * f = fopen(f_name, "rb");
    size_t read_length;

    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (length > DUMP_FILE_SIZE_LIMIT) {
            *err = FILE_TO_LARGE;
            return NULL;
        }

        buffer = (char *)malloc(length + 1);

        if (length) {
            read_length = fread(buffer, 1, length, f);
            if (length != read_length) {
                 *err = FILE_READ_ERROR;
                 return NULL;
            }
        }

        fclose(f);

        *err = FILE_OK;
        buffer[length] = '\0';
        *f_size = length;
    }
    else {
        *err = FILE_NOT_EXIST;

        return NULL;
    }
    return buffer;
}





char* GZPKI_generate_PRIKEY(char *curve_name, char *pwd, char *encrypt_algo,  int *len, char *keyfile)
{
    int r = CMS_RET_UNDEF;
    char *out = NULL;
	char rbuff[32];
    
    GZPKI_CTX ctx;

    GZPKI_init_ctx(&ctx);
    GZPKI_set_genkey(&ctx, 1);
	
	ctx.outtype = FORMAT_MEM;
	ctx.outformat = FORMAT_PEM;
	ctx.noout = 1;

	(is_valid_cipher(encrypt_algo) == 1) ? GZPKI_set_cipher(&ctx, encrypt_algo) : GZPKI_set_cipher(&ctx, (char *)"aes256");
	
	ctx.curve_name = GZPKI_strdup(curve_name);

    IF_VERBOSE fprintf(stderr, "curve: ["ANSI_COLOR_CYAN_BOLD"%s"ANSI_COLOR_RESET"]\n", ctx.curve_name);
	IF_VERBOSE fprintf(stderr, "pwd  : ["ANSI_COLOR_CYAN_BOLD"%s"ANSI_COLOR_RESET"]\n", pwd);

    if(keyfile){
        GZPKI_set_outfile(&ctx, keyfile, FORMAT_PEM);
    } else {
	    GZPKI_set_outfile(&ctx, NULL, FORMAT_PEM);
    }

    GZPKI_set_passout(&ctx, pwd);

    r = GZPKI_do_ECPARAM(&ctx);

	if(r!=CMS_RET_OK) {
		GZPKI_print_errors(&ctx);
		fprintf(stderr, "RET: ["ANSI_COLOR_CYAN_BOLD"%d"ANSI_COLOR_RESET"], CMS_RET_OK=%d, r=%d\n", ctx.errcode, CMS_RET_OK, r);
		fprintf(stderr, "ERR: ["ANSI_COLOR_CYAN_BOLD"%s"ANSI_COLOR_RESET"]\n", ctx.errstr);
	}
	else {
		fprintf(stderr, "success:ret=["ANSI_COLOR_CYAN_BOLD"%d"ANSI_COLOR_RESET"], CMS_RET_OK=%d, r=%d\n", ctx.errcode, CMS_RET_OK, r);
    }

    if(r == CMS_RET_OK) {
        if( ctx.outtype == FORMAT_MEM ) {
		    out = GZPKI_strdup(GZPKI_get_mem(&ctx));
		    fprintf(stderr, "GZPKI_generate_PRIKEY: out string: %s\n", out);
            *len = GZPKI_get_mem_length(&ctx);
        }
        else if( ctx.outtype == FORMAT_FILE) {
            out = GZPKI_strdup(keyfile);
		    fprintf(stderr, "GZPKI_generate_PRIKEY:out file: %s\n", out);
            //IF_VERBOSE fprintf(stderr, "out string: %s\n", GZPKI_get_mem(&ctx));
            //*len = strlen(keyfile);
        }
    }
    else {
        out = NULL;
		*len = -1;
    }

    //ecparam_context_free(&ctx);
    GZPKI_free_ctx(&ctx);
    return out;
}



char* GZPKI_generate_CSR(char *key_pem, char *keyfile, char *pwd, char *configfile, char *dn_str, char *csrfile, 
        char *req_section,
        char *req_exts,
        /*dn_str이 null이면 */
        char *dn_c, 
        char *dn_st, 
        char *dn_l, 
        char *dn_o, 
        char *dn_ou, 
        char *dn_cn, 
        char *dn_e, 
        int format) {
	//char *csr_pem = NULL;
    GZPKI_CTX ctx;
    char *pp = NULL;
    
    char *passin = GZPKI_strdup(pwd);

    int r =  CMS_RET_UNDEF;
   
    GZPKI_init_ctx(&ctx);
    GZPKI_set_newreq(&ctx, CMS_OPT_ON);
    
    if(csrfile) {
        GZPKI_set_outfile(&ctx, csrfile, FORMAT_PEM);
    } else {
        GZPKI_set_outfile(&ctx, NULL, FORMAT_PEM);
	    ctx.outtype = FORMAT_MEM;
    }

    ctx.batch = 1;
    //BUFFER
    if(key_pem && !keyfile) {
	    r = GZPKI_set_key_buffer(&ctx, key_pem, passin, 1);
	    if(CMS_RET_OK != r)  {
		    fprintf(stderr, "error:GZPKI_set_key_buffer():r=%d\n", r);
		    return NULL;
	    }
    }
    //KEY FILE
    else if(!key_pem && keyfile) {
        r = GZPKI_set_keyfile(&ctx, keyfile, passin, 1);
	    if(CMS_RET_OK != r)  {
		    fprintf(stderr, "error:GZPKI_set_keyfile():r=%d\n", r);
		    return NULL;
	    }
    }
    
    int err;
    size_t f_size;
    if(format == FORMAT_FILE) {
        if(configfile) {
            memset(ctx.app_config, 0, sizeof(ctx.app_config));
            sprintf(ctx.app_config, "%s", configfile);    
        }
    }
    else if(format == FORMAT_MEM) {

        memset(ctx.app_config, 0, sizeof(ctx.app_config));
        char *tmp = NULL;
        tmp =  dump_file_content(configfile, &err, &f_size);
        
        //IF_VERBOSE fprintf(stderr, INFO_TAG"ORIGINAL_CFG:\n%s\n", tmp);


        tmp = repl_str(tmp, "__countryName__",         dn_c==NULL ?"":dn_c );
        tmp = repl_str(tmp, "__stateOrProvinceName__", dn_st==NULL?"":dn_st);
        tmp = repl_str(tmp, "__localityName__",        dn_l==NULL ?"":dn_l );
        tmp = repl_str(tmp, "__organizationName__",    dn_o==NULL ?"":dn_o );
        tmp = repl_str(tmp, "__organizationUnitName__",dn_ou==NULL?"":dn_ou);
        tmp = repl_str(tmp, "__commonName__",          dn_cn==NULL?"":dn_cn);
        tmp = repl_str(tmp, "__emailAddress__",        dn_e==NULL ?"":dn_e );

        /*if() StringReplace(tmp, "", dn_st);
        if(dn_l) StringReplace(tmp, "", dn_l);
        if(dn_o) StringReplace(tmp, "", dn_o);
        if() StringReplace(tmp, "", dn_ou);
        if(dn_cn) StringReplace(tmp, "", dn_cn);
        if() StringReplace(tmp, "", dn_e);*/

        //IF_VERBOSE fprintf(stderr, INFO_TAG"REPLACED_CFG:\n%s\n", tmp);
        
        if(tmp)  {
            ctx.req_conf_str = GZPKI_strdup(tmp);
            free(tmp);
        }

    }

    if(dn_str) {
        ctx.subj = GZPKI_strdup(dn_str);
    }
    
    if(req_section)
        ctx.req_section = GZPKI_strdup(req_section);
        
    if(req_exts)
        ctx.req_exts = GZPKI_strdup(req_exts);

    r = GZPKI_do_REQ(&ctx);
    //char tmp[4096];
    //memset(tmp, 0, 4096);
	if(CMS_RET_OK == r) {
        if( ctx.outtype == FORMAT_MEM ) {
            int len = GZPKI_get_mem_length(&ctx);
            pp = (char *)malloc(len);
        
            snprintf(pp, len+1,  "%s", (char *)GZPKI_get_mem(&ctx));
            IF_VERBOSE fprintf(stderr, "REQ(pp):\n%s\n", pp);

        } 
        else if( ctx.outtype == FORMAT_FILE ) {
            pp = (char *)malloc(strlen(csrfile)+1);
            sprintf(pp, "%s", (char *)csrfile);
        }
	}
    else  {
		printf("error: request generation failed, r=%d, errcode=%d, errstr=%s\n", r, ctx.errcode, ctx.errstr); 
        pp = NULL;
        goto end;
        
    }

end:
    if(pp)
        fprintf(stderr,"csr:%s\n", pp);
    GZPKI_free_ctx(&ctx);
    return pp;
}


#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>


int copy_file(const char *to, const char *from)
{
    int fd_from = open(from, O_RDONLY);
    if(fd_from < 0)
        return -1;
    struct stat Stat;
    if(fstat(fd_from, &Stat)<0)
        goto out_error;

    void *mem = mmap(NULL, Stat.st_size, PROT_READ, MAP_SHARED, fd_from, 0);
    if(mem == MAP_FAILED)
        goto out_error;

    int fd_to = creat(to, 0666);
    if(fd_to < 0)
        goto out_error;

    ssize_t nwritten = write(fd_to, mem, Stat.st_size);
    if(nwritten < Stat.st_size)
        goto out_error;

    if(close(fd_to) < 0) {
        fd_to = -1;
        goto out_error;
    }
    close(fd_from);

    /* Success! */
    return 0;

out_error:;
  int saved_errno = errno;

  close(fd_from);
  if(fd_to >= 0)
    close(fd_to);

  errno = saved_errno;
  return -1;
}


const char* getfield(char* line, int num)
{
    const char* tok;
    for (tok = strtok(line, ",");
            tok && *tok;
            tok = strtok(NULL, ",\n"))
    {
        if (!--num)
            return tok;
    }
    return NULL;
}


/* Copyright (C) 1999 Lucent Technologies */
/* Excerpted from 'The Practice of Programming' */
/* by Brian W. Kernighan and Rob Pike */

#include <stdio.h>
#include <string.h>

char buf[1024];		/* input line buffer */
char *field[512];	/* fields */
char *unquote(char *);
/* csvgetline: read and parse line, return field count */
/* sample input: "LU",86.25,"11/4/1998","2:19PM",+4.0625 */
int csvgetline(FILE *fin)
{
    int nfield;
    char *p, *q;
    /* spacer */
    if (fgets(buf, sizeof(buf), fin) == NULL)
        return -1;
    nfield = 0;
    for (q = buf; (p=strtok(q, ",\n\r")) != NULL; q = NULL)
        field[nfield++] = unquote(p);
    return nfield;
}

/* unquote: remove leading and trailing quote */
char *unquote(char *p)
{
	if (p[0] == '"') {
		if (p[strlen(p)-1] == '"')
			p[strlen(p)-1] = '\0';
		p++;
	}
	return p;
}



/*
int main(void)
{
	int i, nf;
    // spacer 
	while ((nf = csvgetline(stdin)) != -1)
		for (i = 0; i < nf; i++)
			printf("field[%d] = '%s'\n", i, field[i]);
	return 0;
}
*/



char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                         'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                         'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                         'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                         'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                         'w', 'x', 'y', 'z', '0', '1', '2', '3',
                         '4', '5', '6', '7', '8', '9', '+', '/'};

static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
    free(decoding_table);
}


char *base64(unsigned char *data,int input_length)
{
    int output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';

    return encoded_data;
}


char *decode64(unsigned char *data, int input_length ) 
{

	int output_length;
    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) {
        IF_VERBOSE printf("error:input length=%d\n", input_length);
        //return NULL;
    }

    
    output_length = input_length / 4 * 3;

    IF_VERBOSE printf("decode64: data=[%s], len=%d, outlen=%d\n", data, input_length, output_length);

	//--fprintf(fp, "    base64 decode in=%d, out=%d\n", input_length, output_length);
    if (data[input_length - 1] == '=') (output_length)--;
    if (data[input_length - 2] == '=') (output_length)--;

    char *decoded_data = malloc(output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}



unsigned char *GZPKI_gen_random_pass(int nbytes)
{
    int r, i, num = nbytes;
    char *p = NULL;

    unsigned char buf[4096];
    memset(buf, 0, sizeof(buf));

    while (num > 0) {
        int chunk;
        chunk = num;
        if (chunk > (int)sizeof(buf))
            chunk = sizeof(buf);

        r = RAND_bytes(buf, chunk);
        if (r <= 0) {
            fprintf(stderr, ERR_TAG"fail to random bytes(%d)\n", nbytes);
            return NULL;
        }
        
        for (i = 0; i < chunk; i++)
                if(0) {
                if (fprintf(stdout, "%02x", buf[i]) != 2)
                    return NULL;
            }
        num -= chunk;
    }

    //p =  malloc(SHA256_DIGEST_LENGTH*2+1);
    //GZPKI_sha256_hash(buf, p);
    //char *GZPKI_ripemd160_hash(unsigned char *string, int len);
    p = GZPKI_ripemd160_hash(buf, nbytes);
    //p =  malloc(nbytes);
    //memcpy(p, buf, nbytes);

    p[8] = 0;

    //IF_VERBOSE fprintf(stderr, "RAND:%d-BYTES: '%s'\n", nbytes, p);
	return p;
}

char *bin2hex(const unsigned char *bin, size_t len)
{
	char   *out;
	size_t  i;

	if (bin == NULL || len == 0)
		return NULL;

	out = malloc(len*2+1);
	for (i=0; i<len; i++) {
		out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
		out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
	}
	out[len*2] = '\0';

	return out;
}

int GZPKI_init_token(TOKEN_CTX *tk, char *token_dir) 
{
    if (app_isdir(token_dir) <= 0) {
        fprintf(stderr, "error:token:init: %s is not a directory\n", token_dir);
        perror(token_dir);
        return -1;
    }
    else {
        tk->token_dir = GZPKI_strdup(token_dir);
        IF_VERBOSE fprintf(stderr,  "init token: dir = %s\n", tk->token_dir);
    }
    //FILE
    tk->device_certfile = tk->server_certfile = tk->ca_certfile = NULL;
    tk->device_keyfile = tk->server_keyfile = tk->ca_keyfile = NULL;

    //X509
    tk->device_cert = tk->server_cert = tk->ca_cert = NULL;

    //EVP_PKEY
    tk->device_key = tk->server_key = tk->ca_key = NULL;
    tk->device_password = NULL;

    //SECRET for ECC P2
    tk->x1_filename = tk->y1_filename = tk->ke_filename = NULL;
    tk->x1_hexstr = tk->y1_hexstr = tk->ke_hexstr = NULL;
    //BIGNUM
    tk->x1 = tk->y1 = tk->ke = NULL;

   
    GZPKI_get_token(tk, 1, 0);

   
    return 0;
}


int GZPKI_free_token(TOKEN_CTX *tk) {

    if(tk->device_certfile) free(tk->device_certfile);
    if(tk->device_keyfile) free(tk->device_keyfile);
    if(tk->device_password) free(tk->device_password);

    if(tk->server_certfile) free(tk->server_certfile);
    if(tk->server_keyfile) free(tk->server_keyfile);

    if(tk->ca_certfile) free(tk->ca_certfile);
    if(tk->ca_keyfile) free(tk->ca_keyfile);


    if(tk->x1_filename) free(tk->x1_filename);
    if(tk->y1_filename) free(tk->y1_filename);
    if(tk->ke_filename) free(tk->ke_filename);

    if(tk->x1_hexstr) free(tk->x1_hexstr);
    if(tk->y1_hexstr) free(tk->y1_hexstr);
    if(tk->ke_hexstr) free(tk->ke_hexstr);
    
    //X509 Certificate free
    if(tk->device_cert) X509_free(tk->device_cert);
    if(tk->server_cert) X509_free(tk->server_cert);
    if(tk->ca_cert) X509_free(tk->ca_cert);


    if(tk->device_key) EVP_PKEY_free(tk->device_key);
    if(tk->server_key) EVP_PKEY_free(tk->server_key);
    if(tk->ca_key) EVP_PKEY_free(tk->ca_key);
    
    return 0;
}

int GZPKI_get_token(TOKEN_CTX *tk, int flag_load_cert, int flag_load_key) {

    char tmp[512];

    if (app_isdir(tk->token_dir) <= 0) {
        fprintf(stderr, "error: %s is not a directory\n", tk->token_dir);
        perror(tk->token_dir);
        return -1;
    }

#define _TOKEN_GET_FILENAME(__target, __src) memset(tmp, 0, sizeof(tmp)); \
    sprintf(tmp, "%s/cert/%s", tk->token_dir, __src); \
    __target = GZPKI_strdup(tmp)

    _TOKEN_GET_FILENAME(tk->device_certfile, "device/device.pem");
    _TOKEN_GET_FILENAME(tk->device_keyfile, "device/device.key");

    _TOKEN_GET_FILENAME(tk->server_certfile, "server/server.pem");
    _TOKEN_GET_FILENAME(tk->server_keyfile, "server/server.key");

    //Secret for ECC P2 Encrypt
    _TOKEN_GET_FILENAME(tk->x1_filename, "server/secret.x1");
    _TOKEN_GET_FILENAME(tk->y1_filename, "server/secret.y1");
    _TOKEN_GET_FILENAME(tk->ke_filename, "server/secret.ke");

    _TOKEN_GET_FILENAME(tk->ca_certfile, "ca/ca.pem");
    _TOKEN_GET_FILENAME(tk->ca_keyfile, "server/server.key");

    //load certifiate
    char data[256];
    if(1 == flag_load_cert) {
        if(tk->device_certfile && is_file_exists(tk->device_certfile)) {
            tk->device_cert = load_cert((const char *)tk->device_certfile, FORMAT_PEM, "Device Certificate");
            IF_VERBOSE {
                fprintf(stderr, "load device certificate:%s\n", tk->device_certfile);
                X509_NAME_oneline(X509_get_issuer_name(tk->device_cert), data, 256); 
                printf("Subject DN: "color_yellow"%s"color_reset"\n", (char *)data);
            }
        }
        else {
            IF_VERBOSE fprintf(stderr, "load device certificate failed:%s\n", tk->device_certfile);
        }

        if(tk->server_certfile && is_file_exists(tk->server_certfile)) {
            tk->server_cert = load_cert((const char *)tk->server_certfile, FORMAT_PEM, "Server Certificate");
            IF_VERBOSE {
                fprintf(stderr, "load server certificate:%s\n", tk->server_certfile);
                X509_NAME_oneline(X509_get_issuer_name(tk->server_cert), data, 256); 
                printf("Subject DN: "color_yellow"%s"color_reset"\n", (char *)data);
            }
        }
        else {
            IF_VERBOSE fprintf(stderr, "load server certificate failed:%s\n", tk->server_certfile);
        }

        if(tk->ca_certfile && is_file_exists(tk->ca_certfile)) {
            tk->ca_cert = load_cert((const char *)tk->ca_certfile, FORMAT_PEM, "CA Certificate");
            IF_VERBOSE {
                fprintf(stderr, "load CA certificate:%s\n", tk->ca_certfile);
                X509_NAME_oneline(X509_get_issuer_name(tk->ca_cert), data, 256); 
                printf("Subject DN: "color_yellow"%s"color_reset"\n", (char *)data);
            }
        }
        else {
            IF_VERBOSE fprintf(stderr, "load CA certificate failed:%s\n", tk->ca_certfile);
        }
    }

    //load secret from file
    char *mode = "rb";
    FILE *fp = NULL;
    if(1) {
        if(tk->x1_filename && is_file_exists(tk->x1_filename)) {
            fp = fopen(tk->x1_filename, mode);
            fread(&tmp,sizeof(tmp),1,fp);
            fclose(fp);
            fp = NULL;
            tk->x1_hexstr = GZPKI_strdup(tmp);
            IF_VERBOSE {
                fprintf(stderr, "secret X1 hex string: '"color_yellow"%s"color_reset"'\n", tk->x1_hexstr);
            }
        }
        else {
            IF_VERBOSE fprintf(stderr, "no secret X1 file: [%s]\n", tk->x1_filename);
        }

        if(tk->y1_filename && is_file_exists(tk->y1_filename)) {
            fp = fopen(tk->y1_filename, mode);
            memset(tmp, 0, sizeof(tmp));
            fread(&tmp,sizeof(tmp),1,fp);
            fclose(fp);
            fp = NULL;
            tk->y1_hexstr = GZPKI_strdup(tmp);
            IF_VERBOSE {
                fprintf(stderr, "secret Y1 hex string: '"color_yellow"%s"color_reset"'\n", tk->y1_hexstr);
            }
        }
        else {
            IF_VERBOSE fprintf(stderr, "no secret Y1 file:%s\n", tk->y1_filename);
        }

        if(tk->ke_filename && is_file_exists(tk->ke_filename)) {
            fp = fopen(tk->ke_filename, mode);
            memset(tmp, 0, sizeof(tmp));
            fread(&tmp,sizeof(tmp),1,fp);
            fclose(fp);
            fp = NULL;
            tk->ke_hexstr = GZPKI_strdup(tmp);
            IF_VERBOSE {
                fprintf(stderr, "secret KE hex string: '"color_yellow"%s"color_reset"'\n", tk->ke_hexstr);
            }
        }
        else {
            IF_VERBOSE fprintf(stderr, "no secret KE file:%s\n", tk->ke_filename);
        }

    }

    if(1 == flag_load_key) {
        //char *keyfile = keyin;   
        //private_key = load_key(keyfile, FORMAT_PEM, 0, passin, NULL, "key");
    }

    return 0;
}

char * GZPKI_get_token_device_password(TOKEN_CTX *tk){
    return generate_device_password(NULL,tk->device_certfile);
}

int GZPKI_get_token_load_key(TOKEN_CTX *tk, int flag_load_key, char *pass) {

    char tmp[512];

    if (flag_load_key & LOAD_NO_KEY) {  
        IF_VERBOSE {
            fprintf(stderr, "no private key load from token:%s\n", tk->token_dir);
        }
        return 0;
    }  

    char *dev_pass = NULL;
    char *keyfile = NULL;
    
    if (flag_load_key == LOAD_DEVICE_KEY) {
        keyfile = tk->device_keyfile;
        IF_VERBOSE fprintf(stderr, "load DEVICE key:flag=0x%x, file="color_yellow"%s"color_reset"\n", flag_load_key, keyfile);
    }
    else if (flag_load_key == LOAD_SERVER_KEY) {
        keyfile = tk->server_keyfile;
        IF_VERBOSE fprintf(stderr, "load SERVER key:flag=0x%x, file="color_yellow"%s"color_reset"\n", flag_load_key, keyfile);
    }
    //---------- CA uses KEYPASS
    else if (flag_load_key & LOAD_CA_KEY) {
        keyfile = tk->ca_keyfile;
    }
    
    if(pass) {
        dev_pass = pass;
        IF_DEBUG fprintf(stderr,"debug:pass:input:%s\n", dev_pass);
    }
    else {
        IF_VERBOSE fprintf(stderr, "null pass: generate device password\n");
        dev_pass = generate_device_password(NULL,tk->device_certfile);
        IF_DEBUG fprintf(stderr,"debug:pass:generated:%s\n", dev_pass);
    }
    
    if(!(keyfile && is_file_exists(keyfile))) {
        IF_VERBOSE fprintf(stderr, "error:load device private key failed:%s\n", keyfile);
        return -1;
    }

    if (flag_load_key == LOAD_DEVICE_KEY) {
        tk->device_key = load_key((const char *)keyfile, FORMAT_PEM, 0, dev_pass, NULL, "token device key");
        if(!tk->device_key) {
           IF_VERBOSE fprintf(stderr, "load device private key:%s\n", keyfile);
           goto err;
        }
    }
    else if (flag_load_key == LOAD_SERVER_KEY) {
        tk->server_key = load_key((const char *)keyfile, FORMAT_PEM, 0, dev_pass, NULL, "token server key");
        if(!tk->server_key) {
           IF_VERBOSE fprintf(stderr, "load device private key:%s\n", keyfile);
           goto err;
        }
    }
    
    return 0;
err:
    return -1;    
}




