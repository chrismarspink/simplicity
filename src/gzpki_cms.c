
#include <stdio.h>
#include <string.h>
#include <unistd.h>

# include <openssl/crypto.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/x509_vfy.h>
# include <openssl/x509v3.h>
# include <openssl/cms.h>
# include <openssl/evp.h>
# include <openssl/ui.h>
//# include <openssl/opensslconf.h>

#include "gzpki_types.h"
#include "gzpki_common.h"
#include "gzpki_ecc.h"
#include "gzpki_cms.h"

/*
 * GZCMS MAIN, 2020/04/28, AUTHOR:jkkim@greenzonesecu.com
 */

/**
 @file gzpki_cms.c
 @date 2019/05/09
 @author jkkim@greenzonesecu.com
 @brief CMS 메시지의 생성, 검증 관련 코드 
  */


static STACK_OF(GENERAL_NAMES) *make_names_stack(STACK_OF(OPENSSL_STRING) *ns);
static void gnames_stack_print(STACK_OF(GENERAL_NAMES) *gns);
static STACK_OF(GENERAL_NAMES) *make_names_stack(STACK_OF(OPENSSL_STRING) *ns);
static int cms_set_pkey_param(EVP_PKEY_CTX *pctx,STACK_OF(OPENSSL_STRING) *param); 
static CMS_ReceiptRequest *make_receipt_request(STACK_OF(OPENSSL_STRING) *rr_to, int rr_allorfirst, STACK_OF(OPENSSL_STRING) *rr_from);
ENGINE *setup_engine(const char *engine, int debug);

static STACK_OF(GENERAL_NAMES) *make_names_stack(STACK_OF(OPENSSL_STRING) *ns) {
    int i;
    STACK_OF(GENERAL_NAMES) *ret;
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    ret = sk_GENERAL_NAMES_new_null();
    if (ret == NULL)
        goto err;
    for (i = 0; i < sk_OPENSSL_STRING_num(ns); i++) {
        char *str = sk_OPENSSL_STRING_value(ns, i);
        gen = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_EMAIL, str, 0);
        if (gen == NULL)
            goto err;
        gens = GENERAL_NAMES_new();
        if (gens == NULL)
            goto err;
        if (!sk_GENERAL_NAME_push(gens, gen))
            goto err;
        gen = NULL;
        if (!sk_GENERAL_NAMES_push(ret, gens))
            goto err;
        gens = NULL;
    }

    return ret;

 err:
    sk_GENERAL_NAMES_pop_free(ret, GENERAL_NAMES_free);
    GENERAL_NAMES_free(gens);
    GENERAL_NAME_free(gen);
    return NULL;
}

static int cms_set_pkey_param(EVP_PKEY_CTX *pctx, STACK_OF(OPENSSL_STRING) *param) {
    char *keyopt;
    int i;
    if (sk_OPENSSL_STRING_num(param) <= 0) {
        return CMS_RET_ERROR;
    }
    for (i = 0; i < sk_OPENSSL_STRING_num(param); i++) {
        keyopt = sk_OPENSSL_STRING_value(param, i);
        if (pkey_ctrl_string(pctx, keyopt) <= 0) {
            //IF_VERBOSE fprintf(stderr, "error:cms_set_pkey_param:parameter error \"%s\"\n", keyopt);
            //IF_VERBOSE fprintf(stderr, "parameter error \"%s\"\n", keyopt);
            ERR_print_errors(bio_err);
            return CMS_RET_ERROR;
        }
    }
    return CMS_RET_OK;
}

/**
    @return   NULL
    @warning 화면출력용/DEBUG-ONLY
*/

//test only
void gzcms_print_operation_str(int op) {
    if(op == SMIME_ENCRYPT) printf("%s ", "SMIME_ENCRYPT");
    if(op == SMIME_DECRYPT) printf("%s ", "SMIME_DECRYPT");        
    if(op == SMIME_SIGN)    printf("%s ", "SMIME_SIGN");        
    if(op == SMIME_VERIFY)  printf("%s ", "SMIME_VERIFY");        
    if(op == SMIME_CMSOUT)  printf("%s ", "SMIME_CMSOUT");        
    if(op == SMIME_RESIGN)  printf("%s ", "SMIME_RESIGN");        
    if(op == SMIME_DATAOUT) printf("%s ", "SMIME_DATAOUT");        
    if(op == SMIME_DATA_CREATE)   printf("%s ", "SMIME_DATA_CREATE");        
    if(op == SMIME_DIGEST_VERIFY) printf("%s ", "SMIME_DIGEST_VERIFY");        
    if(op == SMIME_DIGEST_CREATE) printf("%s ", "SMIME_DIGEST_CREATE");        
    if(op == SMIME_UNCOMPRESS)    printf("%s ", "SMIME_UNCOMPRESS");        
    if(op == SMIME_COMPRESS)      printf("%s ", "SMIME_COMPRESS");        
    if(op == SMIME_ENCRYPTED_DECRYPT)  printf("%s ", "SMIME_ENCRYPTED_DECRYPT");        
    if(op == SMIME_ENCRYPTED_ENCRYPT)  printf("%s ", "SMIME_ENCRYPTED_ENCRYPT");        
    if(op == SMIME_SIGN_RECEIPT)       printf("%s ", "SMIME_SIGN_RECEIPT");        
    if(op == SMIME_VERIFY_RECEIPT)     printf("%s ", "SMIME_VERIFY_RECEIPT");      
    printf("\n");
    return;
}

//test only
char *gzcms_get_format_str(int f) {
    char *fmstr = NULL;
    fmstr = (char *)malloc(32);
    if(f == FORMAT_UNDEF)        sprintf(fmstr, "%s", "FORMAT_UNDEF");
    else if(f == FORMAT_TEXT)    sprintf(fmstr, "%s", "FORMAT_TEXT");        
    else if(f == FORMAT_BINARY)  sprintf(fmstr, "%s", "FORMAT_BINARY");        
    else if(f == FORMAT_BASE64)  sprintf(fmstr, "%s", "FORMAT_BASE64");        
    else if(f == FORMAT_ASN1)    sprintf(fmstr, "%s", "FORMAT_ASN1");        
    else if(f == FORMAT_PEM)     sprintf(fmstr, "%s", "FORMAT_PEM");        
    else if(f == FORMAT_PKCS12)  sprintf(fmstr, "%s", "FORMAT_PKCS12");        
    else if(f == FORMAT_SMIME)   sprintf(fmstr, "%s", "FORMAT_SMIME");                        
    else if(f == FORMAT_ENGINE)  sprintf(fmstr, "%s", "FORMAT_ENGINE");        
    else if(f == FORMAT_PEMRSA)  sprintf(fmstr, "%s", "FORMAT_PEMRSA");        
    else if(f == FORMAT_ASN1RSA) sprintf(fmstr, "%s", "FORMAT_ASN1RSA");        
    else if(f == FORMAT_MSBLOB)  sprintf(fmstr, "%s", "FORMAT_MSBLOB");        
    else if(f == FORMAT_PVK)     sprintf(fmstr, "%s", "FORMAT_PVK");        
    else if(f == FORMAT_HTTP)    sprintf(fmstr, "%s", "FORMAT_HTTP");        
    else if(f == FORMAT_NSS)     sprintf(fmstr, "%s", "FORMAT_NSS");                                
    else                         sprintf(fmstr, "%s", "ERROR_FAIL_TO_GET_FORMAT");
    
    return fmstr;
}


#if 0 //DEL
int gzcms_context_init(GZCMS_CTX *ctx)
{
    IF_VERBOSE fprintf(stderr, "GZPKI: gzcms_ctx init...\n");
    
    ctx->bptr = NULL;
    ctx->intype = FORMAT_MEM;
    ctx->outtype = FORMAT_FILE;
    ctx->econtent_type = NULL;
    ctx->in = ctx->out = ctx->indata = ctx->rctin = NULL;
    ctx->cms = ctx->rcms = NULL;
    ctx->rr = NULL;
    ctx->e = NULL;
    ctx->key = NULL;
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
    ctx->infile = ctx->outfile = ctx->rctfile = NULL;
    ctx->passinarg = ctx->passin = ctx->signerfile = ctx->recipfile = NULL;
    ctx->to = ctx->from = ctx->subject = NULL;
    //ctx->key_first = ctx->key_param = NULL;
    ctx->flags = CMS_DETACHED;//= CMS_DETACHED;
    ctx->noout = CMS_OPT_OFF;
    ctx->print = CMS_OPT_OFF;
    ctx->keyidx = CMS_OPT_UNDEF;
    ctx->vpmtouched = CMS_OPT_OFF;
    ctx->informat = ctx->outformat = FORMAT_SMIME;
    ctx->operation = 0;
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

    if(!ctx->bio_in)    ctx->bio_in = dup_bio_in(FORMAT_TEXT);
    if(!ctx->bio_out)   ctx->bio_out = dup_bio_out(FORMAT_TEXT);
    if(!ctx->bio_err)   ctx->bio_err = dup_bio_err(FORMAT_TEXT);

    ctx->debug = _DEBUG_MODE_;
    ctx->verify_result = -1;
    ctx->digest_verify_result = -1;

    ctx->inbuffer = NULL;
    ctx->inbuffer_size = 0;

    ctx->outbuffer = NULL;
    ctx->outbuffer_size = 0;

    ctx->outdata = NULL;
    ctx->outdata_length = -1;

    ctx->errcode = 0;
    memset(ctx->errstr, 0, sizeof(ctx->errstr));

    //----------------------------------------
    //openssl init process 
    //----------------------------------------
    OpenSSL_add_all_algorithms();

#if 1
    if ((ctx->vpm = X509_VERIFY_PARAM_new()) == NULL) {
        IF_VERBOSE fprintf(stderr, "error:gzcms_context_init():vpm parameter set failed.\n");
        return CMS_RET_ERROR;
    }
#endif

    return CMS_RET_OK;
}
#endif


//TODO: add function to GZPKI_CTX
static int verify_err = 0;
void policies_print(X509_STORE_CTX *ctx);
static int cms_cb(int ok, X509_STORE_CTX *ctx) {
    int error;
    error = X509_STORE_CTX_get_error(ctx);
    verify_err = error;

    if ((error != X509_V_ERR_NO_EXPLICIT_POLICY)
        && ((error != X509_V_OK) || (ok != 2)))
        return ok;

    policies_print(ctx);
    return ok;
}

//FROM(apps.c)
static int save_certs(char *signerfile, STACK_OF(X509) *signers) {
    int i;
    BIO *tmp;
    if (signerfile == NULL) {
        return CMS_RET_ERROR;
    }
    tmp = BIO_new_file(signerfile, "w");
    if (tmp == NULL) {
        return CMS_RET_ERROR;
    }
    for (i = 0; i < sk_X509_num(signers); i++) {
        PEM_write_bio_X509(tmp, sk_X509_value(signers, i));
    }
    BIO_free(tmp);
    return CMS_RET_OK;
}

X509_STORE *setup_verify(const char *CAfile, const char *CApath, int noCAfile, int noCApath);


/**
 * @brief 
 * 암호화에서 사용되는 인증서 파일을 설정
 * @param ctx GZCMS_CTX 포인터
 * @param recipfile CMS 메시지를 수신할 사용자의 인증서
 * @return CMS_RET_OK : 성공
 */
int GZPKI_set_recipfile(GZPKI_CTX *ctx, char *recipfile) {
    ctx->recipfile = (char *)GZPKI_strdup((char *)recipfile);
    return CMS_RET_OK;
}


/**
 * @brief 암호용 인증서 파일 설정 설정.
 * @param ctx GZCMS_CTX 포인터
 * @param recipfile CMS 메시지를 수신할 사용자의 인증서
 * @param format : 인증서 파일 형식(FORMAT_SMIME | FORMAT_PEM | FORMAT_ASN1)
 * @return CMS_RET_OK: 로딩 성공
 * @return CMS_RET_ERROR: 로딩 실패
 */
//int gzcms_load_recip_certificate(GZCMS_CTX *ctx, char *recipfile, int format) {
int GZPKI_load_recip_certificate(GZPKI_CTX *ctx, char *recipfile, int format) {
    GZPKI_set_recipfile(ctx, recipfile);
    if( NULL == (ctx->recip = load_cert(ctx->recipfile, format, "gzcms: load recipient certificate")) )  {
        printf(ERR_TAG"error:GZPKI_load_recip_certificate:%s\n", ctx->recipfile?ctx->recipfile:"null");
        return CMS_RET_ERROR;
    }
    return CMS_RET_OK;
}


#define GZCMS_SetCA gzcms_set_ca
#define cms_set_CAfile gzcms_set_ca
int gzcms_set_ca(GZCMS_CTX *ctx, char *CAfile, char *CApath, int noCAfile, int noCApath)
{
    ctx->CAfile = (char *)GZPKI_strdup(CAfile);
    ctx->CApath = (char *)GZPKI_strdup(CApath);
    ctx->noCAfile = noCAfile;
    ctx->noCApath = noCApath;
    return CMS_RET_OK;
}

#define GZCMS_SetVerifyCallback(X, CB) X509_STORE_set_verify_cb(X->store, CB)

int GZPKI_get_content_type(GZPKI_CTX *ctx) {
    int r = GZCMS_TYPE_UNDEF;
    if(ctx->cms == NULL)
        goto end;

    r = OBJ_obj2nid(CMS_get0_type(ctx->cms));
    return r;

end:
    return GZCMS_TYPE_UNDEF;
}

#define GZCMS_IS_DETACHED       0
#define GZCMS_IS_NOT_DETACHED   1
int GZCMS_IsDetached(GZCMS_CTX *ctx){

    ASN1_OCTET_STRING **pos;
    pos = CMS_get0_content(ctx->cms);
    if (!pos)
        return CMS_RET_ERROR;
    if (*pos)
        return CMS_RET_ERROR;

    return CMS_RET_OK;
}


static void gnames_stack_print(STACK_OF(GENERAL_NAMES) *gns)
{
    STACK_OF(GENERAL_NAME) *gens;
    GENERAL_NAME *gen;
    int i, j;

    for (i = 0; i < sk_GENERAL_NAMES_num(gns); i++) {
        gens = sk_GENERAL_NAMES_value(gns, i);
        for (j = 0; j < sk_GENERAL_NAME_num(gens); j++) {
            gen = sk_GENERAL_NAME_value(gens, j);
            BIO_puts(bio_err, "    ");
            puts("    ");
            GENERAL_NAME_print(bio_err, gen);
            BIO_puts(bio_err, "\n");
            puts("\n");
        }
    }
    return;
}


static void receipt_request_print(CMS_ContentInfo *cms) {
    //TODO
    //bio_err 문제 해결 후 원복 필요
#if 1    
    STACK_OF(CMS_SignerInfo) *sis;
    CMS_SignerInfo *si;
    CMS_ReceiptRequest *rr;
    int allorfirst;
    STACK_OF(GENERAL_NAMES) *rto, *rlist;
    ASN1_STRING *scid;
    int i, rv;
    sis = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(sis); i++) {
        si = sk_CMS_SignerInfo_value(sis, i);
        rv = CMS_get1_ReceiptRequest(si, &rr);
        
        IF_VERBOSE fprintf(stderr, "Signer %d:\n", i + 1);
        printf("Signer %d:\n", i + 1);
        if (rv == 0) {
            IF_VERBOSE fprintf(stderr, "  No Receipt Request\n");
            printf( "  No Receipt Request\n");
        } else if (rv < 0) {
            fprintf(stderr, "  Receipt Request Parse Error\n");
            puts("  Receipt Request Parse Error\n");
            ERR_print_errors(bio_err);
        } else {
            const char *id;
            int idlen;
            CMS_ReceiptRequest_get0_values(rr, &scid, &allorfirst, &rlist, &rto);
            fprintf(stderr, "  Signed Content ID:\n");
            puts("  Signed Content ID:\n");
            idlen = ASN1_STRING_length(scid);
            id = (const char *)ASN1_STRING_get0_data(scid);
            BIO_dump_indent(bio_err, id, idlen, 4);
            fprintf(stderr, "  Receipts From");
            if (rlist != NULL) {
                fprintf(stderr, " List:\n");
                gnames_stack_print(rlist);
            } else if (allorfirst == 1) {
                fprintf(stderr, ": First Tier\n");
            } else if (allorfirst == 0) {
                fprintf(stderr, ": All\n");
            } else {
                fprintf(stderr, " Unknown (%d)\n", allorfirst);
            }
            fprintf(stderr, "  Receipts To:\n");
            gnames_stack_print(rto);
        }
        CMS_ReceiptRequest_free(rr);
    }
#endif    
}

typedef struct cms_key_param_st cms_key_param;
struct cms_key_param_st {
    int idx;
    STACK_OF(OPENSSL_STRING) *param;
    cms_key_param *next;
};

static CMS_ReceiptRequest *make_receipt_request(STACK_OF(OPENSSL_STRING) *rr_to, 
                                        int rr_allorfirst, 
                                        STACK_OF(OPENSSL_STRING) *rr_from)
{
    STACK_OF(GENERAL_NAMES) *rct_to = NULL, *rct_from = NULL;
    CMS_ReceiptRequest *rr;
    rct_to = make_names_stack(rr_to);
    if (rct_to == NULL)
        goto err;
    if (rr_from != NULL) {
        rct_from = make_names_stack(rr_from);
        if (rct_from == NULL)
            goto err;
    } else {
        rct_from = NULL;
    }
    rr = CMS_ReceiptRequest_create0(NULL, -1, rr_allorfirst, rct_from, rct_to);
    return rr;
 err:
    sk_GENERAL_NAMES_pop_free(rct_to, GENERAL_NAMES_free);
    return NULL;
}


//--------------------------------------------------
//FROM(apps.c)
//--------------------------------------------------
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


#ifdef _WIN32
static int WIN32_rename(const char *from, const char *to);
# define rename(from,to) WIN32_rename((from),(to))
#endif

typedef struct {
    const char *name;
    unsigned long flag;
    unsigned long mask;
} NAME_EX_TBL;

int app_init(long mesgwin);


#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(const char *engine)
{
#if 0
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
#else   
    return NULL;
#endif 
}
#endif

ENGINE *setup_engine(const char *engine, int debug)
{
#if 0    
    ENGINE *e = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (engine != NULL) {
        if (strcmp(engine, "auto") == 0) {
            //BIO_printf(bio_err, "enabling auto ENGINE support\n");
            printf("enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL
            && (e = try_load_engine(engine)) == NULL) {
            //BIO_printf(bio_err, "invalid engine \"%s\"\n", engine);
            printf("invalid engine \"%s\"\n", engine);
            //ERR_print_errors(bio_err);
            return NULL;
        }
        if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
        }
        ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ui_method, 0, 1);
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            //BIO_printf(bio_err, "can't use that engine\n");
            printf("can't use that engine\n");
            //ERR_print_errors(bio_err);
            ENGINE_free(e);
            return NULL;
        }

        //BIO_printf(bio_err, "engine \"%s\" set.\n", ENGINE_get_id(e));
        printf("engine \"%s\" set.\n", ENGINE_get_id(e));
    }
#endif
#else 
    return NULL;
#endif     
}

void release_engine(ENGINE *e) {
    #ifndef OPENSSL_NO_ENGINE
        #if 0
            if (e != NULL)
                /* Free our "structural" reference. */
                ENGINE_free(e);
        #endif        
    #endif
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



int set_cert_times(X509 *x, const char *startdate, const char *enddate, int days) {
    if (startdate == NULL || strcmp(startdate, "today") == 0) {
        if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL)
            return 0;
    } else {
        if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(x), startdate))
            return 0;
    }
    if (enddate == NULL) {
        if (X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL) == NULL)
            return 0;
    } else if (!ASN1_TIME_set_string_X509(X509_getm_notAfter(x), enddate)) {
        return 0;
    }
    return 1;
}


int GZPKI_do_CMS(GZPKI_CTX *ctx)
{
    int ret = CMS_RET_UNDEF;
    unsigned char *pwri_tmp = NULL;
    cms_key_param *key_first = NULL;
    cms_key_param *key_param = NULL;
    int i = 0;
        
    //TODO: jkkim
    //flags가 CMS_TEXT인 경우: FORMAT_ASN1인 입력에 대해 복호화 수행 오류 발생
    //영향 최소화 위해 smime/pem format 인 경우에만 cms_text 설정. 
    memset(ctx->errstr, 0, sizeof(ctx->errstr)); 
    
    if(ctx->operation == SMIME_SIGN) {
        if(ctx->outformat == FORMAT_SMIME || ctx->outformat == FORMAT_PEM) {
            ctx->flags |= CMS_TEXT;  
        } 
        else if(ctx->outformat == FORMAT_ASN1) {
            ctx->flags &= ~CMS_DETACHED;   
        }
    }

    if(ctx->operation == SMIME_VERIFY) {
        if(ctx->informat == FORMAT_SMIME || ctx->informat == FORMAT_PEM) {
            ctx->flags |= CMS_TEXT;  
        } else if(ctx->informat == FORMAT_ASN1) {
            ctx->flags &= ~CMS_TEXT;     
            ctx->flags |= CMS_BINARY;   
        }
    }

    ctx->errcode = 0;
    if ((ctx->rr_allorfirst != -1 || ctx->rr_from != NULL) && ctx->rr_to == NULL) {
        sprintf(ctx->errstr, "error:%d:no Signed Receipts Recipients", ctx->errcode++);
        ret = CMS_RET_ERROR;
        goto end;
    }

    ctx->errcode = 200;
    if (!(ctx->operation & SMIME_SIGNERS) && (ctx->rr_to != NULL || ctx->rr_from != NULL)) {
        sprintf(ctx->errstr, "error:%d:signed receipts only allowed with SMIME_SIGN operation", ctx->errcode++);
        ret = CMS_RET_ERROR;
        goto end;
    }
    
    if (!(ctx->operation & SMIME_SIGNERS) && (ctx->skkeys != NULL || ctx->sksigners != NULL)) {
        sprintf(ctx->errstr, "error:%d:multiple signers or keys not allowed", ctx->errcode++);
        ret = CMS_RET_ERROR;
        goto end;
    }

    
    ctx->errcode = 300; 
    if (ctx->operation & SMIME_SIGNERS) {
        if (ctx->keyfile != NULL && ctx->signerfile == NULL) {
            ctx->errcode = 301; 
            sprintf(ctx->errstr, "error(%d:%s):%d:cms_sign:illegal key file without signer file", __LINE__, __FILE__,ctx->errcode);
            ERR_RET(CMS_RET_ERROR);
        }

        /* Check to see if any final signer needs to be appended */
        if (ctx->signerfile != NULL) {
            if (ctx->sksigners == NULL && (ctx->sksigners = sk_OPENSSL_STRING_new_null()) == NULL) {
                ctx->errcode = 302; 
                sprintf(ctx->errstr, "error:%d:null signer file stack", ctx->errcode);
                ERR_RET(CMS_RET_ERROR);
            }
            sk_OPENSSL_STRING_push(ctx->sksigners, ctx->signerfile);
            if (ctx->skkeys == NULL && (ctx->skkeys = sk_OPENSSL_STRING_new_null()) == NULL) {
                ctx->errcode = 303; 
                sprintf(ctx->errstr, "error:(%d:%s):null signer key stack", __LINE__, __FILE__);
                ERR_RET(CMS_RET_ERROR);
            }
            if (ctx->keyfile == NULL) {
                ctx->errcode = 304; 
                sprintf(ctx->errstr, "error:(%d:%s):null key file", __LINE__, __FILE__);
                ctx->keyfile =  GZPKI_strdup(ctx->signerfile);
            }
            sk_OPENSSL_STRING_push(ctx->skkeys, ctx->keyfile);
        }
        if (ctx->sksigners == NULL) {
            sprintf(ctx->errstr, "error:%d:no signer certificate specified", ctx->errcode++);
            ERR_RET(CMS_RET_ERROR);
        }
        ctx->signerfile = NULL;
        ctx->keyfile = NULL;
    } else if (ctx->operation == SMIME_DECRYPT) {
        ctx->errcode = 310;
        if (ctx->recipfile == NULL && ctx->keyfile == NULL && ctx->secret_key == NULL && ctx->pwri_pass == NULL) {
            sprintf(ctx->errstr, "error:(%d:%s):no recipient certificate or key specified", __LINE__, __FILE__);
            ERR_RET(CMS_RET_ERROR);
        }
    } else if (ctx->operation == SMIME_ENCRYPT) {
        ctx->errcode = 320;
        if (ctx->secret_key == NULL && ctx->pwri_pass == NULL && ctx->encerts == NULL) {
            memset(ctx->errstr, 0, sizeof(ctx->errstr));
            sprintf(ctx->errstr, "%s", "No recipient(s) certificate(s) specified");
            ERR_RET(CMS_RET_ERROR);
        }
    } else if (!ctx->operation) {
        sprintf(ctx->errstr, "error:%d:no operation specigied", ctx->errcode++);
        ERR_RET(CMS_RET_ERROR);
    }

    ctx->errcode = 400;
    if (!(ctx->operation & SMIME_SIGNERS)) {
        ctx->flags &= ~CMS_DETACHED;
    }

    if (!(ctx->operation & SMIME_OP)) {
        if (ctx->flags & CMS_BINARY) {
            IF_VERBOSE fprintf(stderr, "info:flags:outout format:binary(1)\n");
            ctx->outformat = FORMAT_BINARY;
        }
    }

    if (!(ctx->operation & SMIME_IP)) {
        if (ctx->flags & CMS_BINARY) {
            IF_VERBOSE fprintf(stderr, "info:flags:input format:binary(1)\n");
            ctx->informat = FORMAT_BINARY;
        }
    }

    if (ctx->operation == SMIME_ENCRYPT) {
        if (!ctx->cipher) {
            IF_VERBOSE fprintf(stderr, "info:operation:SMIME_ENCRYPT\n");
            IF_VERBOSE fprintf(stderr, "info:no_cipher:set:EVP_aes_128_cbc()\n");
            ctx->cipher = EVP_aes_128_cbc();
        }

        if (ctx->secret_key && !ctx->secret_keyid) {
            sprintf(ctx->errstr, "error:no secret key id");
            ERR_RET(CMS_RET_ERROR);            
        }

        if (ctx->encerts == NULL) {
            if ((ctx->encerts = sk_X509_new_null()) == NULL) {
                sprintf(ctx->errstr, "error:%d:no certificate for encryption", ctx->errcode++);
                ERR_RET(CMS_RET_ERROR);            
            }
        }
    }
    
    if (ctx->certfile != NULL) {
        if (!load_certs(ctx->certfile, &ctx->other, FORMAT_PEM, NULL, "certificate file")) {
            //ERR_print_errors(ctx->bio_err);
            sprintf(ctx->errstr, "error:%d:load_certs():certfile=[%s]", ctx->errcode++, ctx->certfile);
            ERR_RET(CMS_RET_ERROR);            
        }
    }

    if (ctx->recipfile != NULL && (ctx->operation == SMIME_DECRYPT)) {
        if ((ctx->recip = load_cert(ctx->recipfile, FORMAT_PEM, "recipient certificate file")) == NULL) {
            //ERR_print_errors(ctx->bio_err);
            sprintf(ctx->errstr, "error:%d:load_certs():recip=[%s]", ctx->errcode++, ctx->recipfile);
            ERR_RET(CMS_RET_ERROR);            
        }
    }

    if (ctx->operation == SMIME_SIGN_RECEIPT) {
        if ((ctx->signer = load_cert(ctx->signerfile, FORMAT_PEM, "receipt signer certificate file")) == NULL) {
            sprintf(ctx->errstr, "error:%d:SMIME_SIGN_RECEIPT:load_certs():signer=[%s]", ctx->errcode++, ctx->signerfile);
            ERR_RET(CMS_RET_ERROR);            
        }
    }

    if (ctx->operation == SMIME_DECRYPT) {
        IF_VERBOSE fprintf(stderr, "info:GZPKI_do_CMS(SMIME_DECRYPT): keyfile=["color_yellow_b"%s"color_reset"]\n", ctx->keyfile);
        if (ctx->keyfile == NULL) {
            ctx->keyfile = GZPKI_strdup(ctx->recipfile);
        }
    } else if ((ctx->operation == SMIME_SIGN) || (ctx->operation == SMIME_SIGN_RECEIPT)) {
        if (ctx->keyfile == NULL)
            ctx->keyfile = GZPKI_strdup(ctx->signerfile);
    } 
    else {
        ctx->keyfile = NULL;
    }


    ctx->errcode = 500;
    if (ctx->keyfile != NULL) {
        IF_VERBOSE fprintf(stderr, "info:GZPKI_do_CMS: passin=["color_yellow_b"%s"color_reset"]\n", ctx->passin);
        ctx->key = load_key(ctx->keyfile, ctx->keyform, 0, ctx->passin, ctx->e, "signing key file");
        if (ctx->key == NULL)  {
            sprintf(ctx->errstr,  "error:%d:unable to load key: %s", ctx->errcode++,ctx->keyfile);
            //GZPKI_print_errors(ctx); 
            //GZPKI_print_errors_std();
            ERR_RET(CMS_RET_ERROR);
        }
    }

    
    #if 0
    if(ctx->infile == NULL) {
        ctx->in = BIO_new(BIO_s_mem());
        //ASN.1의 경우, size 지정해준다
        //NULL이 포함된 이진 데이터는 명시적으로 크기를 지정해준다. 
        if(ctx->informat == FORMAT_SMIME || ctx->informat == FORMAT_PEM) {
            ctx->in = BIO_new_mem_buf(ctx->inbuffer, -1);
        }
        else if(ctx->informat == FORMAT_ASN1) {
            ctx->in = BIO_new_mem_buf(ctx->inbuffer, ctx->inbuffer_size);
        }
    }
    else {
        IF_VERBOSE fprintf(stderr, "info:input file:"color_yellow_b"%s"color_reset"\n", ctx->infile);
        ctx->in = bio_open_default(ctx->infile, 'r', ctx->informat);
        if (ctx->in == NULL) {
            sprintf(ctx->errstr, "error:%d:fail to open:infile:%s\n", ctx->errcode++, ctx->infile);
            ERR_RET(CMS_RET_ERROR);
        }
    }
    #endif

    //  SMIME_DECRYPT(=IP), VERIFY, CMSOUT, RESIGN, DATAOUT, DIGEST_VERIFY, UNCOMPRESS, ENCRYPTED_DECRYPTED, VERIFY_RECEIPT
    if (ctx->operation & SMIME_IP) {
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"SMIME_IP:informat=["color_yellow_b"0x%2x"color_reset"]\n", ctx->informat);
        if (ctx->informat == FORMAT_SMIME) {
            GZPKI_get_flags_str(ctx);
            ctx->cms = SMIME_read_CMS(ctx->in, &ctx->indata);
        } else if (ctx->informat == FORMAT_PEM) {
            if(NULL == ctx->in) {
                IF_VERBOSE fprintf(stderr, "error:input context:null\n");
            }
            ctx->cms = PEM_read_bio_CMS(ctx->in, NULL, NULL, NULL);
        } else if (ctx->informat == FORMAT_ASN1) {
            ctx->cms = d2i_CMS_bio(ctx->in, NULL);
        } else {
            sprintf(ctx->errstr,"error:%d:bad input format for CMS file:informat=[0x%x]", ctx->errcode++, ctx->informat);
            //ERR_print_errors(ctx->bio_err);
            ERR_RET(CMS_RET_ERROR);
        }

        if (ctx->cms == NULL) {
            sprintf(ctx->errstr, "error:%d:reading CMS message:null ctx->cms", ctx->errcode++);
            //ERR_print_errors(ctx->bio_err);
            ERR_RET(CMS_RET_ERROR);
        }
        if (ctx->contfile != NULL) {
            BIO_free(ctx->indata);
            if((ctx->indata = BIO_new_file(ctx->contfile, "rb")) == NULL) {
                sprintf(ctx->errstr, "error:%d:fail to read content file: %s", ctx->errcode++, ctx->contfile);
                ERR_RET(CMS_RET_ERROR);
            }
        }
        if (ctx->certsoutfile != NULL) {
            STACK_OF(X509) *allcerts;
            allcerts = CMS_get1_certs(ctx->cms);
            if (!save_certs(ctx->certsoutfile, allcerts)) {
                sprintf(ctx->errstr, "error:%d:writing certs to: %s", ctx->errcode++, ctx->certsoutfile);
                ERR_RET(CMS_RET_ERROR);
            }
            sk_X509_pop_free(allcerts, X509_free);
        }
    }
	
    ctx->errcode = 600;
    if (ctx->rctfile != NULL) {
        char *rctmode = (ctx->rctformat == FORMAT_ASN1) ? "rb" : "r";
        if ((ctx->rctin = BIO_new_file(ctx->rctfile, rctmode)) == NULL) {
            sprintf(ctx->errstr, "error:%d:fail to open receipt file:%s", ctx->errcode++, ctx->rctfile);
            ERR_RET(CMS_RET_ERROR);
        }

        if (ctx->rctformat == FORMAT_SMIME) {
            ctx->rcms = SMIME_read_CMS(ctx->rctin, NULL);
        } else if (ctx->rctformat == FORMAT_PEM) {
            ctx->rcms = PEM_read_bio_CMS(ctx->rctin, NULL, NULL, NULL);
        } else if (ctx->rctformat == FORMAT_ASN1) {
            ctx->rcms = d2i_CMS_bio(ctx->rctin, NULL);
        } else {
            sprintf(ctx->errstr, "error:%d:bad informat for receipt:0x%x", ctx->errcode++, ctx->rctformat);
            ERR_RET(CMS_RET_ERROR);
        }

        if (ctx->rcms == NULL) {
            sprintf(ctx->errstr, "error:%d:reading receipt", ctx->errcode++);
            ERR_RET(CMS_RET_ERROR);
        }
    }

#if 0

    if(ctx->outfile == NULL) {
        //R/W BIO
        ctx->out = BIO_new(BIO_s_mem());
    }
    else {
        ctx->out = bio_open_default(ctx->outfile, 'w', ctx->outformat);
        if (ctx->out == NULL)  {
            sprintf(ctx->errstr, "error:open output file: %s", ctx->infile);
            ERR_RET(CMS_RET_ERROR);
        }
    }
#endif    

    if ((ctx->operation == SMIME_VERIFY) || (ctx->operation == SMIME_VERIFY_RECEIPT)) {
        if ((ctx->store = setup_verify(ctx->CAfile, ctx->CApath, ctx->noCAfile, ctx->noCApath)) == NULL) {
            IF_VERBOSE fprintf(stderr, "info:fail to setup_verify, CA=["color_red_b"%s"color_reset"]\n", ctx->CAfile);
            ERR_RET(CMS_RET_ERROR);
        }
        X509_STORE_set_verify_cb(ctx->store, cms_cb);
        if (ctx->vpmtouched) {
            X509_VERIFY_PARAM_set_flags(ctx->vpm, X509_V_FLAG_CHECK_SS_SIGNATURE);
            X509_STORE_set1_param(ctx->store, ctx->vpm);
        }
    }

    
    ret = 3;
    ctx->errcode = 700;

    if (ctx->operation == SMIME_DATA_CREATE) {
        ctx->cms = CMS_data_create(ctx->in, ctx->flags);
    } else if (ctx->operation == SMIME_DIGEST_CREATE) {
        IF_VERBOSE fprintf(stderr, "info:CMS_DIGEST:sign md name: %s\n", GZPKI_get_sign_md_name(ctx));
        ctx->cms = CMS_digest_create(ctx->in, ctx->sign_md, ctx->flags);
    } else if (ctx->operation == SMIME_COMPRESS) {
        ctx->cms = CMS_compress(ctx->in, -1, ctx->flags);
    } else if (ctx->operation == SMIME_ENCRYPT) {
        int i;
        ctx->flags |= CMS_PARTIAL;
        ctx->cms = CMS_encrypt(NULL, ctx->in, ctx->cipher, ctx->flags);
        if (ctx->cms == NULL) {
            ctx->errcode = 701;
            sprintf(ctx->errstr, "CMS_ENCRYPT:CMS_encrypt:null");
            ERR_RET(CMS_RET_ERROR);
        }
        for (i = 0; i < sk_X509_num(ctx->encerts); i++) {
            CMS_RecipientInfo *ri;
            cms_key_param *kparam;
            int tflags = ctx->flags;
            X509 *x = sk_X509_value(ctx->encerts, i);
            for (kparam = key_first; kparam; kparam = kparam->next) {                
                if (kparam->idx == i) {
                    tflags |= CMS_KEY_PARAM;
                    break;
                }
            }
            ri = CMS_add1_recipient_cert(ctx->cms, x, tflags);
            if (ri == NULL){
                ctx->errcode = 702;
                sprintf(ctx->errstr, "CMS_ENCRYPT:CMS_add1_recipient_cert():null");
                ERR_RET(CMS_RET_ERROR);
            }
            if (kparam != NULL) {
                EVP_PKEY_CTX *pctx;
                pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
                if (!cms_set_pkey_param(pctx, kparam->param)){
                    ctx->errcode = 703;
                    sprintf(ctx->errstr, "CMS_ENCRYPT:cms_set_pkey_param():null");
                    ERR_RET(CMS_RET_ERROR);
                }
            }
            if (CMS_RecipientInfo_type(ri) == CMS_RECIPINFO_AGREE && ctx->wrap_cipher) {
                EVP_CIPHER_CTX *wctx;
                wctx = CMS_RecipientInfo_kari_get0_ctx(ri);
                EVP_EncryptInit_ex(wctx, ctx->wrap_cipher, NULL, NULL, NULL);
            }
        }

        if (ctx->secret_key != NULL) {
            if (!CMS_add0_recipient_key(ctx->cms, NID_undef, ctx->secret_key, ctx->secret_keylen, ctx->secret_keyid, ctx->secret_keyidlen, NULL, NULL, NULL)) {
                ctx->errcode = 704;
                sprintf(ctx->errstr, "CMS_ENCRYPT:CMS_add0_recipient_key():null");
                ERR_RET(CMS_RET_ERROR);
            }
            /* NULL these because call absorbs them */
            ctx->secret_key = NULL;
            ctx->secret_keyid = NULL;
        }
        if (ctx->pwri_pass != NULL) {
            pwri_tmp = (unsigned char *)GZPKI_strdup((char *)ctx->pwri_pass);
            if (pwri_tmp == NULL) {
                ctx->errcode = 705;
                sprintf(ctx->errstr, "CMS_ENCRYPT:null pass");
                ERR_RET(CMS_RET_ERROR);
            }
            if (CMS_add0_recipient_password(ctx->cms, -1, NID_undef, NID_undef,  pwri_tmp, -1, NULL) == NULL) {
                ctx->errcode = 706;
                sprintf(ctx->errstr, "CMS_add0_recipient_password");
                ERR_RET(CMS_RET_ERROR);
            }
            ctx->pwri_tmp = NULL;
        }
        if (!(ctx->flags & CMS_STREAM)) {
            if (!CMS_final(ctx->cms, ctx->in, NULL, ctx->flags)) {
                ctx->errcode = 707;
                sprintf(ctx->errstr, "CMS_final");
                ERR_RET(CMS_RET_ERROR);
            }
        }
    } else if (ctx->operation == SMIME_ENCRYPTED_ENCRYPT) {
        ctx->cms = CMS_EncryptedData_encrypt(ctx->in, ctx->cipher, ctx->secret_key, ctx->secret_keylen, ctx->flags);
    } else if (ctx->operation == SMIME_SIGN_RECEIPT) {
        CMS_ContentInfo *srcms = NULL;
        STACK_OF(CMS_SignerInfo) *sis;
        CMS_SignerInfo *si;
        sis = CMS_get0_SignerInfos(ctx->cms);
        if (sis == NULL) {
            ctx->errcode = 708;
            sprintf(ctx->errstr, "CMS_get0_SignerInfos");
            ERR_RET(CMS_RET_ERROR);
        }
        si = sk_CMS_SignerInfo_value(sis, 0);
        srcms = CMS_sign_receipt(si, ctx->signer, ctx->key, ctx->other, ctx->flags);
        if (srcms == NULL) {
            ctx->errcode = 709;
            sprintf(ctx->errstr, "CMS_sign_receipt");
            ERR_RET(CMS_RET_ERROR);
        }
        CMS_ContentInfo_free(ctx->cms);
        ctx->cms = srcms;
    } else if (ctx->operation & SMIME_SIGNERS) {
        int i;
        /*
         * If detached data content we enable streaming if S/MIME output format.
         */
        if (ctx->operation == SMIME_SIGN) {
            if (ctx->flags & CMS_DETACHED) {
#if 1
                ctx->flags |= CMS_STREAM;
#else
                if (ctx->outformat == FORMAT_SMIME)
                {
                    ctx->flags |= CMS_STREAM;
                }
#endif                
            }
            ctx->flags |= CMS_PARTIAL;
            ctx->cms = CMS_sign(NULL, NULL, ctx->other, ctx->in, ctx->flags);

            if (ctx->cms == NULL) {
                sprintf(ctx->errstr, "error:%d:CMS_sign", ctx->errcode++);
                ERR_RET(CMS_RET_ERROR);
            }

            if (ctx->econtent_type != NULL) {
                CMS_set1_eContentType(ctx->cms, ctx->econtent_type);
            }

            if (ctx->rr_to != NULL) {
                ctx->rr = make_receipt_request(ctx->rr_to, ctx->rr_allorfirst, ctx->rr_from);
                if (ctx->rr == NULL) {
                    sprintf(ctx->errstr, "error:%d:Signed Receipt Request Creation Error", ctx->errcode++);
                    ERR_RET(CMS_RET_ERROR);
                }
            }
        } 
        else {
            ctx->flags |= CMS_REUSE_DIGEST;
        }
        
        D_printf("----------\n");
        D_printf("total signer # : %d\n", sk_OPENSSL_STRING_num(ctx->sksigners) );
        D_printf("----------\n");
        for (i = 0; i < sk_OPENSSL_STRING_num(ctx->sksigners); i++) {
            CMS_SignerInfo *si;
            cms_key_param *kparam;
            int tflags = ctx->flags;
            ctx->signerfile = sk_OPENSSL_STRING_value(ctx->sksigners, i);
            ctx->keyfile = sk_OPENSSL_STRING_value(ctx->skkeys, i);

            //-------------------------
            //added by jkkim@
            //-------------------------
            ctx->passin = sk_OPENSSL_STRING_value(ctx->skpassins, i);

            IF_VERBOSE fprintf(stderr, "info:%d-th:signer(cert)=[%s]\n", i,ctx->signerfile);
            IF_VERBOSE fprintf(stderr, "info:%d-th:keyfile=[%s]\n", i, ctx->keyfile);
            
            ctx->signer = load_cert(ctx->signerfile, FORMAT_PEM, "signer certificate");
            if (ctx->signer == NULL) {
                sprintf(ctx->errstr, "error:%d:load_cert():fail to load:%s", ctx->errcode, ctx->signerfile);
                ERR_RET(CMS_RET_ERROR);
            }

            ctx->key = load_key(ctx->keyfile, ctx->keyform, 0, ctx->passin, ctx->e, "signing key file");
            if (ctx->key == NULL) {
                sprintf(ctx->errstr, "error:%d:load_key():fail to load:%s", ctx->errcode, ctx->keyfile);
                ERR_RET(CMS_RET_ERROR);
            }
            
            for (kparam = key_first; kparam; kparam = kparam->next) {                
                if (kparam->idx == i) {
                    tflags |= CMS_KEY_PARAM;
                    break;
                }
            }

            si = CMS_add1_signer(ctx->cms, ctx->signer, ctx->key, ctx->sign_md, tflags);
            if (si == NULL) {
                sprintf(ctx->errstr, "error:%d:CMS_add1_signer():failed", ctx->errcode);
                ERR_RET(CMS_RET_ERROR);

            }
            if (kparam != NULL) {
                EVP_PKEY_CTX *pctx;
                pctx = CMS_SignerInfo_get0_pkey_ctx(si);
                if (!cms_set_pkey_param(pctx, kparam->param)) {
                    sprintf(ctx->errstr, "error:%d:cms_set_pkey_param():failed", ctx->errcode);
                    ERR_RET(CMS_RET_ERROR);
                }
            }

            if (ctx->rr != NULL && !CMS_add1_ReceiptRequest(si, ctx->rr)) {
                sprintf(ctx->errstr, "error:%d:CMS_add1_ReceiptRequest():failed", ctx->errcode);
                ERR_RET(CMS_RET_ERROR);
            }

            X509_free(ctx->signer);
            ctx->signer = NULL;
            EVP_PKEY_free(ctx->key);
            ctx->key = NULL;
            ctx->passin = NULL;
        }
        /* If not streaming or resigning finalize structure */
        if ((ctx->operation == SMIME_SIGN) && !(ctx->flags & CMS_STREAM)) {
            if (!CMS_final(ctx->cms, ctx->in, NULL, ctx->flags)) {
                sprintf(ctx->errstr, "error:%d:CMS_final():failed", ctx->errcode);
                ERR_RET(CMS_RET_ERROR);
            }
        }
    }

    if (ctx->cms == NULL) {
        sprintf(ctx->errstr, "error:%d:creating CMS structure:null", ctx->errcode);
        ERR_RET(CMS_RET_ERROR);
    }

    if (ctx->operation == SMIME_DECRYPT) {
        IF_VERBOSE fprintf(stderr, INFO_TAG"SMIME_DECRYPT:flags=["color_yellow_b"0x%02x"color_reset"]\n", ctx->flags);
        if (ctx->flags & CMS_DEBUG_DECRYPT) {
            CMS_decrypt(ctx->cms, NULL, NULL, NULL, NULL, ctx->flags);
            ERR_print_errors(ctx->bio_err);
        }

        if (ctx->secret_key != NULL) {
            if (!CMS_decrypt_set1_key(ctx->cms, ctx->secret_key, ctx->secret_keylen, ctx->secret_keyid, ctx->secret_keyidlen)) {
                sprintf(ctx->errstr, "error:%d:decrypting CMS using secret key():failed", ctx->errcode);
                ERR_RET(CMS_RET_ERROR);
            }
        }

        if (ctx->key != NULL) {
            if (!CMS_decrypt_set1_pkey(ctx->cms, ctx->key, ctx->recip)) {
                sprintf(ctx->errstr, "error:%d:CMS_decrypt_set1_pkey():failed", ctx->errcode);
                ERR_RET(CMS_RET_ERROR);
            }
        }

        if (ctx->pwri_pass != NULL) {
            if (!CMS_decrypt_set1_password(ctx->cms, ctx->pwri_pass, -1)) {
                sprintf(ctx->errstr, "error:%d:decrypting CMS using password:null pass", ctx->errcode);
                ERR_RET(CMS_RET_ERROR);
            }
        }

        if (!CMS_decrypt(ctx->cms, NULL, NULL, ctx->indata, ctx->out, ctx->flags)) {
            sprintf(ctx->errstr, "error:%d:CMS_decrypt:failed", ctx->errcode);
            ERR_RET(CMS_RET_ERROR);
        }
    } 
    else if (ctx->operation == SMIME_DATAOUT) {
        IF_VERBOSE fprintf(stderr, "info:SMIME_DATAOUT:cms data set\n");
        if (!CMS_data(ctx->cms, ctx->out, ctx->flags)) {
            sprintf(ctx->errstr, "error:%d:CMS_data():failed", ctx->errcode);
            ERR_RET(CMS_RET_ERROR);
        }
    } 
    else if (ctx->operation == SMIME_UNCOMPRESS) {
        if (!CMS_uncompress(ctx->cms, ctx->indata, ctx->out, ctx->flags)) {
            sprintf(ctx->errstr, "error:%d:SMIME_UNCOMPRESS:failed", ctx->errcode++);
            ERR_RET(CMS_RET_ERROR);
        }
    } 
    else if (ctx->operation == SMIME_DIGEST_VERIFY) {
        if (CMS_digest_verify(ctx->cms, ctx->indata, ctx->out, ctx->flags) > 0) {
            ctx->digest_verify_result = CMS_VERIFY_OK;
            fprintf(stderr, "Verification successful\n");
        } 
        else {
            fprintf(stderr, "Verification failure\n");
            ctx->digest_verify_result = CMS_VERIFY_FAIL;
            ERR_RET(CMS_RET_ERROR);
        }
    } else if (ctx->operation == SMIME_ENCRYPTED_DECRYPT) {
        if (!CMS_EncryptedData_decrypt(ctx->cms, ctx->secret_key, ctx->secret_keylen, ctx->indata, ctx->out, ctx->flags)) {
            sprintf(ctx->errstr, "error:%d:SMIME_ENCRYPTED_DECRYPT:failed", ctx->errcode++);
            ERR_RET(CMS_RET_ERROR);
        }
    } else if (ctx->operation == SMIME_VERIFY) {
        //TODO: fail인 경우 error code 처리 좀더 확실하게 정리        
        if (CMS_verify(ctx->cms, ctx->other, ctx->store, ctx->indata, ctx->out, ctx->flags) > 0) {
            ctx->verify_result = CMS_VERIFY_OK;
            //NOTICE
            //gzcms-cli에서 verification successful 출력한다. lib내부에서는 code만 전달
            IF_VERBOSE fprintf(stderr, "Verification successful\n");
            IF_VERBOSE GZPKI_get_flags_str(ctx);
        } else {
            ret = CMS_RET_OK;
            ctx->verify_result = CMS_VERIFY_FAIL;
            IF_VERBOSE GZPKI_get_flags_str(ctx);
            if (ctx->verify_retcode)
                ret = verify_err + 32;

            GZPKI_print_errors(ctx);
            ctx->errcode = -51;
#if 0
            /*
             * CACERTS에 인증서가 없는 경우 -51 오류 발생
             */
            ret = CMS_RET_ERROR;
            ctx->errcode = -51;
            ERR_print_errors(ctx->bio_err);
            ret = CMS_RET_ERROR;
            sprintf(ctx->errstr, "%s\n", ctx->signerfile, "certificate has expired");
#endif
            goto end;
        }
        if (ctx->signerfile != NULL) {
            STACK_OF(X509) *signers;
            signers = CMS_get0_signers(ctx->cms);
            if (!save_certs(ctx->signerfile, signers)) {
                sprintf(ctx->errstr, "error:%d:writing signers to %s\n", ctx->errcode++,  ctx->signerfile);
                ERR_RET(CMS_RET_ERROR);
            }
            sk_X509_free(signers);
        }
        if (ctx->rr_print)
            receipt_request_print(ctx->cms);

    } else if (ctx->operation == SMIME_VERIFY_RECEIPT) {
        if (CMS_verify_receipt(ctx->rcms, ctx->cms, ctx->other, ctx->store, ctx->flags) > 0) {
            fprintf(stderr, "Verification successful\n");
        } else {
            fprintf(stderr, "Verification failure\n");
            ctx->errcode++;
            ERR_RET(CMS_RET_ERROR);
        }
    } else {

        if (ctx->noout) {
			IF_VERBOSE fprintf(stderr, "info:noout options: "color_yellow_b"%d"color_reset"\n", ctx->noout);
            if (ctx->print) {
       	        IF_VERBOSE fprintf(stderr, "info:print options: "color_yellow_b"%d"color_reset"\n", ctx->print);
	            CMS_ContentInfo_print_ctx(ctx->out, ctx->cms, 0, NULL);
            }
        } else if (ctx->outformat == FORMAT_SMIME) {
            IF_VERBOSE fprintf(stderr, "info:out format:"color_yellow_b"%s"color_reset"\n", "FORMAT_SMIME");
            if (ctx->to)
                BIO_printf(ctx->out, "To: %s%s", ctx->to, ctx->mime_eol);
            if (ctx->from)
                BIO_printf(ctx->out, "From: %s%s", ctx->from, ctx->mime_eol);
            if (ctx->subject)
                BIO_printf(ctx->out, "Subject: %s%s", ctx->subject, ctx->mime_eol);

            if (ctx->operation == SMIME_RESIGN) {
                IF_VERBOSE fprintf(stderr, "info:opertaion:"color_yellow_b"%s"color_reset"\n", "SMIME_RESIGN");
                ret = SMIME_write_CMS(ctx->out, ctx->cms, ctx->indata, ctx->flags);
            } else {
                IF_VERBOSE fprintf(stderr, "info:opertaion:"color_yellow_b"0x%x"color_reset"\n", ctx->operation);
                ret = SMIME_write_CMS(ctx->out, ctx->cms, ctx->in, ctx->flags);
            }
        } else if (ctx->outformat == FORMAT_PEM) {
            IF_VERBOSE fprintf(stderr, "info:out format:"color_yellow_b"%s"color_reset"\n", "FORMAT_PEM");
            ret = PEM_write_bio_CMS_stream(ctx->out, ctx->cms, ctx->in, ctx->flags);
        } else if (ctx->outformat == FORMAT_ASN1) {
            IF_VERBOSE fprintf(stderr, "info:out format:"color_yellow_b"%s"color_reset"\n", "FORMAT_ASN1");
            ret = i2d_CMS_bio_stream(ctx->out, ctx->cms, ctx->in, ctx->flags);
        } else {
            IF_VERBOSE BIO_printf(ctx->bio_err, "Bad output format for CMS file\n");
            sprintf(ctx->errstr, "error:%d:bad output format for CMS file", ctx->errcode++);
            ERR_RET(CMS_RET_ERROR);
        }
        if (ret <= 0) {
            sprintf(ctx->errstr, "error:%d:unknown error code: %d", ctx->errcode++, ret);
            ERR_RET(CMS_RET_ERROR);
        }
    }

    ret = CMS_RET_OK;
    sprintf(ctx->errstr, "success:ret=%d", ret);
 
 end:

    //--------------------------------------------------
    // ctx->out을 GZPKI_free_ctx에서 free_all하기 전에는 
    // "----- END CMS -----"등 헤더가 완전하게 파일로 flush되지 않음
    // 파일로 출력되는 경우 미리 flush한다
    // FILE_MEM인 경우 출력 이상없음(END CMS까지 출력 정상)
    //--------------------------------------------------
    if(ctx->out) BIO_flush(ctx->out);

    for (key_param = key_first; key_param;) {
        cms_key_param *tparam;
        sk_OPENSSL_STRING_free(key_param->param);
        tparam = key_param->next;
        OPENSSL_free(key_param);
        key_param = tparam;
    }
    /* 
    if (ret) {
        ERR_print_errors(ctx->bio_err);
    */

    return ret;

}
//END_OF(GZPKI_do_CMS)



