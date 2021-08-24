# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <time.h>
# include <assert.h>

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
# include <openssl/ocsp.h>

# include "internal/sockets.h"


#include <openssl/opensslconf.h>

//#ifdef OPENSSL_NO_OCSP
//NON_EMPTY_TRANSLATION_UNIT
//#else
# ifdef OPENSSL_SYS_VMS
#  define _XOPEN_SOURCE_EXTENDED/* So fd_set and friends get properly defined * on OpenVMS */
# endif

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <time.h>
# include <ctype.h>

/* Needs to be included before the openssl headers */
//# include "internal/sockets.h"
# include <openssl/e_os2.h>
# include <openssl/crypto.h>
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/x509v3.h>
# include <openssl/rand.h>


# include "gzpki_types.h"
# include "gzpki_common.h"
# include "gzpki_ocsp.h"



# if defined(OPENSSL_SYS_UNIX) && !defined(OPENSSL_NO_SOCK) \
     && !defined(OPENSSL_NO_POSIX_IO)
#  define OCSP_DAEMON
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <syslog.h>
#  include <signal.h>
#  define MAXERRLEN 1000 /* limit error text sent to syslog to 1000 bytes */
# else
#  undef LOG_INFO
#  undef LOG_WARNING
#  undef LOG_ERR
#  define LOG_INFO      0
#  define LOG_WARNING   1
#  define LOG_ERR       2
# endif


# if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
#  define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
# else
#  define openssl_fdset(a,b) FD_SET(a, b)
# endif



static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md, X509 *issuer, STACK_OF(OCSP_CERTID) *ids);
static int add_ocsp_serial(OCSP_REQUEST **req, char *serial, const EVP_MD *cert_id_md, X509 *issuer, STACK_OF(OCSP_CERTID) *ids);
static void print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req, STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage);
static void make_ocsp_response(BIO *err, OCSP_RESPONSE **resp, OCSP_REQUEST *req,
                              CA_DB *db, STACK_OF(X509) *ca, X509 *rcert,
                              EVP_PKEY *rkey, const EVP_MD *md,
                              STACK_OF(OPENSSL_STRING) *sigopts,
                              STACK_OF(X509) *rother, unsigned long flags,
                              int nmin, int ndays, int badsig);

static char **lookup_serial(CA_DB *db, ASN1_INTEGER *ser);
static BIO *init_responder(const char *port);
static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio, int timeout);
static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp);
static void log_message(int level, const char *fmt, ...);
static char *prog;
static int multi = 0;

# ifdef OCSP_DAEMON
static int acfd = (int) INVALID_SOCKET;
static int index_changed(CA_DB *);
static void spawn_loop(void);
static int print_syslog(const char *str, size_t len, void *levPtr);
static void sock_timeout(int signum);
# endif



# ifndef OPENSSL_NO_SOCK
static OCSP_RESPONSE *query_responder(BIO *cbio, const char *host,
                                      const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout);
#endif

//int ocsp_main(int argc, char **argv)
int GZPKI_do_OCSP(GZPKI_CTX *ctx) {
    
    BIO *acbio = NULL, *cbio = NULL, *derbio = NULL, *out = NULL;
    const EVP_MD *cert_id_md = NULL, *rsign_md = NULL;
    STACK_OF(OPENSSL_STRING) *rsign_sigopts = NULL;
    int trailing_md = 0;
    CA_DB *rdb = NULL;
    EVP_PKEY *key = NULL, *rkey = NULL;
    OCSP_BASICRESP *bs = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    STACK_OF(CONF_VALUE) *headers = NULL;
    STACK_OF(OCSP_CERTID) *ids = NULL;
    STACK_OF(OPENSSL_STRING) *reqnames = NULL;
    STACK_OF(X509) *sign_other = NULL, *verify_other = NULL, *rother = NULL;
    STACK_OF(X509) *issuers = NULL;
    X509 *issuer = NULL, *cert = NULL;
    STACK_OF(X509) *rca_cert = NULL;
    X509 *signer = NULL, *rsigner = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    const char *CAfile = NULL, *CApath = NULL;
    char *header, *value;
    char *host = NULL, *port = NULL, *path = "/", *outfile = NULL;
    char *rca_filename = NULL, *reqin = NULL, *respin = NULL;
    char *reqout = NULL, *respout = NULL, *ridx_filename = NULL;
    char *rsignfile = NULL, *rkeyfile = NULL;
    char *sign_certfile = NULL, *verify_certfile = NULL, *rcertfile = NULL;
    char *signfile = NULL, *keyfile = NULL;
    char *thost = NULL, *tport = NULL, *tpath = NULL;
    int noCAfile = 0, noCApath = 0;
    int accept_count = -1, add_nonce = 1, noverify = 0, use_ssl = -1;
    int vpmtouched = 0, badsig = 0, i, ignore_err = 0, nmin = 0, ndays = -1;
    int req_text = 0, resp_text = 0;
    int ret = CMS_RET_UNDEF;
    int req_timeout = -1;
    long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
    unsigned long sign_flags = 0, verify_flags = 0, rflags = 0;
    //OPTION_CHOICE o;

    reqnames = sk_OPENSSL_STRING_new_null();

    if (reqnames == NULL)
        goto end;
    
    ids = sk_OCSP_CERTID_new_null();
    if (ids == NULL)
        goto end;
    
    if ((vpm = X509_VERIFY_PARAM_new()) == NULL)
        return 1;

    outfile = ctx->outfile;
    req_timeout = ctx->req_timeout;

    //==================================================
    // URL 설정
    //==================================================
    OPENSSL_free(thost);
    OPENSSL_free(tport);
    OPENSSL_free(tpath);
    thost = tport = tpath = NULL;

    char *ocsp_url = ctx->ocsp_url;

    if (!OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl)) { 
        BIO_printf(bio_err, "gzpki:Error parsing URL\n"); 
        goto end; 
    }
    thost = host;
    tport = port;
    tpath = path;

    char *ocsp_host = ctx->ocsp_host;
    int ocsp_port = ctx->ocsp_port; //int

    ignore_err = ctx->ocsp_opt_ignore_err;
    noverify = ctx->ocsp_opt_noverify;
    add_nonce = ctx->ocsp_opt_add_nonce; //nonce:2, no_nonce=0 

    //--------------------------------------------------
    // rflags 설정
    //--------------------------------------------------
    if(ctx->ocsp_opt_resp_no_certs)     rflags |= OCSP_NOCERTS;
    if(ctx->ocsp_opt_resp_key_id)       rflags |= OCSP_RESPID_KEY;

    //--------------------------------------------------
    // sign_flags 설정
    //--------------------------------------------------
    if(ctx->ocsp_opt_no_certs)     sign_flags |= OCSP_NOCERTS;

    //--------------------------------------------------
    // verify_flags 설정
    //--------------------------------------------------
    if(ctx->ocsp_opt_no_signature_verify)     
                                        verify_flags |= OCSP_NOSIGS;
    if(ctx->ocsp_opt_no_cert_verify)    verify_flags |= OCSP_NOVERIFY;
    if(ctx->ocsp_opt_no_chain)          verify_flags |= OCSP_NOCHAIN;
    if(ctx->ocsp_opt_no_cert_checks)    verify_flags |= OCSP_NOCHECKS;
    if(ctx->ocsp_opt_no_explicit)       verify_flags |= OCSP_NOEXPLICIT;
    if(ctx->ocsp_opt_trust_other)       verify_flags |= OCSP_TRUSTOTHER;
    if(ctx->ocsp_opt_no_intern)         verify_flags |= OCSP_NOINTERN;

    //--------------------------------------------------
    //badsig, req_text,...
    //--------------------------------------------------
    badsig      = ctx->ocsp_opt_badsig; 
    req_text    = ctx->ocsp_opt_req_text;   //case OPT_TEXT: req_text = resp_text = 1; 
    resp_text   = ctx->ocsp_opt_resp_text;  //case OPT_REQ_TEXT: req_text = 1; , case OPT_RESP_TEXT: resp_text = 1;
    
    //--------------------------------------------------
    //REQIN
    //--------------------------------------------------
    reqin       = ctx->ocsp_reqin;       //case OPT_REQIN: reqin = opt_arg(); break;
    respin      = ctx->ocsp_respin;      //case OPT_RESPIN: respin = opt_arg(); break;
    signfile    = ctx->ocsp_signerfile;  //case OPT_SIGNER: signfile = opt_arg();break;

    //--------------------------------------------------
    //
    //--------------------------------------------------
    verify_certfile = ctx->ocsp_verify_certfile;
    if(verify_certfile)
        verify_flags |= OCSP_TRUSTOTHER;    //case OPT_VAFILE: verify_certfile = opt_arg(); verify_flags |= OCSP_TRUSTOTHER; break;

    sign_certfile = ctx->ocsp_sign_certfile;     //case OPT_SIGN_OTHER: sign_certfile = opt_arg();

    //--------------------------------------------------
    //
    //--------------------------------------------------
    //case OPT_VERIFY_OTHER: verify_certfile = opt_arg(); break;


    //--------------------------------------------------
    // CA 설정: 기존 common 함수를 사용.
    //--------------------------------------------------
    CAfile = ctx->CAfile;     //case OPT_CAFILE: CAfile = opt_arg(); break;
    CApath = ctx->CApath;     //case OPT_CAPATH: CApath = opt_arg(); break;
    noCAfile = ctx->noCAfile; //case OPT_NOCAFILE: noCAfile = 1; break;
    noCApath = ctx->noCApath; //case OPT_NOCAPATH: noCApath = 1; break;

    //==================================================
    //TODO VPM : 별도 함수로 분리
    //==================================================
    //case OPT_V_CASES: if (!opt_verify(o, vpm)) goto end; vpmtouched++; break;
    #if 0
    # define OPT_V_CASES \
        OPT_V__FIRST: case OPT_V__LAST: break; \
        case OPT_V_POLICY: \
        case OPT_V_PURPOSE: \
        case OPT_V_VERIFY_NAME: \
        case OPT_V_VERIFY_DEPTH: \
        case OPT_V_VERIFY_AUTH_LEVEL: \
        case OPT_V_ATTIME: \
        case OPT_V_VERIFY_HOSTNAME: \
        case OPT_V_VERIFY_EMAIL: \
        case OPT_V_VERIFY_IP: \
        case OPT_V_IGNORE_CRITICAL: \
        case OPT_V_ISSUER_CHECKS: \
        case OPT_V_CRL_CHECK: \
        case OPT_V_CRL_CHECK_ALL: \
        case OPT_V_POLICY_CHECK: \
        case OPT_V_EXPLICIT_POLICY: \
        case OPT_V_INHIBIT_ANY: \
        case OPT_V_INHIBIT_MAP: \
        case OPT_V_X509_STRICT: \
        case OPT_V_EXTENDED_CRL: \
        case OPT_V_USE_DELTAS: \
        case OPT_V_POLICY_PRINT: \
        case OPT_V_CHECK_SS_SIG: \
        case OPT_V_TRUSTED_FIRST: \
        case OPT_V_SUITEB_128_ONLY: \
        case OPT_V_SUITEB_128: \
        case OPT_V_SUITEB_192: \
        case OPT_V_PARTIAL_CHAIN: \
        case OPT_V_NO_ALT_CHAINS: \
        case OPT_V_NO_CHECK_TIME: \
        case OPT_V_ALLOW_PROXY_CERTS
    #endif
    //==================================================
    //TODO VPM
    //==================================================


    nsec = ctx->ocsp_valididy_period;   //case OPT_VALIDITY_PERIOD: opt_long(opt_arg(), &nsec); 
    maxage = ctx->ocsp_status_age;      //case OPT_STATUS_AGE: opt_long(opt_arg(), &maxage);
    keyfile = ctx->keyfile;             //case OPT_SIGNKEY: keyfile = opt_arg(); 
    reqout  = ctx->ocsp_reqout;         //case OPT_REQOUT: reqout = opt_arg();
    respout  = ctx->ocsp_respout;       //case OPT_RESPOUT: respout = opt_arg();
    path  = ctx->ocsp_path;             //case OPT_PATH: path = opt_arg();

    char *ocsp_issuer_certfile = NULL;
    //--------------------------------------------------
    // GZPKI_add_ocsp_issuer_certificate(): 별도 함수로 분리
    //--------------------------------------------------
    ocsp_issuer_certfile  = ctx->ocsp_issuer_certfile;  
    if(ocsp_issuer_certfile) {
        issuer = load_cert(ocsp_issuer_certfile, FORMAT_PEM, "issuer certificate");
        if (issuer == NULL)
                goto end;
            if (issuers == NULL) {
                if ((issuers = sk_X509_new_null()) == NULL)
                    goto end;
            }
            sk_X509_push(issuers, issuer);
    }
        
    #if 0    
        case OPT_ISSUER:
            issuer = load_cert(opt_arg(), FORMAT_PEM, "issuer certificate");
            if (issuer == NULL)
                goto end;
            if (issuers == NULL) {
                if ((issuers = sk_X509_new_null()) == NULL)
                    goto end;
            }
            sk_X509_push(issuers, issuer);
            break;
    #endif            

    //--------------------------------------------------
    // GZPKI_add_ocsp_certificate() 별도 함수로 분리
    //--------------------------------------------------
    char *ocsp_certfile = NULL;
    ocsp_certfile = ctx->ocsp_certfile;
    if(ocsp_certfile) {
        X509_free(cert);
        cert = load_cert(ocsp_certfile, FORMAT_PEM, "certificate");
        if (cert == NULL)
            goto end;
        
        cert_id_md = ctx->sign_md;
        if (cert_id_md == NULL)
            cert_id_md = EVP_sha1();
                    
        if (!add_ocsp_cert(&req, cert, cert_id_md, issuer, ids)) {
            goto end;
        }
        if (!sk_OPENSSL_STRING_push(reqnames, ocsp_certfile)) {
            goto end;
        }
        trailing_md = 0;
    }
    #if 0
        case OPT_CERT:
            X509_free(cert);
            cert = load_cert(opt_arg(), FORMAT_PEM, "certificate");
            if (cert == NULL)
                goto end;
            if (cert_id_md == NULL)
                cert_id_md = EVP_sha1();
            if (!add_ocsp_cert(&req, cert, cert_id_md, issuer, ids))
                goto end;
            if (!sk_OPENSSL_STRING_push(reqnames, opt_arg()))
                goto end;
            trailing_md = 0;
            break;
    #endif         


    
    //--serial: 검증할 인증서의 시리얼 번호
    char *ocsp_serial = NULL;
    ocsp_serial = ctx->ocsp_serial;
    if(ocsp_serial) {
        cert_id_md = ctx->sign_md;
        if (cert_id_md == NULL)
            cert_id_md = EVP_sha1();
        
        if (!add_ocsp_serial(&req, ocsp_serial, cert_id_md, issuer, ids))
                goto end;
            if (!sk_OPENSSL_STRING_push(reqnames, ocsp_serial))
                goto end;
            trailing_md = 0;
    }

    #if 0    
        case OPT_SERIAL:
            if (cert_id_md == NULL)
                cert_id_md = EVP_sha1();
            if (!add_ocsp_serial(&req, opt_arg(), cert_id_md, issuer, ids))
                goto end;
            if (!sk_OPENSSL_STRING_push(reqnames, opt_arg()))
                goto end;
            trailing_md = 0;
            break;
    #endif


    //--------------------------------------------------
    // opt_index: 인증서 상태 포함 인덱스 파일
    //--------------------------------------------------
    ridx_filename = ctx->ocsp_index_filename;   // case OPT_INDEX: ridx_filename = opt_arg(); break;
    if(ctx->debug_mode == 1) {
        printf("ridx_filename:ocsp_index_filename: %s\n", ridx_filename);
    }

    //--------------------------------------------------
    // CA certificat
    //--------------------------------------------------
    rca_filename = ctx->ocsp_ca_filename;   // case OPT_CA: rca_filename = opt_arg(); break;
    if(ctx->debug_mode == 1) {
        printf("rca_filename:ocsp_ca_filename: %s\n", ridx_filename);
    }

    //--------------------------------------------------
    // Number of minutes before next update
    //--------------------------------------------------
    nmin = ctx->ocsp_next_minutes;  // case OPT_NMIN: opt_int(opt_arg(), &nmin); if (ndays == -1) ndays = 0; break;
    if(ctx->debug_mode == 1) {
        printf("nmin:ocsp_next_minutes: %d\n", nmin);
    }

    //--------------------------------------------------
    // Number of requests to accept (default unlimited)
    // case OPT_REQUEST: opt_int(opt_arg(), &accept_count); 
    //--------------------------------------------------
    accept_count = ctx->ocsp_accept_count;
    if(ctx->debug_mode == 1) {
        printf("accept_count:ocsp_accept_count: %d\n", accept_count);
    }
        
    //--------------------------------------------------
    // Number of days before next update
    // case OPT_NDAYS: ndays = atoi(opt_arg()); 
    //--------------------------------------------------
    ndays = ctx->ocsp_ndays;
    if(ctx->debug_mode == 1) {
        printf("ndays:ocsp_ndays: %d\n", ndays);
    }
        
    //--------------------------------------------------
    // Responder certificate to sign responses with
    // case OPT_RSIGNER: rsignfile = opt_arg();
    //--------------------------------------------------
    rsignfile = ctx->ocsp_resp_signfile;
    if(ctx->debug_mode == 1) {
        printf("rsignfile:ocsp_resp_signfile: %s\n", rsignfile);
    }
       
    //--------------------------------------------------
    // Responder key to sign responses with
    // case OPT_RKEY: rkeyfile = opt_arg(); 
    //--------------------------------------------------
    rkeyfile = ctx->ocsp_resp_keyfile;
    if(ctx->debug_mode == 1) {
        printf("rkeyfile:ocsp_resp_keyfile: %s\n", rkeyfile);
    }
        
    //--------------------------------------------------
    // Other certificates to include in response
    // case OPT_ROTHER: rcertfile = opt_arg();
    //--------------------------------------------------
    rcertfile = ctx->ocsp_resp_other_certfile;
    if(ctx->debug_mode == 1) {
        printf("rcertfile:ocsp_resp_other_certfile: %s\n", rcertfile);
    }

    //--------------------------------------------------
    // Digest Algorithm to use in signature of OCSP respons
    // case OPT_RMD:   /* Response MessageDigest */
    //        if (!opt_md(opt_arg(), &rsign_md))
    //--------------------------------------------------
    rsign_md =  ctx->ocsp_resp_sign_md;

      
    //--------------------------------------------------
    // OCSP response signature parameter in n:v form
    // 별도 함수로 분리
    //--------------------------------------------------
    #if 0
        case OPT_RSIGOPT:
            if (rsign_sigopts == NULL)
                rsign_sigopts = sk_OPENSSL_STRING_new_null();
            if (rsign_sigopts == NULL || !sk_OPENSSL_STRING_push(rsign_sigopts, opt_arg()))
                goto end;
            break;
    #endif

    //--------------------------------------------------
    // key=value header to add
    // 별도의 함수로 분리
    //--------------------------------------------------
    #if 0
        case OPT_HEADER:
            header = opt_arg();
            value = strchr(header, '=');
            if (value == NULL) {
                BIO_printf(bio_err, "Missing = in header key=value\n");
                goto opthelp;
            }
            *value++ = '\0';
            if (!X509V3_add_value(header, value, &headers))
                goto end;
            break;
    #endif

    //--------------------------------------------------
    // "Any supported digest algorithm (sha1,sha256, ... )
    //--------------------------------------------------
    #if 0
        case OPT_MD:
            if (trailing_md) {
                BIO_printf(bio_err, "gzpki: Digest must be before -cert or -serial\n");
                goto opthelp;
            }
            if (!opt_md(opt_unknown(), &cert_id_md))
                goto opthelp;
            trailing_md = 1;
            break;
    #endif

    //--------------------------------------------------
    // run multiple responder processes
    // 1 or 0
    //--------------------------------------------------
    #ifdef OCSP_DAEMON
    multi = ctx->ocsp_multi;
    #endif

    /* Have we anything to do? */
    if (req == NULL && reqin == NULL && respin == NULL && !(port != NULL && ridx_filename != NULL)) {
        //goto opthelp;
        sprintf(ctx->errstr, "Insufficient information for OCSP processing");
        ret = CMS_RET_ERROR;
        return CMS_RET_ERROR;
    }
    
    if(ctx->debug_mode == 1) {
        printf("reqin: %s\n", reqin);
        printf("respin: %s\n", respin);
        printf("port: %s\n", port);
        printf("ridx_filename: %s\n", ridx_filename);
    }
    
        

    out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL) 
        goto end;

    if (req == NULL && (add_nonce != 2))
        add_nonce = 0;

    if (req == NULL && reqin != NULL) {
        derbio = bio_open_default(reqin, 'r', FORMAT_ASN1);
        if (derbio == NULL) {
            sprintf(ctx->errstr, "Fail to open request input file:%s", reqin);
            ret = CMS_RET_ERROR;
            goto end;
        }
        req = d2i_OCSP_REQUEST_bio(derbio, NULL);
        BIO_free(derbio);
        if (req == NULL) {
            BIO_printf(bio_err, "Error reading OCSP request\n");
            sprintf(ctx->errstr, "Error reading OCSP request");
            ret = CMS_RET_ERROR;
            goto end;
        }
    }

    if (req == NULL && port != NULL) {
        acbio = init_responder(port);
        if (acbio == NULL) {
            sprintf(ctx->errstr, "Fail to init responser");
            ret = CMS_RET_ERROR;
            goto end;
        }
    }

    if (rsignfile != NULL) {
        if (rkeyfile == NULL) {
            rkeyfile = rsignfile;
        }
        rsigner = load_cert(rsignfile, FORMAT_PEM, "responder certificate");
        if (rsigner == NULL) {
            BIO_printf(bio_err, "Error loading responder certificate\n");
            sprintf(ctx->errstr, "Fail to load responser signer certificate: %s", rsignfile);
            ret = CMS_RET_ERROR;
            goto end;
        }

        if (!load_certs(rca_filename, &rca_cert, FORMAT_PEM, NULL, "CA certificate")) {
            sprintf(ctx->errstr, "Fail to load responser CA file: %s", rca_filename);
            ret = CMS_RET_ERROR;
            goto end;
        }

        if (rcertfile != NULL) {
            if (!load_certs(rcertfile, &rother, FORMAT_PEM, NULL, "responder other certificates")) {
                sprintf(ctx->errstr, "Fail to load responser other certificate: %s", rcertfile);
                ret = CMS_RET_ERROR;
                goto end;
            }
        }
        rkey = load_key(rkeyfile, FORMAT_PEM, 0, NULL, NULL, "responder private key");
        if (rkey == NULL) {
            sprintf(ctx->errstr, "Fail to load responser private key: %s", rkeyfile);
            ret = CMS_RET_ERROR;
            goto end;
        }
    }

    if (ridx_filename != NULL && (rkey == NULL || rsigner == NULL || rca_cert == NULL)) {
        BIO_printf(bio_err, "Responder mode requires certificate, key, and CA.\n");
        sprintf(ctx->errstr, "No certificate, key or CA ti generate response message");
        ret = CMS_RET_ERROR;
        goto end;
    }

    if(ctx->debug_mode==1) {
        printf("ridx_filename: %s\n", ridx_filename);
    }
    if (ridx_filename != NULL) {
        rdb = load_index(ridx_filename, NULL);
        if (rdb == NULL || index_index(rdb) <= 0) {
            //ret = 1;
            sprintf(ctx->errstr, "Fail to load index: %s", ridx_filename);
            ret = CMS_RET_ERROR;
            goto end;
        }
    }

# ifdef OCSP_DAEMON
    if (multi && acbio != NULL)
        spawn_loop();
    if (acbio != NULL && req_timeout > 0)
        signal(SIGALRM, sock_timeout);
#endif

    if (acbio != NULL) {
        log_message(LOG_INFO, "waiting for OCSP client connections...");
    }

redo_accept:

    if (acbio != NULL) {
# ifdef OCSP_DAEMON
        if (index_changed(rdb)) {
            CA_DB *newrdb = load_index(ridx_filename, NULL);

            if (newrdb != NULL && index_index(newrdb) > 0) {
                free_index(rdb);
                rdb = newrdb;
            } else {
                free_index(newrdb);
                log_message(LOG_ERR, "error reloading updated index: %s", ridx_filename);
            }
        }
# endif

        req = NULL;
        if (!do_responder(&req, &cbio, acbio, req_timeout))
            goto redo_accept;

        if (req == NULL) {
            resp = OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, NULL);
            send_ocsp_response(cbio, resp);
            goto done_resp;
        }
    }

    if (req == NULL && (signfile != NULL || reqout != NULL || host != NULL || add_nonce || ridx_filename != NULL)) {
        BIO_printf(bio_err, "Need an OCSP request for this operation!\n");
        sprintf(ctx->errstr, "Need an OCSP request for this operation");
        ret = CMS_RET_ERROR;
        goto end;
    }

    if (req != NULL && add_nonce)
        OCSP_request_add1_nonce(req, NULL, -1);

    if (signfile != NULL) {
        if (keyfile == NULL)
            keyfile = signfile;
        signer = load_cert(signfile, FORMAT_PEM, "signer certificate");
        if (signer == NULL) {
            BIO_printf(bio_err, "Error loading signer certificate\n");
            sprintf(ctx->errstr, "Error loading signer certificate: %s", signfile);
            ret = CMS_RET_ERROR;
            goto end;
        }
        if (sign_certfile != NULL) {
            if (!load_certs(sign_certfile, &sign_other, FORMAT_PEM, NULL, "signer certificates")) {
                sprintf(ctx->errstr, "Fail to load signer certificate file: %s", sign_certfile);
                ret = CMS_RET_ERROR;
                goto end;
            }
        }
        key = load_key(keyfile, FORMAT_PEM, 0, NULL, NULL, "signer private key");
        if (key == NULL) {
            sprintf(ctx->errstr, "Fail to load key file: %s", keyfile);
            ret = CMS_RET_ERROR;
            goto end;
        }

        if (!OCSP_request_sign (req, signer, key, NULL, sign_other, sign_flags)) {
            sprintf(ctx->errstr, "Error signing OCSP request");
            ret = CMS_RET_ERROR;
            BIO_printf(bio_err, "Error signing OCSP request\n");
            goto end;
        }
    }

    if (req_text && req != NULL)
        OCSP_REQUEST_print(out, req, 0);

    if (reqout != NULL) {
        derbio = bio_open_default(reqout, 'w', FORMAT_ASN1);
        if (derbio == NULL) {
            sprintf(ctx->errstr, "fail to open file:%s", reqout);
            ret = CMS_RET_ERROR;
            goto end;
        }
        i2d_OCSP_REQUEST_bio(derbio, req);
        BIO_free(derbio);
    }

    if (rdb != NULL) {
        make_ocsp_response(bio_err, &resp, req, rdb, rca_cert, rsigner, rkey,
                               rsign_md, rsign_sigopts, rother, rflags, nmin, ndays, badsig);
        if (cbio != NULL)
            send_ocsp_response(cbio, resp);
    } else if (host != NULL) {
# ifndef OPENSSL_NO_SOCK
        resp = process_responder(req, host, path, port, use_ssl, headers, req_timeout);
        if (resp == NULL) {
            sprintf(ctx->errstr, "fail to generate responder: host=%s, path=%s, port=%s, use_ssl=%d, req_timeout=%d"
                , host, path, port, use_ssl, req_timeout);
            ret = CMS_RET_ERROR;
            goto end;
        }
# else
        BIO_printf(bio_err,
                   "Error creating connect BIO - sockets not supported.\n");
        goto end;
# endif
    } else if (respin != NULL) {
        derbio = bio_open_default(respin, 'r', FORMAT_ASN1);
        if (derbio == NULL) {
            sprintf(ctx->errstr, "fail to open response file: %s", respin);
            ret = CMS_RET_ERROR;
            goto end;
        }
        resp = d2i_OCSP_RESPONSE_bio(derbio, NULL);
        BIO_free(derbio);
        if (resp == NULL) {
            BIO_printf(bio_err, "Error reading OCSP response\n");
            sprintf(ctx->errstr, "Error reading OCSP response");
            ret = CMS_RET_ERROR;
            goto end;
        }
    } else {
        ret = 0;
        goto end;
    }

 done_resp:

    if (respout != NULL) {
        derbio = bio_open_default(respout, 'w', FORMAT_ASN1);
        if (derbio == NULL) {
            ret = CMS_RET_ERROR;
            goto end;
        }
        i2d_OCSP_RESPONSE_bio(derbio, resp);
        BIO_free(derbio);
    }

    i = OCSP_response_status(resp);
    if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        BIO_printf(out, "Responder Error: %s (%d)\n", OCSP_response_status_str(i), i);
        if (!ignore_err) {
                ret = CMS_RET_ERROR;
                goto end;
        }
    }

    if (resp_text)
        OCSP_RESPONSE_print(out, resp, 0);

    /* If running as responder don't verify our own response */
    if (cbio != NULL) {
        /* If not unlimited, see if we took all we should. */
        if (accept_count != -1 && --accept_count <= 0) {
            //ret = 0;
            ret = CMS_RET_ERROR;
            goto end;
        }
        BIO_free_all(cbio);
        cbio = NULL;
        OCSP_REQUEST_free(req);
        req = NULL;
        OCSP_RESPONSE_free(resp);
        resp = NULL;
        goto redo_accept;
    }
    if (ridx_filename != NULL) {
        //ret = 0;
        ret = CMS_RET_ERROR;
        goto end;
    }

    if (store == NULL) {
        store = setup_verify(CAfile, CApath, noCAfile, noCApath);
        if (!store) {
            ret = CMS_RET_ERROR;
            goto end;
        }
    }
    if (vpmtouched)
        X509_STORE_set1_param(store, vpm);
    if (verify_certfile != NULL) {
        if (!load_certs(verify_certfile, &verify_other, FORMAT_PEM, NULL, "validator certificate")) {
            ret = CMS_RET_ERROR;
            goto end;
        }
    }

    bs = OCSP_response_get1_basic(resp);
    if (bs == NULL) {
        BIO_printf(bio_err, "Error parsing response\n");
        goto end;
    }

    ret = 0;

    if (!noverify) {
        if (req != NULL && ((i = OCSP_check_nonce(req, bs)) <= 0)) {
            if (i == -1) {
                BIO_printf(bio_err, "WARNING: no nonce in response\n");
                ctx->ocsp_verify_result = OCSP_VERIFY_WARN;
                ctx->ocsp_verify_result_str = GZPKI_strdup("WARNING: no nonce in response");
            }
            else {
                ctx->ocsp_verify_result = OCSP_VERIFY_FAIL;
                ctx->ocsp_verify_result_str = GZPKI_strdup("Nonce Verify error");
                BIO_printf(bio_err, "Nonce Verify error\n");
                //ret = 1;
                ret = CMS_RET_ERROR;
                goto end;
            }
        }

        i = OCSP_basic_verify(bs, verify_other, store, verify_flags);
        if (i <= 0 && issuers) {
            i = OCSP_basic_verify(bs, issuers, store, OCSP_TRUSTOTHER);
            if (i > 0)
                ERR_clear_error();
        }
        if (i <= 0) {
            BIO_printf(bio_err, "Response Verify Failure\n");
            ERR_print_errors(bio_err);
            ctx->ocsp_verify_result = OCSP_VERIFY_FAIL;
            ctx->ocsp_verify_result_str = GZPKI_strdup("Response verify Failure");
            ret = CMS_RET_ERROR;
        } else {
            BIO_printf(bio_err, "Response verify OK\n");
            ctx->ocsp_verify_result = OCSP_VERIFY_OK;
            ctx->ocsp_verify_result_str = GZPKI_strdup("Response verify OK");
        }
    }

    print_ocsp_summary(out, bs, req, reqnames, ids, nsec, maxage);

    ret = CMS_RET_OK;

 end:
    ERR_print_errors(bio_err);
    X509_free(signer);
    X509_STORE_free(store);
    X509_VERIFY_PARAM_free(vpm);
    sk_OPENSSL_STRING_free(rsign_sigopts);
    EVP_PKEY_free(key);
    EVP_PKEY_free(rkey);
    X509_free(cert);
    sk_X509_pop_free(issuers, X509_free);
    X509_free(rsigner);
    sk_X509_pop_free(rca_cert, X509_free);
    free_index(rdb);
    BIO_free_all(cbio);
    BIO_free_all(acbio);
    BIO_free_all(out);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    OCSP_BASICRESP_free(bs);
    sk_OPENSSL_STRING_free(reqnames);
    sk_OCSP_CERTID_free(ids);
    sk_X509_pop_free(sign_other, X509_free);
    sk_X509_pop_free(verify_other, X509_free);
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    OPENSSL_free(thost);
    OPENSSL_free(tport);
    OPENSSL_free(tpath);

    return ret;
}

static void
log_message(int level, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
# ifdef OCSP_DAEMON
    if (multi) {
        char buf[1024];
        if (vsnprintf(buf, sizeof(buf), fmt, ap) > 0) {
            syslog(level, "%s", buf);
        }
        if (level >= LOG_ERR)
            ERR_print_errors_cb(print_syslog, &level);
    }
# endif
    if (!multi) {
        BIO_printf(bio_err, "%s: ", prog);
        BIO_vprintf(bio_err, fmt, ap);
        BIO_printf(bio_err, "\n");
    }
    va_end(ap);
}

# ifdef OCSP_DAEMON

static int print_syslog(const char *str, size_t len, void *levPtr)
{
    int level = *(int *)levPtr;
    int ilen = (len > MAXERRLEN) ? MAXERRLEN : len;

    syslog(level, "%.*s", ilen, str);

    return ilen;
}

static int index_changed(CA_DB *rdb)
{
    struct stat sb;

    if (rdb != NULL && stat(rdb->dbfname, &sb) != -1) {
        if (rdb->dbst.st_mtime != sb.st_mtime
            || rdb->dbst.st_ctime != sb.st_ctime
            || rdb->dbst.st_ino != sb.st_ino
            || rdb->dbst.st_dev != sb.st_dev) {
            syslog(LOG_INFO, "index file changed, reloading");
            return 1;
        }
    }
    return 0;
}

static void killall(int ret, pid_t *kidpids)
{
    int i;

    for (i = 0; i < multi; ++i)
        if (kidpids[i] != 0)
            (void)kill(kidpids[i], SIGTERM);
    sleep(1);
    exit(ret);
}

static int termsig = 0;

static void noteterm (int sig)
{
    termsig = sig;
}

/*
 * Loop spawning up to `multi` child processes, only child processes return
 * from this function.  The parent process loops until receiving a termination
 * signal, kills extant children and exits without returning.
 */
static void spawn_loop(void)
{
    pid_t *kidpids = NULL;
    int status;
    int procs = 0;
    int i;

    openlog(prog, LOG_PID, LOG_DAEMON);

    if (setpgid(0, 0)) {
        syslog(LOG_ERR, "fatal: error detaching from parent process group: %s", strerror(errno));
        exit(1);
    }
    kidpids = app_malloc(multi * sizeof(*kidpids), "child PID array");
    for (i = 0; i < multi; ++i)
        kidpids[i] = 0;

    signal(SIGINT, noteterm);
    signal(SIGTERM, noteterm);

    while (termsig == 0) {
        pid_t fpid;

        /*
         * Wait for a child to replace when we're at the limit.
         * Slow down if a child exited abnormally or waitpid() < 0
         */
        while (termsig == 0 && procs >= multi) {
            if ((fpid = waitpid(-1, &status, 0)) > 0) {
                for (i = 0; i < procs; ++i) {
                    if (kidpids[i] == fpid) {
                        kidpids[i] = 0;
                        --procs;
                        break;
                    }
                }
                if (i >= multi) {
                    syslog(LOG_ERR, "fatal: internal error: " "no matching child slot for pid: %ld", (long) fpid);
                    killall(1, kidpids);
                }
                if (status != 0) {
                    if (WIFEXITED(status))
                        syslog(LOG_WARNING, "child process: %ld, exit status: %d",
                               (long)fpid, WEXITSTATUS(status));
                    else if (WIFSIGNALED(status))
                        syslog(LOG_WARNING, "child process: %ld, term signal %d%s",
                               (long)fpid, WTERMSIG(status),
#ifdef WCOREDUMP
                               WCOREDUMP(status) ? " (core dumped)" :
#endif
                               "");
                    sleep(1);
                }
                break;
            } else if (errno != EINTR) {
                syslog(LOG_ERR, "fatal: waitpid(): %s", strerror(errno));
                killall(1, kidpids);
            }
        }
        if (termsig)
            break;

        switch(fpid = fork()) {
        case -1:            /* error */
            /* System critically low on memory, pause and try again later */
            sleep(30);
            break;
        case 0:             /* child */
            OPENSSL_free(kidpids);
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            if (termsig)
                _exit(0);
            if (RAND_poll() <= 0) {
                syslog(LOG_ERR, "fatal: RAND_poll() failed");
                _exit(1);
            }
            return;
        default:            /* parent */
            for (i = 0; i < multi; ++i) {
                if (kidpids[i] == 0) {
                    kidpids[i] = fpid;
                    procs++;
                    break;
                }
            }
            if (i >= multi) {
                syslog(LOG_ERR, "fatal: internal error: no free child slots");
                killall(1, kidpids);
            }
            break;
        }
    }

    /* The loop above can only break on termsig */
    OPENSSL_free(kidpids);
    syslog(LOG_INFO, "terminating on signal: %d", termsig);
    killall(0, kidpids);
}
# endif

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;

    if (issuer == NULL) {
        BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
    if (*req == NULL)
        *req = OCSP_REQUEST_new();
    if (*req == NULL)
        goto err;
    id = OCSP_cert_to_id(cert_id_md, cert, issuer);
    if (id == NULL || !sk_OCSP_CERTID_push(ids, id))
        goto err;
    if (!OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}

static int add_ocsp_serial(OCSP_REQUEST **req, char *serial,
                           const EVP_MD *cert_id_md, X509 *issuer,
                           STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    X509_NAME *iname;
    ASN1_BIT_STRING *ikey;
    ASN1_INTEGER *sno;

    if (issuer == NULL) {
        BIO_printf(bio_err, "No issuer certificate specified\n");
        return 0;
    }
    if (*req == NULL)
        *req = OCSP_REQUEST_new();
    if (*req == NULL)
        goto err;
    iname = X509_get_subject_name(issuer);
    ikey = X509_get0_pubkey_bitstr(issuer);
    sno = s2i_ASN1_INTEGER(NULL, serial);
    if (sno == NULL) {
        BIO_printf(bio_err, "Error converting serial number %s\n", serial);
        return 0;
    }
    id = OCSP_cert_id_new(cert_id_md, iname, ikey, sno);
    ASN1_INTEGER_free(sno);
    if (id == NULL || !sk_OCSP_CERTID_push(ids, id))
        goto err;
    if (!OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    BIO_printf(bio_err, "Error Creating OCSP request\n");
    return 0;
}

static void print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage)
{
    OCSP_CERTID *id;
    const char *name;
    int i, status, reason;
    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

    if (bs == NULL || req == NULL || !sk_OPENSSL_STRING_num(names)
        || !sk_OCSP_CERTID_num(ids))
        return;

    for (i = 0; i < sk_OCSP_CERTID_num(ids); i++) {
        id = sk_OCSP_CERTID_value(ids, i);
        name = sk_OPENSSL_STRING_value(names, i);
        BIO_printf(out, "%s: ", name);

        if (!OCSP_resp_find_status(bs, id, &status, &reason, &rev, &thisupd, &nextupd)) {
            BIO_puts(out, "ERROR: No Status found.\n");
            continue;
        }

        /*
         * Check validity: if invalid write to output BIO so we know which
         * response this refers to.
         */
        if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
            BIO_puts(out, "WARNING: Status times invalid.\n");
            ERR_print_errors(out);
        }
        BIO_printf(out, "%s\n", OCSP_cert_status_str(status));

        BIO_puts(out, "\tThis Update: ");
        ASN1_GENERALIZEDTIME_print(out, thisupd);
        BIO_puts(out, "\n");

        if (nextupd) {
            BIO_puts(out, "\tNext Update: ");
            ASN1_GENERALIZEDTIME_print(out, nextupd);
            BIO_puts(out, "\n");
        }

        if (status != V_OCSP_CERTSTATUS_REVOKED)
            continue;

        if (reason != -1)
            BIO_printf(out, "\tReason: %s\n", OCSP_crl_reason_str(reason));

        BIO_puts(out, "\tRevocation Time: ");
        ASN1_GENERALIZEDTIME_print(out, rev);
        BIO_puts(out, "\n");
    }
}

static void make_ocsp_response(BIO *err, OCSP_RESPONSE **resp, OCSP_REQUEST *req,
                              CA_DB *db, STACK_OF(X509) *ca, X509 *rcert,
                              EVP_PKEY *rkey, const EVP_MD *rmd,
                              STACK_OF(OPENSSL_STRING) *sigopts,
                              STACK_OF(X509) *rother, unsigned long flags,
                              int nmin, int ndays, int badsig)
{
    ASN1_TIME *thisupd = NULL, *nextupd = NULL;
    OCSP_CERTID *cid;
    OCSP_BASICRESP *bs = NULL;
    int i, id_count;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pkctx = NULL;

    id_count = OCSP_request_onereq_count(req);

    if (id_count <= 0) {
        *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, NULL);
        goto end;
    }

    bs = OCSP_BASICRESP_new();
    thisupd = X509_gmtime_adj(NULL, 0);
    if (ndays != -1)
        nextupd = X509_time_adj_ex(NULL, ndays, nmin * 60, NULL);

    /* Examine each certificate id in the request */
    for (i = 0; i < id_count; i++) {
        OCSP_ONEREQ *one;
        ASN1_INTEGER *serial;
        char **inf;
        int jj;
        int found = 0;
        ASN1_OBJECT *cert_id_md_oid;
        const EVP_MD *cert_id_md;
        one = OCSP_request_onereq_get0(req, i);
        cid = OCSP_onereq_get0_id(one);

        OCSP_id_get0_info(NULL, &cert_id_md_oid, NULL, NULL, cid);

        cert_id_md = EVP_get_digestbyobj(cert_id_md_oid);
        if (cert_id_md == NULL) {
            *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR, NULL);
            goto end;
        }
        for (jj = 0; jj < sk_X509_num(ca) && !found; jj++) {
            X509 *ca_cert = sk_X509_value(ca, jj);
            OCSP_CERTID *ca_id = OCSP_cert_to_id(cert_id_md, NULL, ca_cert);

            if (OCSP_id_issuer_cmp(ca_id, cid) == 0)
                found = 1;

            OCSP_CERTID_free(ca_id);
        }

        if (!found) {
            OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_UNKNOWN, 0, NULL, thisupd, nextupd);
            continue;
        }
        OCSP_id_get0_info(NULL, NULL, NULL, &serial, cid);
        inf = lookup_serial(db, serial);
        if (inf == NULL) {
            OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_UNKNOWN, 0, NULL, thisupd, nextupd);
        } else if (inf[DB_type][0] == DB_TYPE_VAL) {
            OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_GOOD, 0, NULL, thisupd, nextupd);
        } else if (inf[DB_type][0] == DB_TYPE_REV) {
            ASN1_OBJECT *inst = NULL;
            ASN1_TIME *revtm = NULL;
            ASN1_GENERALIZEDTIME *invtm = NULL;
            OCSP_SINGLERESP *single;
            int reason = -1;
            unpack_revinfo(&revtm, &reason, &inst, &invtm, inf[DB_rev_date]);
            single = OCSP_basic_add1_status(bs, cid, V_OCSP_CERTSTATUS_REVOKED, reason, revtm, thisupd, nextupd);
            if (invtm != NULL)
                OCSP_SINGLERESP_add1_ext_i2d(single, NID_invalidity_date, invtm, 0, 0);
            else if (inst != NULL) 
                OCSP_SINGLERESP_add1_ext_i2d(single, NID_hold_instruction_code, inst, 0, 0);
            ASN1_OBJECT_free(inst);
            ASN1_TIME_free(revtm);
            ASN1_GENERALIZEDTIME_free(invtm);
        }
    }

    OCSP_copy_nonce(bs, req);

    mctx = EVP_MD_CTX_new();
    if ( mctx == NULL || !EVP_DigestSignInit(mctx, &pkctx, rmd, NULL, rkey)) {
        *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR, NULL);
        goto end;
    }
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);

        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
            BIO_printf(err, "parameter error \"%s\"\n", sigopt);
            ERR_print_errors(bio_err);
            *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR, NULL);
            goto end;
        }
    }
    OCSP_basic_sign_ctx(bs, rcert, mctx, rother, flags);

    if (badsig) {
        const ASN1_OCTET_STRING *sig = OCSP_resp_get0_signature(bs);
        corrupt_signature(sig);
    }

    *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

 end:
    EVP_MD_CTX_free(mctx);
    ASN1_TIME_free(thisupd);
    ASN1_TIME_free(nextupd);
    OCSP_BASICRESP_free(bs);
}

static char **lookup_serial(CA_DB *db, ASN1_INTEGER *ser)
{
    int i;
    BIGNUM *bn = NULL;
    char *itmp, *row[DB_NUMBER], **rrow;
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    bn = ASN1_INTEGER_to_BN(ser, NULL);
    OPENSSL_assert(bn);         /* FIXME: should report an error at this
                                 * point and abort */
    if (BN_is_zero(bn))
        itmp = OPENSSL_strdup("00");
    else
        itmp = BN_bn2hex(bn);
    row[DB_serial] = itmp;
    BN_free(bn);
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    OPENSSL_free(itmp);
    return rrow;
}

/* Quick and dirty OCSP server: read in and parse input request */

static BIO *init_responder(const char *port)
{
# ifdef OPENSSL_NO_SOCK
    BIO_printf(bio_err,
               "Error setting up accept BIO - sockets not supported.\n");
    return NULL;
# else
    BIO *acbio = NULL, *bufbio = NULL;

    bufbio = BIO_new(BIO_f_buffer());
    if (bufbio == NULL)
        goto err;
    acbio = BIO_new(BIO_s_accept());
    if (acbio == NULL
        || BIO_set_bind_mode(acbio, BIO_BIND_REUSEADDR) < 0
        || BIO_set_accept_port(acbio, port) < 0) {
        log_message(LOG_ERR, "Error setting up accept BIO");
        goto err;
    }

    BIO_set_accept_bios(acbio, bufbio);
    bufbio = NULL;
    if (BIO_do_accept(acbio) <= 0) {
        log_message(LOG_ERR, "Error starting accept");
        goto err;
    }

    return acbio;

 err:
    BIO_free_all(acbio);
    BIO_free(bufbio);
    return NULL;
# endif
}

#define _UC(c) ((unsigned char)(c))

# ifndef OPENSSL_NO_SOCK
/*
 * Decode %xx URL-decoding in-place. Ignores mal-formed sequences.
 */
static int urldecode(char *p)
{
    unsigned char *out = (unsigned char *)p;
    unsigned char *save = out;

    for (; *p; p++) {
        if (*p != '%')
            *out++ = *p;
        else if (isxdigit(_UC(p[1])) && isxdigit(_UC(p[2]))) {
            /* Don't check, can't fail because of ixdigit() call. */
            *out++ = (OPENSSL_hexchar2int(p[1]) << 4)
                   | OPENSSL_hexchar2int(p[2]);
            p += 2;
        }
        else
            return -1;
    }
    *out = '\0';
    return (int)(out - save);
}
# endif

# ifdef OCSP_DAEMON
static void sock_timeout(int signum)
{
    if (acfd != (int)INVALID_SOCKET)
        (void)shutdown(acfd, SHUT_RD);
}
# endif

static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio,
                        int timeout)
{
# ifdef OPENSSL_NO_SOCK
    return 0;
# else
    int len;
    OCSP_REQUEST *req = NULL;
    char inbuf[2048], reqbuf[2048];
    char *p, *q;
    BIO *cbio = NULL, *getbio = NULL, *b64 = NULL;
    const char *client;

    *preq = NULL;

    /* Connection loss before accept() is routine, ignore silently */
    if (BIO_do_accept(acbio) <= 0)
        return 0;

    cbio = BIO_pop(acbio);
    *pcbio = cbio;
    client = BIO_get_peer_name(cbio);

#  ifdef OCSP_DAEMON
    if (timeout > 0) {
        (void) BIO_get_fd(cbio, &acfd);
        alarm(timeout);
    }
#  endif

    /* Read the request line. */
    len = BIO_gets(cbio, reqbuf, sizeof(reqbuf));
    if (len <= 0)
        goto out;

    if (strncmp(reqbuf, "GET ", 4) == 0) {
        /* Expecting GET {sp} /URL {sp} HTTP/1.x */
        for (p = reqbuf + 4; *p == ' '; ++p)
            continue;
        if (*p != '/') {
            log_message(LOG_INFO, "Invalid request -- bad URL: %s", client);
            goto out;
        }
        p++;

        /* Splice off the HTTP version identifier. */
        for (q = p; *q; q++)
            if (*q == ' ')
                break;
        if (strncmp(q, " HTTP/1.", 8) != 0) {
            log_message(LOG_INFO, "Invalid request -- bad HTTP version: %s", client);
            goto out;
        }
        *q = '\0';

        /*
         * Skip "GET / HTTP..." requests often used by load-balancers
         */
        if (p[1] == '\0')
            goto out;

        len = urldecode(p);
        if (len <= 0) {
            log_message(LOG_INFO, "Invalid request -- bad URL encoding: %s", client);
            goto out;
        }
        if ((getbio = BIO_new_mem_buf(p, len)) == NULL
            || (b64 = BIO_new(BIO_f_base64())) == NULL) {
            log_message(LOG_ERR, "Could not allocate base64 bio: %s", client);
            goto out;
        }
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        getbio = BIO_push(b64, getbio);
    } else if (strncmp(reqbuf, "POST ", 5) != 0) {
        log_message(LOG_INFO, "Invalid request -- bad HTTP verb: %s", client);
        goto out;
    }

    /* Read and skip past the headers. */
    for (;;) {
        len = BIO_gets(cbio, inbuf, sizeof(inbuf));
        if (len <= 0)
            goto out;
        if ((inbuf[0] == '\r') || (inbuf[0] == '\n'))
            break;
    }

#  ifdef OCSP_DAEMON
    /* Clear alarm before we close the client socket */
    alarm(0);
    timeout = 0;
#  endif

    /* Try to read OCSP request */
    if (getbio != NULL) {
        req = d2i_OCSP_REQUEST_bio(getbio, NULL);
        BIO_free_all(getbio);
    } else {
        req = d2i_OCSP_REQUEST_bio(cbio, NULL);
    }

    if (req == NULL)
        log_message(LOG_ERR, "Error parsing OCSP request");

    *preq = req;

out:
#  ifdef OCSP_DAEMON
    if (timeout > 0)
        alarm(0);
    acfd = (int)INVALID_SOCKET;
#  endif
    return 1;
# endif
}

static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp)
{
    char http_resp[] =
        "HTTP/1.0 200 OK\r\nContent-type: application/ocsp-response\r\n"
        "Content-Length: %d\r\n\r\n";
    if (cbio == NULL)
        return 0;
    BIO_printf(cbio, http_resp, i2d_OCSP_RESPONSE(resp, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, resp);
    (void)BIO_flush(cbio);
    return 1;
}

# ifndef OPENSSL_NO_SOCK
static OCSP_RESPONSE *query_responder(BIO *cbio, const char *host,
                                      const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    int rv;
    int i;
    int add_host = 1;
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;

    if (req_timeout != -1)
        BIO_set_nbio(cbio, 1);

    rv = BIO_do_connect(cbio);

    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
        BIO_puts(bio_err, "Error connecting BIO\n");
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) < 0) {
        BIO_puts(bio_err, "Can't get connection fd\n");
        goto err;
    }

    if (req_timeout != -1 && rv <= 0) {
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        if (rv == 0) {
            BIO_puts(bio_err, "Timeout on connect\n");
            return NULL;
        }
    }

    ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
    if (ctx == NULL)
        return NULL;

    for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
        CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
        if (add_host == 1 && strcasecmp("host", hdr->name) == 0)
            add_host = 0;
        if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
            goto err;
    }

    if (add_host == 1 && OCSP_REQ_CTX_add1_header(ctx, "Host", host) == 0)
        goto err;

    if (!OCSP_REQ_CTX_set1_req(ctx, req))
        goto err;

    for (;;) {
        rv = OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;
        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio)) {
            rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
        } else if (BIO_should_write(cbio)) {
            rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        } else {
            BIO_puts(bio_err, "Unexpected retry condition\n");
            goto err;
        }
        if (rv == 0) {
            BIO_puts(bio_err, "Timeout on request\n");
            break;
        }
        if (rv == -1) {
            BIO_puts(bio_err, "Select error\n");
            break;
        }

    }
 err:
    OCSP_REQ_CTX_free(ctx);

    return rsp;
}

OCSP_RESPONSE *process_responder(OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 STACK_OF(CONF_VALUE) *headers,
                                 int req_timeout)
{
    BIO *cbio = NULL;
    SSL_CTX *ctx = NULL;
    OCSP_RESPONSE *resp = NULL;

    cbio = BIO_new_connect(host);
    if (cbio == NULL) {
        BIO_printf(bio_err, "Error creating connect BIO\n");
        goto end;
    }
    if (port != NULL)
        BIO_set_conn_port(cbio, port);
    if (use_ssl == 1) {
        BIO *sbio;
        ctx = SSL_CTX_new(TLS_client_method());
        if (ctx == NULL) {
            BIO_printf(bio_err, "Error creating SSL context.\n");
            goto end;
        }
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        sbio = BIO_new_ssl(ctx, 1);
        cbio = BIO_push(sbio, cbio);
    }

    resp = query_responder(cbio, host, path, headers, req, req_timeout);
    if (resp == NULL)
        BIO_printf(bio_err, "Error querying OCSP responder\n");
 end:
    BIO_free_all(cbio);
    SSL_CTX_free(ctx);
    return resp;
}
# endif


