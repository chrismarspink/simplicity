#ifndef _GZPKI_TYPES_H_
#define _GZPKI_TYPES_H_



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


extern int _G_DEBUG_MODE_;
extern int _G_VERBOSE_MODE_;
#define IF_VERBOSE if(_G_VERBOSE_MODE_)
//#define IF_VERBOSE if(_G_DEBUG_MODE_)
#define IF_DEBUG if(_G_DEBUG_MODE_)
#define IF_NO_DEBUG if(!_G_DEBUG_MODE_)
#define if_debug IF_VERBOSE
#define if_no_debug IF_NO_DEBUG
#define ELSE else
#define ELIF else if


#define DEBUG_OFF   0
#define DEBUG_ON    1
static int api_debug_mode = DEBUG_OFF;
//#define D_printf if(api_debug_mode == DEBUG_ON) printf("%s:%s:%d ", __FILE__,__FUNCTION__, __LINE__); printf
#define D_printf IF_VERBOSE  printf
#define if_D if(api_debug_mode == DEBUG_ON)

/* Additional revocation information types */
typedef enum {
    REV_VALID             = -1, /* Valid (not-revoked) status */
    REV_NONE              = 0, /* No additional information */
    REV_CRL_REASON        = 1, /* Value is CRL reason code */
    REV_HOLD              = 2, /* Value is hold instruction */
    REV_KEY_COMPROMISE    = 3, /* Value is cert key compromise time */
    REV_CA_COMPROMISE     = 4  /* Value is CA key compromise time */
} REVINFO_TYPE;


#define GZCMS_TYPE_UNDEF        NID_undef
#define GZCMS_TYPE_DATA         NID_pkcs7_data
#define GZCMS_TYPE_SIGNED       NID_pkcs7_signed
#define GZCMS_TYPE_ENCRYPTED    NID_pkcs7_encrypted
#define GZCMS_TYPE_ENVELOPED    NID_pkcs7_enveloped
#define GZCMS_TYPE_DIGEST       NID_pkcs7_digest
#define GZCMS_TYPE_SIGNED_AND_ENCRYPTED NID_pkcs7_signedAndEnveloped

#define ERR_TAG     ANSI_COLOR_RED_BOLD"error:"ANSI_COLOR_RESET
#define INFO_TAG    ANSI_COLOR_YELLOW_BOLD"info:"ANSI_COLOR_RESET
#define DEBUG_TAG   ANSI_COLOR_CYAN_BOLD"debug:"ANSI_COLOR_RESET

#define GZCMS_IS_DETACHED       0
#define GZCMS_IS_NOT_DETACHED   1

# define FORMAT_FILE    1
# define FORMAT_MEM     2

//FROM(apps.h)
# define B_FORMAT_TEXT   0x8000
# define FORMAT_UNDEF    0
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */
# define FORMAT_BINARY   2                      /* Generic binary */
# define FORMAT_BASE64  (3 | B_FORMAT_TEXT)     /* Base64 */
# define FORMAT_ASN1     4                      /* ASN.1/DER */
# define FORMAT_PEM     (5 | B_FORMAT_TEXT)
# define FORMAT_PKCS12   6
# define FORMAT_SMIME   (7 | B_FORMAT_TEXT)
# define FORMAT_ENGINE   8                      /* Not really a file format */
# define FORMAT_PEMRSA  (9 | B_FORMAT_TEXT)     /* PEM RSAPubicKey format */
# define FORMAT_ASN1RSA  10                     /* DER RSAPubicKey format */
# define FORMAT_MSBLOB   11                     /* MS Key blob format */
# define FORMAT_PVK      12                     /* MS PVK file format */
# define FORMAT_HTTP     13                     /* Download using HTTP */
# define FORMAT_NSS      14                     /* NSS keylog format */
# define EXT_COPY_NONE   0
# define EXT_COPY_ADD    1
# define EXT_COPY_ALL    2
# define NETSCAPE_CERT_HDR       "certificate"
# define APP_PASS_LEN    1024


# define B_TOKEN_LOAD_KEY   0x8000
# define LOAD_NO_KEY        0
# define LOAD_DEVICE_KEY    (1 | B_TOKEN_LOAD_KEY)
# define LOAD_CLIENT_KEY    (2 | B_TOKEN_LOAD_KEY)
# define LOAD_SERVER_KEY    (3 | B_TOKEN_LOAD_KEY)
# define LOAD_CA_KEY        (4 | B_TOKEN_LOAD_KEY)



//==============================
// CMS RETURN VALUE
//==============================
#define CMS_RET_OK      0x10 //16
#define CMS_RET_FAIL    0x20 //32
#define CMS_RET_ERROR   0x30 //48
#define CMS_RET_UNDEF   0x40 //64

#define CMS_VERIFY_OK  (1 | CMS_RET_OK)
#define CMS_VERIFY_FAIL  (1 | CMS_RET_FAIL)

#define CMS_OPT_ON  1
#define CMS_OPT_OFF 0
#define CMS_OPT_UNDEF 0

#define OCSP_VERIFY_OK      (1 | CMS_RET_OK)
#define OCSP_VERIFY_FAIL    (1 | CMS_RET_FAIL)
#define OCSP_VERIFY_WARN    (2 | CMS_RET_FAIL)


# define SMIME_OP               0x10
# define SMIME_IP               0x20
# define SMIME_SIGNERS          0x40
# define SMIME_ENCRYPT           (1  | SMIME_OP)
# define SMIME_DECRYPT           (2  | SMIME_IP)
# define SMIME_SIGN              (3  | SMIME_OP | SMIME_SIGNERS)
# define SMIME_VERIFY            (4  | SMIME_IP)
# define SMIME_CMSOUT            (5  | SMIME_IP | SMIME_OP)
# define SMIME_RESIGN            (6  | SMIME_IP | SMIME_OP | SMIME_SIGNERS)
# define SMIME_DATAOUT           (7  | SMIME_IP)
# define SMIME_DATA_CREATE       (8  | SMIME_OP)
# define SMIME_DIGEST_VERIFY     (9  | SMIME_IP)
# define SMIME_DIGEST_CREATE     (10 | SMIME_OP)
# define SMIME_UNCOMPRESS        (11 | SMIME_IP)
# define SMIME_COMPRESS          (12 | SMIME_OP)
# define SMIME_ENCRYPTED_DECRYPT (13 | SMIME_IP)
# define SMIME_ENCRYPTED_ENCRYPT (14 | SMIME_OP)
# define SMIME_SIGN_RECEIPT      (15 | SMIME_IP | SMIME_OP)
# define SMIME_VERIFY_RECEIPT    (16 | SMIME_IP)


# define GZPKI_OP   0x50
# define GZPKI_RAND                 (1  | GZPKI_OP)
# define GZPKI_KEYPASS              (2  | GZPKI_OP)
# define GZPKI_ENCRYPT              (3  | GZPKI_OP)
# define GZPKI_DECRYPT              (4  | GZPKI_OP)
# define GZPKI_CIPHER_LIST          (5  | GZPKI_OP)
# define GZPKI_CIPHER_LIST_ALL      (6  | GZPKI_OP)
# define GZPKI_CIPHER_LIST_COMPAT   (7  | GZPKI_OP)
# define GZPKI_DIGEST_LIST          (8  | GZPKI_OP)

# define ECC_OP   0x60
# define ECC_ENCRYPT                (1 | ECC_OP)
# define ECC_DECRYPT                (2 | ECC_OP)
# define ECCP2_ENCRYPT              (3 | ECC_OP)
# define ECCP2_DECRYPT              (4 | ECC_OP)
# define ECCP2_GENERATE_SECRET      (5 | ECC_OP)


#if 1
    #define REQ_ATTR_UNKNOWN_S      "unknownAttribute"
    #define REQ_ATTR_CHAP_S         "challengePassword"
    #define REQ_ATTR_UNSNAME_S      "unstructuredName"
    #define REQ_ATTR_CONTENT_TYPE_S "contentType"

    #define REQ_TYPE_NEW      "new"
    #define REQ_TYPE_RENEW    "renew"
    #define REQ_TYPE_UPDATE   "update"
    #define REQ_TYPE_REVOKE   "revoke"
    #define REQ_TYPE_DELETE   "delete"
    #define REQ_TYPE_GETCERT  "get-cert"
    #define REQ_TYPE_GETCRL   "get-crl"
    #define REQ_TYPE_GETCA    "get-ca"

    #define REQ_CERT_TYPE_CLIENT     "client"
    #define REQ_CERT_TYPE_SERVER     "server"
    #define REQ_CERT_TYPE_MANAGER    "manager"
    #define REQ_CERT_TYPE_SELFSIGNED "selfsigned"

    #define REQ_STATUS_PENDING    "pending"
    #define REQ_STATUS_APPROVAL   "approval"
    #define REQ_STATUS_REJECTED   "rejected"
    #define REQ_STATUS_COMPLETED  "completed"
    #define REQ_STATUS_ISSUED     "issued"
    #define REQ_STATUS_ERROR      "error"
#endif

#define PREFIX_CTRL_SET_PREFIX  (1 << 15)



typedef struct cmm_token_st {
    int type; /*USB, FILE, ...*/
    char *token_dir;

    char *device_certfile;
    char *device_keyfile;
    char *device_password;

    char *server_certfile;
    char *server_keyfile;

    char *ca_certfile;
    char *ca_keyfile;

    X509 *device_cert;
    X509 *server_cert;
    X509 *ca_cert;
    
    EVP_PKEY *device_key;
    EVP_PKEY *server_key;
    EVP_PKEY *ca_key;
    
    char *x1_filename;
    char *y1_filename;
    char *ke_filename;

    char *x1_hexstr;
    char *y1_hexstr;
    char *ke_hexstr;

    BIGNUM *x1;
    BIGNUM *y1;
    BIGNUM *ke;
} TOKEN_CTX ;



struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */ ;


/* TODO:
 * 1. 모든 경우 default는 FORMAT_SMIME -> FORMAT_PEM으로 변경한다. 
   2. 우리는 이메일 라이브러리가 아니다. PEM이 크기도 작다.
 */
struct gzpki_ctx_st {

    int operation; // 0
    
    unsigned char *device_password;
    //==================================================
    //공통변수
    //==================================================
        char *infile;
        BIO *in;
        int informat;   //FORMAT_SMIME
        int intype ;
       
        char *outfile;
        BIO *out;
        int outformat;  //FORMAT_SMIME;
        int outtype ;

        int keyformat;  //X509
        int CAformat;   //X509
        int CAkeyformat;//X509

        BIO *bio_in ;
        BIO *bio_out;
        BIO *bio_err ;

        ENGINE *e;

        //TODO : req에서 사용, 확인 후 변경
        char *passargin;
        char *passargout;
        char *outdata;
        char *passin;
        char *passout;
        char *passinarg;
        char *passoutarg;
        
        int noout; // 0
        int errcode;
        
        char errstr[256];

        BUF_MEM *bptr;
        
    //ECC KEY 관련 변수
    //ECC PARAM
        BIGNUM *ec_gen;
        BIGNUM *ec_orderL;
        BIGNUM *ec_cofactorL;
        BIGNUM *ec_p;
        BIGNUM *ec_a;
        BIGNUM *ec_b;
        BIGNUM *ec_order;
        BIGNUM *ec_cofactor;
        
        EC_GROUP *group;
        
        point_conversion_form_t form;// = POINT_CONVERSION_UNCOMPRESSED;
        
        char *curve_name;
        unsigned char *buffer;
        int asn1_flag;// = OPENSSL_EC_NAMED_CURVE;
        int new_asn1_flag;// = 0;
        //DEL int C;// = 0;
        int ret;// = 1;
        int private;// = 0;
        int no_seed;// = 0;
        int check;// = 0;
        int new_form;// = 0;
        int text;// = 0;
        int genkey;// = 0;
    
    //--------------------------------------------------
    // ECC KEY 
    //--------------------------------------------------
        int param_out;
        int pubin;
        int pubout;
        int no_public;
        char *name;
        const EVP_CIPHER *enc;
    
    //--------------------------------------------------
    // REQ 
    //--------------------------------------------------
        int newreq;
        int batch;
        int newhdr;
        int verify;
        int verbose;
        int modulus;
        int chtype;
        int pubkey;
        int x509;
        int days; //REQ+X509+CA
        int multirdn;
        int subject_out; //CMS subject 존재 -> subject_out
        int precert;
        char *keyout;
        char *keyoutfile;
        char *keyalg;
        char *inserial;
        char *subj;    
        char *extensions;
        char *req_exts;
        char *default_config_file;
        CONF *req_conf;
        CONF *addext_conf;
        char *req_section;

        char app_config[256];

        X509_REQ *req;
        ASN1_INTEGER *serial;
        EVP_PKEY *pkey; //기존 CMS용 key 존재
        EVP_PKEY_CTX *genctx; //개인키 생성 정보, REQ에서 사용

        STACK_OF(OPENSSL_STRING) *pkeyopts;
        STACK_OF(OPENSSL_STRING) *sigopts;
        LHASH_OF(OPENSSL_STRING) *addexts;
        X509 *x509ss;
        const EVP_MD *md_alg;
        const EVP_MD *digest;

    //--------------------------------------------------
    //VERIFY 관련 변수
    //--------------------------------------------------
        int opt_verify_trusted;
        int opt_verify_crl_download;
        int opt_verify_show_chain;
        char *trusted_certfile;
        char *untrusted_certfile;
        char *verify_opts;

        char *verify_add_policy; //"adds policy to the acceptable policy set"
        char *verify_purpose;
        char *verify_name;
        int verify_depth;
        int verify_auth_level;
        char *verify_epoch_time;
        char *verify_host_name;
        char *verify_email;
        char *verify_ip;


    //--------------------------------------------------
    //CA VERIFICATION CA 관련 변수
    //--------------------------------------------------
        char *CAfile; // CMA, X509
        int  cafileformat;
        char *CApath;
        
        int noCAfile;
        int noCApath;
    
        //almost common
        const EVP_CIPHER *cipher; //CMS/REQ에서 사용
        const EVP_CIPHER *wrap_cipher;

        EVP_MD *sign_md;

        char *keyfile; //REQ
        EVP_PKEY *key;
    
        char *certfile;
        char *crlfile;
        X509 *cert;
    
        char *signerfile;
        X509 *signer;

        X509_STORE *store;



    //GZCMS
        char *cipher_name;
        ASN1_OBJECT *econtent_type;
        BIO *indata;
        BIO *rctin;
        CMS_ContentInfo *cms;
        CMS_ContentInfo *rcms;
        CMS_ReceiptRequest *rr;
        
        STACK_OF(OPENSSL_STRING) *rr_to;
        STACK_OF(OPENSSL_STRING) *rr_from;
        STACK_OF(OPENSSL_STRING) *sksigners;
        STACK_OF(OPENSSL_STRING) *skkeys;
        STACK_OF(OPENSSL_STRING) *skpassins;
        STACK_OF(X509) *encerts;
        STACK_OF(X509) *other;

        X509 *recip;
        
        X509_VERIFY_PARAM *vpm;
            
        char *contfile;
        char *certsoutfile;
        char *rctfile;
        
        char *recipfile;
        char *to;
        char *from;
        char *subject;
        //char *prog; //DELETE THIS

        //pki_key_param *key_first;
        //pki_key_param *key_param;

        int flags; // CMS_DETACHED
        
        int print; //0
        int keyidx; // -1
        int vpmtouched; // 0
    
        int rr_print; // 0
        int rr_allorfirst; // -1;
        
        int verify_retcode; // 0
        int rctformat; // FORMAT_SMIME
        int keyform; // FORMAT_PEM: (cms, req)
        
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
        
        int outdata_length;

    //----------
    // REQ Config
    //----------
        char *default_bits;
        char *default_keyfile; //check
        char *string_mask; //check
        char *default_md; //check

        char *distinguished_name;
        char *req_extensions;
        char *x509_extensions ;
    
    //subject
        char *countryName;
        char *stateOrProvinceName;
        char *localityName;
        char *organizationName;
        char *organizationUnitName;
        char *commonName;
        char *emailAddress;

        char *countryName_default;
        char *stateOrProvinceName_default;
        char *localityName_default;
        char *organizationName_default;
        char *organizationUnitName_default;
        char *commonName_default;
        char *emailAddress_default;

    //X509 Extensions + REQ Extension
        char *subjectKeyIdentifier;
        char *issuerKeyIdentifier;
        char *basicConstraints;
        char *keyUsage;
        char *subjectAltName;
        char *nsComment; //REMOVE
        char *extendedKeyUsage;
        char *authorityKeyIdentifier;
    //REQ req_attributes
        char *challengePassword;
        char *challengePassword_default;
        char *contentType;
        char *contentType_default;
        char *unstructuredName;
        char *unstructuredName_default;

    //REQ VALUE RETURNED by text option
    //함수는 나중에...
        int reqVersion;
        char *reqSubjectDN;
        char *reqAlgorithmName;
        int reqErrcode;
        char *reqErrstr;       
        char *reqChallengePassword;
        char *reqContentType;
        char *reqUnstructuredName;
        char *reqRole;
        char *reqSubjectKeyIdentifier;

        char *reqCN;
        char *reqEmail;
        char *reqUUID;
        char *reqData;
        char *reqDate;
        char *reqFilename;
        int reqKeyBits;

        //char *content_type;
        //char *unstructured_name;
        //char *challenge_password;

    //DNS.1에서 DNS.8까지 정의함
    //필요에 따라 수를 늘릴수 있음
        char *DNS1;
        char *DNS2;
        char *DNS3;
        char *DNS4;
        char *DNS5;
        char *DNS6;
        char *DNS7;
        char *DNS8;

        char *req_conf_str;

        char *utf8; //"yes" or ....

    // RA SERVER
        char *ra_ip;
        char *ra_reqin;
        char *ra_reqinfile;
        int   ra_port;
        int   ra_use_ssl;

    // REQ option
        int opt_req_verify;
        int req_verify_result;
    
     //==================================================
    //X509 
    //==================================================
        char *extfile;
        char *extsect;
        //char *CAfile;

        int opt_sign_flag;
        int opt_CA_flag;

        char *CAkeyfile;
        char *CAserial;
        char *randfile;
        //char *inserial; //REQ, X509
        char *fkeyfile;
        char *addtrust;
        char *addreject;
        char *alias;
        char *checkhost;
        char *checkip;
    
        int certflag ; //int //set_cert_ex 참조 설정함수를 만든다. GZPKI_set_certflag() 외부 call
        int opt_email;
        int opt_ocsp_uri;
        int opt_serial;
        int opt_next_serial;
        int opt_modulus;
        int opt_pubkey;
        int opt_x509req;
        int opt_text;
        int opt_subject;
        int opt_issuer;
        int opt_fingerprint;
        int opt_subject_hash;
        int opt_subject_hash_old;
        int opt_issuer_hash;
        int opt_issuer_hash_old;
        int opt_pprint;
        int opt_startdate;
        int opt_enddate;
        int opt_noout;
        int opt_ext;
        int opt_nocert;
        int opt_trustout;
        int opt_clrtrust;
        int opt_clrreject;
        int opt_aliasout;
        int opt_CA_createserial;
        int opt_clrext;
        int opt_ocspid;
        int opt_badsig;
        int opt_checkend;
        int opt_preserve_dates;
        int opt_reqfile;

    // CERTIFICATE FIELD RETURN
        char *x509_field_email; 
        char *x509_field_ocsp_uri; 
        char *x509_field_serial;
        char *x509_field_next_serial; 
        char *x509_field_modulus; 
        char *x509_field_pubkey; 
        char *x509_field_x509req; 
        char *x509_field_text; 
        char *x509_field_subject; 
        char *x509_field_issuer; 
        char *x509_field_fingerprint; 
        char *x509_field_subject_hash; 
        char *x509_field_subject_hash_old; 
        char *x509_field_issuer_hash; 
        char *x509_field_issuer_hash_old; 
        char *x509_field_pprint; 
        char *x509_field_startdate; 
        char *x509_field_enddate; 
        char *x509_field_noout; 
        char *x509_field_ext; 
        char *x509_field_clrtrust; 
        char *x509_field_clrreject; 
        char *x509_field_aliasout; 
        char *x509_field_CA_createserial; 
        char *x509_field_ocspid; 

        char *req_field_subject; 

        int opt_get_field_all;


    //--------------------------------------------------
    // OCSP
    //--------------------------------------------------
        int req_timeout;
        int ocsp_port;
        int ocsp_opt_ignore_err;
        int ocsp_opt_noverify;
        int ocsp_opt_add_nonce;
        int ocsp_opt_resp_no_certs;
        int ocsp_opt_resp_key_id;
        int ocsp_opt_no_certs;
        int ocsp_opt_no_signature_verify;
        int ocsp_opt_no_cert_verify;
        int ocsp_opt_no_chain;
        int ocsp_opt_no_cert_checks;
        int ocsp_opt_no_explicit;
        int ocsp_opt_trust_other;
        int ocsp_opt_no_intern;
        int ocsp_opt_badsig;
        int ocsp_opt_req_text;
        int ocsp_opt_resp_text;
        int ocsp_valididy_period; //nsec
        int ocsp_status_age; //maxage
        int ocsp_accept_count;
        int ocsp_ndays;
        int ocsp_next_minutes;
        int ocsp_multi;


        char *ocsp_url;
        char *ocsp_host;
        char *ocsp_reqin;
        char *ocsp_respin;
        char *ocsp_signerfile;
        char *ocsp_verify_certfile;
        char *ocsp_sign_certfile;
        char *ocsp_reqout;
        char *ocsp_respout;
        char *ocsp_path;
        char *ocsp_issuer_certfile;
        char *ocsp_certfile;
        char *ocsp_serial;
        char *ocsp_index_filename;
        char *ocsp_ca_filename;
        char *ocsp_resp_signfile;
        char *ocsp_resp_keyfile;
        char *ocsp_resp_other_certfile;
        EVP_MD *ocsp_resp_sign_md;

        int ocsp_verify_result;
        char *ocsp_verify_result_str;

    //----------
    // CA
    //----------
        char *configfile;
        char *section_name;
        char *subjec_str;
        int opt_ca_rand_serial;
        int opt_ca_create_serial;
        int opt_ca_multivalue_rdn;
        int opt_ca_load_private_key;
        char *startdate;
        char *enddate;
        int certificate_days;
        char *ca_policy;
        char *sign_md_alg;
        int opt_ca_selfsign;
        char *ca_outdir;
        char *ca_signature_parameters;
        int opt_ca_no_text;

        int opt_preserve_dn;
        int opt_ca_email_dn;
        int opt_ca_msie_hack;
        int opt_ca_generate_crl;
        int crl_crldays;
        int crl_crlhours;
        int crl_crlsec;
        //int ca_opt_reqinfile;
        int opt_ca_reqinfile; // opt_ca_reqin과 같이 유지, req를 파일에서 읽는 경우 사용한다. 
        int opt_ca_do_revoke;
        int opt_ca_update_database;

        char *ca_selfsigned_certificate;
        char *spkac_file;
        char *caconf_entensions_section_name;
        char *caconf_crl_entensions_section_name;
        char *ca_status_serial;
        char *caconf_entensions_file_name;
        char *crl_revoke_reason;
        REVINFO_TYPE crl_revoke_type;
        int ca_request_file_cnt;
        char *ca_request_file[8]; //FIX

        int debug_mode;

        //new added
        int opt_ca_reqin;

        int use_sqldb;
        int use_txtdb;
        char *ca_name;
        char *key_pem;
        char *csr_pem;
        char *key_pass;

        //database
        char *db_ip;
        int   db_port;
        char *db_file;
        char *db_user;
        char *db_name;
        char *db_pwd;

        int opt_ca_index_db_sync;

        //---- ca out data
        char *caCertFilename;
        char *caSerial;
        char *caCertKey;
        char *caSubjectDN;
        char *caIssuerDN;
        char *caIssueDate;
        char *caNotBefore;
        char *template_id;

        //common
        //unsigned long req_nameoft; 
        unsigned long opt_req_nameopt; //XN_FLAG_SEP_COMMA_PLUS
        unsigned long opt_cert_nameopt;
        unsigned long opt_nameopt;

        //char *req_uuid;

    //ENC
        int base64;
        int olb64;
        int cipher_list;
        int printkey;
        int nopad;
        int nosalt;
        int pbkdf2; //0
        int iter;
        char *passphrase;
        char *passphrase_file;
        char *rawkey_hex;
        char *salt_hex;
        char *iv_hex;
        char *dgst_name;
    
};

typedef struct gzpki_ctx_st GZPKI_CTX;



# define ASN1_STRFLGS_RFC2253_GZ    (ASN1_STRFLGS_ESC_2253 | \
                                ASN1_STRFLGS_ESC_CTRL | \
                                ASN1_STRFLGS_UTF8_CONVERT | \
                                ASN1_STRFLGS_DUMP_UNKNOWN | \
                                ASN1_STRFLGS_DUMP_DER)                        
# define XN_FLAG_RFC2253_GZ (ASN1_STRFLGS_RFC2253_GZ | \
                        XN_FLAG_SEP_COMMA_PLUS | \
                        XN_FLAG_DN_REV | \
                        XN_FLAG_FN_SN | \
                        XN_FLAG_DUMP_UNKNOWN_FIELDS)

//#define GZPKI_NAME_OPTS "RFC2253,utf8,dn_rev"
#define GZPKI_NAME_OPTS "sep_comma,utf8"
#define GZPKI_DEFAULT_NAME_OPT XN_FLAG_RFC2253_GZ
//#define GZPKI_DEFAULT_NAME_OPT_STR "XN_FLAG_RFC2253_GZ"
#define GZPKI_DEFAULT_NAME_OPT_STR "utf8"
//ASN1_STRFLGS_RFC2253 | XN_FLAG_SEP_COMMA_PLUS
//(ASN1_STRFLGS_RFC2253 | XN_FLAG_SEP_COMMA_PLUS | ASN1_STRFLGS_UTF8_CONVERT | XN_FLAG_FN_SN | XN_FLAG_DUMP_UNKNOWN_FIELDS)



//ASN1_STRFLGS_RFC2253 | XN_FLAG_SEP_COMMA_PLUS | XN_FLAG_FN_SN | XN_FLAG_DUMP_UNKNOWN_FIELDS | ASN1_STRFLGS_UTF8_CONVERT


//==============================
// ANSI COLOR
//==============================
#define ANSI_COLOR_RED 		"\x1b[31m"
#define ANSI_COLOR_GREEN 	"\x1b[32m"
#define ANSI_COLOR_YELLOW	"\x1b[33m"
#define ANSI_COLOR_BLUE		"\x1b[34m"
#define ANSI_COLOR_MAGENTA	"\x1b[35m"
#define ANSI_COLOR_CYAN 	"\x1b[36m"
#define ANSI_COLOR_RESET	"\x1b[0m"

#define ANSI_COLOR_RED_BOLD		"\x1b[1;31m"
#define ANSI_COLOR_GREEN_BOLD 	"\x1b[1;32m"
#define ANSI_COLOR_YELLOW_BOLD	"\x1b[1;33m"
#define ANSI_COLOR_BLUE_BOLD	"\x1b[1;34m"
#define ANSI_COLOR_MAGENTA_BOLD	"\x1b[1;35m"
#define ANSI_COLOR_CYAN_BOLD 	"\x1b[1;36m"
#define ANSI_COLOR_RESET_BOLD	"\x1b[0m"

#define ANSI_COLOR_RED_BLINK	"\x1b[5;31m"

#define color_red       ANSI_COLOR_RED
#define color_green     ANSI_COLOR_GREEN
#define color_yellow    ANSI_COLOR_YELLOW
#define color_blue      ANSI_COLOR_BLUE
#define color_magenta   ANSI_COLOR_MAGENTA
#define color_cyan      ANSI_COLOR_CYAN
#define color_reset     ANSI_COLOR_RESET

#define color_red_b      ANSI_COLOR_RED_BOLD
#define color_green_b    ANSI_COLOR_GREEN_BOLD
#define color_yellow_b   ANSI_COLOR_YELLOW_BOLD
#define color_blue_b     ANSI_COLOR_BLUE_BOLD
#define color_magenta_b  ANSI_COLOR_MAGENTA_BOLD
#define color_cyan_b     ANSI_COLOR_CYAN_BOLD





#endif /*_GZPKI_TYPES_H_*/

