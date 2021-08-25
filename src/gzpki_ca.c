# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <time.h>
# include <assert.h>
# include <ctype.h>

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

# include "gzpki_types.h"
# include "gzpki_common.h"
# include "gzpki_ca.h"

#define GZPKI_POLICY_ON     1
#define GZPKI_POLICY_OFF    0
#define GZPKI_CMM_HOME       "/home/gzpki/"


//2 COMMON.H
static const char *crl_reasons[] = {
    /* CRL reason strings */
    "unspecified",
    "keyCompromise",
    "CACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
    "removeFromCRL",
    "holdInstruction",     /* Additional pseudo reasons */
    "keyTime",
    "CAkeyTime"
};

#ifndef _NO_CA_
int is_valid_crl_reason(char *rev_arg) {

    int i = 0;
    for (i = 0; i < 8; i++) {
            if (strcasecmp(rev_arg, crl_reasons[i]) == 0) {
                return 0;
            }
        }
        return 1;
}


int GZPKI_set_sqldb(GZPKI_CTX *ctx, char *db_ip, int db_port, char *db_user, char *db_name, char *db_pwd) {
    if(db_ip)   ctx->db_ip = GZPKI_strdup(db_ip);
    ctx->db_port = db_port;
    if(db_user) ctx->db_user = GZPKI_strdup(db_user);
    if(db_name) ctx->db_name = GZPKI_strdup(db_name);
    if(db_pwd)  ctx->db_pwd = GZPKI_strdup(db_pwd);

    return CMS_RET_OK;
}

int gzpki_cadb_init(PKIDB_CTX *sql, char *host, char *user, char *file, char *passwd, char *db, int port) {
    
    int fields = 0;
    int cnt = 0;
    
    printf("gzpki_cadb_init(): BEGIN\n");

#ifdef __WITH_MYSQL__

    mysql_init(&sql->DB_CONN);

	if(!mysql_real_connect(&sql->DB_CONN, NULL, user,passwd, db ,port, (char *)NULL, 0)) {
		printf("%s\n",mysql_error(&sql->mysql));
		return CMS_RET_ERROR;
	}
#elif defined(__WITH_SQLITE__)
    int rc=-1;
    rc = sqlite3_open(file, &sql->DB_CONN);

    if (rc != SQLITE_OK) {
        fprintf(stderr,"error:fail to open database: %s\n", file);
        return CMS_RET_ERROR;
    }
#endif

	printf("[gzpki_cadb_init] sussecc to connect database...\n") ;

    return CMS_RET_OK;
}

int gzpki_cadb_free(PKIDB_CTX *sql) {

    printf("gzpki_cadb_free()\n");

#ifdef __WITH_MYSQL__
	if(&DB_CONN) 
        mysql_close(&sql->DB_CONN) ;
#elif defined __WITH_SQLITE__ 
    if(&DB_CONN) 
        sqlite3_close(sql->DB_CONN) ;
#endif         
    return CMS_RET_OK;
}


int gzpki_policy_init(GZPKI_POLICY *p) {
    p->use              = GZPKI_POLICY_ON;

    //출력명
    p->policy_name      = NULL; //CA 섹션, DIR, 확장필드섹션명
    p->policy_id        = 0;

    p->home             = GZPKI_CMM_HOME;
    //[ca]    
    p->base_section     = BASE_SECTION;  //"ca"

    //default_ca = CA_policy_###ID###
    p->default_ca       = NULL; //"CA_default"
    //정책명에 따라 이름을 동적으로 생성한다. 
    //섹션명
    //x509_extensions = "x509ext." + ###ID###
    p->x509_extensions = NULL;          
    //CRL 확장 필드 [crlext.###ID###]
    p->crl_extensions    = NULL;       //section name    
    p->policy            = NULL;       //ENV_POLICY    "policy"
    
    //dir = GZPKI_CMM_HOME + "ca." ###ID###
    p->dir              = NULL;

    //certs = $dir/certs
    p->certs            = "certs";

    //crl_dir = $dir/crl
    p->crl_dir          = "crl";

    //database = $dir/index.txt
    p->database         = "index.txt";

    //new_certs_dir = $dir/new_certs_dir
    p->new_certs_dir    = ENV_NEW_CERTS_DIR; //"new_certs_dir"

    //certificate = $dir/cacert.pem
    p->certificate      = ENV_CERTIFICATE;   //"certificate"

    //serial = $dir/serial
    p->serial           = ENV_SERIAL; //"serial"

    //serial = $dir/rand_serial
    p->serial           = ENV_RAND_SERIAL; //"rand_serial"

    //crl_number = $dir/crlnumber
    p->rand_serial       = ENV_CRLNUMBER; //"crlnumber"

    //private_key = $dir/private_key
    p->private_key      = ENV_PRIVATE_KEY;   //"private_key"
    //
    p->randfile         = "randfile";

    //단순 yes/no
    p->unique_subject	    = "no";

    //
    p->default_days         = 365;      //ENV_DEFAULT_DAYS      "default_days"
    p->default_crl_days     = 1;        //ENV_DEFAULT_CRL_DAYS  "default_crl_days"
    p->default_crl_hours    = 0;        //ENV_DEFAULT_CRL_HOURS "default_crl_hours"

    p->default_startdate    = NULL;     //ENV_DEFAULT_STARTDATE "default_startdate"
    p->default_enddate      = NULL;     //ENV_DEFAULT_ENDDATE   "default_enddate"
    p->default_md           = "SHA256";                  //ENV_DEFAULT_MD        "default_md"
    p->default_email_in_dn;         //ENV_DEFAULT_EMAIL_DN  "email_in_dn"
    p->preserve             = "no";                    //ENV_PRESERVE          "preserve"

    //불필요함. 확인 후 삭제
    p->name_opt             = NULL; //ENV_NAMEOPT           "name_opt"
    //불필요함. 확인 후 삭제
    p->cert_opt             = NULL; //ENV_CERTOPT           "cert_opt"
    
    //policy_section
    //[policy.001]
    p->countryName              = "optional";  //match, optional, supplied
    p->stateOrProvinceName      = "optional";
    p->localityName             = "optional";
    p->organizationName         = "optional";
    p->organizationalUnitName   = "optional";
    p->commonName               = "optional";
    p->emailAddress             = "optional";

    //인증서 확장 필드
    //[x509_extension]
    p->basicConstraints;
    p->keyUsage;                 //ex) nonRepudiation, digitalSignature, keyEncipherment, ex) cRLSign, keyCertSign
    p->nsCertType;               //ex) client, email, objsign, ex) sslCA, emailCA
    p->nsComment                = NULL;
    p->subjectKeyIdentifier     = NULL;     //ex) hash
    p->authorityKeyIdentifier   = NULL;     //ex) keyid,issuer:always
    p->subjectAltName           = NULL;     //ex) email:copy
    p->issuerAltName            = NULL;     //ex) issuer:copy
    p->nsCaRevocationUrl        = NULL;     //ex) http://www.domain.dom/ca-crl.pem
    p->nsBaseUrl                = NULL;
    p->nsRevocationUrl          = NULL;
    p->nsRenewalUrl             = NULL;
    p->nsCaPolicyUrl            = NULL;
    p->nsSslServerName          = NULL;


    //[crlext.001]    
    char *crl_issuerAltName;
    char *crl_authorityKeyIdentifier;

    char *string_mask;          //STRING_MASK           "string_mask"
    char *utf8_in;              //UTF8_IN               "utf8"
    
    
    char *extensions;           //ENV_EXTENSIONS        "x509_extensions"
    //char *crlext;               //ENV_CRLEXT            "crl_extensions"
    char *msie_hack;            //ENV_MSIE_HACK         "msie_hack"
    char copy_extensions;       //ENV_EXTCOPY           "copy_extensions"
    //char *unique_subject;       //ENV_UNIQUE_SUBJECT    "unique_subject"

    char *tsa_config;
    char *tsa_dir;
    char *tsa_serial;
    char *tsa_crypto_device;
    char *tsa_single_cert;
    char *tsa_certs;
    char *tsa_signer_key;
    char *tsa_signer_digest;
    char *tsa_policy;
    char *tsa_otherPolicies;
    char *tsa_digest;
    char *tsa_accuracy;
    char *tsa_ordering;
    char *tsa_name;
    char *tsa_ess_cert_id_chain;
    char *tsa_ess_cert_id_alg;
    int   tsa_clock_precision_digits;
};
#endif //_NO_CA_

#include <iconv.h>

char * convert(char *tgt, char *src, char *input, float rate)
{
    iconv_t it = iconv_open(tgt, src);
    if(it == (iconv_t) -1)
    {
        fprintf(stderr, "iconv open error");
        return NULL;
    }
    size_t nSrc = strlen(input) + 1;  // for '\0'
    size_t nTgt = nSrc * rate;
    char * output = (char *)malloc(nTgt);
    char * pOutput = output;
    // printf("s:%lu\tt:%lu\n", nSrc, nTgt);

    if(iconv(it, (char **)&input, &nSrc, &pOutput, &nTgt) == (size_t) -1)
    {
        fprintf(stderr, "iconv error\n");
        return NULL;
    }
    // printf("s:%lu\tt:%lu\n", nSrc, nTgt);
    return output;    // Don't forget to 'free()'!!
}

char * u2e(char * input) { 
	return convert("CP949//TRANSLIT//IGNORE", "UTF-8//TRANSLIT//IGNORE", input, 1); 
}

char * e2u(char * input) { 
	return convert("UTF-8//TRANSLIT//IGNORE", "CP949//TRANSLIT//IGNORE", input, 3); 
}


static char *lookup_conf(const CONF *conf, const char *group, const char *tag);

static int certify(GZPKI_CTX *ctx, X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                   BIGNUM *serial, const char *subj, unsigned long chtype,
                   int multirdn, int email_dn, const char *startdate,
                   const char *enddate,
                   long days, int batch, const char *ext_sect, CONF *conf,
                   int verbose, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign);
static int certify_cert(GZPKI_CTX *ctx, X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                        const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                        STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                        BIGNUM *serial, const char *subj, unsigned long chtype,
                        int multirdn, int email_dn, const char *startdate,
                        const char *enddate, long days, int batch, const char *ext_sect,
                        CONF *conf, int verbose, unsigned long certopt,
                        unsigned long nameopt, int default_op, int ext_copy);
#if 0                        
static int certify_spkac(X509 **xret, const char *infile, EVP_PKEY *pkey,
                         X509 *x509, const EVP_MD *dgst,
                         STACK_OF(OPENSSL_STRING) *sigopts,
                         STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                         BIGNUM *serial, const char *subj, unsigned long chtype,
                         int multirdn, int email_dn, const char *startdate,
                         const char *enddate, long days, const char *ext_sect, CONF *conf,
                         int verbose, unsigned long certopt,
                         unsigned long nameopt, int default_op, int ext_copy);
#endif 

static int do_body(GZPKI_CTX *ctx, X509 **xret, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db, BIGNUM *serial,
                   const char *subj, unsigned long chtype, int multirdn,
                   int email_dn, const char *startdate, const char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, const char *ext_sect,
                   CONF *conf, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign);
static int get_certificate_status(const char *ser_status, CA_DB *db);
static int get_certificate_status_SQL(const char *ser_status, char *file);
static int do_updatedb(CA_DB *db);
static int check_time_format(const char *str);
static int do_revoke(X509 *x509, CA_DB *db, REVINFO_TYPE rev_type, const char *extval);
static int do_revoke2(GZPKI_CTX *ctx, X509 *x509, CA_DB *db, REVINFO_TYPE rev_type, const char *extval);
static char *make_revocation_str(REVINFO_TYPE rev_type, const char *rev_arg);
static int make_revoked(X509_REVOKED *rev, const char *str);
static int old_entry_print(const ASN1_OBJECT *obj, const ASN1_STRING *str);
static void write_new_certificate(BIO *bp, X509 *x, int output_der, int notext);

static CONF *extconf = NULL;
static int preserve = 0;
static int msie_hack = 0;

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_VERBOSE, OPT_CONFIG, OPT_NAME, OPT_SUBJ, OPT_UTF8,
    OPT_CREATE_SERIAL, OPT_MULTIVALUE_RDN, OPT_STARTDATE, OPT_ENDDATE,
    OPT_DAYS, OPT_MD, OPT_POLICY, OPT_KEYFILE, OPT_KEYFORM, OPT_PASSIN,
    OPT_KEY, OPT_CERT, OPT_SELFSIGN, OPT_IN, OPT_OUT, OPT_OUTDIR,
    OPT_SIGOPT, OPT_NOTEXT, OPT_BATCH, OPT_PRESERVEDN, OPT_NOEMAILDN,
    OPT_GENCRL, OPT_MSIE_HACK, OPT_CRLDAYS, OPT_CRLHOURS, OPT_CRLSEC,
    OPT_INFILES, OPT_SS_CERT, OPT_SPKAC, OPT_REVOKE, OPT_VALID,
    OPT_EXTENSIONS, OPT_EXTFILE, OPT_STATUS, OPT_UPDATEDB, OPT_CRLEXTS,
    OPT_RAND_SERIAL,
    OPT_R_ENUM,
    /* Do not change the order here; see related case statements below */
    OPT_CRL_REASON, OPT_CRL_HOLD, OPT_CRL_COMPROMISE, OPT_CRL_CA_COMPROMISE
} OPTION_CHOICE;

char *db_ip = NULL;
char *db_user = NULL;
char *db_name = NULL;
char *db_pwd = NULL;
int db_port = 0;

#if 0 //DELETE
const OPTIONS ca_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output during processing"},
    {"config", OPT_CONFIG, 's', "A config file"},
    {"name", OPT_NAME, 's', "The particular CA definition to use"},
    {"subj", OPT_SUBJ, 's', "Use arg instead of request's subject"},
    {"utf8", OPT_UTF8, '-', "Input characters are UTF8 (default ASCII)"},
    {"create_serial", OPT_CREATE_SERIAL, '-',"If reading serial fails, create a new random serial"}, 
    {"rand_serial", OPT_RAND_SERIAL, '-', "Always create a random serial; do not store it"}, 
    {"multivalue-rdn", OPT_MULTIVALUE_RDN, '-', "Enable support for multivalued RDNs"},
    {"startdate", OPT_STARTDATE, 's', "Cert notBefore, YYMMDDHHMMSSZ"},
    {"enddate", OPT_ENDDATE, 's', "YYMMDDHHMMSSZ cert notAfter (overrides -days)"},
    {"days", OPT_DAYS, 'p', "Number of days to certify the cert for"},
    {"md", OPT_MD, 's', "md to use; one of md2, md5, sha or sha1"},
    {"policy", OPT_POLICY, 's', "The CA 'policy' to support"},
    {"keyfile", OPT_KEYFILE, 's', "Private key"},
    {"keyform", OPT_KEYFORM, 'f', "Private key file format (PEM or ENGINE)"},
    {"passin", OPT_PASSIN, 's', "Input file pass phrase source"},
    {"key", OPT_KEY, 's', "Key to decode the private key if it is encrypted"},
    {"cert", OPT_CERT, '<', "The CA cert"},
    {"selfsign", OPT_SELFSIGN, '-', "Sign a cert with the key associated with it"},
    {"in", OPT_IN, '<', "The input PEM encoded cert request(s)"},
    {"out", OPT_OUT, '>', "Where to put the output file(s)"},
    {"outdir", OPT_OUTDIR, '/', "Where to put output cert"},
    {"sigopt", OPT_SIGOPT, 's', "Signature parameter in n:v form"},
    {"notext", OPT_NOTEXT, '-', "Do not print the generated certificate"},
    {"batch", OPT_BATCH, '-', "Don't ask questions"},
    {"preserveDN", OPT_PRESERVEDN, '-', "Don't re-order the DN"},
    {"noemailDN", OPT_NOEMAILDN, '-', "Don't add the EMAIL field to the DN"},
    {"gencrl", OPT_GENCRL, '-', "Generate a new CRL"},
    {"msie_hack", OPT_MSIE_HACK, '-', "msie modifications to handle all those universal strings"},
    {"crldays", OPT_CRLDAYS, 'p', "Days until the next CRL is due"},
    {"crlhours", OPT_CRLHOURS, 'p', "Hours until the next CRL is due"},
    {"crlsec", OPT_CRLSEC, 'p', "Seconds until the next CRL is due"},
    {"infiles", OPT_INFILES, '-', "The last argument, requests to process"},
    {"ss_cert", OPT_SS_CERT, '<', "File contains a self signed cert to sign"},
    {"spkac", OPT_SPKAC, '<', "File contains DN and signed public key and challenge"},
    {"revoke", OPT_REVOKE, '<', "Revoke a cert (given in file)"},
    {"valid", OPT_VALID, 's',"Add a Valid(not-revoked) DB entry about a cert (given in file)"},
    {"extensions", OPT_EXTENSIONS, 's',"Extension section (override value in config file)"},
    {"extfile", OPT_EXTFILE, '<',"Configuration file with X509v3 extensions to add"},
    {"status", OPT_STATUS, 's', "Shows cert status given the serial number"},
    {"updatedb", OPT_UPDATEDB, '-', "Updates db for expired cert"},
    {"crlexts", OPT_CRLEXTS, 's', "CRL extension section (override value in config file)"},
    {"crl_reason", OPT_CRL_REASON, 's', "revocation reason"},
    {"crl_hold", OPT_CRL_HOLD, 's', "the hold instruction, an OID. Sets revocation reason to certificateHold"},
    {"crl_compromise", OPT_CRL_COMPROMISE, 's', "sets compromise time to val and the revocation reason to keyCompromise"},
    {"crl_CA_compromise", OPT_CRL_CA_COMPROMISE, 's',"sets compromise time to val and the revocation reason to CACompromise"},
    OPT_R_OPTIONS,
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};
#endif


//CA_DB *load_index(const char *dbfile, DB_ATTR *db_attr)
int load_sqldb(char *ca_name, char *dbfile)
{
    #define BSIZE   (8*1024)
    //char *dbfile = "index.txt";
    CONF *dbattr_conf = NULL;
    char buf[BSIZE];
    int unique_subject = 1;

    BIO_snprintf(buf, sizeof(buf), "%s.attr", dbfile);

    printf("load_sqldb: attr file : %s\n", buf);
    dbattr_conf = app_load_config(buf);

    if (dbattr_conf) {
        char *p = NCONF_get_string(dbattr_conf, NULL, "unique_subject");
        if (p) {
            unique_subject = parse_yesno(p, 1);
        }
    }
    else
        unique_subject = 1;
        

    return unique_subject;
}


//--------------------------------------------------
// 변경
//--------------------------------------------------
//int ca_main(int argc, char **argv)
int GZPKI_do_CA(GZPKI_CTX *ctx)
{
    CONF *conf = NULL;
    ENGINE *e = NULL;
    BIGNUM *crlnumber = NULL, *serial = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *in = NULL, *out = NULL, *Sout = NULL;
    ASN1_INTEGER *tmpser;
    ASN1_TIME *tmptm;
    CA_DB *db = NULL;
    DB_ATTR db_attr;
    STACK_OF(CONF_VALUE) *attribs = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    STACK_OF(X509) *cert_sk = NULL;
    X509_CRL *crl = NULL;
    const EVP_MD *dgst = NULL;
    char *configfile = default_config_file, *section = NULL;
    char *md = NULL, *policy = NULL, *keyfile = NULL;
    char *certfile = NULL, *crl_ext = NULL, *crlnumberfile = NULL, *key = NULL;
    const char *infile = NULL, *spkac_file = NULL, *ss_cert_file = NULL;
    const char *extensions = NULL, *extfile = NULL, *passinarg = NULL;
    char *outdir = NULL, *outfile = NULL, *rev_arg = NULL, *ser_status = NULL;
    const char *serialfile = NULL, *subj = NULL;
    char *prog, *startdate = NULL, *enddate = NULL;
    char *dbfile = NULL, *f;
    char new_cert[PATH_MAX];
    char tmp[10 + 1] = "\0";
    char *const *pp;
    const char *p;
    size_t outdirlen = 0;
    int create_ser = 0, free_key = 0, total = 0, total_done = 0;
    int batch = 0, default_op = 1, doupdatedb = 0, ext_copy = EXT_COPY_NONE;
    int keyformat = FORMAT_PEM, multirdn = 0, notext = 0, output_der = 0;
    int ret = 1, email_dn = 1, req = 0, verbose = 0, gencrl = 0, dorevoke = 0;
    int rand_ser = 0, i, j, selfsign = 0, def_nid, def_ret;
    long crldays = 0, crlhours = 0, crlsec = 0, days = 0;
    unsigned long chtype = MBSTRING_ASC, certopt = 0;
    X509 *x509 = NULL, *x509p = NULL, *x = NULL;
    REVINFO_TYPE rev_type = REV_NONE;
    X509_REVOKED *r = NULL;
    char *ca_name = NULL;
    
    int use_sqldb = 0; //0: use RDBMS, ex. MySQL
    int use_txtdb = 1; //0: use index.txt/TXT_DB
    int index_db_sync = ctx->opt_ca_index_db_sync;

    //---------------------------------------------
    //index.txt |,& mysql db
    //---------------------------------------------
    use_sqldb = ctx->use_sqldb; //default: 1
    use_txtdb = ctx->use_txtdb; //default: 1

    //OPTION_CHOICE o;
    //prog = opt_init(argc, argv, ca_options);
    if(ctx->infile) {
        infile = ctx->infile;
        req = 1;
    }

    
    if(ctx->outfile) outfile = ctx->outfile;
    if(ctx->debug_mode == 1) verbose = 1;
    if(ctx->configfile) configfile = ctx->configfile;
    if(ctx->section_name) section = ctx->section_name;
    if(ctx->subjec_str) subj = ctx->subjec_str;

    if(ctx->chtype) 
        chtype = ctx->chtype;
    else 
        chtype = MBSTRING_UTF8;
    
    rand_ser = ctx->opt_ca_rand_serial;
    create_ser = ctx->opt_ca_create_serial;
    multirdn = ctx->opt_ca_multivalue_rdn;

    if(ctx->startdate) startdate = ctx->startdate;
    if(ctx->enddate) enddate = ctx->enddate;
    if(ctx->certificate_days) days = ctx->certificate_days;
    if(ctx->sign_md_alg) md = ctx->sign_md_alg;
    if(ctx->ca_policy) policy = ctx->ca_policy;
    if(ctx->keyfile) keyfile = ctx->keyfile;
    if(ctx->keyformat) keyformat = ctx->keyformat;
    if(ctx->passinarg) passinarg = ctx->passinarg;
    if(ctx->passin) key = ctx->passin; //key is 'passin'
    if(ctx->certfile) certfile = ctx->certfile;

    selfsign = ctx->opt_ca_selfsign;

    if(ctx->ca_outdir) outdir = ctx->ca_outdir;

    if(ctx->ca_signature_parameters) {
        if (sigopts == NULL)
            sigopts = sk_OPENSSL_STRING_new_null();
        if (sigopts == NULL || !sk_OPENSSL_STRING_push(sigopts, ctx->ca_signature_parameters)) {
            return CMS_RET_ERROR;
        }
    }

    set_nameopt_v(XN_FLAG_RFC2253_GZ);
    
    notext = ctx->opt_ca_no_text; //refactoring
    batch = 1;
    preserve = ctx->opt_preserve_dn;
    email_dn = ctx->opt_ca_email_dn; //OPT "NO" EMAIL DN
    
    msie_hack = ctx->opt_ca_msie_hack;
    gencrl = ctx->opt_ca_generate_crl;
    crldays = ctx->crl_crldays;
    crlhours = crldays = ctx->crl_crlhours;
    crlsec = crldays = ctx->crl_crlsec;

    //if(ctx->ca_opt_reqinfile) req = ctx->ca_opt_reqinfile;
    req = ctx->opt_ca_reqin; // 반드시 파일은 아님, CA인 경우 DB의 string을 읽음

    if(ctx->ca_selfsigned_certificate) {
        req = 1;
        ss_cert_file = (const char *)ctx->ca_selfsigned_certificate; //RENAME
    }

    if(ctx->spkac_file) {
        req = 1;
        spkac_file = ctx->spkac_file;
    }

    dorevoke    = ctx->opt_ca_do_revoke; //0: do nothing, 1: revoke 2: add valid DB entry about cert
    extensions  = ctx->caconf_entensions_section_name;
    extfile     = ctx->caconf_entensions_file_name;
    ser_status  = ctx->ca_status_serial;
    doupdatedb  = ctx->opt_ca_update_database;
    crl_ext  = ctx->caconf_crl_entensions_section_name;

    rev_arg = ctx->crl_revoke_reason;
    rev_type = ctx->crl_revoke_type; // REVOKE, HOLD, KEY_COMPROMISE, CA_COMPROMISE 신규 정의 필요
    
    e = ctx->e; //실제 설정은 외부에서. GZPKI_setup_engine()

#if 0
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) { 
        case OPT_REVOKE: infile = opt_arg(); dorevoke = 1; break;
        case OPT_VALID: infile = opt_arg(); dorevoke = 2; break;
        case OPT_EXTENSIONS: extensions = opt_arg(); break;
        case OPT_EXTFILE: extfile = opt_arg(); break;
        case OPT_STATUS: ser_status = opt_arg(); break;
        case OPT_UPDATEDB: doupdatedb = 1; break;
        case OPT_CRLEXTS: crl_ext = opt_arg(); break;
        case OPT_CRL_REASON:   // := REV_CRL_REASON 
        case OPT_CRL_HOLD: case OPT_CRL_COMPROMISE: case OPT_CRL_CA_COMPROMISE: rev_arg = opt_arg(); rev_type = (o - OPT_CRL_REASON) + REV_CRL_REASON; break;
        case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break; }
        case OPT_EOF: case OPT_ERR:  opthelp: BIO_printf(bio_err, "%s: Use -help for summary.\n", prog); goto end;
        case OPT_HELP: opt_help(ca_options); ret = 0; goto end;
        case OPT_IN: req = 1; infile = opt_arg(); break;
        case OPT_OUT: outfile = opt_arg(); break;
        case OPT_VERBOSE: verbose = 1; break;
        case OPT_CONFIG: configfile = opt_arg(); break;
        case OPT_NAME: section = opt_arg(); break;
        case OPT_SUBJ: subj = opt_arg(); /* preserve=1; */ break;
        /case OPT_UTF8: chtype = MBSTRING_UTF8; break;
        case OPT_RAND_SERIAL: rand_ser = 1; break;
        case OPT_CREATE_SERIAL: create_ser = 1; break;
        case OPT_MULTIVALUE_RDN: multirdn = 1; break;
        case OPT_STARTDATE: startdate = opt_arg(); break;
        case OPT_ENDDATE: enddate = opt_arg();break;
        case OPT_DAYS: days = atoi(opt_arg()); break;
        case OPT_MD: md = opt_arg(); break;
        case OPT_POLICY: policy = opt_arg(); break;
        case OPT_KEYFILE: keyfile = opt_arg(); break;
        case OPT_KEYFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &keyformat)) goto opthelp; break;
        case OPT_PASSIN: passinarg = opt_arg(); break;
        CHECK: case OPT_R_CASES: if (!opt_rand(o)) goto end; break;
        case OPT_CERT: certfile = opt_arg(); break;
        case OPT_KEY: key = opt_arg(); break;
        case OPT_SELFSIGN: selfsign = 1; break;
        case OPT_OUTDIR: outdir = opt_arg(); break;
            STACK_OF(OPENSSL_STRING) *sigopts = NULL;
        case OPT_SIGOPT: if (sigopts == NULL) sigopts = sk_OPENSSL_STRING_new_null(); if (sigopts == NULL || !sk_OPENSSL_STRING_push(sigopts, opt_arg())) goto end; break;
        case OPT_NOTEXT: notext = 1; break;
        case OPT_BATCH: batch = 1; break;
        case OPT_PRESERVEDN: preserve = 1; break;
        case OPT_NOEMAILDN: email_dn = 0; break;
        case OPT_GENCRL: gencrl = 1; break;
        case OPT_MSIE_HACK: msie_hack = 1; break;
        case OPT_CRLDAYS: crldays = atol(opt_arg()); break;
        case OPT_CRLHOURS: crlhours = atol(opt_arg()); break;
        case OPT_CRLSEC: crlsec = atol(opt_arg()); break;
        case OPT_INFILES: req = 1; goto end_of_options;
        case OPT_SS_CERT: ss_cert_file = opt_arg(); req = 1; break;
        case OPT_SPKAC: spkac_file = opt_arg(); req = 1; break;
    }
end_of_options:
    argc = opt_num_rest();
    argv = opt_rest();
#endif

    
    // DN 형식 통일을 위해 RFC2253 형식을 이용한다. 
    // TODO: check    
    // ctx->opt_nameopt = GZPKI_strdup("utf8");
    ctx->opt_nameopt = XN_FLAG_RFC2253_GZ;
    set_nameopt_v(ctx->opt_nameopt);
    IF_VERBOSE fprintf(stderr , DEBUG_TAG"GZPKI_do_CA:GZPKI_DEFAULT_NAME_OPT_STR: %s\n", GZPKI_DEFAULT_NAME_OPT_STR);
    IF_VERBOSE fprintf(stderr , "GZPKI_do_CA:NAME opt_nameopt: %ld\n", ctx->opt_nameopt);

    // 설정파일에 등록된 nameopt를 우선 처리한다. 
    // RFC2253을 사용하지 않는 경우에 해당하나, RA/CA가 동일한 옵션을 사용해야 함
    f = NCONF_get_string(conf, section, ENV_NAMEOPT);
    if (f != NULL) {
        printf("DEBUG: set_nameopt from %s:%s : %s\n", section, ENV_NAMEOPT, f);
        if (!set_nameopt(f)) {
            BIO_printf(bio_err, "Invalid name options: \"%s\"\n", f);
            goto end;
        }
        default_op = 0;
    }

    // 설정파일(외부 설정) 우선
    f = NCONF_get_string(conf, section, ENV_CERTOPT);

    BIO_printf(bio_err, "Using configuration from %s\n", configfile);

    if ((conf = app_load_config(configfile)) == NULL)   {
        ctx->errcode = 100;
        sprintf(ctx->errstr, "fail to load config: %s", configfile);
        goto end;
    }

    if (configfile != default_config_file && !app_load_modules(conf)) {
        ctx->errcode = 101;
        sprintf(ctx->errstr, "fail to load config: %s", configfile);
        goto end;
    }

    /* Lets get the config section we are using */
    if (section == NULL && (section = lookup_conf(conf, BASE_SECTION, ENV_DEFAULT_CA)) == NULL) {
        ctx->errcode = 102;
        sprintf(ctx->errstr, "fail to load section: %s", section);
        goto end;
    }

    p = NCONF_get_string(conf, NULL, "oid_file");
    if (p == NULL)
        ERR_clear_error();

    if (p != NULL) {
        BIO *oid_bio = BIO_new_file(p, "r");

        if (oid_bio == NULL) {
            ERR_clear_error();
        } else {
            OBJ_create_objects(oid_bio);
            BIO_free(oid_bio);
        }
    }

    if (!add_oid_section(conf)) {
        ERR_print_errors(bio_err);
        ctx->errcode = 103;
        sprintf(ctx->errstr, "fail to add OID section");
        goto end;
    }

    app_RAND_load_conf(conf, BASE_SECTION);

    f = NCONF_get_string(conf, section, STRING_MASK);
    if (f == NULL)
        ERR_clear_error();

    if (f != NULL && !ASN1_STRING_set_default_mask_asc(f)) {
        BIO_printf(bio_err, "Invalid global string mask setting %s\n", f);
        ctx->errcode = 104;
        sprintf(ctx->errstr, "Invalid global string mask setting %s\n", f);
        goto end;
    }

    if (chtype != MBSTRING_UTF8) {
        f = NCONF_get_string(conf, section, UTF8_IN);
        if (f == NULL)
            ERR_clear_error();
        else if (strcmp(f, "yes") == 0)
            chtype = MBSTRING_UTF8;
    }

//DELETE
    chtype = MBSTRING_UTF8;

    db_attr.unique_subject = 1;
    p = NCONF_get_string(conf, section, ENV_UNIQUE_SUBJECT);
    if (p != NULL)
        db_attr.unique_subject = parse_yesno(p, 1);
    else
        ERR_clear_error();


    if(use_sqldb==1) {
        p = NCONF_get_string(conf, section, ENV_DATABASE_SQLITE);
        ctx->db_file = GZPKI_strdup(p);
        IF_VERBOSE fprintf(stderr, "USE_SQLDB(%d): CTX->DB_FILE(%s:%s)\n", use_sqldb, ENV_DATABASE_SQLITE, ctx->db_file );
    }
    /*****************************************************************/
    /* report status of cert with serial number given on command line */
    // serial 번호가 parameter로 주어진 경우, 해당 certificate의 상태
    /*****************************************************************/
    if (ser_status && use_txtdb == 1) {
    //if (ser_status) {
        dbfile = lookup_conf(conf, section, ENV_DATABASE);

        IF_VERBOSE fprintf(stderr, "INDEX_TXT(%s:%s) : %s\n", section, ENV_DATABASE_SQLITE, dbfile );

        if (dbfile == NULL) {
            ctx->errcode = 106;
            sprintf(ctx->errstr, "fail to get database(txt) in section:%s\n", section);
            goto end;
        }

        db = load_index(dbfile, &db_attr);
        if (db == NULL) {
            ctx->errcode = 107;
            sprintf(ctx->errstr, "fail to load database from %s\n", dbfile);
            goto end;
        }


        if (index_index(db) <= 0) {
            ctx->errcode = 108;
            sprintf(ctx->errstr, "fail to indexing: %s\n", dbfile);
            goto end;
        }

        if (get_certificate_status(ser_status, db) != 1) {
            BIO_printf(bio_err, "Error verifying serial %s!\n", ser_status);
        }
        goto end;
    }

    if (ser_status && use_sqldb == 1) {
    
        sqlite3 *db;
        dbfile = lookup_conf(conf, section, ENV_DATABASE_SQLITE);
        
        IF_VERBOSE fprintf(stderr, "CMMDB(%s:%s) : %s\n", section, ENV_DATABASE_SQLITE, dbfile );

        if (dbfile == NULL) {
            ctx->errcode = 106;
            sprintf(ctx->errstr, "fail to get database(sql) in section:%s\n", section);
            goto end;
        }
        if (get_certificate_status_SQL(ser_status, dbfile) != 1) {
            BIO_printf(bio_err, "Error verifying serial %s!\n", ser_status);
        }
        goto end;
    }

    /*****************************************************************/
    /* we definitely need a private key, so let's get it             */  
    /* opt_ca_load_private_key: default(1)                           */  

    /*****************************************************************/
    if(ctx->opt_ca_load_private_key == 1) 
    {
        if (keyfile == NULL && (keyfile = lookup_conf(conf, section, ENV_PRIVATE_KEY)) == NULL) {
            goto end;
        }

        if (key == NULL) {
            free_key = 1;
            if (!app_passwd(passinarg, NULL, &key, NULL)) {
                BIO_printf(bio_err, "Error getting password\n");
                goto end;
            }
        }
        pkey = load_key(keyfile, keyformat, 0, key, e, "CA private key");
        if (key != NULL)
            OPENSSL_cleanse(key, strlen(key));

        if (pkey == NULL) {
            /* load_key() has already printed an appropriate message */
            ctx->errcode = -100;
            memset(ctx->errstr, 0, sizeof(ctx->errstr));
            sprintf(ctx->errstr, "fail to read private key");
            goto end;
        }
    }

    IF_VERBOSE fprintf(stderr, "ctx->opt_ca_load_private_key: %d\n", ctx->opt_ca_load_private_key);
    if(ctx->opt_ca_load_private_key == 1) 
    {
        /*****************************************************************/
        /* we need a certificate */
        if (!selfsign || spkac_file || ss_cert_file || gencrl) {
            if (certfile == NULL && (certfile = lookup_conf(conf, section, ENV_CERTIFICATE)) == NULL)
            {
                IF_VERBOSE fprintf(stderr, "config lookup failed: sect=%s, cert=%s\n", section, ENV_CERTIFICATE);
                goto end;
            }

            x509 = load_cert(certfile, FORMAT_PEM, "CA certificate");
            if (x509 == NULL) {
                IF_VERBOSE fprintf(stderr, "CA certificate load failed, cert=%s\n", certfile);
                goto end;
            }

            IF_VERBOSE fprintf(stderr, "load CA certificate: %s\n", certfile);

            if (!X509_check_private_key(x509, pkey)) {
                BIO_printf(bio_err, "CA certificate and CA private key do not match\n");
                goto end;
            }

            IF_VERBOSE fprintf(stderr, "CA certificate and CA private key are MATCHED\n");
            //ADD: x509(CA 인증서)에서 subjectDN을 가지고 온다
            //DN 포멧은 ONELINE 함수 사용하지 않고 NAMEOPT가 적용되도록 한다. 
            
            //ctx->caIssuerDN = print_name_str(X509_get_subject_name(x509), get_nameopt());
            //printf("X509_NAME_oneline: CA SUBJECT DN: [%s]\n", ctx->caIssuerDN);
        }

        if (!selfsign) {
            x509p = x509;
            IF_VERBOSE fprintf(stderr, "NOT SELFSIGN: x509p <- x509\n");
        }
    }

    f = NCONF_get_string(conf, BASE_SECTION, ENV_PRESERVE);
    if (f == NULL)
        ERR_clear_error();
    if ((f != NULL) && ((*f == 'y') || (*f == 'Y')))
        preserve = 1;
    f = NCONF_get_string(conf, BASE_SECTION, ENV_MSIE_HACK);
    if (f == NULL)
        ERR_clear_error();
    if ((f != NULL) && ((*f == 'y') || (*f == 'Y')))
        msie_hack = 1;


#if 0
    f = NCONF_get_string(conf, section, ENV_NAMEOPT);
        if (f != NULL) {
            printf("DEBUG: set_nameopt from %s:%s : %s\n", section, ENV_NAMEOPT, f);
            if (!set_nameopt(f)) {
                BIO_printf(bio_err, "Invalid name options: \"%s\"\n", f);
                goto end;
            }
            default_op = 0;
        }
    // 설정파일에서는 nameopt를 다루지 않도록 한다.
    // DN 형식 통일을 위해 RFC2253 형식을 이용한다. 

    // 설정파일(외부 설정) 우선
        f = NCONF_get_string(conf, section, ENV_CERTOPT);
#endif

    if (f != NULL) {
        if (!set_cert_ex(&certopt, f)) {
            BIO_printf(bio_err, "Invalid certificate options: \"%s\"\n", f);
            fprintf(stderr, "Invalid certificate options: \"%s\"\n", f);
            goto end;
        }
        default_op = 0;
    } else {
        ERR_clear_error();
    }

    f = NCONF_get_string(conf, section, ENV_EXTCOPY);

    if (f != NULL) {
        if (!set_ext_copy(&ext_copy, f)) {
            BIO_printf(bio_err, "Invalid extension copy option: \"%s\"\n", f);
            IF_VERBOSE fprintf(stderr, "Invalid extension copy option: \"%s\"\n", f);
            goto end;
        }
    } else {
        ERR_clear_error();
    }

    /*****************************************************************/
    /* lookup where to write new certificates */
    if ((outdir == NULL) && (req)) {

        outdir = NCONF_get_string(conf, section, ENV_NEW_CERTS_DIR);
        if (outdir == NULL) {
            BIO_printf(bio_err, "there needs to be defined a directory for new certificate to be placed in\n");
            IF_VERBOSE fprintf(stderr, "no new certificate outout path defined: \"%s\"\n", f);
            goto end;
        }
#ifndef OPENSSL_SYS_VMS
        /* outdir is a directory spec, but access() for VMS demands a filename.  
         * We could use the DEC C routine to convert the directory syntax to Unix, 
         * and give that to app_isdir,
         * but for now the fopen will catch the error if it's not a directory */
        if (app_isdir(outdir) <= 0) {
            BIO_printf(bio_err, "%s: %s is not a directory\n", prog, outdir);
            perror(outdir);
            goto end;
        }
#endif
    }

    //--------------------------------------------------------------------------------
    // we need to load the database file 
    //--------------------------------------------------------------------------------
    if(use_txtdb == 1) {
        dbfile = lookup_conf(conf, section, ENV_DATABASE);
        if (dbfile == NULL)
            goto end;

        db = load_index(dbfile, &db_attr);
    
        if (db == NULL)
            goto end;

        /* Lets check some fields */
        for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
            pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
            if ((pp[DB_type][0] != DB_TYPE_REV) && (pp[DB_rev_date][0] != '\0')) {
                BIO_printf(bio_err, "entry %d: not revoked yet, but has a revocation date\n", i + 1);
                fprintf(stderr, "entry %d: not revoked yet, but has a revocation date\n", i + 1);
                goto end;
            }

            if ((pp[DB_type][0] == DB_TYPE_REV) && !make_revoked(NULL, pp[DB_rev_date])) {
                BIO_printf(bio_err, " in entry %d\n", i + 1);
                fprintf(stderr, " in entry %d\n", i + 1);
                ctx->errcode = -101;
                sprintf(ctx->errstr, "TXT_DB:in entry: %d", i+1);
                goto end;
            }

            if (!check_time_format((char *)pp[DB_exp_date])) {
                BIO_printf(bio_err, "entry %d: invalid expiry date\n", i + 1);
                ctx->errcode = -102;
                sprintf(ctx->errstr, "TXT_DB:check_time_format:entry %d: invalid expiry date\n", i + 1);
                goto end;
            }

            p = pp[DB_serial];
            j = strlen(p);
            if (*p == '-') {
                p++;
                j--;
            }
            if ((j & 1) || (j < 2)) {
                BIO_printf(bio_err, "entry %d: bad serial number length (%d)\n", i + 1, j);
                fprintf(stderr, "entry %d: bad serial number length (%d)\n", i + 1, j);
                
                ctx->errcode = -103;
                sprintf(ctx->errstr, "TXT_DB:entry %d: bad serial number length (%d)\n", i + 1, j);
                goto end;
            }
            for ( ; *p; p++) {
                if (!isxdigit(_UC(*p))) {
                    BIO_printf(bio_err, "entry %d: bad char 0%o '%c' in serial number\n", i + 1, *p, *p);
                    ctx->errcode = -104;
                    sprintf(ctx->errstr, "TXT_DB:entry %d: bad char 0%o '%c' in serial number\n", i + 1, *p, *p);
                    goto end;
                }
            }
        }

        if (verbose) {
            TXT_DB_write(bio_out, db->db);
            BIO_printf(bio_err, "%d entries loaded from the database\n", sk_OPENSSL_PSTRING_num(db->db->data));
            BIO_printf(bio_err, "generating index\n");

            fprintf(stderr, "%d entries loaded from the database\n", sk_OPENSSL_PSTRING_num(db->db->data));
            fprintf(stderr, "generating index\n");
        }

        int ret1 = index_index(db);
        if ( ret1 <= 0) {
            ctx->errcode = -105;
            sprintf(ctx->errstr, "indexing index failed. ret=%d\n", ret1);
            fprintf(stderr, "error: %s\n", ctx->errstr);
            goto end;
        }
    } // IF(USE_TXTDB==1)

    //==================================================
    //USE_SQLDB == 1, jkkim@greenzonesecu.com
    //테스트를 위해 index.txt의 내용을 certificate DB로 이동시킨다. 
    //테스트 이후 삭제 필요
    //==================================================
#if 1
    if(use_sqldb == 1 && index_db_sync == 1) 
    {
        sqlite3 *SQLDB;
        sqlite3_stmt *stmt = NULL;
   	    char *zErrMsg = 0;
   	    int rc;
        int num = 0;

        //subject가 유일한지여부, index.txt.attr에서 읽는다. 일단 0으로 둔다
        int uniq_subj = 0;
        char insertQry[1024];
        char *tmpRevDate = NULL, *revReason = NULL, *tmp = NULL, *ptr = NULL;
        memset(insertQry, 0, sizeof(insertQry));
        
        //dbfile명 불필요
        dbfile = lookup_conf(conf, section, ENV_DATABASE_SQLITE);
        IF_VERBOSE printf("CMMDB: "color_yellow_b"%s"color_reset"\n", dbfile);
        if (dbfile == NULL)  {
            fprintf(stderr, "CMMDB: "color_yellow_b"%s"color_reset" load failed.\n", dbfile);
            goto end;
        }

        rc = sqlite3_open(dbfile, &SQLDB);
        if( rc ) {
    	    fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(SQLDB));
      	    return -1;
   	    } else {
    	    fprintf(stderr, "Open cmmdb(%s) successfully.\n", dbfile);
   	    }

        //sprintf(insertQry, "PRAGMA encoding = \"UTF-8\"");

        IF_VERBOSE fprintf(stderr, "SQL: ");
        IF_VERBOSE fprintf(stderr, color_blue_b"%s"color_reset"\n", insertQry);

        rc = sqlite3_exec(SQLDB, insertQry, 0, 0, &zErrMsg);

        //char *ca_name = GZPKI_get_ca_name(ctx);
        //uniq_subj = load_sqldb(ca_name, dbfile);
        uniq_subj = 1;

        /* Lets check some fields */
        for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
            pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
            if ((pp[DB_type][0] != DB_TYPE_REV) && (pp[DB_rev_date][0] != '\0')) {
                BIO_printf(bio_err, "entry %d: not revoked yet, but has a revocation date\n", i + 1);
                goto end;
            }
            
            if ((pp[DB_type][0] == DB_TYPE_REV) && !make_revoked(NULL, pp[DB_rev_date])) {
                BIO_printf(bio_err, " in entry %d\n", i + 1);
                goto end;
            }
            if (!check_time_format((char *)pp[DB_exp_date])) {
                BIO_printf(bio_err, "entry %d: invalid expiry date\n", i + 1);
                goto end;
            }
            
            p = pp[DB_serial];

            j = strlen(p);
            if (*p == '-') {
                p++;
                j--;
            }
            if ((j & 1) || (j < 2)) {
                BIO_printf(bio_err, "entry %d: bad serial number length (%d)\n", i + 1, j);
                goto end;
            }
            for ( ; *p; p++) {
                if (!isxdigit(_UC(*p))) {
                    BIO_printf(bio_err, "entry %d: bad char 0%o '%c' in serial number\n", i + 1, *p, *p);
                    goto end;
                }
            }

            printf("============================================================\n"); 
            printf("%d: PP[DB_type] ==> ["ANSI_COLOR_YELLOW_BOLD"%c"ANSI_COLOR_RESET"]\n", DB_type, pp[DB_type][0]); //0
            printf("%d: PP[DB_exp_date] ==> ["ANSI_COLOR_YELLOW_BOLD"%s"ANSI_COLOR_RESET"]\n", DB_exp_date, pp[DB_exp_date]);//1
            printf("%d: PP[DB_rev_date] ==> ["ANSI_COLOR_YELLOW_BOLD"%s"ANSI_COLOR_RESET"]\n", DB_rev_date, pp[DB_rev_date]);//2 "date,reason"
            printf("%d: PP[DB_serial] ==> ["ANSI_COLOR_YELLOW_BOLD"%s"ANSI_COLOR_RESET"]\n", DB_serial, pp[DB_serial]); //3
            printf("%d: PP[DB_file] ==> ["ANSI_COLOR_YELLOW_BOLD"%s"ANSI_COLOR_RESET"]\n", DB_file, pp[DB_file]); //4?
            printf("%d: PP[DB_name] ==> ["ANSI_COLOR_YELLOW_BOLD"%s"ANSI_COLOR_RESET"]\n", DB_name, pp[DB_name]); //4?
            
            char rev_date[16];
            char rev_reason[32];

            memset(rev_date, 0, 16);
            memset(rev_reason, 0, 16);
            
            if(pp[DB_type][0]=='R') {
                tmp = pp[DB_rev_date];
                printf("    ** tmp: %s\n", tmp);
                if(strchr(tmp, ','))
                {
                    char *tmp2 = GZPKI_strdup(pp[DB_rev_date]);
                    printf("tmp: %s\n", tmp); 
                    printf("tmp2: %s\n", tmp2); 
                    ptr = strtok(tmp2, ",");
                    if(ptr != NULL) {
                        sprintf(rev_date, "%s", ptr);
                        printf("    ** crl_reason: rev_date  [%s]\n", rev_date);

                        ptr = strtok(NULL, ",");
                        sprintf(rev_reason, "%s", ptr);
                        printf("    ** crl_reason: rev_reason [%s]\n", rev_reason);
                    }
                }    
                else
                {
                    sprintf(rev_date, "%s",  pp[DB_rev_date]);
                    printf("    ** no crl_reason, rev_date [%s]\n", rev_date);
                }
            }

            sprintf(insertQry, "INSERT INTO certificate (serial, status, notafter, revoked_date, revoked_reason, serial, filename, dn )"
                " VALUES ('%s', '%c', '%s', '%s', '%s', '%s', '%s', '%s' )"
                , pp[DB_serial], pp[DB_type][0], pp[DB_exp_date], rev_date?rev_date:"", rev_reason?rev_reason:"", pp[DB_serial], pp[DB_file], pp[DB_name] );

            fprintf(stderr, "SQL: ");
            fprintf(stderr, color_blue_b"%s"color_reset"\n", e2u(insertQry));

            //char * e2u(char * input)
            rc = sqlite3_exec(SQLDB, e2u(insertQry), 0, 0, &zErrMsg);
            if( rc != SQLITE_OK ){
    	        fprintf(stderr, "error:sql:%s\n", zErrMsg);
                sqlite3_free(zErrMsg);  	
   	        } else {
    	        fprintf(stderr, "success:index/sqldb sync successfully\n");
   	        }
       }    

        sqlite3_close(SQLDB);

        goto end_success;
       
    } // IF(USE_SQLDB==1)
#endif    



    //static int do_updatedb(CA_DB *db)
    if (doupdatedb && use_sqldb == 1)
    {
        ASN1_UTCTIME *a_tm = NULL;
        int i, cnt = 0;
        int db_y2k, a_y2k;          /* flags = 1 if y >= 2000 */
        char **rrow, *a_tm_s;
        char SQL[1024];

        a_tm = ASN1_UTCTIME_new();
        if (a_tm == NULL)
            return -1;

        /* get actual time and make a string */
        if (X509_gmtime_adj(a_tm, 0) == NULL) {
            ASN1_UTCTIME_free(a_tm);
            return -1;
        }
        a_tm_s = app_malloc(a_tm->length + 1, "time string");

        memcpy(a_tm_s, a_tm->data, a_tm->length);
        a_tm_s[a_tm->length] = '\0';

        printf("a_tm_s : [%s]\n", a_tm_s);

        if (strncmp(a_tm_s, "49", 2) <= 0)
            a_y2k = 1;
        else
            a_y2k = 0;

        int fields = 0;
        
        char lstatus = '0';

#define N_ID        0            
#define N_STATUS    1
#define N_NOTAFTER  2            
#define N_SERIAL    3            
#define N_DN        4


        sqlite3 *conn;
        sqlite3_stmt *stmt = NULL;
        int rowcount;
        int rc;
                
        #define SQL_LIMIT 10000
        //약 10M
        char updateQuery[SQL_LIMIT][512];

        char *query = "SELECT id, status, notafter, serial, dn FROM certificate WHERE status = 'V';";

        rc = sqlite3_open(ctx->db_file, &conn);
        rc = sqlite3_prepare_v2(conn, query, -1, &stmt, NULL);
        
        int colCount = sqlite3_column_count(stmt);
        rc = sqlite3_step(stmt);
    
        int rowCount = 0;

        while (rc != SQLITE_DONE && rc != SQLITE_OK) {
            rowCount++; 
            if(rowCount > SQL_LIMIT) {
                break;
            }
            printf("rowCount: %d\n", rowCount);

            #define N_ID        0            
            #define N_STATUS    1
            #define N_NOTAFTER  2            
            #define N_SERIAL    3            
            #define N_DN        4 
            
            char row_dn[256];
            char row_id[32];
            char row_status[16];
            char row_notafter[32];
            char row_serial[128];

            memset(row_dn, 0, sizeof(row_dn));
            memset(row_id, 0, sizeof(row_id));
            memset(row_status, 0, sizeof(row_status));
            memset(row_notafter, 0, sizeof(row_notafter));
            memset(row_serial, 0, sizeof(row_serial));
            
            int colCount = sqlite3_column_count(stmt);
            printf("  colCount: %d\n", colCount);

            for (int colIndex = 0; colIndex < colCount; colIndex++) {
                int type = sqlite3_column_type(stmt, colIndex);
                
                const char * columnName = sqlite3_column_name(stmt, colIndex);
                if (type == SQLITE_TEXT) {
                    const unsigned char * valChar = NULL;
                    valChar = sqlite3_column_text(stmt, colIndex);
                    if(0==strcmp("id", columnName)) {
                        sprintf(row_id, "%s", valChar);
                    }
                    else if(0==strcmp("status", columnName)) {
                        sprintf(row_status, "%s", valChar);
                    } 
                    else if(0==strcmp("notafter", columnName)) {
                        sprintf(row_notafter, "%s", valChar);
                    }
                    else if(0==strcmp("serial", columnName)) {
                        sprintf(row_serial, "%s", valChar);
                    }
                    else if(0==strcmp("dn", columnName)) {
                        sprintf(row_dn, "%s", valChar);
                    }
                }
                
            }
            printf("GET(%d): %s %s %s %s %s\n", rowCount, row_id, row_status, row_notafter, row_serial, row_dn);
            if (row_status[0] == DB_TYPE_VAL) { //DB_TYPE_VAL("V"), ignore entries that are not valid
                if (strncmp(row_notafter, "49", 2) <= 0) db_y2k = 1; else db_y2k = 0;
                IF_VERBOSE fprintf(stderr, "CHK: db_y2k=%d, a_y2k=%d\n", db_y2k, a_y2k);

                if (db_y2k == a_y2k) { /* all on the same y2k side */
                    if (strcmp(row_notafter, a_tm_s) <= 0) {
                        IF_VERBOSE fprintf(stderr, "SERIAL=%s, DB[%s] < E[%s], expired\n", row_serial, row_notafter, a_tm_s);
                        memset(updateQuery[rowCount], 0, sizeof(updateQuery[rowCount]));
                        sprintf(updateQuery[rowCount], "UPDATE certificate SET status = 'E' WHERE serial='%s' AND DN='%s';", row_serial, row_dn);
                        //GZPKI_do_SQL(ctx->db_user, ctx->db_pwd, ctx->db_name, ctx->db_port, SQL);
                    }
                    else 
                    {
                        printf( "DB[%s] > E[%s], not yet expired\n", row_notafter, a_tm_s);

                    }
                } else if (db_y2k < a_y2k) {
                    BIO_printf(bio_err, "Expired=[%s]\n", row_notafter);
                    printf( "serial=%s, DB[%s] < E[%s], expired\n", row_serial, row_notafter, a_tm_s);
                    memset(updateQuery[rowCount], 0, sizeof(updateQuery[rowCount]));
                    sprintf(updateQuery[rowCount], "UPDATE certificate SET status = 'E' WHERE serial='%s' AND id='%s';", row_serial, row_id);
                }
            }

            rc = sqlite3_step(stmt);
        }
        
        rc = sqlite3_finalize(stmt);
        rc = sqlite3_close(conn);

        int loop = 0;
        char *errmsg = NULL;
        rc = sqlite3_open(ctx->db_file, &conn);
        for(loop=0; loop <rowCount; loop++) {
            rc = sqlite3_exec(conn, updateQuery[loop], NULL, 0, &errmsg);
            if( rc != SQLITE_OK ){
    	        fprintf(stderr, "error:init:sql:%s\n", errmsg);
                sqlite3_free(errmsg);  
   	        } else {
            	IF_VERBOSE fprintf(stderr, DEBUG_TAG"keypass table created successfully\n");
   	        }

        }

        rc = sqlite3_close(conn);
        

        ASN1_UTCTIME_free(a_tm);
        OPENSSL_free(a_tm_s);
        
        //return cnt;
    }


    /*****************************************************************/
    /* Update the db file for expired certificates */
    if (doupdatedb && use_txtdb == 1) {
        if (verbose)
            BIO_printf(bio_err, "Updating %s ...\n", dbfile);

        i = do_updatedb(db);
        if (i == -1) {
            BIO_printf(bio_err, "Malloc failure\n");
            goto end;
        } else if (i == 0) {
            if (verbose)
                BIO_printf(bio_err, "No entries found to mark expired\n");
        } else {
            if (!save_index(dbfile, "new", db))
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;

            if (verbose)
                BIO_printf(bio_err, "Done. %d entries marked as expired\n", i);
        }
    }



    /*****************************************************************/
    /* Read extensions config file                                   */
    if (extfile) {
        printf("DEBUG: extfile=[%s]\n", extfile);
        if ((extconf = app_load_config(extfile)) == NULL) {
            ret = 1;
            goto end;
        }

        if (verbose)
            BIO_printf(bio_err, "Successfully loaded extensions file %s\n", extfile);

        /* We can have sections in the ext file */
        if (extensions == NULL) {
            extensions = NCONF_get_string(extconf, "default", "extensions");
            if (extensions == NULL)
                extensions = "default";
        }
    }

    /*****************************************************************/
    if (req || gencrl) {
        if (spkac_file != NULL) {
            output_der = 1;
            batch = 1;
        }
    }

    if(ctx->opt_ca_load_private_key == 1) {
        def_ret = EVP_PKEY_get_default_digest_nid(pkey, &def_nid);
    }
    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is
     * mandatory for this algorithm.
     */
    if (def_ret == 2 && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        dgst = EVP_md_null();
    } else if (md == NULL && (md = lookup_conf(conf, section, ENV_DEFAULT_MD)) == NULL) {
        goto end;
    } else {
        if (strcmp(md, "default") == 0) {
            if (def_ret <= 0) {
                BIO_puts(bio_err, "no default digest\n");
                goto end;
            }
            md = (char *)OBJ_nid2sn(def_nid);
        }

        //if (!opt_md(md, &dgst))
        //    goto end;
        dgst =  (EVP_MD *)EVP_get_digestbyname(md);
        if(dgst == NULL) {
            return CMS_RET_ERROR;
        }
    }


//============================================================
// ISSUE X.509 CERTIFICATE
//============================================================
    if (req) {
        if (email_dn == 1) {
            char *tmp_email_dn = NULL;

            tmp_email_dn = NCONF_get_string(conf, section, ENV_DEFAULT_EMAIL_DN);
            if (tmp_email_dn != NULL && strcmp(tmp_email_dn, "no") == 0)
                email_dn = 0;
        }
        if (verbose)
            BIO_printf(bio_err, "message digest is %s\n", OBJ_nid2ln(EVP_MD_type(dgst)));

        if (policy == NULL && (policy = lookup_conf(conf, section, ENV_POLICY)) == NULL) {
            goto end;
        }

        if (verbose)
            BIO_printf(bio_err, "policy is %s\n", policy);

        if (NCONF_get_string(conf, section, ENV_RAND_SERIAL) != NULL) {
            rand_ser = 1;
        } else {
            serialfile = lookup_conf(conf, section, ENV_SERIAL);
            if (serialfile == NULL)
                goto end;
        }

        //CA_server. x509_extensions = server_cert와 같이 없는 필드가 주어진 경우
        //segfault
        if (extconf == NULL) {
            /* no '-extfile' option, so we look for extensions in the main configuration file */
            if (extensions == NULL) {
                extensions = NCONF_get_string(conf, section, ENV_EXTENSIONS);
                if (extensions == NULL)
                    ERR_clear_error();
            }
            if (extensions != NULL) { /* Check syntax of file */
                X509V3_CTX ctx;
                X509V3_set_ctx_test(&ctx);
                X509V3_set_nconf(&ctx, conf);
                if (!X509V3_EXT_add_nconf(conf, &ctx, extensions, NULL)) {
                    //BIO_printf(bio_err, "Error Loading extension section %s\n", extensions);
                    fprintf(stderr, "Error Loading extension section %s\n", extensions);
                    ret = 1;
                    goto end;
                }
            }
        }

        if (startdate == NULL) {
            startdate = NCONF_get_string(conf, section, ENV_DEFAULT_STARTDATE);
            if (startdate == NULL)
                ERR_clear_error();
        }
        if (startdate != NULL && !ASN1_TIME_set_string_X509(NULL, startdate)) {
            BIO_printf(bio_err, "start date is invalid, it should be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ\n");
            goto end;
        }
        if (startdate == NULL)
            startdate = "today";

        if (enddate == NULL) {
            enddate = NCONF_get_string(conf, section, ENV_DEFAULT_ENDDATE);
            if (enddate == NULL)
                ERR_clear_error();
        }
        if (enddate != NULL && !ASN1_TIME_set_string_X509(NULL, enddate)) {
            BIO_printf(bio_err, "end date is invalid, it should be YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ\n");
            goto end;
        }

        if (days == 0) {
            if (!NCONF_get_number(conf, section, ENV_DEFAULT_DAYS, &days))
                days = 0;
        }
        if (enddate == NULL && days == 0) {
            BIO_printf(bio_err, "cannot lookup how many days to certify for\n");
            goto end;
        }

        if (rand_ser) {
            if ((serial = BN_new()) == NULL || !rand_serial(serial, NULL)) {
                BIO_printf(bio_err, "error generating serial number\n");
                goto end;
            }
        } else {
            if ((serial = load_serial(serialfile, create_ser, NULL)) == NULL) {
                BIO_printf(bio_err, "error while loading serial number\n");
                goto end;
            }
            if (verbose) {
                if (BN_is_zero(serial)) {
                    BIO_printf(bio_err, "next serial number is 00\n");
                } else {
                    if ((f = BN_bn2hex(serial)) == NULL)
                        goto end;
                    BIO_printf(bio_err, "next serial number is %s\n", f);
                    OPENSSL_free(f);
                }
            }
        }

        if ((attribs = NCONF_get_section(conf, policy)) == NULL) {
            BIO_printf(bio_err, "unable to find 'section' for %s\n", policy);
            goto end;
        }

        if ((cert_sk = sk_X509_new_null()) == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }


        //infile은 REQUEST 파일
        //serial ?
        IF_VERBOSE {
            printf("CA: SERIAL: %s\n", BN_bn2hex(serial));
            printf("CA: INFILE: %s\n", infile);
            printf("CA: SUBJ  : %s\n", subj);
        }


        ctx->caSerial = GZPKI_strdup(BN_bn2hex(serial));
//--------------------------------------------------
// DO NOT DELETE
// SPKAC 처리는 현 버전에서는 불필요함
//--------------------------------------------------
#if 0        
        if (spkac_file != NULL) {
            total++;
            j = certify_spkac(&x, spkac_file, pkey, x509, dgst, sigopts,
                              attribs, db, serial, subj, chtype, multirdn,
                              email_dn, startdate, enddate, days, extensions,
                              conf, verbose, certopt, get_nameopt(), default_op,
                              ext_copy);
            if (j < 0)
                goto end;
            if (j > 0) {
                total_done++;
                BIO_printf(bio_err, "\n");
                if (!BN_add_word(serial, 1))
                    goto end;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
                }
            }
        }
#endif        
        if (ss_cert_file != NULL) {
            total++;
            j = certify_cert(ctx, &x, ss_cert_file, pkey, x509, dgst, sigopts,
                             attribs,
                             db, serial, subj, chtype, multirdn, email_dn,
                             startdate, enddate, days, batch, extensions,
                             conf, verbose, certopt, get_nameopt(), default_op,
                             ext_copy);
            if (j < 0)
                goto end;
            if (j > 0) {
                total_done++;
                BIO_printf(bio_err, "\n");
                if (!BN_add_word(serial, 1))
                    goto end;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
                }
            }
        }
        

        if (infile != NULL) {
            total++;
            j = certify(ctx, &x, infile, pkey, x509p, dgst, sigopts, attribs, db,
                        serial, subj, chtype, multirdn, email_dn, startdate,
                        enddate, days, batch, extensions, conf, verbose,
                        certopt, get_nameopt(), default_op, ext_copy, selfsign);
            if (j < 0) {
                fprintf(stderr, "CERIFY: j=%d\n", j);
                goto end;
            }
            if (j > 0) {
                total_done++;
                BIO_printf(bio_err, "\n");
                if (!BN_add_word(serial, 1))
                    goto end;
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
                }
            }
        }
        
        //--------------------------------------------------
        // ARGC ==> REQUEST갯수
        //--------------------------------------------------
        //for (i = 0; i < argc; i++) {
        //--------------------------------------------------
        //추가 REQUEST는 없는 것으로 가정한다.             
        //--------------------------------------------------
#if 0        
        IF_VERBOSE fprintf(stderr, "certify(cnt:%d)\n", ctx->ca_request_file_cnt);

        for (i = 0; i < ctx->ca_request_file_cnt; i++) {

            total++;
            j = certify(ctx, &x, ctx->ca_request_file[i], pkey, x509p, dgst, sigopts, attribs, db,
                        serial, subj, chtype, multirdn, email_dn, startdate,
                        enddate, days, batch, extensions, conf, verbose,
                        certopt, get_nameopt(), default_op, ext_copy, selfsign);
            if (j < 0) {
                IF_VERBOSE fprintf(stderr, "error: certify(total:%d), j=%d, %s, %d\n", total, j, ctx->errstr, ctx->errcode);
                goto end;
            }
            
            if (j > 0) {
                total_done++;
                BIO_printf(bio_err, "\n");
                if (!BN_add_word(serial, 1)) {
                    X509_free(x);
                    goto end;
                }
                if (!sk_X509_push(cert_sk, x)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    X509_free(x);
                    goto end;
                }
            }
        }
#endif        
        /*
         * we have a stack of newly certified certificates and a data base
         * and serial number that need updating
         */

        if (sk_X509_num(cert_sk) > 0) {
            if (!batch) {
                BIO_printf(bio_err, "\n%d out of %d certificate requests certified, commit? [y/n]", total_done, total);
                (void)BIO_flush(bio_err);
                tmp[0] = '\0';
                if (fgets(tmp, sizeof(tmp), stdin) == NULL) {
                    BIO_printf(bio_err, "CERTIFICATION CANCELED: I/O error\n");
                    ret = 0;
                    goto end;
                }
                if (tmp[0] != 'y' && tmp[0] != 'Y') {
                    BIO_printf(bio_err, "CERTIFICATION CANCELED\n");
                    ret = 0;
                    goto end;
                }
            }

            BIO_printf(bio_err, "Write out database with %d new entries\n", sk_X509_num(cert_sk));

            if (serialfile != NULL && !save_serial(serialfile, "new", serial, NULL))
                goto end;

            if (!save_index(dbfile, "new", db))
                goto end;
        }

        outdirlen = OPENSSL_strlcpy(new_cert, outdir, sizeof(new_cert));
#ifndef OPENSSL_SYS_VMS
        outdirlen = OPENSSL_strlcat(new_cert, "/", sizeof(new_cert));
#endif

        if (verbose)
            BIO_printf(bio_err, "writing new certificates\n");

        for (i = 0; i < sk_X509_num(cert_sk); i++) {
            BIO *Cout = NULL;
            X509 *xi = sk_X509_value(cert_sk, i);
            ASN1_INTEGER *serialNumber = X509_get_serialNumber(xi);
            const unsigned char *psn = ASN1_STRING_get0_data(serialNumber);
            const int snl = ASN1_STRING_length(serialNumber);
            const int filen_len = 2 * (snl > 0 ? snl : 1) + sizeof(".pem");
            char *n = new_cert + outdirlen;

            if (outdirlen + filen_len > PATH_MAX) {
                BIO_printf(bio_err, "certificate file name too long\n");
                goto end;
            }

            if (snl > 0) {
                static const char HEX_DIGITS[] = "0123456789ABCDEF";

                for (j = 0; j < snl; j++, psn++) {
                    *n++ = HEX_DIGITS[*psn >> 4];
                    *n++ = HEX_DIGITS[*psn & 0x0F];
                }
            } else {
                *(n++) = '0';
                *(n++) = '0';
            }
            *(n++) = '.';
            *(n++) = 'p';
            *(n++) = 'e';
            *(n++) = 'm';
            *n = '\0';          /* closing new_cert */
            if (verbose)
                BIO_printf(bio_err, "writing %s\n", new_cert);

            Sout = bio_open_default(outfile, 'w', output_der ? FORMAT_ASN1 : FORMAT_TEXT);

            printf("===========\n");
            printf("OUTFILE: %s\n", outfile);

            if (Sout == NULL)
                goto end;

            ctx->caCertFilename = GZPKI_strdup(new_cert);
            printf("NEWCERT: %s\n", new_cert);
            printf("===========\n");

            Cout = BIO_new_file(new_cert, "w");
            if (Cout == NULL) {
                perror(new_cert);
                goto end;
            }
            write_new_certificate(Cout, xi, 0, notext);
            write_new_certificate(Sout, xi, output_der, notext);
            BIO_free_all(Cout);
            BIO_free_all(Sout);
            Sout = NULL;
        }

        if (sk_X509_num(cert_sk)) {
            /* Rename the database and the serial file */
            if (serialfile != NULL && !rotate_serial(serialfile, "new", "old"))
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;

            BIO_printf(bio_err, "Data Base Updated\n");
        }
    }  //end if(req)

    /*****************************************************************/
    if (gencrl) {
        int crl_v2 = 0;
        if (crl_ext == NULL) {
            crl_ext = NCONF_get_string(conf, section, ENV_CRLEXT);
            if (crl_ext == NULL)
                ERR_clear_error();
        }
        if (crl_ext != NULL) {
            /* Check syntax of file */
            X509V3_CTX x509ctx;
            X509V3_set_ctx_test(&x509ctx);
            X509V3_set_nconf(&x509ctx, conf);
            if (!X509V3_EXT_add_nconf(conf, &x509ctx, crl_ext, NULL)) {
                BIO_printf(bio_err, "Error Loading CRL extension section %s\n", crl_ext);
                sprintf(ctx->errstr, "Error Loading CRL extension section %s\n", crl_ext);
                ret = 1;
                goto end;
            }
        }

        if ((crlnumberfile = NCONF_get_string(conf, section, ENV_CRLNUMBER))
            != NULL)
            if ((crlnumber = load_serial(crlnumberfile, 0, NULL)) == NULL) {
                BIO_printf(bio_err, "error while loading CRL number\n");
                goto end;
            }

        if (!crldays && !crlhours && !crlsec) {
            if (!NCONF_get_number(conf, section, ENV_DEFAULT_CRL_DAYS, &crldays))
                crldays = 0;
            if (!NCONF_get_number(conf, section, ENV_DEFAULT_CRL_HOURS, &crlhours))
                crlhours = 0;
            ERR_clear_error();
        }
        if ((crldays == 0) && (crlhours == 0) && (crlsec == 0)) {
            BIO_printf(bio_err, "cannot lookup how long until the next CRL is issued\n");
            goto end;
        }

        if (verbose)
            BIO_printf(bio_err, "making CRL\n");
        if ((crl = X509_CRL_new()) == NULL)
            goto end;
        if (!X509_CRL_set_issuer_name(crl, X509_get_subject_name(x509)))
            goto end;

        tmptm = ASN1_TIME_new();
        if (tmptm == NULL
                || X509_gmtime_adj(tmptm, 0) == NULL
                || !X509_CRL_set1_lastUpdate(crl, tmptm)
                || X509_time_adj_ex(tmptm, crldays, crlhours * 60 * 60 + crlsec,
                                    NULL) == NULL) {
            BIO_puts(bio_err, "error setting CRL nextUpdate\n");
            ASN1_TIME_free(tmptm);
            goto end;
        }
        X509_CRL_set1_nextUpdate(crl, tmptm);

        ASN1_TIME_free(tmptm);

        for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
            pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
            if (pp[DB_type][0] == DB_TYPE_REV) {
                if ((r = X509_REVOKED_new()) == NULL)
                    goto end;
                j = make_revoked(r, pp[DB_rev_date]);
                if (!j)
                    goto end;
                if (j == 2)
                    crl_v2 = 1;
                if (!BN_hex2bn(&serial, pp[DB_serial]))
                    goto end;
                tmpser = BN_to_ASN1_INTEGER(serial, NULL);
                BN_free(serial);
                serial = NULL;
                if (!tmpser)
                    goto end;
                X509_REVOKED_set_serialNumber(r, tmpser);
                ASN1_INTEGER_free(tmpser);
                X509_CRL_add0_revoked(crl, r);
            }
        }

        /*
         * sort the data so it will be written in serial number order
         */
        X509_CRL_sort(crl);

        /* we now have a CRL */
        if (verbose)
            BIO_printf(bio_err, "signing CRL\n");

        /* Add any extensions asked for */

        if (crl_ext != NULL || crlnumberfile != NULL) {
            X509V3_CTX crlctx;
            X509V3_set_ctx(&crlctx, x509, NULL, NULL, crl, 0);
            X509V3_set_nconf(&crlctx, conf);

            if (crl_ext != NULL)
                if (!X509V3_EXT_CRL_add_nconf(conf, &crlctx, crl_ext, crl))
                    goto end;
            if (crlnumberfile != NULL) {
                tmpser = BN_to_ASN1_INTEGER(crlnumber, NULL);
                if (!tmpser)
                    goto end;
                X509_CRL_add1_ext_i2d(crl, NID_crl_number, tmpser, 0, 0);
                ASN1_INTEGER_free(tmpser);
                crl_v2 = 1;
                if (!BN_add_word(crlnumber, 1))
                    goto end;
            }
        }
        if (crl_ext != NULL || crl_v2) {
            if (!X509_CRL_set_version(crl, 1)) {
                goto end;       /* version 2 CRL */
            }
        }

        /* we have a CRL number that need updating */
        if (crlnumberfile != NULL && !save_serial(crlnumberfile, "new", crlnumber, NULL)) {
            goto end;
        }

        BN_free(crlnumber);
        crlnumber = NULL;

        if (!do_X509_CRL_sign(crl, pkey, dgst, sigopts))
            goto end;

        Sout = bio_open_default(outfile, 'w', output_der ? FORMAT_ASN1 : FORMAT_TEXT);
        if (Sout == NULL) {
            goto end;
        }

        PEM_write_bio_X509_CRL(Sout, crl);

        /* Rename the crlnumber file */
        if (crlnumberfile != NULL && !rotate_serial(crlnumberfile, "new", "old")) {

            goto end;
        }

    }
    /*****************************************************************/
    if (dorevoke) {
        if (infile == NULL) {
            BIO_printf(bio_err, "no input files\n");
            sprintf(ctx->errstr, "no input files");
            goto end;
        } else {
            X509 *revcert;
            revcert = load_cert(infile, FORMAT_PEM, infile);
            if (revcert == NULL)
                goto end;
            if (dorevoke == 2)
                rev_type = REV_VALID;
            //j = do_revoke(revcert, db, rev_type, rev_arg);

            IF_VERBOSE fprintf(stderr, "REVOKE: rev_type= %d\n", rev_type);
            IF_VERBOSE fprintf(stderr, "REVOKE: rev_arg = %s\n", rev_arg);

            j = do_revoke2(ctx, revcert, db, rev_type, rev_arg);
            if (j <= 0) {
                ctx->errcode = -401;
                //GZPKI_print_errors(ctx);
                goto end;
            }
            X509_free(revcert);

            if (!save_index(dbfile, "new", db))
                goto end;

            if (!rotate_index(dbfile, "new", "old"))
                goto end;

            BIO_printf(bio_err, "Data Base Updated\n");
        }
    }
    //ret = 0;
    ret = CMS_RET_OK;
 
 end_success:
    if (ret) 
        ERR_print_errors(bio_err);

    ret = CMS_RET_OK;

    BIO_free_all(Sout);
    BIO_free_all(out);
    BIO_free_all(in);
    sk_X509_pop_free(cert_sk, X509_free);

    if (free_key)
        OPENSSL_free(key);
    BN_free(serial);
    BN_free(crlnumber);
    free_index(db);
    sk_OPENSSL_STRING_free(sigopts);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    X509_CRL_free(crl);
    NCONF_free(conf);
    NCONF_free(extconf);
    //TODO: release_engine(e);
    return ret;

 end:
    ret = CMS_RET_ERROR;

    if (ret)
        ERR_print_errors(bio_err);

    BIO_free_all(Sout);
    BIO_free_all(out);
    BIO_free_all(in);
    sk_X509_pop_free(cert_sk, X509_free);

    if (free_key)
        OPENSSL_free(key);
    BN_free(serial);
    BN_free(crlnumber);
    free_index(db);
    sk_OPENSSL_STRING_free(sigopts);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    X509_CRL_free(crl);
    NCONF_free(conf);
    NCONF_free(extconf);
    //TODO: release_engine(e);
    return ret;
}

static char *lookup_conf(const CONF *conf, const char *section, const char *tag)
{
    char *entry = NCONF_get_string(conf, section, tag);
    if (entry == NULL)
        BIO_printf(bio_err, "variable lookup failed for %s::%s\n", section, tag);
    return entry;
}

static int certify(GZPKI_CTX *ctx, X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                   BIGNUM *serial, const char *subj, unsigned long chtype,
                   int multirdn, int email_dn, const char *startdate,
                   const char *enddate,
                   long days, int batch, const char *ext_sect, CONF *lconf,
                   int verbose, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign)
{
    X509_REQ *req = NULL;
    BIO *in = NULL;
    EVP_PKEY *pktmp = NULL;
    int ok = -1, i;

    fprintf(stderr, "%s", "BEGIN certify()...\n");

    in = BIO_new_file(infile, "r");
    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if ((req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL)) == NULL) {
        //BIO_printf(bio_err, "Error reading certificate request in %s\n", infile);
        fprintf(stderr, "error: reading certificate request in %s\n", infile);
        goto end;
    }
    if (verbose)
        X509_REQ_print_ex(bio_err, req, nameopt, X509_FLAG_COMPAT);

    //BIO_printf(bio_err, "Check that the request matches the signature\n");
    fprintf(stderr, "check: request/signature matching...\n");

    if (selfsign && !X509_REQ_check_private_key(req, pkey)) {
        //BIO_printf(bio_err, "Certificate request and CA private key do not match\n");
        fprintf(stderr, "selfsigned: CSR and CA private key do not match\n");
        ok = 0;
        goto end;
    }
    if ((pktmp = X509_REQ_get0_pubkey(req)) == NULL) {
        //BIO_printf(bio_err, "error unpacking public key\n");
        fprintf(stderr, "error unpacking public key\n");
        goto end;
    }
    i = X509_REQ_verify(req, pktmp);
    pktmp = NULL;
    if (i < 0) {
        ok = 0;
        //BIO_printf(bio_err, "Signature verification problems....\n");
        fprintf(stderr, "Signature verification problems....\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    if (i == 0) {
        ok = 0;
        //BIO_printf(bio_err, "Signature did not match the certificate request\n");
        fprintf(stderr, "Signature did not match the certificate request\n");
        ERR_print_errors(bio_err);
        goto end;
    } else {
        //BIO_printf(bio_err, "Signature ok\n");
        fprintf(stderr, "Signature ok\n");
    }

    ok = do_body(ctx, xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, batch,
                 verbose, req, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, selfsign);

    fprintf(stderr, "cerify_do_body() ok=%d\n", ok);                 

 end:
    X509_REQ_free(req);
    BIO_free(in);
    return ok;
}

static int certify_cert(GZPKI_CTX *ctx, X509 **xret, const char *infile, EVP_PKEY *pkey, X509 *x509,
                        const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                        STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                        BIGNUM *serial, const char *subj, unsigned long chtype,
                        int multirdn, int email_dn, const char *startdate,
                        const char *enddate, long days, int batch, const char *ext_sect,
                        CONF *lconf, int verbose, unsigned long certopt,
                        unsigned long nameopt, int default_op, int ext_copy)
{
    X509 *req = NULL;
    X509_REQ *rreq = NULL;
    EVP_PKEY *pktmp = NULL;
    int ok = -1, i;

    if ((req = load_cert(infile, FORMAT_PEM, infile)) == NULL)
        goto end;
    if (verbose)
        X509_print(bio_err, req);

    BIO_printf(bio_err, "Check that the request matches the signature\n");

    if ((pktmp = X509_get0_pubkey(req)) == NULL) {
        BIO_printf(bio_err, "error unpacking public key\n");
        goto end;
    }
    i = X509_verify(req, pktmp);
    if (i < 0) {
        ok = 0;
        BIO_printf(bio_err, "Signature verification problems....\n");
        goto end;
    }
    if (i == 0) {
        ok = 0;
        BIO_printf(bio_err, "Signature did not match the certificate\n");
        goto end;
    } else {
        BIO_printf(bio_err, "Signature ok\n");
    }

    if ((rreq = X509_to_X509_REQ(req, NULL, NULL)) == NULL)
        goto end;

    ok = do_body(ctx, xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, batch,
                 verbose, rreq, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, 0);

 end:
    X509_REQ_free(rreq);
    X509_free(req);
    return ok;
}

static int do_body(GZPKI_CTX *ctx, X509 **xret, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db, BIGNUM *serial,
                   const char *subj, unsigned long chtype, int multirdn,
                   int email_dn, const char *startdate, const char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, const char *ext_sect,
                   CONF *lconf, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign)
{
    X509_NAME *name = NULL, *CAname = NULL, *subject = NULL;
    const ASN1_TIME *tm;
    ASN1_STRING *str, *str2;
    ASN1_OBJECT *obj;
    X509 *ret = NULL;
    X509_NAME_ENTRY *ne, *tne;
    EVP_PKEY *pktmp;
    int ok = -1, i, j, last, nid;
    const char *p;
    CONF_VALUE *cv;
    OPENSSL_STRING row[DB_NUMBER];
    OPENSSL_STRING *irow = NULL;
    OPENSSL_STRING *rrow = NULL;
    char buf[25];

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    if (subj) {
        X509_NAME *n = parse_name(subj, chtype, multirdn);

        if (!n) {
            ok  = -100;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "%s", "subject chtype error");
            ERR_print_errors(bio_err);
            goto end;
        }
        X509_REQ_set_subject_name(req, n);
        X509_NAME_free(n);
    }

    ok  = 0;
    ctx->errcode = ok;
    //sprintf(ctx->errstr, "%s", "GZPKI do_body()");
    fprintf(stderr, "%s", "BEGIN do_body()...\n");

    if (default_op)
        fprintf(stderr, "do_body: Subject DN:\n");
        //BIO_printf(bio_err, "The Subject's Distinguished Name is as follows\n");

    name = X509_REQ_get_subject_name(req);
    for (i = 0; i < X509_NAME_entry_count(name); i++) {
        ne = X509_NAME_get_entry(name, i);
        str = X509_NAME_ENTRY_get_data(ne);
        obj = X509_NAME_ENTRY_get_object(ne);
        nid = OBJ_obj2nid(obj);

        if (msie_hack) {
            /* assume all type should be strings */

            if (str->type == V_ASN1_UNIVERSALSTRING)
                ASN1_UNIVERSALSTRING_to_string(str);

            if (str->type == V_ASN1_IA5STRING && nid != NID_pkcs9_emailAddress)
                str->type = V_ASN1_T61STRING;

            if (nid == NID_pkcs9_emailAddress
                && str->type == V_ASN1_PRINTABLESTRING)
                str->type = V_ASN1_IA5STRING;
        }

        /* If no EMAIL is wanted in the subject */
        if (nid == NID_pkcs9_emailAddress && !email_dn)
            continue;

        /* check some things */
        if (nid == NID_pkcs9_emailAddress && str->type != V_ASN1_IA5STRING) {
            BIO_printf(bio_err, "\nemailAddress type needs to be of type IA5STRING\n");
            ok  = -101;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "%s", "emailAddress type needs to be of type IA5STRING");
            goto end;
        }
        if (str->type != V_ASN1_BMPSTRING && str->type != V_ASN1_UTF8STRING) {
            j = ASN1_PRINTABLE_type(str->data, str->length);
            if ((j == V_ASN1_T61STRING && str->type != V_ASN1_T61STRING) ||
                (j == V_ASN1_IA5STRING && str->type == V_ASN1_PRINTABLESTRING))
            {
                BIO_printf(bio_err, "\nThe string contains characters that are illegal for the ASN.1 type\n");
                ok  = -102;
                ctx->errcode = ok;
                sprintf(ctx->errstr, "%s", "The string contains characters that are illegal for the ASN.1 type");
                goto end;
            }
        }

        if (default_op)
            old_entry_print(obj, str);
    }

    /* Ok, now we check the 'policy' stuff. */
    if ((subject = X509_NAME_new()) == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        ok  = -103;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "%s", "Memory for X509 NAME allocation failure");
        goto end;
    }

    /* take a copy of the issuer name before we mess with it. */
    if (selfsign)
        CAname = X509_NAME_dup(name);
    else
        CAname = X509_NAME_dup(X509_get_subject_name(x509));

    if (CAname == NULL) {
        ok  = -104;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "%s", "NULL CA Name");
        goto end;
    }

    str = str2 = NULL;

    for (i = 0; i < sk_CONF_VALUE_num(policy); i++) {
        cv = sk_CONF_VALUE_value(policy, i); /* get the object id */
        if ((j = OBJ_txt2nid(cv->name)) == NID_undef) {
            BIO_printf(bio_err, "%s:unknown object type in 'policy' configuration\n", cv->name);
            ok  = -105;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "%s:unknown object type in 'policy' configuration\n", cv->name);
            goto end;
        }
        obj = OBJ_nid2obj(j);

        last = -1;
        for (;;) {
            X509_NAME_ENTRY *push = NULL;

            /* lookup the object in the supplied name list */
            j = X509_NAME_get_index_by_OBJ(name, obj, last);
            if (j < 0) {
                if (last != -1)
                    break;
                tne = NULL;
            } else {
                tne = X509_NAME_get_entry(name, j);
            }
            last = j;

            /* depending on the 'policy', decide what to do. */
            if (strcmp(cv->value, "optional") == 0) {
                if (tne != NULL)
                    push = tne;
            } else if (strcmp(cv->value, "supplied") == 0) {
                if (tne == NULL) {
                    BIO_printf(bio_err, "The %s field needed to be supplied and was missing\n", cv->name);
                    goto end;
                } else {
                    push = tne;
                }
            } else if (strcmp(cv->value, "match") == 0) {
                int last2;

                if (tne == NULL) {
                    BIO_printf(bio_err, "The mandatory %s field was missing\n", cv->name);
                    goto end;
                }

                last2 = -1;

 again2:
                j = X509_NAME_get_index_by_OBJ(CAname, obj, last2);
                if ((j < 0) && (last2 == -1)) {
                    BIO_printf(bio_err, "The %s field does not exist in the CA certificate,\n" "the 'policy' is misconfigured\n", cv->name);
                    goto end;
                }
                if (j >= 0) {
                    push = X509_NAME_get_entry(CAname, j);
                    str = X509_NAME_ENTRY_get_data(tne);
                    str2 = X509_NAME_ENTRY_get_data(push);
                    last2 = j;
                    if (ASN1_STRING_cmp(str, str2) != 0)
                        goto again2;
                }
                if (j < 0) {
                    BIO_printf(bio_err, "The %s field is different between\n" "CA certificate (%s) and the request (%s)\n",
                               cv->name,
                               ((str2 == NULL) ? "NULL" : (char *)str2->data),
                               ((str == NULL) ? "NULL" : (char *)str->data));

                    ok  = -107;
                    ctx->errcode = ok;
                    //sprintf(ctx->errstr, "%s:unknown object type in 'policy' configuration\n", cv->name);                               
                    sprintf(ctx->errstr, "The %s field is different between  CA certificate (%s) and the request (%s)",
                               cv->name,
                               ((str2 == NULL) ? "NULL" : (char *)str2->data),
                               ((str == NULL) ? "NULL" : (char *)str->data));
                    goto end;
                }
            } else {
                BIO_printf(bio_err, "%s:invalid type in 'policy' configuration\n", cv->value);
                ok  = -107;
                ctx->errcode = ok;
                sprintf(ctx->errstr, "%s:invalid type in 'policy' configuration", cv->value);
                goto end;
            }

            if (push != NULL) {
                if (!X509_NAME_add_entry(subject, push, -1, 0)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    ok  = -108;
                    ctx->errcode = ok;
                    sprintf(ctx->errstr, "Mem alloc failed");
                    goto end;
                }
            }
            if (j < 0)
                break;
        }
    }

    if (preserve) {
        X509_NAME_free(subject);
        /* subject=X509_NAME_dup(X509_REQ_get_subject_name(req)); */
        subject = X509_NAME_dup(name);
        if (subject == NULL) {
            ok  = -109;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "Subject(X509 Name) NULL");
            goto end;
        }
    }

    /* We are now totally happy, lets make and sign the certificate */
    if (verbose)
        BIO_printf(bio_err, "Everything appears to be ok, creating and signing the certificate\n");

    if ((ret = X509_new()) == NULL) {
        ok  = -110;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "X509 Object Create failed");
        goto end;
    }

#ifdef X509_V3
    /* Make it an X509 v3 certificate. */
    if (!X509_set_version(ret, 2)) {
        ok  = -110;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "fail to set X509 version");
        goto end;
    }
#endif

    if (BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(ret)) == NULL) {
        ok  = -111;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "fail to set X509 serial number");
        goto end;
    }
    if (selfsign) {
        if (!X509_set_issuer_name(ret, subject)) {
            ok  = -112;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "fail to set issuer name");
            goto end;
        }
    } else {
        if (!X509_set_issuer_name(ret, X509_get_subject_name(x509))) {
            ok  = -113;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "fail to set issuer name");
            goto end;
        }
    }

    if (!set_cert_times(ret, startdate, enddate, days)) {
        ok  = -114;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "fail to set certificate time");
        goto end;
    }

    if (enddate != NULL) {
        int tdays;

        if (!ASN1_TIME_diff(&tdays, NULL, NULL, X509_get0_notAfter(ret))) {
            ok  = -115;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "fail to get notAfter");
            goto end;
        }
        days = tdays;
    }

    if (!X509_set_subject_name(ret, subject)) {
        ok  = -116;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "fail to set subject dn");
        goto end;
    }

    pktmp = X509_REQ_get0_pubkey(req);
    i = X509_set_pubkey(ret, pktmp);
    if (!i) {
        ok  = -117;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "fail to get REQ public key");
        goto end;
    }

    /* Lets add the extensions, if there are any */
    if (ext_sect) {
        X509V3_CTX v3ctx;

        /* Initialize the context structure */
        if (selfsign)
            X509V3_set_ctx(&v3ctx, ret, ret, req, NULL, 0);
        else
            X509V3_set_ctx(&v3ctx, x509, ret, req, NULL, 0);

        if (extconf != NULL) {
            if (verbose)
                BIO_printf(bio_err, "Extra configuration file found\n");

            /* Use the extconf configuration db LHASH */
            X509V3_set_nconf(&v3ctx, extconf);

            /* Test the structure (needed?) */
            /* X509V3_set_ctx_test(&v3ctx); */

            /* Adds exts contained in the configuration file */
            if (!X509V3_EXT_add_nconf(extconf, &v3ctx, ext_sect, ret)) {
                BIO_printf(bio_err, "ERROR: adding extensions in section %s\n", ext_sect);
                fprintf(stderr, "ERROR: adding extensions in section %s\n", ext_sect);
                ERR_print_errors(bio_err);
                ok  = -118;
                ctx->errcode = ok;
                sprintf(ctx->errstr, "ERROR: adding extensions in section %s", ext_sect);
                goto end;
            }
            if (verbose)
                BIO_printf(bio_err, "Successfully added extensions from file.\n");
        } else if (ext_sect) {
            /* We found extensions to be set from config file */
            X509V3_set_nconf(&v3ctx, lconf);

            if (!X509V3_EXT_add_nconf(lconf, &v3ctx, ext_sect, ret)) {
                BIO_printf(bio_err, "ERROR: adding extensions in section %s\n", ext_sect);
                fprintf(stderr, "ERROR: adding extensions in section %s\n", ext_sect);
                ERR_print_errors(bio_err);
                ok  = -119;
                ctx->errcode = ok;
                sprintf(ctx->errstr, "ERROR: adding extensions in section %s", ext_sect);
                goto end;
            }

            if (verbose)
                BIO_printf(bio_err, "Successfully added extensions from config\n");
        }
    }

    /* Copy extensions from request (if any) */

    if (!copy_extensions(ret, req, ext_copy)) {
        BIO_printf(bio_err, "ERROR: adding extensions from request\n");
        ERR_print_errors(bio_err);
        ok  = -200;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "ERROR: adding extensions from request");
        goto end;
    }

    {
        const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(ret);

        if (exts != NULL && sk_X509_EXTENSION_num(exts) > 0)
            /* Make it an X509 v3 certificate. */
            if (!X509_set_version(ret, 2)) {
                ok  = -201;
                ctx->errcode = ok;
                sprintf(ctx->errstr, "ERROR: fail to set version(2)");
                goto end;
            }
    }

    if (verbose)
        BIO_printf(bio_err, "The subject name appears to be ok, checking data base for clashes\n");

    /* Build the correct Subject if no e-mail is wanted in the subject. */
    if (!email_dn) {
        X509_NAME_ENTRY *tmpne;
        X509_NAME *dn_subject;

        /*
         * Its best to dup the subject DN and then delete any email addresses
         * because this retains its structure.
         */
        if ((dn_subject = X509_NAME_dup(subject)) == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            ok  = -202;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "Memory allocation failure");
            goto end;
        }
        i = -1;
        while ((i = X509_NAME_get_index_by_NID(dn_subject, NID_pkcs9_emailAddress, i)) >= 0) {
            tmpne = X509_NAME_delete_entry(dn_subject, i--);
            X509_NAME_ENTRY_free(tmpne);
        }

        if (!X509_set_subject_name(ret, dn_subject)) {
            X509_NAME_free(dn_subject);
            ok  = -203;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "fail to set subject DN");
            goto end;
        }
        X509_NAME_free(dn_subject);
    }

    // jkkim@greenzonesecu.com
    // MOD
    // CN format을 변경한다. "/C=KR" ==> "C=KR,"
//Check    
    X509_NAME *nm1 = X509_get_subject_name(ret);
    X509_NAME *nm2 = X509_get_subject_name(ret);

    if(!nm1 || !nm2) {
        fprintf(stderr, "error: fail to get subjet name of certificate\n");
        return CMS_RET_ERROR;
    }
    
    
    {
        /*char *buf;
        BIO *out = NULL;
        BUF_MEM *bptr;
        char mline = 0;
        int indent = 0;

        out = BIO_new(BIO_s_mem());
        X509_NAME_print_ex(out, tmp_nm, 0, ASN1_STRFLGS_RFC2253_GZ);
        BIO_get_mem_ptr( out, &bptr); 
        
        BIO *out1 = BIO_new_fp(stdout, BIO_NOCLOSE);
        out = BIO_new(BIO_s_mem());
        BIO_puts(out1, "\n------> delete this\n");
        print_name(out1, "subject=", X509_get_subject_name(ret), get_nameopt);
        //X509_NAME_print_ex(out1, nm2, 0, get_nameopt);
        */
        
        char *p = print_name_str(nm1, get_nameopt());


        IF_VERBOSE fprintf(stderr, "do_body(XN_FLAG_RFC2253_GZ): "color_red_b"%s"color_reset"\n",  p);

        free(p);
        
    }


//TODO
//CHECK
//UTF8 - revoke에서 문제됨
    row[DB_name] = X509_NAME_oneline(nm2, NULL, 0);
    //get_nameopt();
    //row[DB_name] = print_name_str(X509_get_subject_name(ret), get_nameopt());
    
    IF_VERBOSE fprintf(stderr, "do_body(1):row[DB_name] ==> %s\n", row[DB_name]);



    // 인증서 생성 여부 검증용
    // CASERVER에서 사용
    //ctx->caSubjectDN = GZPKI_strdup(row[DB_name]);

    if (row[DB_name] == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        ok  = -203;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "MEM alloc failed");
        goto end;
    }

    if (BN_is_zero(serial))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = BN_bn2hex(serial);
    if (row[DB_serial] == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        fprintf(stderr, "Memory allocation failure\n");
        ok  = -204;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "MEM alloc failed");
        goto end;
    }

    if (row[DB_name][0] == '\0') {
        /* An empty subject! We'll use the serial number instead. If unique_subject is in use then we don't want different entries with empty subjects matching each other. */
        OPENSSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
        if (row[DB_name] == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            ok  = -205;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "MEM alloc failed");
            goto end;
        }
    }

    if (db->attributes.unique_subject) {
        OPENSSL_STRING *crow = row;
        rrow = TXT_DB_get_by_index(db->db, DB_name, crow);
        if (rrow != NULL) {
            BIO_printf(bio_err, "ERROR:There is already a certificate for %s\n", row[DB_name]);
            fprintf(stderr, "ERROR:There is already a certificate for %s\n", row[DB_name]);
            ok  = -206;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "ERROR:ATTR=UNIQUE:There is already a certificate for [%s]", row[DB_name]);
        }
    }

    if (rrow == NULL) {
        rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
        if (rrow != NULL) {
            BIO_printf(bio_err, "ERROR:Serial number %s has already been issued,\n", row[DB_serial]);
            BIO_printf(bio_err, "      check the database/serial_file for corruption\n");

            fprintf(stderr, "ERROR:Serial number %s has already been issued,\n", row[DB_serial]);
            fprintf(stderr, "      check the database/serial_file for corruption\n");

            ok  = -206;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "Certificate(Serial : %s) already been issued", row[DB_serial]);
        }
    }

    if (rrow != NULL) {
        BIO_printf(bio_err, "The matching entry has the following details\n");
        fprintf(stderr, "The matching entry has the following details\n");
        if (rrow[DB_type][0] == DB_TYPE_EXP)      p = "Expired";
        else if (rrow[DB_type][0] == DB_TYPE_REV) p = "Revoked";
        else if (rrow[DB_type][0] == DB_TYPE_VAL) p = "Valid";
        else                                      p = "\ninvalid type, Data base error\n";

        //sprintf(ctx->errstr, "Certificate(Serial : %s) already been issued, status=%s", row[DB_serial], p);
        //sprintf(ctx->errstr, "Certificate status: %s", p);
        
        BIO_printf(bio_err, "Type          :%s\n", p);
        fprintf(stderr, "Type          :%s\n", p);
        if (rrow[DB_type][0] == DB_TYPE_REV) {
            p = rrow[DB_exp_date];
            if (p == NULL)
                p = "undef";
            BIO_printf(bio_err, "Was revoked on:%s\n", p);
        }
        p = rrow[DB_exp_date];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Expires on    :%s\n", p);
        fprintf(stderr, "Expires on    :%s\n", p);

        p = rrow[DB_serial];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Serial Number :%s\n", p);
        fprintf(stderr, "Serial Number :%s\n", p);

        p = rrow[DB_file];
        if (p == NULL)
            p = "undef";
        
        BIO_printf(bio_err, "File name     :%s\n", p);
        fprintf(stderr, "File name     :%s\n", p);
        p = rrow[DB_name];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Subject Name  :%s\n", p);
        fprintf(stderr, "Subject Name  :%s\n", p);
        ok = -1;                /* This is now a 'bad' error. */
        ok  = -207;
        ctx->errcode = ok;
        
        goto end;
    }

    if (!default_op) {
        BIO_printf(bio_err, "Certificate Details:\n");
        /* Never print signature details because signature not present */
        certopt |= X509_FLAG_NO_SIGDUMP | X509_FLAG_NO_SIGNAME;
        X509_print_ex(bio_err, ret, nameopt, certopt);
    }

    BIO_printf(bio_err, "Certificate is to be certified until ");
    ASN1_TIME_print(bio_err, X509_get0_notAfter(ret));
    if (days)
        BIO_printf(bio_err, " (%ld days)", days);
    BIO_printf(bio_err, "\n");

    if (!batch) {

        BIO_printf(bio_err, "Sign the certificate? [y/n]:");
        (void)BIO_flush(bio_err);
        buf[0] = '\0';
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            BIO_printf(bio_err, "CERTIFICATE WILL NOT BE CERTIFIED: I/O error\n");
            ok = 0;
            goto end;
        }
        if (!(buf[0] == 'y' || buf[0] == 'Y')) {
            BIO_printf(bio_err, "CERTIFICATE WILL NOT BE CERTIFIED\n");
            ok = 0;
            goto end;
        }
    }

    pktmp = X509_get0_pubkey(ret);
    if (EVP_PKEY_missing_parameters(pktmp) &&
        !EVP_PKEY_missing_parameters(pkey))
        EVP_PKEY_copy_parameters(pktmp, pkey);

    if (!do_X509_sign(ret, pkey, dgst, sigopts)) {
        ok  = -208;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "%s", "error so sign X.509");
        goto end;
    }

    /* We now just add it to the database as DB_TYPE_VAL('V') */
    row[DB_type] = OPENSSL_strdup("V");
    tm = X509_get0_notAfter(ret);
    row[DB_exp_date] = app_malloc(tm->length + 1, "row expdate");
    memcpy(row[DB_exp_date], tm->data, tm->length);
    row[DB_exp_date][tm->length] = '\0';
    row[DB_rev_date] = NULL;
    row[DB_file] = OPENSSL_strdup("unknown");
    if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
        (row[DB_file] == NULL) || (row[DB_name] == NULL)) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        ok  = -209;
        ctx->errcode = ok;
        sprintf(ctx->errstr, "%s", "Memory allocation failure");
        goto end;
    }

    irow = app_malloc(sizeof(*irow) * (DB_NUMBER + 1), "row space");
    for (i = 0; i < DB_NUMBER; i++) {
        irow[i] = row[i];
        IF_VERBOSE fprintf(stderr, "[%d] TXT_DB irow[%d]=%s\n", i, i, irow[i]);
    }
        
    irow[DB_NUMBER] = NULL;


    if(ctx->use_txtdb == 1) {
        if (!TXT_DB_insert(db->db, irow)) {
            BIO_printf(bio_err, "failed to update database\n");
            BIO_printf(bio_err, "error:txt_db:number %ld\n", db->db->error);
            fprintf(stderr, "failed to update database\n");
            fprintf(stderr, "error:txt_db:number %ld\n", db->db->error);
            ok  = -210;
            ctx->errcode = ok;
            sprintf(ctx->errstr, "error:txt_db:number:%ld\n", db->db->error);
            goto end;
        }
    }

    
    if(ctx->use_sqldb == 1) {
        char insertQry[8192*2]; 
        BIO *tmpbio = BIO_new(BIO_s_mem());
        BUF_MEM *bptr;

        PEM_write_bio_X509(tmpbio, ret);
        BIO_get_mem_ptr( tmpbio, &bptr);

        
        sqlite3 *CONN;
   	    char *zErrMsg = 0;
   	    int rc;
        int num = 0;

        rc = sqlite3_open(ctx->db_file, &CONN);
        if( rc ) {
    	    fprintf(stderr, "error: open database: %s\n", sqlite3_errmsg(CONN/*db*/));
      	    goto end;
   	    } else {
    	    IF_VERBOSE fprintf(stderr, "Open gzcmm database successfully.\n");
   	    }

        memset(insertQry, 0, sizeof(insertQry));
        sprintf(insertQry, "INSERT INTO certificate (reqid, status, notafter, serial, filename, dn, cdate, mdate)"
            " VALUES ( '%s', '%s', '%s', '%s', '%s', '%s' , DATETIME(\'now\'), DATETIME(\'now\') )"
            , ctx->reqUUID?ctx->reqUUID:row[DB_serial]
            , row[DB_type]
            , row[DB_exp_date]
            , row[DB_serial]
            , ctx->outfile?ctx->outfile:row[DB_file]
            , print_name_str(X509_get_subject_name(ret), get_nameopt())
        );
        /*
            . *bptr->data,
            . ctx->csr_pem?ctx->csr_pem:""
            . ctx->key_pem?ctx->key_pem:""

        */

        fprintf(stderr, "GZPKI_DO_CA:SIGN: "color_yellow_b"%s"color_reset"\n", insertQry);

        rc = sqlite3_exec(CONN, insertQry, 0, 0, &zErrMsg);
        if( rc != SQLITE_OK ){
    	    fprintf(stderr, "error:sql:%s\n", zErrMsg);
            sqlite3_free(zErrMsg);  	
   	    } else {
    	    fprintf(stderr, "add certificate to table successfully\n");
   	    }
        sqlite3_close(CONN);
    }
    
    irow = NULL;
    ok = 1;
 end:
    if (ok != 1) {
        for (i = 0; i < DB_NUMBER; i++)
            OPENSSL_free(row[i]);
    }
    OPENSSL_free(irow);

    X509_NAME_free(CAname);
    X509_NAME_free(subject);
    if (ok <= 0)
        X509_free(ret);
    else
        *xret = ret;
    return ok;
}

#if 0
static int do_body(GZPKI_CTX *ctx, X509 **xret, EVP_PKEY *pkey, X509 *x509,
                   const EVP_MD *dgst, STACK_OF(OPENSSL_STRING) *sigopts,
                   STACK_OF(CONF_VALUE) *policy, CA_DB *db, BIGNUM *serial,
                   const char *subj, unsigned long chtype, int multirdn,
                   int email_dn, const char *startdate, const char *enddate, long days,
                   int batch, int verbose, X509_REQ *req, const char *ext_sect,
                   CONF *lconf, unsigned long certopt, unsigned long nameopt,
                   int default_op, int ext_copy, int selfsign)
{
    X509_NAME *name = NULL, *CAname = NULL, *subject = NULL;
    const ASN1_TIME *tm;
    ASN1_STRING *str, *str2;
    ASN1_OBJECT *obj;
    X509 *ret = NULL;
    X509_NAME_ENTRY *ne, *tne;
    EVP_PKEY *pktmp;
    int ok = -1, i, j, last, nid;
    const char *p;
    CONF_VALUE *cv;
    OPENSSL_STRING row[DB_NUMBER];
    OPENSSL_STRING *irow = NULL;
    OPENSSL_STRING *rrow = NULL;
    char buf[25];

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    if (subj) {
        X509_NAME *n = parse_name(subj, chtype, multirdn);

        if (!n) {
            ERR_print_errors(bio_err);
            goto end;
        }
        X509_REQ_set_subject_name(req, n);
        X509_NAME_free(n);
    }

    if (default_op)
        BIO_printf(bio_err, "The Subject's Distinguished Name is as follows\n");

    name = X509_REQ_get_subject_name(req);
    for (i = 0; i < X509_NAME_entry_count(name); i++) {
        ne = X509_NAME_get_entry(name, i);
        str = X509_NAME_ENTRY_get_data(ne);
        obj = X509_NAME_ENTRY_get_object(ne);
        nid = OBJ_obj2nid(obj);

        if (msie_hack) {
            /* assume all type should be strings */

            if (str->type == V_ASN1_UNIVERSALSTRING)
                ASN1_UNIVERSALSTRING_to_string(str);

            if (str->type == V_ASN1_IA5STRING && nid != NID_pkcs9_emailAddress)
                str->type = V_ASN1_T61STRING;

            if (nid == NID_pkcs9_emailAddress
                && str->type == V_ASN1_PRINTABLESTRING)
                str->type = V_ASN1_IA5STRING;
        }

        /* If no EMAIL is wanted in the subject */
        if (nid == NID_pkcs9_emailAddress && !email_dn)
            continue;

        /* check some things */
        if (nid == NID_pkcs9_emailAddress && str->type != V_ASN1_IA5STRING) {
            BIO_printf(bio_err, "\nemailAddress type needs to be of type IA5STRING\n");
            goto end;
        }
        if (str->type != V_ASN1_BMPSTRING && str->type != V_ASN1_UTF8STRING) {
            j = ASN1_PRINTABLE_type(str->data, str->length);
            if ((j == V_ASN1_T61STRING && str->type != V_ASN1_T61STRING) ||
                (j == V_ASN1_IA5STRING && str->type == V_ASN1_PRINTABLESTRING))
            {
                BIO_printf(bio_err, "\nThe string contains characters that are illegal for the ASN.1 type\n");
                goto end;
            }
        }

        if (default_op)
            old_entry_print(obj, str);
    }

    /* Ok, now we check the 'policy' stuff. */
    if ((subject = X509_NAME_new()) == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    /* take a copy of the issuer name before we mess with it. */
    if (selfsign)
        CAname = X509_NAME_dup(name);
    else
        CAname = X509_NAME_dup(X509_get_subject_name(x509));
    if (CAname == NULL)
        goto end;
    str = str2 = NULL;

    for (i = 0; i < sk_CONF_VALUE_num(policy); i++) {
        cv = sk_CONF_VALUE_value(policy, i); /* get the object id */
        if ((j = OBJ_txt2nid(cv->name)) == NID_undef) {
            BIO_printf(bio_err, "%s:unknown object type in 'policy' configuration\n", cv->name);
            goto end;
        }
        obj = OBJ_nid2obj(j);

        last = -1;
        for (;;) {
            X509_NAME_ENTRY *push = NULL;

            /* lookup the object in the supplied name list */
            j = X509_NAME_get_index_by_OBJ(name, obj, last);
            if (j < 0) {
                if (last != -1)
                    break;
                tne = NULL;
            } else {
                tne = X509_NAME_get_entry(name, j);
            }
            last = j;

            /* depending on the 'policy', decide what to do. */
            if (strcmp(cv->value, "optional") == 0) {
                if (tne != NULL)
                    push = tne;
            } else if (strcmp(cv->value, "supplied") == 0) {
                if (tne == NULL) {
                    BIO_printf(bio_err, "The %s field needed to be supplied and was missing\n", cv->name);
                    goto end;
                } else {
                    push = tne;
                }
            } else if (strcmp(cv->value, "match") == 0) {
                int last2;

                if (tne == NULL) {
                    BIO_printf(bio_err, "The mandatory %s field was missing\n", cv->name);
                    goto end;
                }

                last2 = -1;

 again2:
                j = X509_NAME_get_index_by_OBJ(CAname, obj, last2);
                if ((j < 0) && (last2 == -1)) {
                    BIO_printf(bio_err, "The %s field does not exist in the CA certificate,\n" "the 'policy' is misconfigured\n", cv->name);
                    goto end;
                }
                if (j >= 0) {
                    push = X509_NAME_get_entry(CAname, j);
                    str = X509_NAME_ENTRY_get_data(tne);
                    str2 = X509_NAME_ENTRY_get_data(push);
                    last2 = j;
                    if (ASN1_STRING_cmp(str, str2) != 0)
                        goto again2;
                }
                if (j < 0) {
                    BIO_printf(bio_err, "The %s field is different between\n" "CA certificate (%s) and the request (%s)\n",
                               cv->name,
                               ((str2 == NULL) ? "NULL" : (char *)str2->data),
                               ((str == NULL) ? "NULL" : (char *)str->data));
                    goto end;
                }
            } else {
                BIO_printf(bio_err, "%s:invalid type in 'policy' configuration\n", cv->value);
                goto end;
            }

            if (push != NULL) {
                if (!X509_NAME_add_entry(subject, push, -1, 0)) {
                    BIO_printf(bio_err, "Memory allocation failure\n");
                    goto end;
                }
            }
            if (j < 0)
                break;
        }
    }

    if (preserve) {
        X509_NAME_free(subject);
        /* subject=X509_NAME_dup(X509_REQ_get_subject_name(req)); */
        subject = X509_NAME_dup(name);
        if (subject == NULL)
            goto end;
    }

    /* We are now totally happy, lets make and sign the certificate */
    if (verbose)
        BIO_printf(bio_err, "Everything appears to be ok, creating and signing the certificate\n");

    if ((ret = X509_new()) == NULL)
        goto end;

#ifdef X509_V3
    /* Make it an X509 v3 certificate. */
    if (!X509_set_version(ret, 2))
        goto end;
#endif

    if (BN_to_ASN1_INTEGER(serial, X509_get_serialNumber(ret)) == NULL)
        goto end;
    if (selfsign) {
        if (!X509_set_issuer_name(ret, subject))
            goto end;
    } else {
        if (!X509_set_issuer_name(ret, X509_get_subject_name(x509)))
            goto end;
    }

    if (!set_cert_times(ret, startdate, enddate, days))
        goto end;

    if (enddate != NULL) {
        int tdays;

        if (!ASN1_TIME_diff(&tdays, NULL, NULL, X509_get0_notAfter(ret)))
            goto end;
        days = tdays;
    }

    if (!X509_set_subject_name(ret, subject))
        goto end;

    pktmp = X509_REQ_get0_pubkey(req);
    i = X509_set_pubkey(ret, pktmp);
    if (!i)
        goto end;

    /* Lets add the extensions, if there are any */
    if (ext_sect) {
        X509V3_CTX ctx;

        /* Initialize the context structure */
        if (selfsign)
            X509V3_set_ctx(&ctx, ret, ret, req, NULL, 0);
        else
            X509V3_set_ctx(&ctx, x509, ret, req, NULL, 0);

        if (extconf != NULL) {
            if (verbose)
                BIO_printf(bio_err, "Extra configuration file found\n");

            /* Use the extconf configuration db LHASH */
            X509V3_set_nconf(&ctx, extconf);

            /* Test the structure (needed?) */
            /* X509V3_set_ctx_test(&ctx); */

            /* Adds exts contained in the configuration file */
            if (!X509V3_EXT_add_nconf(extconf, &ctx, ext_sect, ret)) {
                BIO_printf(bio_err, "ERROR: adding extensions in section %s\n", ext_sect);
                ERR_print_errors(bio_err);
                goto end;
            }
            if (verbose)
                BIO_printf(bio_err, "Successfully added extensions from file.\n");
        } else if (ext_sect) {
            /* We found extensions to be set from config file */
            X509V3_set_nconf(&ctx, lconf);

            if (!X509V3_EXT_add_nconf(lconf, &ctx, ext_sect, ret)) {
                BIO_printf(bio_err, "ERROR: adding extensions in section %s\n", ext_sect);
                ERR_print_errors(bio_err);
                goto end;
            }

            if (verbose)
                BIO_printf(bio_err, "Successfully added extensions from config\n");
        }
    }

    /* Copy extensions from request (if any) */

    if (!copy_extensions(ret, req, ext_copy)) {
        BIO_printf(bio_err, "ERROR: adding extensions from request\n");
        ERR_print_errors(bio_err);
        goto end;
    }

    {
        const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(ret);

        if (exts != NULL && sk_X509_EXTENSION_num(exts) > 0)
            /* Make it an X509 v3 certificate. */
            if (!X509_set_version(ret, 2))
                goto end;
    }

    if (verbose)
        BIO_printf(bio_err, "The subject name appears to be ok, checking data base for clashes\n");

    /* Build the correct Subject if no e-mail is wanted in the subject. */
    if (!email_dn) {
        X509_NAME_ENTRY *tmpne;
        X509_NAME *dn_subject;

        /*
         * Its best to dup the subject DN and then delete any email addresses
         * because this retains its structure.
         */
        if ((dn_subject = X509_NAME_dup(subject)) == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }
        i = -1;
        while ((i = X509_NAME_get_index_by_NID(dn_subject, NID_pkcs9_emailAddress, i)) >= 0) {
            tmpne = X509_NAME_delete_entry(dn_subject, i--);
            X509_NAME_ENTRY_free(tmpne);
        }

        if (!X509_set_subject_name(ret, dn_subject)) {
            X509_NAME_free(dn_subject);
            goto end;
        }
        X509_NAME_free(dn_subject);
    }

    row[DB_name] = X509_NAME_oneline(X509_get_subject_name(ret), NULL, 0);
    if (row[DB_name] == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    if (BN_is_zero(serial))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = BN_bn2hex(serial);
    if (row[DB_serial] == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    if (row[DB_name][0] == '\0') {
        /*
         * An empty subject! We'll use the serial number instead. If
         * unique_subject is in use then we don't want different entries with
         * empty subjects matching each other.
         */
        OPENSSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
        if (row[DB_name] == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }
    }

    if (db->attributes.unique_subject) {
        OPENSSL_STRING *crow = row;

        rrow = TXT_DB_get_by_index(db->db, DB_name, crow);
        if (rrow != NULL) {
            BIO_printf(bio_err, "ERROR:There is already a certificate for %s\n", row[DB_name]);
        }
    }
    if (rrow == NULL) {
        rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
        if (rrow != NULL) {
            BIO_printf(bio_err, "ERROR:Serial number %s has already been issued,\n", row[DB_serial]);
            BIO_printf(bio_err, "      check the database/serial_file for corruption\n");
        }
    }

    if (rrow != NULL) {
        BIO_printf(bio_err, "The matching entry has the following details\n");
        if (rrow[DB_type][0] == DB_TYPE_EXP)
            p = "Expired";
        else if (rrow[DB_type][0] == DB_TYPE_REV)
            p = "Revoked";
        else if (rrow[DB_type][0] == DB_TYPE_VAL)
            p = "Valid";
        else
            p = "\ninvalid type, Data base error\n";
        BIO_printf(bio_err, "Type          :%s\n", p);;
        if (rrow[DB_type][0] == DB_TYPE_REV) {
            p = rrow[DB_exp_date];
            if (p == NULL)
                p = "undef";
            BIO_printf(bio_err, "Was revoked on:%s\n", p);
        }
        p = rrow[DB_exp_date];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Expires on    :%s\n", p);
        p = rrow[DB_serial];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Serial Number :%s\n", p);
        p = rrow[DB_file];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "File name     :%s\n", p);
        p = rrow[DB_name];
        if (p == NULL)
            p = "undef";
        BIO_printf(bio_err, "Subject Name  :%s\n", p);
        ok = -1;                /* This is now a 'bad' error. */
        goto end;
    }

    if (!default_op) {
        BIO_printf(bio_err, "Certificate Details:\n");
        /*
         * Never print signature details because signature not present
         */
        certopt |= X509_FLAG_NO_SIGDUMP | X509_FLAG_NO_SIGNAME;
        X509_print_ex(bio_err, ret, nameopt, certopt);
    }

    BIO_printf(bio_err, "Certificate is to be certified until ");
    ASN1_TIME_print(bio_err, X509_get0_notAfter(ret));
    if (days)
        BIO_printf(bio_err, " (%ld days)", days);
    BIO_printf(bio_err, "\n");

    if (!batch) {

        BIO_printf(bio_err, "Sign the certificate? [y/n]:");
        (void)BIO_flush(bio_err);
        buf[0] = '\0';
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            BIO_printf(bio_err, "CERTIFICATE WILL NOT BE CERTIFIED: I/O error\n");
            ok = 0;
            goto end;
        }
        if (!(buf[0] == 'y' || buf[0] == 'Y')) {
            BIO_printf(bio_err, "CERTIFICATE WILL NOT BE CERTIFIED\n");
            ok = 0;
            goto end;
        }
    }

    pktmp = X509_get0_pubkey(ret);
    if (EVP_PKEY_missing_parameters(pktmp) &&
        !EVP_PKEY_missing_parameters(pkey))
        EVP_PKEY_copy_parameters(pktmp, pkey);

    if (!do_X509_sign(ret, pkey, dgst, sigopts))
        goto end;

    /* We now just add it to the database as DB_TYPE_VAL('V') */
    row[DB_type] = OPENSSL_strdup("V");
    tm = X509_get0_notAfter(ret);
    row[DB_exp_date] = app_malloc(tm->length + 1, "row expdate");
    memcpy(row[DB_exp_date], tm->data, tm->length);
    row[DB_exp_date][tm->length] = '\0';
    row[DB_rev_date] = NULL;
    row[DB_file] = OPENSSL_strdup("unknown");
    if ((row[DB_type] == NULL) || (row[DB_exp_date] == NULL) ||
        (row[DB_file] == NULL) || (row[DB_name] == NULL)) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    irow = app_malloc(sizeof(*irow) * (DB_NUMBER + 1), "row space");
    for (i = 0; i < DB_NUMBER; i++)
        irow[i] = row[i];
    irow[DB_NUMBER] = NULL;

//TODO 
    if (!TXT_DB_insert(db->db, irow)) {
        BIO_printf(bio_err, "failed to update database\n");
        BIO_printf(bio_err, "TXT_DB error number %ld\n", db->db->error);
        goto end;
    }

    if(ctx->use_sqldb) {


    }

    irow = NULL;
    ok = 1;
 end:
    if (ok != 1) {
        for (i = 0; i < DB_NUMBER; i++)
            OPENSSL_free(row[i]);
    }
    OPENSSL_free(irow);

    X509_NAME_free(CAname);
    X509_NAME_free(subject);
    if (ok <= 0)
        X509_free(ret);
    else
        *xret = ret;
    return ok;
}

#endif

static void write_new_certificate(BIO *bp, X509 *x, int output_der, int notext)
{

    if (output_der) {
        (void)i2d_X509_bio(bp, x);
        return;
    }
    if (!notext)
        X509_print(bp, x);
    PEM_write_bio_X509(bp, x);
}

#if 0
static int certify_spkac(X509 **xret, const char *infile, EVP_PKEY *pkey,
                         X509 *x509, const EVP_MD *dgst,
                         STACK_OF(OPENSSL_STRING) *sigopts,
                         STACK_OF(CONF_VALUE) *policy, CA_DB *db,
                         BIGNUM *serial, const char *subj, unsigned long chtype,
                         int multirdn, int email_dn, const char *startdate,
                         const char *enddate, long days, const char *ext_sect,
                         CONF *lconf, int verbose, unsigned long certopt,
                         unsigned long nameopt, int default_op, int ext_copy)
{
    STACK_OF(CONF_VALUE) *sk = NULL;
    LHASH_OF(CONF_VALUE) *parms = NULL;
    X509_REQ *req = NULL;
    CONF_VALUE *cv = NULL;
    NETSCAPE_SPKI *spki = NULL;
    char *type, *buf;
    EVP_PKEY *pktmp = NULL;
    X509_NAME *n = NULL;
    X509_NAME_ENTRY *ne = NULL;
    int ok = -1, i, j;
    long errline;
    int nid;

    /*
     * Load input file into a hash table.  (This is just an easy
     * way to read and parse the file, then put it into a convenient
     * STACK format).
     */
    parms = CONF_load(NULL, infile, &errline);
    if (parms == NULL) {
        BIO_printf(bio_err, "error on line %ld of %s\n", errline, infile);
        ERR_print_errors(bio_err);
        goto end;
    }

    sk = CONF_get_section(parms, "default");
    if (sk_CONF_VALUE_num(sk) == 0) {
        BIO_printf(bio_err, "no name/value pairs found in %s\n", infile);
        goto end;
    }

    /*
     * Now create a dummy X509 request structure.  We don't actually
     * have an X509 request, but we have many of the components
     * (a public key, various DN components).  The idea is that we
     * put these components into the right X509 request structure
     * and we can use the same code as if you had a real X509 request.
     */
    req = X509_REQ_new();
    if (req == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    /*
     * Build up the subject name set.
     */
    n = X509_REQ_get_subject_name(req);

    for (i = 0;; i++) {
        if (sk_CONF_VALUE_num(sk) <= i)
            break;

        cv = sk_CONF_VALUE_value(sk, i);
        type = cv->name;
        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (buf = cv->name; *buf; buf++)
            if ((*buf == ':') || (*buf == ',') || (*buf == '.')) {
                buf++;
                if (*buf)
                    type = buf;
                break;
            }

        buf = cv->value;
        if ((nid = OBJ_txt2nid(type)) == NID_undef) {
            if (strcmp(type, "SPKAC") == 0) {
                spki = NETSCAPE_SPKI_b64_decode(cv->value, -1);
                if (spki == NULL) {
                    BIO_printf(bio_err, "unable to load Netscape SPKAC structure\n");
                    ERR_print_errors(bio_err);
                    goto end;
                }
            }
            continue;
        }

        if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char *)buf, -1, -1, 0))
            goto end;
    }
    if (spki == NULL) {
        BIO_printf(bio_err, "Netscape SPKAC structure not found in %s\n", infile);
        goto end;
    }

    /*
     * Now extract the key from the SPKI structure.
     */

    BIO_printf(bio_err, "Check that the SPKAC request matches the signature\n");

    if ((pktmp = NETSCAPE_SPKI_get_pubkey(spki)) == NULL) {
        BIO_printf(bio_err, "error unpacking SPKAC public key\n");
        goto end;
    }

    j = NETSCAPE_SPKI_verify(spki, pktmp);
    if (j <= 0) {
        EVP_PKEY_free(pktmp);
        BIO_printf(bio_err, "signature verification failed on SPKAC public key\n");
        goto end;
    }
    BIO_printf(bio_err, "Signature ok\n");

    X509_REQ_set_pubkey(req, pktmp);
    EVP_PKEY_free(pktmp);
    ok = do_body(xret, pkey, x509, dgst, sigopts, policy, db, serial, subj,
                 chtype, multirdn, email_dn, startdate, enddate, days, 1,
                 verbose, req, ext_sect, lconf, certopt, nameopt, default_op,
                 ext_copy, 0);
 end:
    X509_REQ_free(req);
    CONF_free(parms);
    NETSCAPE_SPKI_free(spki);
    X509_NAME_ENTRY_free(ne);

    return ok;
}
#endif //certify_spkac

static int check_time_format(const char *str)
{
    return ASN1_TIME_set_string(NULL, str);
}

static int do_revoke2(GZPKI_CTX *ctx, X509 *x509, CA_DB *db, REVINFO_TYPE rev_type, const char *value)
{
    const ASN1_TIME *tm = NULL;
    char *row[DB_NUMBER], **rrow, **irow;
    char *rev_str = NULL;
    BIGNUM *bn = NULL;
    int ok = -1, i;

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    row[DB_name] = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
    bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), NULL);
    if (!bn)
        goto end;

    if (BN_is_zero(bn))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = BN_bn2hex(bn);

    BN_free(bn);
    if (row[DB_name] != NULL && row[DB_name][0] == '\0') {
        /* Entries with empty Subjects actually use the serial number instead */
        OPENSSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
    }
    if ((row[DB_name] == NULL) || (row[DB_serial] == NULL)) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }
    /*
     * We have to lookup by serial number because name lookup skips revoked
     * certs
     */
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        BIO_printf(bio_err, "Adding Entry with serial number %s to DB for %s\n", row[DB_serial], row[DB_name]);
        sprintf(ctx->errstr, "Adding Entry with serial number %s to DB for %s\n", row[DB_serial], row[DB_name]);

        /* We now just add it to the database as DB_TYPE_REV('V') */
        row[DB_type] = OPENSSL_strdup("V");
        tm = X509_get0_notAfter(x509);
        row[DB_exp_date] = app_malloc(tm->length + 1, "row exp_data");
        memcpy(row[DB_exp_date], tm->data, tm->length);
        row[DB_exp_date][tm->length] = '\0';
        row[DB_rev_date] = NULL;
        row[DB_file] = OPENSSL_strdup("unknown");

        if (row[DB_type] == NULL || row[DB_file] == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            sprintf(ctx->errstr, "Memory allocation failure\n");
            goto end;
        }

        irow = app_malloc(sizeof(*irow) * (DB_NUMBER + 1), "row ptr");
        for (i = 0; i < DB_NUMBER; i++)
            irow[i] = row[i];
        irow[DB_NUMBER] = NULL;

        if (!TXT_DB_insert(db->db, irow)) {
            BIO_printf(bio_err, "failed to update database\n");
            BIO_printf(bio_err, "TXT_DB error number %ld\n", db->db->error);
            sprintf(ctx->errstr, "failed to update database\nTXT_DB error number %ld\n", db->db->error);
            OPENSSL_free(irow);
            goto end;
        }

        for (i = 0; i < DB_NUMBER; i++)
            row[i] = NULL;

        /* Revoke Certificate */
        if (rev_type == REV_VALID)
            ok = 1;
        else
            /* Retry revocation after DB insertion */
            ok = do_revoke2(ctx, x509, db, rev_type, value);

        goto end;

    } else if (index_name_cmp_noconst(row, rrow)) {
        BIO_printf(bio_err, "ERROR:name does not match %s\n", row[DB_name]);
        IF_VERBOSE fprintf(stderr, "ERROR:name does not match %s\n", row[DB_name]);
        sprintf(ctx->errstr, "name does not match %s\n", row[DB_name]);
        goto end;
    } else if (rev_type == REV_VALID) {
        IF_VERBOSE fprintf(stderr, "ERROR:Already present, serial number %s\n", row[DB_serial]);
        BIO_printf(bio_err, "ERROR:Already present, serial number %s\n", row[DB_serial]);
        sprintf(ctx->errstr, "name does not match %s\n", row[DB_name]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_REV) {
        BIO_printf(bio_err, "ERROR:Already revoked, serial number %s\n", row[DB_serial]);
        IF_VERBOSE fprintf(stderr, "ERROR:Already revoked, serial number %s\n", row[DB_serial]);
        sprintf(ctx->errstr, "Already revoked, serial number %s\n", row[DB_serial]);
        goto end;
    } else {
        BIO_printf(bio_err, "Revoking Certificate %s.\n", rrow[DB_serial]);
        IF_VERBOSE fprintf(stderr, "Revoking Certificate %s.\n", rrow[DB_serial]);
        sprintf(ctx->errstr, "Revoking Certificate %s.\n", rrow[DB_serial]);
        rev_str = make_revocation_str(rev_type, value);
        if (!rev_str) {
            BIO_printf(bio_err, "Error in revocation arguments\n");
            sprintf(ctx->errstr, "Error in revocation arguments\n");
            goto end;
        }
        rrow[DB_type][0] = DB_TYPE_REV;
        rrow[DB_type][1] = '\0';
        rrow[DB_rev_date] = rev_str;
    }
    ok = 1;
 end:
    for (i = 0; i < DB_NUMBER; i++)
        OPENSSL_free(row[i]);
    return ok;
}

#if 1
static int do_revoke(X509 *x509, CA_DB *db, REVINFO_TYPE rev_type, const char *value)
{
    const ASN1_TIME *tm = NULL;
    char *row[DB_NUMBER], **rrow, **irow;
    char *rev_str = NULL;
    BIGNUM *bn = NULL;
    int ok = -1, i;

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    row[DB_name] = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
    bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), NULL);
    if (!bn)
        goto end;

    if (BN_is_zero(bn))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = BN_bn2hex(bn);

    BN_free(bn);
    if (row[DB_name] != NULL && row[DB_name][0] == '\0') {
        /* Entries with empty Subjects actually use the serial number instead */
        OPENSSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
    }
    if ((row[DB_name] == NULL) || (row[DB_serial] == NULL)) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }
    /*
     * We have to lookup by serial number because name lookup skips revoked
     * certs
     */
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        BIO_printf(bio_err, "Adding Entry with serial number %s to DB for %s\n", row[DB_serial], row[DB_name]);

        /* We now just add it to the database as DB_TYPE_REV('V') */
        row[DB_type] = OPENSSL_strdup("V");
        tm = X509_get0_notAfter(x509);
        row[DB_exp_date] = app_malloc(tm->length + 1, "row exp_data");
        memcpy(row[DB_exp_date], tm->data, tm->length);
        row[DB_exp_date][tm->length] = '\0';
        row[DB_rev_date] = NULL;
        row[DB_file] = OPENSSL_strdup("unknown");

        if (row[DB_type] == NULL || row[DB_file] == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }

        irow = app_malloc(sizeof(*irow) * (DB_NUMBER + 1), "row ptr");
        for (i = 0; i < DB_NUMBER; i++)
            irow[i] = row[i];
        irow[DB_NUMBER] = NULL;

        if (!TXT_DB_insert(db->db, irow)) {
            BIO_printf(bio_err, "failed to update database\n");
            OPENSSL_free(irow);
            goto end;
        }

        for (i = 0; i < DB_NUMBER; i++)
            row[i] = NULL;

        /* Revoke Certificate */
        if (rev_type == REV_VALID)
            ok = 1;
        else
            /* Retry revocation after DB insertion */
            //original - do not modify
            ok = do_revoke(x509, db, rev_type, value);

        goto end;

    } else if (index_name_cmp_noconst(row, rrow)) {
        BIO_printf(bio_err, "ERROR:name does not match %s\n", row[DB_name]);
        goto end;
    } else if (rev_type == REV_VALID) {
        BIO_printf(bio_err, "ERROR:Already present, serial number %s\n", row[DB_serial]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_REV) {
        BIO_printf(bio_err, "ERROR:Already revoked, serial number %s\n", row[DB_serial]);
        goto end;
    } else {
        BIO_printf(bio_err, "Revoking Certificate %s.\n", rrow[DB_serial]);
        rev_str = make_revocation_str(rev_type, value);
        if (!rev_str) {
            BIO_printf(bio_err, "Error in revocation arguments\n");
            goto end;
        }
        rrow[DB_type][0] = DB_TYPE_REV;
        rrow[DB_type][1] = '\0';
        rrow[DB_rev_date] = rev_str;
    }
    ok = 1;
 end:
    for (i = 0; i < DB_NUMBER; i++)
        OPENSSL_free(row[i]);
    return ok;
}
#endif

static int get_certificate_status(const char *serial, CA_DB *db)
{
    char *row[DB_NUMBER], **rrow;
    int ok = -1, i;
    size_t serial_len = strlen(serial);

    /* Free Resources */
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;

    /* Malloc needed char spaces */
    row[DB_serial] = app_malloc(serial_len + 2, "row serial#");

    if (serial_len % 2) {
        /*
         * Set the first char to 0
         */
        row[DB_serial][0] = '0';

        /* Copy String from serial to row[DB_serial] */
        memcpy(row[DB_serial] + 1, serial, serial_len);
        row[DB_serial][serial_len + 1] = '\0';
    } else {
        /* Copy String from serial to row[DB_serial] */
        memcpy(row[DB_serial], serial, serial_len);
        row[DB_serial][serial_len] = '\0';
    }

    /* Make it Upper Case */
    make_uppercase(row[DB_serial]);

    ok = 1;

    /* Search for the certificate */
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        BIO_printf(bio_err, "Serial %s not present in db.\n", row[DB_serial]);
        ok = -1;
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_VAL) {
        BIO_printf(bio_err, "%s=Valid (%c)\n", row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_REV) {
        BIO_printf(bio_err, "%s=Revoked (%c)\n", row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_EXP) {
        BIO_printf(bio_err, "%s=Expired (%c)\n", row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else if (rrow[DB_type][0] == DB_TYPE_SUSP) {
        BIO_printf(bio_err, "%s=Suspended (%c)\n", row[DB_serial], rrow[DB_type][0]);
        goto end;
    } else {
        BIO_printf(bio_err, "%s=Unknown (%c).\n", row[DB_serial], rrow[DB_type][0]);
        ok = -1;
    }
 end:
    for (i = 0; i < DB_NUMBER; i++) {
        OPENSSL_free(row[i]);
    }
    return ok;
}

static int get_certificate_status_SQL(const char *serial, char *file)
{
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
   	char *zErrMsg = 0;
    int rc = 0;
    int num = 0;
    char sql[1024];
    char stat[8];
    int ok = -1;


    rc = sqlite3_open(file, &db);
    if( rc ) {
    	fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(db));
      	return -1;
   	} else {
    	fprintf(stderr, "open database(%s) successfully.\n", file);
   	}
	
    memset(sql, 0, 1024);
    sprintf(sql, "SELECT status FROM certificate WHERE serial='%s'", (char *)serial);
    IF_VERBOSE fprintf(stderr, "SQL: %s\n", sql);

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,"error:get_certificate_status_SQL:fail to open database: %s\n", file);
        return -1;
    }
    rc = sqlite3_step(stmt);
    int rowCount = 0;
    int i = 0;
    memset(stat, 0, sizeof(stat));
    while (rc != SQLITE_DONE && rc != SQLITE_OK) {
        rowCount++; 
        int colCount = sqlite3_column_count(stmt);
        
        for (int colIndex = 0; colIndex < colCount; colIndex++) {
            
            int type = sqlite3_column_type(stmt, colIndex);
            const char * columnName = sqlite3_column_name(stmt, colIndex);
            if (type == SQLITE_TEXT)
            {
                const unsigned char * valChar = NULL;
                valChar = sqlite3_column_text(stmt, colIndex);
            
                if(0==strcmp(columnName, "stat")) {
                    memset(stat, 0, sizeof(stat));
                    sprintf(stat, "%s", valChar);
                }
            }
        }
        rc = sqlite3_step(stmt);
    }

    rc = sqlite3_finalize(stmt);
    rc = sqlite3_close(db);

    if (stat == NULL) {
        BIO_printf(bio_err, "Serial %s not present in db.\n", stat);
        ok = -1;
        goto end;
    } else if (stat[0] == DB_TYPE_VAL) {
        BIO_printf(bio_err, "%s=Valid (%c)\n", serial, stat[0]);
        goto end;
    } else if (stat[0] == DB_TYPE_REV) {
        BIO_printf(bio_err, "%s=Revoked (%c)\n", serial, stat[0]);
        goto end;
    } else if (stat[0] == DB_TYPE_EXP) {
        BIO_printf(bio_err, "%s=Expired (%c)\n", serial, stat[0]);
        goto end;
    } else if (stat[0] == DB_TYPE_SUSP) {
        BIO_printf(bio_err, "%s=Suspended (%c)\n", serial, stat[0]);
        goto end;
    } else {
        BIO_printf(bio_err, "%s=Unknown (%c).\n", serial, stat[0]);
        ok = -1;
    }
 end:
    
    return ok;
}

static int do_updatedb(CA_DB *db)
{
    ASN1_UTCTIME *a_tm = NULL;
    int i, cnt = 0;
    int db_y2k, a_y2k;          /* flags = 1 if y >= 2000 */
    char **rrow, *a_tm_s;

    a_tm = ASN1_UTCTIME_new();
    if (a_tm == NULL)
        return -1;

    /* get actual time and make a string */
    if (X509_gmtime_adj(a_tm, 0) == NULL) {
        ASN1_UTCTIME_free(a_tm);
        return -1;
    }
    a_tm_s = app_malloc(a_tm->length + 1, "time string");

    memcpy(a_tm_s, a_tm->data, a_tm->length);
    a_tm_s[a_tm->length] = '\0';

    if (strncmp(a_tm_s, "49", 2) <= 0)
        a_y2k = 1;
    else
        a_y2k = 0;

    for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
        rrow = sk_OPENSSL_PSTRING_value(db->db->data, i);

        if (rrow[DB_type][0] == DB_TYPE_VAL) {
            /* ignore entries that are not valid */
            if (strncmp(rrow[DB_exp_date], "49", 2) <= 0)
                db_y2k = 1;
            else
                db_y2k = 0;

            if (db_y2k == a_y2k) {
                /* all on the same y2k side */
                if (strcmp(rrow[DB_exp_date], a_tm_s) <= 0) {
                    rrow[DB_type][0] = DB_TYPE_EXP;
                    rrow[DB_type][1] = '\0';
                    cnt++;

                    BIO_printf(bio_err, "%s=Expired\n", rrow[DB_serial]);
                }
            } else if (db_y2k < a_y2k) {
                rrow[DB_type][0] = DB_TYPE_EXP;
                rrow[DB_type][1] = '\0';
                cnt++;

                BIO_printf(bio_err, "%s=Expired\n", rrow[DB_serial]);
            }

        }
    }

    ASN1_UTCTIME_free(a_tm);
    OPENSSL_free(a_tm_s);
    return cnt;
}



#define NUM_REASONS OSSL_NELEM(crl_reasons)

/* Given revocation information convert to a DB string. The format of the
 * string is: revtime[,reason,extra]. Where 'revtime' is the revocation time
 * (the current time). 'reason' is the optional CRL reason and 'extra' is any
 * additional argument */

static char *make_revocation_str(REVINFO_TYPE rev_type, const char *rev_arg)
{
    char *str;
    const char *reason = NULL, *other = NULL;
    ASN1_OBJECT *otmp;
    ASN1_UTCTIME *revtm = NULL;
    int i;

    switch (rev_type) {
    case REV_NONE:
    case REV_VALID:
        break;

    case REV_CRL_REASON:
        for (i = 0; i < 8; i++) {
            if (strcasecmp(rev_arg, crl_reasons[i]) == 0) {
                reason = crl_reasons[i];
                break;
            }
        }
        if (reason == NULL) {
            BIO_printf(bio_err, "Unknown CRL reason %s\n", rev_arg);
            return NULL;
        }
        break;

    case REV_HOLD:
        /* Argument is an OID */
        otmp = OBJ_txt2obj(rev_arg, 0);
        ASN1_OBJECT_free(otmp);

        if (otmp == NULL) {
            BIO_printf(bio_err, "Invalid object identifier %s\n", rev_arg);
            return NULL;
        }

        reason = "holdInstruction";
        other = rev_arg;
        break;

    case REV_KEY_COMPROMISE:
    case REV_CA_COMPROMISE:
        /* Argument is the key compromise time  */
        if (!ASN1_GENERALIZEDTIME_set_string(NULL, rev_arg)) {
            BIO_printf(bio_err, "Invalid time format %s. Need YYYYMMDDHHMMSSZ\n", rev_arg);
            return NULL;
        }
        other = rev_arg;
        if (rev_type == REV_KEY_COMPROMISE)
            reason = "keyTime";
        else
            reason = "CAkeyTime";

        break;
    }

    revtm = X509_gmtime_adj(NULL, 0);

    if (!revtm)
        return NULL;

    i = revtm->length + 1;

    if (reason)
        i += strlen(reason) + 1;
    if (other)
        i += strlen(other) + 1;

    str = app_malloc(i, "revocation reason");
    OPENSSL_strlcpy(str, (char *)revtm->data, i);
    if (reason) {
        OPENSSL_strlcat(str, ",", i);
        OPENSSL_strlcat(str, reason, i);
    }
    if (other) {
        OPENSSL_strlcat(str, ",", i);
        OPENSSL_strlcat(str, other, i);
    }
    ASN1_UTCTIME_free(revtm);
    return str;
}

/*-
 * Convert revocation field to X509_REVOKED entry
 * return code:
 * 0 error
 * 1 OK
 * 2 OK and some extensions added (i.e. V2 CRL)
 */

static int make_revoked(X509_REVOKED *rev, const char *str)
{
    char *tmp = NULL;
    int reason_code = -1;
    int i, ret = 0;
    ASN1_OBJECT *hold = NULL;
    ASN1_GENERALIZEDTIME *comp_time = NULL;
    ASN1_ENUMERATED *rtmp = NULL;

    ASN1_TIME *revDate = NULL;

    i = unpack_revinfo(&revDate, &reason_code, &hold, &comp_time, str);

    if (i == 0)
        goto end;

    if (rev && !X509_REVOKED_set_revocationDate(rev, revDate))
        goto end;

    if (rev && (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)) {
        rtmp = ASN1_ENUMERATED_new();
        if (rtmp == NULL || !ASN1_ENUMERATED_set(rtmp, reason_code))
            goto end;
        if (!X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rtmp, 0, 0))
            goto end;
    }

    if (rev && comp_time) {
        if (!X509_REVOKED_add1_ext_i2d
            (rev, NID_invalidity_date, comp_time, 0, 0))
            goto end;
    }
    if (rev && hold) {
        if (!X509_REVOKED_add1_ext_i2d
            (rev, NID_hold_instruction_code, hold, 0, 0))
            goto end;
    }

    if (reason_code != OCSP_REVOKED_STATUS_NOSTATUS)
        ret = 2;
    else
        ret = 1;

 end:

    OPENSSL_free(tmp);
    ASN1_OBJECT_free(hold);
    ASN1_GENERALIZEDTIME_free(comp_time);
    ASN1_ENUMERATED_free(rtmp);
    ASN1_TIME_free(revDate);

    return ret;
}

static int old_entry_print(const ASN1_OBJECT *obj, const ASN1_STRING *str)
{
    char buf[25], *pbuf;
    const char *p;
    int j;

    j = i2a_ASN1_OBJECT(bio_err, obj);
    pbuf = buf;
    for (j = 22 - j; j > 0; j--)
        *(pbuf++) = ' ';
    *(pbuf++) = ':';
    *(pbuf++) = '\0';
    BIO_puts(bio_err, buf);

    if (str->type == V_ASN1_PRINTABLESTRING)
        BIO_printf(bio_err, "PRINTABLE:'");
    else if (str->type == V_ASN1_T61STRING)
        BIO_printf(bio_err, "T61STRING:'");
    else if (str->type == V_ASN1_IA5STRING)
        BIO_printf(bio_err, "IA5STRING:'");
    else if (str->type == V_ASN1_UNIVERSALSTRING)
        BIO_printf(bio_err, "UNIVERSALSTRING:'");
    else
        BIO_printf(bio_err, "ASN.1 %2d:'", str->type);

    p = (const char *)str->data;
    for (j = str->length; j > 0; j--) {
        if ((*p >= ' ') && (*p <= '~'))
            BIO_printf(bio_err, "%c", *p);
        else if (*p & 0x80)
            BIO_printf(bio_err, "\\0x%02X", *p);
        else if ((unsigned char)*p == 0xf7)
            BIO_printf(bio_err, "^?");
        else
            BIO_printf(bio_err, "^%c", *p + '@');
        p++;
    }
    BIO_printf(bio_err, "'\n");
    return 1;
}


int GZPKI_do_QUERY(GZPKI_CTX *ctx, char *sql)
{
    
    int fields, cnt;

#ifdef __WITH_MYSQL__	
    mysql_set_character_set(&mysql,"utf8");
	if(!mysql_real_connect(&mysql, NULL, db_user, db_pwd, db_name, db_port, (char *)NULL, 0)) {
		printf("%s\n",mysql_error(&mysql));
        printf("DB: user=%s, pwd=%s, name=%s, port=%d\n", db_user, db_pwd, db_name, db_port);
		return CMS_RET_ERROR;
	}

	printf("GZPKI_do_SQL:sussecc to connect database\n") ;

    if(mysql_query(&mysql, sql)) {
        printf("error:%s\n", mysql_error(&mysql));
        return CMS_RET_ERROR;
    }
#elif defined(__WITH_SQLITE__)
    int rc = 0;
    char *errmsg = NULL;
    rc = sqlite3_exec(db, sql, NULL, 0, &errmsg);
    
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:init:sql:%s\n", errmsg);
        sqlite3_free(errmsg);  
        return CMS_RET_ERROR;
   	} 

    IF_VERBOSE fprintf(stderr, "gzpki: query exec successfully\n");

#endif


    return CMS_RET_OK;

}

int GZPKI_do_SQL(char *db_user, char *db_pwd, char *db_name, int db_port, char *sql)
{
#ifdef __WITH_MYSQL__

    
    MYSQL mysql ;
    int fields, cnt;
	mysql_init(&mysql) ;
    mysql_set_character_set(&mysql,"utf8");

	if(!mysql_real_connect(&mysql, NULL, db_user, db_pwd, db_name, db_port, (char *)NULL, 0)) {
		printf("%s\n",mysql_error(&mysql));
        printf("DB: user=%s, pwd=%s, name=%s, port=%d\n", db_user, db_pwd, db_name, db_port);
		return CMS_RET_ERROR;
	}

	printf("GZPKI_do_SQL:sussecc to connect database\n") ;

    if(mysql_query(&mysql, sql)) {
        printf("error:%s\n", mysql_error(&mysql));
        return CMS_RET_ERROR;
    }

	mysql_close(&mysql) ;
#elif defined(__WITH_SQLITE__)
    //TODO
#endif
    return CMS_RET_OK;

}


int GZPKI_fetch_count_SQL(char *db_user, char *db_pwd, char *db_name, int db_port, char *sql)
{
    int fields, cnt;
	
#ifdef __WITH_MYSQL__    
    MYSQL mysql ;
	MYSQL_RES *res;
	MYSQL_ROW row;
	
	mysql_init(&mysql) ;

	if(!mysql_real_connect(&mysql, NULL, db_user, db_pwd, db_name, db_port, (char *)NULL, 0)) {
		printf("%s\n",mysql_error(&mysql));
        printf("DB: user=%s, pwd=%s, name=%s, port=%d\n", db_user, "*****", db_name, db_port);
		return -1;
	}

	printf("GZPKI_fetch_count_SQL:connection ok\n") ;
    
    if(mysql_query(&mysql, sql)) {
        printf("error:%s\n", mysql_error(&mysql));
        return -2;
    }

    res = mysql_store_result(&mysql);
	fields = mysql_num_fields(res);
	printf("DEBUG:GZPKI_fetch_count_SQL:mysql_num_fields:%d\n", fields);

    row = mysql_fetch_row(res);
        
    printf("GZPKI_fetch_count_SQL: #data: %s\n", row[0]);

    cnt = atoi(row[0]);

    mysql_free_result(res);
	mysql_close(&mysql) ;
#elif defined(__WITH_SQLITE__)
    // TODO: SQLITE
#endif    
    return cnt;
}



//--------------------------------------------------
// key pass DB file generate.
// sqlite --> only for CA
//--------------------------------------------------
//#ifndef _NO_CA_

#include <sqlite3.h>

int GZPKI_gzcmm_database_init(char *file)
{
	sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int r = 0;

    rc = sqlite3_open(file, &db);
   	
    if( rc ) {
    	fprintf(stderr, "error: init gzcmm database %s: %s\n", file, sqlite3_errmsg(db));
      	return -1;
   	} 
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"Open/Create GZCMM database(%s) successfully.\n", file);
   	
	//const char *sql1 = "CREATE TABLE request ("  
    const char *sql1 = "CREATE TABLE reqdb ("  \
        "id      INTEGER    PRIMARY KEY   AUTOINCREMENT," \
        "status    CHAR(16)," \
        "username   CHAR(128)," \
        "deviceinfo CHAR(128)," \
        "type       CHAR(16)," \
        "caname     CHAR(64)," \
        "extension  CHAR(32)," \
        "cdate   DATETIME," \
        "mdate   DATETIME," \
        "UNIQUE(username, deviceinfo, status)  );";

    //const char *sql2 = "CREATE TABLE certificate (" 
    const char *sql2 = "CREATE TABLE certdb ("  \
        "id      INTEGER    PRIMARY KEY   AUTOINCREMENT," \
        "status       CHAR(1)," \
        "notafter   CHAR(32)," \
        "filename   CHAR(256)," \
        "dn         CHAR(256)," \
        "revoked_reason  CHAR(64)," \
        "revoked_date    CHAR(32)," \
        "serial     CHAR(32)," \
        "cdate      DATETIME," \
        "mdate      DATETIME," \
        "reqid      INTEGER," \
        "UNIQUE(dn, serial)  );";

    const char *sql3 = "CREATE TABLE crl ("  \
        "id      INTEGER    PRIMARY KEY   AUTOINCREMENT," \
        "status       CHAR(1)," \
        "notafter   CHAR(32)," \
        "filename   CHAR(256)," \
        "serial     CHAR(32)," \
        "cdate      DATETIME);";

    //REQUEST DB
	rc = sqlite3_exec(db, sql1, NULL, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:gzcmm:database:request:init:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  
        r = -1;	
        goto end;
   	} else {
    	fprintf(stderr, "request database table created successfully\n");
   	}

    //CERTIFICATE DB
    rc = sqlite3_exec(db, sql2, NULL, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:gzcmm:database:certificate:init:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  
        r = -1;	
        goto end;
   	} else {
    	fprintf(stderr, "certificate database table created successfully\n");
   	}

    rc = sqlite3_exec(db, sql3, NULL, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:gzcmm:database:crl:init:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  
        r = -1;	
        goto end;
   	} else {
    	fprintf(stderr, "crl database table created successfully\n");
   	}
    
end:
   	sqlite3_close(db);
	return r;
}

int get_request_userid(char *file, char *sql)
{
	sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int r = 0;
    //char sql[1024];
    char stat[32];
    int reqid = -1;

    rc = sqlite3_open(file, &db);
    if( rc ) {
    	fprintf(stderr, "error: init gzcmm database %s: %s\n", file, sqlite3_errmsg(db));
      	return -1;
   	} 
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,"error:%s:%d: fail to open database: %s\n", __FILE__, __LINE__, file);
        return -1;
    }
    rc = sqlite3_step(stmt);
    int rowCount = 0;
    int i = 0;

    while (rc != SQLITE_DONE && rc != SQLITE_OK) {
        rowCount++; 
        int colCount = sqlite3_column_count(stmt);
        
        for (int colIndex = 0; colIndex < colCount; colIndex++) {
            
            int type = sqlite3_column_type(stmt, colIndex);
            const char * columnName = sqlite3_column_name(stmt, colIndex);
            if (type == SQLITE_INTEGER)
            {
                if(0==strcmp(columnName, "id"))         
                    reqid = sqlite3_column_int(stmt, colIndex);
                    printf("columnName = %s, Integer val = %d", columnName, reqid);
            }    
            
        }
        rc = sqlite3_step(stmt);
    }

    rc = sqlite3_finalize(stmt);
    rc = sqlite3_close(db);

    
	return reqid;
}

int reqdb_status_comp(char *file, char *userid, char *stat_args)
{
	sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int r = 0;
    char sql[1024];
    char stat[32];

    rc = sqlite3_open(file, &db);
    if( rc ) {
    	fprintf(stderr, "error: init gzcmm database %s: %s\n", file, sqlite3_errmsg(db));
      	return -1;
   	} 
    
    fprintf(stderr, DEBUG_TAG"approval: file:%s opened successfully.\n", file);
    
    memset(sql, 0, 1024);
    sprintf(sql, "SELECT status FROM reqdb WHERE id=%s", userid);
    
    fprintf(stderr, DEBUG_TAG"query: %s\n", sql);
    
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,"error:reqdb_status_comp:fail to open database: %s\n", file);
        return -1;
    }
    rc = sqlite3_step(stmt);
    int rowCount = 0;
    int i = 0;

    while (rc != SQLITE_DONE && rc != SQLITE_OK) {
        rowCount++; 
        int colCount = sqlite3_column_count(stmt);
        
        for (int colIndex = 0; colIndex < colCount; colIndex++) {
            
            int type = sqlite3_column_type(stmt, colIndex);
            const char * columnName = sqlite3_column_name(stmt, colIndex);
            if (type == SQLITE_TEXT)
            {
                const unsigned char * valChar = NULL;
                valChar = sqlite3_column_text(stmt, colIndex);
                if(0==strcmp(columnName, "status")) {
                    memset(stat, 0, sizeof(stat));
                    sprintf(stat, "%s", valChar);
                }
            }
        }
        rc = sqlite3_step(stmt);
    }

    rc = sqlite3_finalize(stmt);
    rc = sqlite3_close(db);

    if(stat  && 0==strcmp(stat, stat_args)) {
        return 0;
    }

	return 1;
}

int reqdb_status_update(char *file, char *userid, char *status)
{
	sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int r = 0;
    char sql[1024];
    char stat[32];

    rc = sqlite3_open(file, &db);
    if( rc ) {
    	fprintf(stderr, "error: init gzcmm database %s: %s\n", file, sqlite3_errmsg(db));
      	return -1;
   	} 
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"approval?  %s opened successfully.\n", file);
    
    memset(sql, 0, 1024);
    sprintf(sql, "UPDATE reqdb SET status='%s' WHERE id=%s", REQ_STATUS_COMPLETED, userid);
    
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"query: %s\n", sql);
    
    rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  	
        sqlite3_close(db);
        return -1;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"keypass table export successfully\n");
   	}

    rc = sqlite3_close(db);

	return 0;
}
//#endif //_NO_CA_
