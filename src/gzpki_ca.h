# ifndef _GZPKI_CA_H_
# define _GZPKI_CA_H_


//index.txt를 대체 하는 버전으로 개선
#if 0
# ifdef __WITH_MYSQL__
    # include "mysql.h" 
# elif defined(__WITH_SQLITE__)
    #include <sqlite3.h>
# endif
#endif


#ifndef _NO_CA_
    #include "sqlite3.h"
    #include "gzpki_ca.h"
#endif

# include "gzpki_common.h"
# include "gzpki_types.h"


//--------------------------------------------------
//TODO: RENAME
//--------------------------------------------------
#ifndef W_OK
# define F_OK 0
# define W_OK 2
# define R_OK 4
#endif


#ifdef __WITH_MYSQL__
    MYSQL mysql; 
    MYSQL_RES *res;
    MYSQL_ROW row;
    #define  DB_CONN mysql
#elif defined(__WITH_SQLITE__)

    sqlite3 *db;
    //sqlite3_stmt *stmt = NULL;

    #define DB_CONN db
    //#define DB_STMT stmt
#endif

typedef struct ca_sqldb_st {
#ifdef __WITH_MYSQL__        
    MYSQL mysql ;
    MYSQL_RES *res;
    MYSQL_ROW row;
#elif defined(__WITH_SQLITE__)
    sqlite3 *db;
#endif
    char *user;
    char *passwd;
    char *dbname;
    char *host;
    int  port;
    int error;
    char *errstr;
} PKIDB_CTX;


#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

#define BASE_SECTION            "ca"

#define ENV_DEFAULT_CA          "default_ca"

#define STRING_MASK             "string_mask"
#define UTF8_IN                 "utf8"

#define ENV_NEW_CERTS_DIR       "new_certs_dir"
#define ENV_CERTIFICATE         "certificate"
#define ENV_SERIAL              "serial"
#define ENV_RAND_SERIAL         "rand_serial"
#define ENV_CRLNUMBER           "crlnumber"
#define ENV_PRIVATE_KEY         "private_key"
#define ENV_DEFAULT_DAYS        "default_days"
#define ENV_DEFAULT_STARTDATE   "default_startdate"
#define ENV_DEFAULT_ENDDATE     "default_enddate"
#define ENV_DEFAULT_CRL_DAYS    "default_crl_days"
#define ENV_DEFAULT_CRL_HOURS   "default_crl_hours"
#define ENV_DEFAULT_MD          "default_md"
#define ENV_DEFAULT_EMAIL_DN    "email_in_dn"
#define ENV_PRESERVE            "preserve"
#define ENV_POLICY              "policy"
#define ENV_EXTENSIONS          "x509_extensions"
#define ENV_CRLEXT              "crl_extensions"
#define ENV_MSIE_HACK           "msie_hack"
#define ENV_NAMEOPT             "name_opt"
#define ENV_CERTOPT             "cert_opt"
#define ENV_EXTCOPY             "copy_extensions"
#define ENV_UNIQUE_SUBJECT      "unique_subject"

#define ENV_DATABASE            "database"
#define ENV_DATABASE_SQLITE     "cmmdb"

#define ENV_PKI                 "pki"
#define ENV_PKI_CA_NAME         "ca_name"


#if 0
/* Additional revocation information types */
typedef enum {
    REV_VALID             = -1, /* Valid (not-revoked) status */
    REV_NONE              = 0, /* No additional information */
    REV_CRL_REASON        = 1, /* Value is CRL reason code */
    REV_HOLD              = 2, /* Value is hold instruction */
    REV_KEY_COMPROMISE    = 3, /* Value is cert key compromise time */
    REV_CA_COMPROMISE     = 4  /* Value is CA key compromise time */
} REVINFO_TYPE;
#endif

#define _UC(c) ((unsigned char)(c))



int gzpki_cadb_init(PKIDB_CTX *sql, char *host, char *user, char *file, char *passwd, char *db, int port);
int gzpki_cadb_free(PKIDB_CTX *sql);
int GZPKI_do_CA(GZPKI_CTX *ctx);


struct gzpki_capolicy_ctx_st {

    int use;
    char *home;

    char *policy_name;
    int policy_id;

    char *base_section;         //BASE_SECTION          "ca"
    char *default_ca;           //ENV_DEFAULT_CA        "default_ca" = CA_default'

    char *dir;
    char *certs;
    char *crl_dir;
    char *database;
    char *new_certs_dir;        //ENV_NEW_CERTS_DIR     "new_certs_dir"
    char *certificate;          //ENV_CERTIFICATE       "certificate"
    char *private_key;          //ENV_PRIVATE_KEY       "private_key"
    char *randfile;
    //char *unique_subject;
        
    int  default_days;         //ENV_DEFAULT_DAYS      "default_days"
    int  default_crl_days;     //ENV_DEFAULT_CRL_DAYS  "default_crl_days"
    int  default_crl_hours;    //ENV_DEFAULT_CRL_HOURS "default_crl_hours"

    int   default_ca_id;        //CA 이름 INT 버전
    
    char *default_startdate;    //ENV_DEFAULT_STARTDATE "default_startdate"
    char *default_enddate;      //ENV_DEFAULT_ENDDATE   "default_enddate"
    char *default_md;           //ENV_DEFAULT_MD        "default_md"
    char *default_email_in_dn;  //ENV_DEFAULT_EMAIL_DN  "email_in_dn"
    char *preserve;             //ENV_PRESERVE          "preserve"
    
    //policy_section
    char *policy;               //ENV_POLICY            "policy"
    char *countryName;          //match, optional, supplied
    char *stateOrProvinceName;
    char *localityName;
    char *organizationName;
    char *organizationalUnitName;
    char *commonName;
    char *emailAddress;

    //인증서 확장 필드
    char *x509_extensions;          //ex) "usr_cert"
    char *basicConstraints;
    char *keyUsage;                 //ex) nonRepudiation, digitalSignature, keyEncipherment
                                    //ex) cRLSign, keyCertSign
    char *nsCertType;               //ex) client, email, objsign
                                    //ex) sslCA, emailCA
    char *nsComment;
    char *subjectKeyIdentifier;     //ex) hash
    char *authorityKeyIdentifier;   //ex) keyid,issuer:always
    char *subjectAltName;           //ex) email:copy
    char *issuerAltName;            //ex) issuer:copy
    char *nsCaRevocationUrl;        //ex) http://www.domain.dom/ca-crl.pem
    char *nsBaseUrl;
    char *nsRevocationUrl;
    char *nsRenewalUrl;
    char *nsCaPolicyUrl;
    char *nsSslServerName;

    //CRL 확장 필드
    char *crl_extensions;       //section name
    char *crl_issuerAltName;
    char *crl_authorityKeyIdentifier;

    char *string_mask;          //STRING_MASK           "string_mask"
    char *utf8_in;              //UTF8_IN               "utf8"
    
    char *serial;               //ENV_SERIAL            "serial"
    char *rand_serial;          //ENV_RAND_SERIAL       "rand_serial"
    char *crl_number;           //ENV_CRLNUMBER         "crlnumber"
    
    char *extensions;           //ENV_EXTENSIONS        "x509_extensions"
    char *crlext;               //ENV_CRLEXT            "crl_extensions"
    char *msie_hack;            //ENV_MSIE_HACK         "msie_hack"
    char *name_opt;             //ENV_NAMEOPT           "name_opt"
    char *cert_opt;             //ENV_CERTOPT           "cert_opt"
    char copy_extensions;       //ENV_EXTCOPY           "copy_extensions"
    char *unique_subject;       //ENV_UNIQUE_SUBJECT    "unique_subject"

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

typedef struct gzpki_capolicy_ctx_st GZPKI_POLICY;


int GZPKI_set_sqldb(GZPKI_CTX *ctx, char *db_ip, int db_port, char *db_user, char *db_name, char *db_pwd);
//int GZPKI_do_SQL(GZPKI_CTX *ctx, char *sql);
int GZPKI_do_SQL(char *db_user, char *db_pwd, char *db_name, int db_port, char *sql);
//SQL에 해당하는 결과 갯수를 반환환다
int GZPKI_fetch_count_SQL(char *db_user, char *db_pwd, char *db_name, int db_port, char *sql);


#define DEFAULT_CANAME          "gzpkica"
#define DEFAULT_CADIR           "/usr/local/gzcmm/ca/"
#define DEFAULT_CAKEY_DIR       "key"
#define DEFAULT_CAKEY_FILE      "ca.key"
#define DEFAULT_CACERT_DIR      DEFAULT_CADIR
#define DEFAULT_CACERT_FILE     "ca.pem"

int is_valid_crl_reason(char *rev_arg) ;


#endif /* _GZPKI_CA_H_ */
