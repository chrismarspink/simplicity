
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
# include <openssl/pem.h>

# include <sys/ioctl.h>
# include <sys/utsname.h>
# include <sys/time.h>
# include <sys/socket.h>
# include <sys/wait.h>
# include <net/if.h>
# include <arpa/inet.h>
# include <netinet/in.h>

# include "gzpki_types.h"
# include "gzpki_common.h"
# include "gzpki_ecc.h"
# include "gzpki_req.h"

static CONF *req_conf = NULL;
static CONF *addext_conf = NULL;
static int batch = 1;

#define SECTION             "req"
#define BITS                "default_bits"
#define KEYFILE             "default_keyfile"
#define PROMPT              "prompt"
#define DISTINGUISHED_NAME  "distinguished_name"
#define ATTRIBUTES          "attributes"
#define V3_EXTENSIONS       "x509_extensions"
#define REQ_EXTENSIONS      "req_extensions"
#define STRING_MASK         "string_mask"
#define UTF8_IN             "utf8"
#define DEFAULT_KEY_LENGTH  2048
#define MIN_KEY_LENGTH      512

#define RASERVER_IP     "127.0.0.1"
#define RASERVER_PORT   10072

#if 1
    #define REQ_ATTR_UNKNOWN        0
    #define REQ_ATTR_CHAP           1
    #define REQ_ATTR_UNSNAME        2
    #define REQ_ATTR_CONTENT_TYPE   3
#endif

#if 0
    static const char *REQ_ATTR_UNKNOWN_S      = "unknownAttribute";
    static const char *REQ_ATTR_CHAP_S         = "challengePassword";
    static const char *REQ_ATTR_UNSNAME_S      = "unstructuredName";
    static const char *REQ_ATTR_CONTENT_TYPE_S = "contentType";

    static const char *REQ_TYPE_NEW    = "new";
    static const char *REQ_TYPE_RENEW  = "renew";
    static const char *REQ_TYPE_UPDATE = "update";
    static const char *REQ_TYPE_REVOKE = "revoke";
    static const char *REQ_TYPE_DELETE = "delete";
    static const char *REQ_TYPE_GETCERT = "get-cert";
    static const char *REQ_TYPE_GETCRL = "get-crl";
    static const char *REQ_TYPE_GETCA = "get-ca";

    static const char *REQ_CERT_TYPE_CLIENT = "client";
    static const char *REQ_CERT_TYPE_SERVER = "server";
    static const char *REQ_CERT_TYPE_MANAGER = "manager";
    static const char *REQ_CERT_TYPE_SELFSIGNED = "selfsigned";

    static const char *REQ_STATUS_PENDING    = "pending";
    static const char *REQ_STATUS_APPROVAL   = "approval";
    static const char *REQ_STATUS_REJECTED   = "rejected";
    static const char *REQ_STATUS_COMPLETED  = "completed";
    static const char *REQ_STATUS_ISSUED  = "issued";
    static const char *REQ_STATUS_ERROR  = "error";
#endif

int GZPKI_do_REQ(GZPKI_CTX *ctx);
int do_X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);
int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);


static void exts_cleanup(OPENSSL_STRING *x);
static int build_subject(X509_REQ *req, const char *subject, unsigned long chtype, int multirdn);
static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, char *subj, int multirdn, int attribs, unsigned long chtype, char* rs);
static int prompt_info(X509_REQ *req, STACK_OF(CONF_VALUE) *dn_sk, const char *dn_sect, STACK_OF(CONF_VALUE) *attr_sk, const char *attr_sect, int attribs, unsigned long chtype);
static int auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *dn_sk, STACK_OF(CONF_VALUE) *attr_sk, int attribs, unsigned long chtype);
static int gzpki_auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *attr_sk, int attribs, unsigned long chtype);
static int add_attribute_object(X509_REQ *req, char *text, const char *def, char *value, int nid, int n_min, int n_max, unsigned long chtype);
static int build_data(char *text, const char *def, char *value, int n_min, int n_max, char *buf, const int buf_size, const char *desc1, const char *desc2);
static int add_DN_object(X509_NAME *n, char *text, const char *def, char *value, int nid, int n_min, int n_max, unsigned long chtype, int mval);
static int req_check_len(int len, int n_min, int n_max);
static int check_end(const char *str, const char *end);
static int join(char buf[], size_t buf_size, const char *name, const char *tail, const char *desc);
static int genpkey_cb(EVP_PKEY_CTX *ctx);
static EVP_PKEY_CTX *set_keygen_ctx(const char *gstr, int *pkey_type, long *pkeylen, char **palgnam, ENGINE *keygen_engine);

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai); //apps

void exts_cleanup(OPENSSL_STRING *x) {
    OPENSSL_free((char *)x);
}

static int build_subject(X509_REQ *req, const char *subject, unsigned long chtype, int multirdn) {
    X509_NAME *n;
    if ((n = (X509_NAME *)parse_name(subject, chtype, multirdn)) == NULL)
        return 0;
    if (!X509_REQ_set_subject_name(req, n)) {
        X509_NAME_free(n);
        return 0;
    }
    X509_NAME_free(n);
    return 1;
}


int client_socket;
struct sockaddr_in server_addr;

int init_raserver(GZPKI_CTX *ctx) {
	memset( &server_addr, 0, sizeof( server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons( ctx->ra_port);
	server_addr.sin_addr.s_addr= inet_addr( ctx->ra_ip);  // server IP address 
	
	client_socket = socket( PF_INET, SOCK_STREAM, 0);
	if( -1 == client_socket) {
   		fprintf(stderr, "error:%d:%s\n", errno, strerror(errno));
   		exit(1);
	}

	if( -1 == connect( client_socket, (struct sockaddr*)&server_addr, sizeof( server_addr))) {
      fprintf(stderr, color_red_b"error"color_reset":connection:%s:%d\n", ctx->ra_ip, ctx->ra_port);
      exit( 1);
   	} else {
		fprintf(stderr, "success:connect:%s:%d\n", ctx->ra_ip, ctx->ra_port);
	}
	
	return CMS_RET_OK;
}

static int net_send = 1;

int send_message2server(GZPKI_CTX *ctx) {

	int total = 0;
	#define  MAX_MESSAGE 8192
	char buffer[MAX_MESSAGE];
    char reqdata[MAX_MESSAGE];
	char recv_buf[MAX_MESSAGE*4];

    BIO *in = NULL;
    
    in = bio_open_default(ctx->infile, 'r', FORMAT_PEM);
    if (in == NULL) {
        sprintf(ctx->errstr, "error:fail to open:%s", ctx->infile);
        ctx->errcode = -1;
        return CMS_RET_ERROR;
    }

    if(!BIO_read(in, reqdata, sizeof(reqdata))) {
        sprintf(ctx->errstr, "error:fail to request data from: %s", ctx->infile);
        ctx->errcode = -2;
        return CMS_RET_ERROR;
    }

    char *msg =  &reqdata[0];
	if(net_send == 1) {
		memset(buffer, 0, MAX_MESSAGE);
		write(client_socket, msg, strlen(msg));
        total = recv(client_socket,buffer,sizeof(buffer),0);

		if(total <=0) {
			close(client_socket);
            sprintf(ctx->errstr, "error:recv:pid=%d,total=%d", getpid(), total);
            ctx->errcode = -3;
			exit(0);
		}
		strncpy( recv_buf, buffer, total); 
		recv_buf[total -1] = 0;
		IF_VERBOSE fprintf(stderr, "info:received(%d bytes): ["color_yellow_b"%s"color_reset"]\n", total, recv_buf);
	}
	return total;
}



int GZPKI_send_REQ(GZPKI_CTX *ctx) {
    int r = CMS_RET_UNDEF;
    r = init_raserver(ctx);
    r = send_message2server(ctx);
    close(client_socket);

    return CMS_RET_OK;
}



int GZPKI_do_REQ(GZPKI_CTX *ctx ) {
    ASN1_INTEGER *serial = NULL;
    
    ENGINE *e = NULL, *gen_eng = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *genctx = NULL;
    STACK_OF(OPENSSL_STRING) *pkeyopts = NULL, *sigopts = NULL;
    LHASH_OF(OPENSSL_STRING) *addexts = NULL;
    X509 *x509ss = NULL;

    X509_REQ *req = NULL;
    //modified by jkkim
    //X509_REQ *req = ctx->req;

    const EVP_CIPHER *cipher = NULL;
    const EVP_MD *md_alg = NULL, *digest = NULL;
    BIO *addext_bio = NULL;
    char *extensions = NULL, *infile = NULL;
    char *outfile = NULL, *keyfile = NULL;
    char *keyalgstr = NULL, *p, *prog, *passargin = NULL, *passargout = NULL;
    char *passin = NULL, *passout = NULL;
    char *nofree_passin = NULL, *nofree_passout = NULL;
    char *req_exts = NULL, *subj = NULL;
    char *template = NULL; //default_config_file;
    char *keyout = NULL;
    const char *keyalg = NULL;
    char *req_section = NULL;
    
    int ret = 1, x509 = 0, days = 0, i = 0, newreq = 0, verbose = 0;
    int pkey_type = -1, private = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyform = FORMAT_PEM;
    int modulus = 0, multirdn = 0, verify = 0, noout = 0, text = 0;
    int nodes = 0, newhdr = 0, pubkey = 0, precert = 0;
    
    //jkkim@added
    int subject = 0;
    long newkey = -1;
    
    unsigned long chtype = MBSTRING_UTF8;
    unsigned long reqflag = 0;
    int batch = 1; 

    BIO *in = NULL;
    BIO *out = NULL;

    int  opt_get_field_all = ctx->opt_get_field_all;
        
    verify =  ctx->opt_req_verify;

    cipher = ctx->cipher;
    informat = ctx->informat;
    outformat = ctx->outformat;
    keyfile = ctx->keyfile;
    pubkey = ctx->pubkey;
    newreq = ctx->newreq;
    keyform = ctx->keyform;

    infile = ctx->infile;
    outfile = ctx->outfile;

    keyout = ctx->keyoutfile;
    
    //passargin -> passinarg으로 변경
    //passargout -> passoutarg으로 변경
    passargin = ctx->passargin;
    passargout = ctx->passargout;

    keyalg = ctx->keyalg;
    batch = ctx->batch;
    newhdr = ctx->newhdr;
    noout = ctx->noout;
    
    modulus = ctx->modulus;
    verbose = ctx->verbose;
    chtype = ctx->chtype; //MBSTRING_UTF8;
       
    digest = ctx->sign_md;
    text = ctx->text;
    x509 = ctx->x509;
    days = ctx->days;

    if(ctx->req_section) {
        req_section = ctx->req_section;
    }
    else
    {
        req_section = GZPKI_strdup(SECTION); // gzpki_req.c: #define SECTION "req"
    }

    if(ctx->inserial)
        serial = s2i_ASN1_INTEGER(NULL, ctx->inserial); //ctx->serial is char*

    subject = ctx->subject_out;
    subj = ctx->subj;
    multirdn = ctx->multirdn;
    extensions = ctx->extensions;
    req_exts = ctx->req_exts;
    precert = ctx->precert;

    template = ctx->default_config_file; //

    //jkkim@add
    pkey = ctx->key;

    char *CONFIG_BUFF = NULL; 

    char *errtmp = NULL;

    unsigned long opt_req_nameopt =  ctx->opt_req_nameopt;

    set_nameopt_v(ctx->opt_nameopt);


#if 0
        
    //[req]
    str_append(&CONFIG_BUFF,"[req]\n");
    if(ctx->default_bits)               str_append(&CONFIG_BUFF,"default_bits = %s\n", ctx->default_bits);
    if(ctx->default_keyfile)            str_append(&CONFIG_BUFF,"default_keyfile = %s\n", ctx->default_keyfile);
    if(ctx->distinguished_name)         str_append(&CONFIG_BUFF,"distinguished_name = %s\n", ctx->distinguished_name);
    if(ctx->req_extensions)             str_append(&CONFIG_BUFF,"req_extensions = %s\n", ctx->req_extensions);
    if(ctx->x509_extensions)            str_append(&CONFIG_BUFF,"x509_extensions = %s\n", ctx->x509_extensions);
    if(ctx->string_mask)                str_append(&CONFIG_BUFF,"string_mask = %s\n", ctx->string_mask);
    if(1)                               str_append(&CONFIG_BUFF,"utf8 = yes\n");
    if(ctx->default_md)                 str_append(&CONFIG_BUFF,"default_md = %s\n", ctx->default_md);

    #define REQ_SECT_ATTR     "req_attributes"
    str_append(&CONFIG_BUFF,"attributes = %s\n",REQ_SECT_ATTR );

    //TODO
    str_append(&CONFIG_BUFF,"policy = policy_name\n");
    
    //[subject]
    str_append(&CONFIG_BUFF,"[%s]\n", ctx->distinguished_name);
    /*
    if(ctx->countryName)                  str_append(&CONFIG_BUFF,"countryName = %s\n", ctx->countryName);
    if(ctx->countryName_default)          str_append(&CONFIG_BUFF,"countryName_default = %s\n", ctx->countryName_default);
    if(ctx->stateOrProvinceName)          str_append(&CONFIG_BUFF,"stateOrProvinceName = %s\n", ctx->stateOrProvinceName);
    if(ctx->stateOrProvinceName_default)  str_append(&CONFIG_BUFF,"stateOrProvinceName_default = %s\n", ctx->stateOrProvinceName_default);
    if(ctx->localityName)                 str_append(&CONFIG_BUFF,"localityName = %s\n", ctx->localityName);
    if(ctx->localityName_default)         str_append(&CONFIG_BUFF,"localityName_default = %s\n", ctx->localityName_default);
    if(ctx->organizationName)             str_append(&CONFIG_BUFF,"organizationName = %s\n", ctx->organizationName);
    if(ctx->organizationName_default)     str_append(&CONFIG_BUFF,"organizationName_default = %s\n", ctx->organizationName_default);
    if(ctx->organizationUnitName)         str_append(&CONFIG_BUFF,"organizationalUnitName	 = %s\n", ctx->organizationUnitName);
    if(ctx->organizationUnitName_default) str_append(&CONFIG_BUFF,"organizationalUnitName_default = %s\n", ctx->organizationUnitName_default);
    if(ctx->commonName)                   str_append(&CONFIG_BUFF,"commonName = %s\n", ctx->commonName);
    if(ctx->commonName_default)           str_append(&CONFIG_BUFF,"commonName_default = %s\n", ctx->commonName_default);
    if(ctx->emailAddress)                 str_append(&CONFIG_BUFF,"emailAddress = %s\n", ctx->emailAddress);
    if(ctx->emailAddress_default)         str_append(&CONFIG_BUFF,"emailAddress_default = %s\n", ctx->emailAddress_default);
    */

    if(ctx->countryName)                  str_append(&CONFIG_BUFF,"C  = %s\n", ctx->countryName);
    if(ctx->stateOrProvinceName)          str_append(&CONFIG_BUFF,"ST = %s\n", ctx->stateOrProvinceName);
    if(ctx->localityName)                 str_append(&CONFIG_BUFF,"L = %s\n", ctx->localityName);
    if(ctx->organizationName)             str_append(&CONFIG_BUFF,"O = %s\n", ctx->organizationName);
    if(ctx->organizationUnitName)         str_append(&CONFIG_BUFF,"OU = %s\n", ctx->organizationUnitName);
    if(ctx->commonName)                   str_append(&CONFIG_BUFF,"CN = %s\n", ctx->commonName);
    if(ctx->emailAddress)                 str_append(&CONFIG_BUFF,"emailAddress = %s\n", ctx->emailAddress);

    /*
    //[x509_extensions]
    str_append(&CONFIG_BUFF,"[%s]\n", ctx->x509_extensions);
    if(ctx->subjectKeyIdentifier)       str_append(&CONFIG_BUFF,"subjectKeyIdentifier = %s\n", ctx->subjectKeyIdentifier);
    if(ctx->authorityKeyIdentifier)     str_append(&CONFIG_BUFF,"authorityKeyIdentifier = %s\n", ctx->authorityKeyIdentifier);
    if(ctx->basicConstraints)           str_append(&CONFIG_BUFF,"basicConstraints = %s\n", ctx->basicConstraints);
    if(ctx->keyUsage)                   str_append(&CONFIG_BUFF,"keyUsage = %s\n", ctx->keyUsage);

    if(ctx->DNS1)
        if(ctx->subjectAltName)         str_append(&CONFIG_BUFF,"subjectAltName = %s\n", ctx->subjectAltName);

    if(ctx->nsComment)                  str_append(&CONFIG_BUFF,"nsComment = %s\n", ctx->nsComment);
    if(ctx->extendedKeyUsage)           str_append(&CONFIG_BUFF,"extendedKeyUsage = %s\n", ctx->extendedKeyUsage);
    
    //[req_attributes]    
    str_append(&CONFIG_BUFF,"[%s]\n",REQ_SECT_ATTR );
    if(ctx->challengePassword )         str_append(&CONFIG_BUFF,"challengePassword  = %s\n", ctx->challengePassword );
    if(ctx->challengePassword_default ) str_append(&CONFIG_BUFF,"challengePassword_default  = %s\n", ctx->challengePassword_default );

    if(ctx->contentType )               str_append(&CONFIG_BUFF,"contentType  = %s\n", ctx->contentType );
    if(ctx->contentType_default )       str_append(&CONFIG_BUFF,"contentType_default  = %s\n", ctx->contentType_default );

    if(ctx->unstructuredName )          str_append(&CONFIG_BUFF,"unstructuredName  = %s\n", ctx->unstructuredName );
    if(ctx->unstructuredName_default )  str_append(&CONFIG_BUFF,"unstructuredName_default  = %s\n", ctx->unstructuredName_default );

    //[req_extensions]
    str_append(&CONFIG_BUFF,"[%s]\n", ctx->req_extensions);
    if(ctx->subjectKeyIdentifier)       str_append(&CONFIG_BUFF,"subjectKeyIdentifier = %s\n", ctx->subjectKeyIdentifier);
    if(ctx->basicConstraints)           str_append(&CONFIG_BUFF,"basicConstraints = %s\n", ctx->basicConstraints);
    if(ctx->keyUsage)                   str_append(&CONFIG_BUFF,"keyUsage = %s\n", ctx->keyUsage);

    if(ctx->DNS1)
        if(ctx->subjectAltName)         str_append(&CONFIG_BUFF,"subjectAltName = %s\n", ctx->subjectAltName);

    if(ctx->nsComment)                  str_append(&CONFIG_BUFF,"nsComment = %s\n", ctx->nsComment);
    if(ctx->extendedKeyUsage)           str_append(&CONFIG_BUFF,"extendedKeyUsage = %s\n", ctx->extendedKeyUsage);

    str_append(&CONFIG_BUFF,"[policy_name]\n");
    str_append(&CONFIG_BUFF,"stateOrProvinceName = optional\n");
    str_append(&CONFIG_BUFF,"localityName = optional\n");
    str_append(&CONFIG_BUFF,"organizationName = optional\n");
    str_append(&CONFIG_BUFF,"organizationalUnitName = optional\n");
    str_append(&CONFIG_BUFF,"commonName = optional\n");
    str_append(&CONFIG_BUFF,"emailAddress = optional\n");
    */
    
    //ctx->req_conf_str = GZPKI_strdup(CONFIG_BUFF);
    ctx->req_conf_str = CONFIG_BUFF;

    //NAMEOPT, CERTOPT를 외부에서 설정?

    //DO NOT DELETE
    printf("%s\n", ctx->req_conf_str);
#endif 

    
    memset(ctx->errstr, 0, sizeof(ctx->errstr));
    ctx->errcode = CMS_RET_OK;
    
    if (days && !x509) {
        sprintf(ctx->errstr, "Ignoring [days] option; not generating a certificate");
    }
    if (x509 && infile == NULL) {
        newreq = 1;
    }

    /* TODO: simplify this as pkey is still always NULL here */
    private = newreq && (pkey == NULL) ? 1 : 0;
 
    if (verbose) {
        sprintf(ctx->errstr, "Using configuration from %s", template);
    }
    
    //==================================================
    //CHECK: app_config 우선 
    //==================================================
#if 1   
    if(ctx->req_conf_str) {
        req_conf = gzpki_load_config(ctx->req_conf_str);
        fprintf(stderr, "load req config from buffer: "color_yellow_b"CONFIG_BUFFER"color_reset"\n");
    }
    else if(ctx->app_config ) {
        req_conf = app_load_config(ctx->app_config);
        fprintf(stderr, "load req config from app config: "color_yellow_b"%s"color_reset"\n", ctx->app_config);
    }
    

    if (addext_bio) {
        if (verbose)
            BIO_printf(bio_err, "Using additional configuration from command line\n");

        addext_conf = app_load_config_bio(addext_bio, NULL);
    }
    if (template != default_config_file && !app_load_modules(req_conf)) {
        ctx->errcode = -1;
        goto end;
    }

    if (req_conf != NULL) {
        p = NCONF_get_string(req_conf, NULL, "oid_file");
        if (p == NULL)
            ERR_clear_error();
        if (p != NULL) {
            BIO *oid_bio;

            oid_bio = BIO_new_file(p, "r");
            if (oid_bio == NULL) {
                /*-
                BIO_printf(bio_err,"problems opening %s for extra oid's\n",p);
                ERR_print_errors(bio_err);
                */
            } else {
                OBJ_create_objects(oid_bio);
                BIO_free(oid_bio);
            }
        }
    }
    if (!add_oid_section(req_conf)) {
        ctx->errcode = -2;
        goto end;
    }
#endif

    //--------------------------------------------------
    //digest알고리즘: GZPKI_set_sign_md()
    //--------------------------------------------------
#if 1 //REMOVE CONFIG
    if (md_alg == NULL) {
        p = NCONF_get_string(req_conf, SECTION, "default_md");
        if (p == NULL) {
            ERR_clear_error();
        } else {
            digest = md_alg =  (EVP_MD *)EVP_get_digestbyname(p);
        }
    }
#endif    

#if 1 //REMOVE CONFIG
    if (extensions == NULL) {
        //extensions = NCONF_get_string(req_conf, SECTION, V3_EXTENSIONS);
        extensions = NCONF_get_string(req_conf, req_section, V3_EXTENSIONS);
        if (extensions == NULL) {
            ctx->errcode = -3;
            ERR_clear_error();
        }
    }
#endif    
    if (extensions != NULL) {
        /* Check syntax of file */
        X509V3_CTX x509ctx; //ctx ==> x509ctx
        X509V3_set_ctx_test(&x509ctx);
        X509V3_set_nconf(&x509ctx, req_conf);
        if (!X509V3_EXT_add_nconf(req_conf, &x509ctx, extensions, NULL)) {
            BIO_printf(bio_err, "Error Loading extension section %s\n", extensions);
            printf("error:load():extension:%s\n", extensions);
            ctx->errcode = -4;
            goto end;
        }
    }
    if (addext_conf != NULL) {
        /* Check syntax of command line extensions */
        X509V3_CTX x509ctx;
        X509V3_set_ctx_test(&x509ctx);
        X509V3_set_nconf(&x509ctx, addext_conf);
        if (!X509V3_EXT_add_nconf(addext_conf, &x509ctx, "default", NULL)) {
            BIO_printf(bio_err, "Error Loading command line extensions\n");
            ctx->errcode = -5;
            goto end;
        }
    }

    if (passin == NULL) {
        //passin = nofree_passin = NCONF_get_string(req_conf, SECTION, "input_password");
        passin = nofree_passin = NCONF_get_string(req_conf, req_section, "input_password");
        if (passin == NULL) 
            ERR_clear_error();
    }

#if 1    
    if (passout == NULL) {
        //passout = nofree_passout = NCONF_get_string(req_conf, SECTION, "output_password");
        passout = nofree_passout = NCONF_get_string(req_conf, req_section, "output_password");
        if (passout == NULL)
            ERR_clear_error();
    }
    //p = NCONF_get_string(req_conf, SECTION, STRING_MASK);
    p = NCONF_get_string(req_conf, req_section, STRING_MASK);
#else
    if(ctx->passout)
        passout = nofree_passout = ctx->passout;
    
    if (passout == NULL)
            ERR_clear_error();

    p = ctx->string_mask;
#endif
    
    if (p == NULL)
        ERR_clear_error();

    if (p != NULL && !ASN1_STRING_set_default_mask_asc(p)) {
        BIO_printf(bio_err, "Invalid global string mask setting %s\n", p);
        ctx->errcode = -6;
        goto end;
    }

    if (chtype != MBSTRING_UTF8) {
#if 1        
        //p = NCONF_get_string(req_conf, SECTION, UTF8_IN);
        p = NCONF_get_string(req_conf, req_section, UTF8_IN);
#else
        p = ctx->utf8;
#endif        
        if (p == NULL)
            ERR_clear_error();
        else if (strcmp(p, "yes") == 0)
            chtype = MBSTRING_UTF8;
    }

    //무조건 UTF8로 설정한다.,
    chtype = MBSTRING_UTF8;

    if (req_exts == NULL) {
        //req_exts = NCONF_get_string(req_conf, SECTION, REQ_EXTENSIONS);
        req_exts = NCONF_get_string(req_conf, req_section, REQ_EXTENSIONS);
        if (req_exts == NULL)
            ERR_clear_error();
    }
    IF_VERBOSE fprintf(stderr, "REQ(request extension) section: %s\n", req_exts);

    if (req_exts != NULL) {
        /* Check syntax of file */
        X509V3_CTX x509ctx;
        X509V3_set_ctx_test(&x509ctx);
        X509V3_set_nconf(&x509ctx, req_conf);
        if (!X509V3_EXT_add_nconf(req_conf, &x509ctx, req_exts, NULL)) {
            BIO_printf(bio_err, "Error Loading request extension section %s\n", req_exts);
            ctx->errcode = -7;
            goto end;
        }
    }

    //--------------------------------------------------
    // NOTICE
    // - GZPKI_set_keyfile()로 사전에 pkey를 생성할 수 있다
    // - pkey = ctx->key
    // - 이 경우 아래와 같이 다시 로드하면 안됨
    //--------------------------------------------------
    //if (keyfile != NULL) {
    if (keyfile != NULL && pkey==NULL) {
        pkey = load_key(keyfile, keyform, 0, passin, e, "Private Key");
        if (pkey == NULL) {
            /* load_key() has already printed an appropriate message */
            ctx->errcode = -8;
            goto end;
        } else {
            //app_RAND_load_conf(req_conf, SECTION);
            app_RAND_load_conf(req_conf, req_section);
        }
    }

    if (newreq && (pkey == NULL)) {
        //app_RAND_load_conf(req_conf, SECTION);
        app_RAND_load_conf(req_conf, req_section);

        //if (!NCONF_get_number(req_conf, SECTION, BITS, &newkey)) {
        if (!NCONF_get_number(req_conf, req_section, BITS, &newkey)) {
            newkey = DEFAULT_KEY_LENGTH;
        }

        if (keyalg != NULL) {
            genctx = set_keygen_ctx(keyalg, &pkey_type, &newkey, &keyalgstr, gen_eng);
            if (genctx == NULL) {
                ctx->errcode = -9;
                goto end;
            }
        }

        if (newkey < MIN_KEY_LENGTH && (pkey_type == EVP_PKEY_RSA || pkey_type == EVP_PKEY_DSA)) {
            BIO_printf(bio_err, "private key length is too short,\n");
            BIO_printf(bio_err, "it needs to be at least %d bits, not %ld\n", MIN_KEY_LENGTH, newkey);
            ctx->errcode = -10;
            goto end;
        }

        if (pkey_type == EVP_PKEY_RSA && newkey > OPENSSL_RSA_MAX_MODULUS_BITS)
            BIO_printf(bio_err, "Warning: It is not recommended to use more than %d bit for RSA keys.\n"
                       "         Your key size is %ld! Larger key size may behave not as expected.\n",
                       OPENSSL_RSA_MAX_MODULUS_BITS, newkey);

#ifndef OPENSSL_NO_DSA
        if (pkey_type == EVP_PKEY_DSA && newkey > OPENSSL_DSA_MAX_MODULUS_BITS)
            BIO_printf(bio_err,
                       "Warning: It is not recommended to use more than %d bit for DSA keys.\n"
                       "         Your key size is %ld! Larger key size may behave not as expected.\n",
                       OPENSSL_DSA_MAX_MODULUS_BITS, newkey);
#endif

        if (genctx == NULL) {
            genctx = set_keygen_ctx(NULL, &pkey_type, &newkey, &keyalgstr, gen_eng);
            if (!genctx) {
                ctx->errcode = -11;
                goto end;
            }
        }

        if (pkeyopts != NULL) {
            char *genopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(pkeyopts); i++) {
                genopt = sk_OPENSSL_STRING_value(pkeyopts, i);
                if (pkey_ctrl_string(genctx, genopt) <= 0) {
                    IF_VERBOSE fprintf(stderr, "parameter error \"%s\"\n", genopt);
                    ERR_print_errors(bio_err);
                    ctx->errcode = -12;
                    goto end;
                }
            }
        }

        if (pkey_type == EVP_PKEY_EC) {
            BIO_printf(bio_err, "Generating an EC private key\n");
        } else {
            BIO_printf(bio_err, "Generating a %s private key\n", keyalgstr);
        }

        EVP_PKEY_CTX_set_cb(genctx, genpkey_cb);
        EVP_PKEY_CTX_set_app_data(genctx, bio_err);

        if (EVP_PKEY_keygen(genctx, &pkey) <= 0) {
            BIO_puts(bio_err, "Error Generating Key\n");
            sprintf(ctx->errstr, "%s", "error:generate private key.");
            ctx->errcode = -13;
            goto end;
        }

        EVP_PKEY_CTX_free(genctx);
        genctx = NULL;

        if (keyout == NULL) {
            //keyout = NCONF_get_string(req_conf, SECTION, KEYFILE);
            keyout = NCONF_get_string(req_conf, req_section, KEYFILE);
            if (keyout == NULL)
                ERR_clear_error();
        }

        if (keyout == NULL)
            BIO_printf(bio_err, "writing new private key to stdout\n");
        else
            BIO_printf(bio_err, "writing new private key to '%s'\n", keyout);

        out = bio_open_owner(keyout, outformat, private);
        if (out == NULL)
            goto end;

        //p = NCONF_get_string(req_conf, SECTION, "encrypt_rsa_key");
        p = NCONF_get_string(req_conf, req_section, "encrypt_rsa_key");
        if (p == NULL) {
            ERR_clear_error();
            //p = NCONF_get_string(req_conf, SECTION, "encrypt_key");
            p = NCONF_get_string(req_conf, req_section, "encrypt_key");
            if (p == NULL)
                ERR_clear_error();
        }
        if ((p != NULL) && (strcmp(p, "no") == 0))
            cipher = NULL;
        if (nodes)
            cipher = NULL;

        i = 0;
 loop:
        assert(private);
        if (!PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, passout)) {
            if ((ERR_GET_REASON(ERR_peek_error()) == PEM_R_PROBLEMS_GETTING_PASSWORD) && (i < 3)) {
                ERR_clear_error();
                i++;
                goto loop;
            }
            goto end;
        }
        BIO_free(out);
        out = NULL;
        BIO_printf(bio_err, "-----\n");
    }



    if (!newreq) {
        if(infile == NULL)
            in = ctx->in;
        else
            in = bio_open_default(infile, 'r', informat);
            
        if (in == NULL) {
            ctx->errcode = -14;
            goto end;
        }

        if (informat == FORMAT_ASN1)
            req = d2i_X509_REQ_bio(in, NULL);
        else
            req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
        if (req == NULL) {
            BIO_printf(bio_err, "unable to load X509 request\n");
            ctx->errcode = -15;
            goto end;
        }
    }

    //==================================================
    //REQUEST GENERATION
    //==================================================
    if (newreq || x509) {
        if (pkey == NULL) {
            BIO_printf(bio_err, "you need to specify a private key\n");
            ctx->errcode = -16;
            goto end;
        }

        if (req == NULL) {
            req = X509_REQ_new();
            if (req == NULL) {
                ctx->errcode = -17;
                goto end;
            }

            i = make_REQ(req, pkey, subj, multirdn, !x509, chtype, req_section);
            subj = NULL; /* done processing '-subj' option */
            if (!i) {
                BIO_printf(bio_err, "problems making Certificate Request\n");
                ctx->errcode = -18;
                goto end;
            }
        }

        if (x509) {
            EVP_PKEY *tmppkey;
            X509V3_CTX ext_ctx;
            if ((x509ss = X509_new()) == NULL)
                ctx->errcode = -19;
                goto end;

            /* Set version to V3 */
            if ((extensions != NULL || addext_conf != NULL) && !X509_set_version(x509ss, 2)) {
                ctx->errcode = -20;
                goto end;
            }
            if (serial != NULL) {
                if (!X509_set_serialNumber(x509ss, serial)) {
                    ctx->errcode = -21;
                    goto end;
                }
            } else {
                if (!rand_serial(NULL, X509_get_serialNumber(x509ss))) {
                    ctx->errcode = -22;
                    goto end;
                }
            }

            if (!X509_set_issuer_name(x509ss, X509_REQ_get_subject_name(req))) {
                ctx->errcode = -23;
                goto end;
            }
            if (days == 0) {
                /* set default days if it's not specified */
                days = 30;
            }
            if (!set_cert_times(x509ss, NULL, NULL, days)) {
                ctx->errcode = -25;
                goto end;
            }
            
            if (!X509_set_subject_name (x509ss, X509_REQ_get_subject_name(req))) {
                ctx->errcode = -26;
                goto end;
            }
            tmppkey = X509_REQ_get0_pubkey(req);
            if (!tmppkey || !X509_set_pubkey(x509ss, tmppkey)) {
                ctx->errcode = -27;
                goto end;
            }

            /* Set up V3 context struct */

            X509V3_set_ctx(&ext_ctx, x509ss, x509ss, NULL, NULL, 0);
            X509V3_set_nconf(&ext_ctx, req_conf);

            /* Add extensions */
            if (extensions != NULL && !X509V3_EXT_add_nconf(req_conf, &ext_ctx, extensions, x509ss)) {
                BIO_printf(bio_err, "Error Loading extension section %s\n", extensions);
                ctx->errcode = -28;
                goto end;
            }
            if (addext_conf != NULL && !X509V3_EXT_add_nconf(addext_conf, &ext_ctx, "default", x509ss)) {
                BIO_printf(bio_err, "Error Loading command line extensions\n");
                ctx->errcode = -29;
                goto end;
            }

            /* If a pre-cert was requested, we need to add a poison extension */
            if (precert) {
                if (X509_add1_ext_i2d(x509ss, NID_ct_precert_poison, NULL, 1, 0) != 1) {
                    BIO_printf(bio_err, "Error adding poison extension\n");
                    ctx->errcode = -30;
                    goto end;
                }
            }

            i = do_X509_sign(x509ss, pkey, digest, sigopts);
            if (!i) {
                ERR_print_errors(bio_err);
                ctx->errcode = -31;
                goto end;
            }
        } else {
            X509V3_CTX ext_ctx;

            /* Set up V3 context struct */

            X509V3_set_ctx(&ext_ctx, NULL, NULL, req, NULL, 0);
            X509V3_set_nconf(&ext_ctx, req_conf);

            /* Add extensions */
            if (req_exts != NULL
                && !X509V3_EXT_REQ_add_nconf(req_conf, &ext_ctx, req_exts, req)) {
                BIO_printf(bio_err, "Error Loading extension section %s\n", req_exts);
                ctx->errcode = -32;
                goto end;
            }
            if (addext_conf != NULL && !X509V3_EXT_REQ_add_nconf(addext_conf, &ext_ctx, "default", req)) {
                BIO_printf(bio_err, "Error Loading command line extensions\n");
                ctx->errcode = -33;
                goto end;
            }
            i = do_X509_REQ_sign(req, pkey, digest, sigopts);
            if (!i) {
                ERR_print_errors(bio_err);
                ctx->errcode = -34;
                goto end;
            }
        }
    }

    if (subj && x509) {
        BIO_printf(bio_err, "Cannot modify certificate subject\n");
        ctx->errcode = -35;
        goto end;
    }

    if (subj && !x509) {
        if (verbose) {
            BIO_printf(bio_err, "Modifying Request's Subject\n");
            print_name(bio_err, "old subject=", X509_REQ_get_subject_name(req), get_nameopt());
        }

        if (build_subject(req, subj, chtype, multirdn) == 0) {
            BIO_printf(bio_err, "ERROR: cannot modify subject\n");
            ret = 1;
            ctx->errcode = -36;
            goto end;
        }

        if (verbose) {
            print_name(bio_err, "new subject=", X509_REQ_get_subject_name(req), get_nameopt());
        }
    }

    if (verify && !x509) {
        EVP_PKEY *tpubkey = pkey;

        if (tpubkey == NULL) {
            tpubkey = X509_REQ_get0_pubkey(req);
            if (tpubkey == NULL) {
                ctx->errcode = -37;
                goto end;
            }
        }

        i = X509_REQ_verify(req, tpubkey);

        if (i < 0) {
            ctx->req_verify_result = CMS_VERIFY_FAIL;
            goto end;
        } else if (i == 0) {
            ctx->req_verify_result = CMS_VERIFY_FAIL;
            BIO_printf(bio_err, "verify failure\n");
            ERR_print_errors(bio_err);
        } else {                 /* if (i > 0) */
            ctx->req_verify_result = CMS_VERIFY_OK;
            BIO_printf(bio_err, "verify OK\n");
        }
    }

    if (noout && !text && !modulus && !subject && !pubkey) {
        ret = 0;
        goto end;
        ctx->errcode = -38;
    }

#if 1
    out = ctx->out;
#else    
    out = bio_open_default(outfile, keyout != NULL && outfile != NULL && strcmp(keyout, outfile) == 0 ? 'a' : 'w', outformat);
#endif    
    if (out == NULL) {
        ctx->errcode = -39;
        goto end;
    }

    if (pubkey) {
        EVP_PKEY *tpubkey = X509_REQ_get0_pubkey(req);

        if (tpubkey == NULL) {
            BIO_printf(bio_err, "Error getting public key\n");
            ERR_print_errors(bio_err);
            ctx->errcode = -40;
            goto end;
        }
        PEM_write_bio_PUBKEY(out, tpubkey);
    }

    if (text) {
        BIO *tmpbio = BIO_new(BIO_s_mem());
        BUF_MEM *bptr = NULL;

        if (x509) {
            X509_print_ex(out, x509ss, get_nameopt(), reqflag);
        }
        else {
            X509_REQ_print_ex(out, req, get_nameopt(), reqflag);
            //jkkim@ADD
            //--------------------------------------------------
            //basic req field
            //get 
            //(1) keybits ==> "Public-Key: (521 bit)"
            //(2) if ecdsa
            //    "ANS1 OID: secp521r1"
            //    "NIST CURVE: P-521"
            //(3) "Signature Algorithm: ecdsa-with-SHA256"
            //--------------------------------------------------
            if(opt_get_field_all == 1) {
                X509_REQ_print_ex(tmpbio, req, get_nameopt(), reqflag);
                BIO_get_mem_ptr( tmpbio, &bptr); 
            }
        }
    }

    //--------------------------------------------------
    //basic req field
    //--------------------------------------------------
    long reqVersion;
    X509_NAME *req_dn = NULL;
    char *req_subject_str = NULL;
    X509_PUBKEY *xpkey;
    ASN1_OBJECT *koid;
    char *pubkey_alg_name = NULL;
    
    if (opt_get_field_all && req) {
        
        BIO *tmpbio = BIO_new(BIO_s_mem());
        BUF_MEM *bptr = NULL;

        BIO *tmpbio2 = BIO_new(BIO_s_mem());
        BUF_MEM *bptr2 = NULL;

        IF_VERBOSE fprintf(stderr, "info:parse REQ fields...\n");
        
        reqVersion = X509_REQ_get_version(req);
        IF_VERBOSE fprintf(stderr, "info:REQ VERSION: ["color_yellow_b"%ld"color_reset"]\n", reqVersion + 1);
        
        ctx->reqVersion = reqVersion + 1;

#if 0
        req_dn = X509_REQ_get_subject_name(req);
        req_subject_str = GZPKI_strdup(X509_NAME_oneline(X509_REQ_get_subject_name(req), 0, 0));
#else 
        ctx->reqSubjectDN = print_name_str(X509_REQ_get_subject_name(req), get_nameopt());
        IF_VERBOSE fprintf(stderr, "info:REQ SUBJECT: ["color_yellow_b"%s"color_reset"]\n", ctx->reqSubjectDN);
#endif
       
        xpkey = X509_REQ_get_X509_PUBKEY(req);
        X509_PUBKEY_get0_param(&koid, NULL, NULL, NULL, xpkey);
        if (i2a_ASN1_OBJECT(tmpbio, koid) <= 0) {
            goto end;
        } 
        
        BIO_get_mem_ptr( tmpbio, &bptr); 
       
        ctx->reqAlgorithmName = GZPKI_strdup(bptr->data);
        ctx->reqAlgorithmName[bptr->length] = 0;
        
        IF_VERBOSE fprintf(stderr, "info:REQ PUBKEY ALGORITHM: ["color_yellow_b"%s"color_reset"]\n", ctx->reqAlgorithmName );

        pkey = X509_REQ_get0_pubkey(req);
        if (pkey == NULL) {
            //ctx->reqErrstr = GZPKI_strdup("fail to load public key");
            //ERR_print_errors(tmpbio);
            GZPKI_print_errors(ctx);
        } else {
            if (EVP_PKEY_print_public(tmpbio, pkey, 16, NULL) <= 0)
                goto end;
        }
    }

    char STR_CN[128] = {0,};
    char STR_EMAIL[128] = {0,};

    //--------------------------------------------------
    //attributes : opt_get_field_all
    //--------------------------------------------------
    if (opt_get_field_all && req) {
        
        int attr_cnt = 0;
        int attr_type = REQ_ATTR_UNKNOWN;

        attr_cnt = X509_REQ_get_attr_count(req);

        printf("#ATTR: ["ANSI_COLOR_YELLOW_BOLD"%d"ANSI_COLOR_RESET"]\n", attr_cnt);

    
        for (i = 0; i < attr_cnt; i++) {
            ASN1_TYPE *at;
            X509_ATTRIBUTE *a;
            ASN1_BIT_STRING *bs = NULL;
            ASN1_OBJECT *aobj;
            int j, type = 0, count = 1, ii = 0;
            char *attrName = NULL;

            BIO *tmpbio = BIO_new(BIO_s_mem());
            BUF_MEM *bptr = NULL;

            BIO *tmpbio1 = BIO_new(BIO_s_mem());
            BUF_MEM *bptr1 = NULL;

            a = X509_REQ_get_attr(req, i);
            aobj = X509_ATTRIBUTE_get0_object(a);
            if (X509_REQ_extension_nid(OBJ_obj2nid(aobj)))
                continue;
                
            if ((j = i2a_ASN1_OBJECT(tmpbio1, aobj)) > 0) {
                ii = 0;
                char *tmp;
                BIO_get_mem_ptr( tmpbio1, &bptr1); 
                if(bptr1->data) {
                    tmp = GZPKI_strdup(bptr1->data) ;
                    tmp[bptr1->length] = 0;
                }
                printf("ATTR_NAME: ["ANSI_COLOR_BLUE_BOLD"%s"ANSI_COLOR_RESET"], size=%ld\n", tmp, bptr1->length);

                if(!strcmp(tmp, REQ_ATTR_CHAP_S))  {
                    attr_type = REQ_ATTR_CHAP;
                } else if(!strcmp(tmp, REQ_ATTR_UNSNAME_S))  {
                    attr_type = REQ_ATTR_UNSNAME;
                } else if(!strcmp(tmp, REQ_ATTR_CONTENT_TYPE_S)) {
                    attr_type = REQ_ATTR_CONTENT_TYPE;
                } else {
                    attr_type = REQ_ATTR_UNKNOWN;
                }

                printf("attr_type = [%d]\n", attr_type);

                count = X509_ATTRIBUTE_count(a);

get_next:
                at = X509_ATTRIBUTE_get0_type(a, ii);
                type = at->type;
                bs = at->value.asn1_string;
            }

            switch (type) {
                case V_ASN1_PRINTABLESTRING:
                case V_ASN1_T61STRING:
                case V_ASN1_NUMERICSTRING:
                case V_ASN1_UTF8STRING:
                case V_ASN1_IA5STRING:

                if (BIO_write(tmpbio, (char *)bs->data, bs->length) != bs->length)
                    goto end;

                if (BIO_puts(tmpbio, "\n") <= 0)
                    goto end;

                BIO_get_mem_ptr( tmpbio, &bptr); 
                
                if(attr_type == REQ_ATTR_CHAP)  {
                    ctx->reqChallengePassword = GZPKI_strdup(bptr->data);
                    ctx->reqChallengePassword[bptr->length-1] = 0;
                    printf("GET challengePassword: [%s]\n", ctx->reqChallengePassword);
                } else if(attr_type == REQ_ATTR_UNSNAME)  {
                    ctx->reqUnstructuredName = GZPKI_strdup(bptr->data);
                    ctx->reqUnstructuredName[bptr->length-1] = 0;

                    IF_VERBOSE fprintf(stderr, "GET reqUnstructuredName ["ANSI_COLOR_RED_BOLD"%s"ANSI_COLOR_RESET"], size=%ld\n", ctx->reqUnstructuredName, bptr->length);
                } else if(attr_type == REQ_ATTR_CONTENT_TYPE) {
                    char *tmp = NULL, *ptr = NULL;
                    tmp = GZPKI_strdup(bptr->data);
                    tmp[bptr->length-1] = 0;

                    printf("GET tmp  ["ANSI_COLOR_RED_BOLD"%s"ANSI_COLOR_RESET"]\n", tmp);

                    ptr = strtok(tmp, ",");
                    printf("GET ptr1 ["ANSI_COLOR_RED_BOLD"%s"ANSI_COLOR_RESET"]\n", ptr);
                    if(ptr) {
                        ctx->reqContentType = GZPKI_strdup(ptr);
                        printf("GET reqContentType1 ["ANSI_COLOR_RED_BOLD"%s"ANSI_COLOR_RESET"]\n", ctx->reqContentType);
                        printf("GET ptr2 ["ANSI_COLOR_RED_BOLD"%s"ANSI_COLOR_RESET"]\n", ptr);
                        ptr = strtok(NULL, ",");
                        printf("GET ptr3 ["ANSI_COLOR_RED_BOLD"%s"ANSI_COLOR_RESET"]\n", ptr);
                        ctx->reqRole = GZPKI_strdup(ptr);
                    }
                        
                    printf("GET reqContentType ["ANSI_COLOR_RED_BOLD"%s"ANSI_COLOR_RESET"]\n", ctx->reqContentType);
                    printf("GET reqRole        ["ANSI_COLOR_RED_BOLD"%s"ANSI_COLOR_RESET"]\n", ctx->reqRole);
                        
                } else {
                    attr_type = REQ_ATTR_UNKNOWN;
                }
                break;
            default:
                if (BIO_puts(tmpbio, "unable to print attribute\n") <= 0)
                    goto end;
                break;
            }
            if (++ii < count)
                goto get_next;
        }
    }
        
    if (subject) {
        if (x509)
            print_name(out, "subject=", X509_get_subject_name(x509ss), get_nameopt());
        else
            print_name(out, "subject=", X509_REQ_get_subject_name(req), get_nameopt());
    }

    if (modulus) {
        EVP_PKEY *tpubkey;

        if (x509)
            tpubkey = X509_get0_pubkey(x509ss);
        else
            tpubkey = X509_REQ_get0_pubkey(req);
        if (tpubkey == NULL) {
            fprintf(stdout, "Modulus=unavailable\n");
            ctx->errcode = -41;
            goto end;
        }
        fprintf(stdout, "Modulus=");
#ifndef OPENSSL_NO_RSA
        if (EVP_PKEY_base_id(tpubkey) == EVP_PKEY_RSA) {
            const BIGNUM *n;
            RSA_get0_key(EVP_PKEY_get0_RSA(tpubkey), &n, NULL, NULL);
            BN_print(out, n);
        } else
#endif
        fprintf(stdout, "Wrong Algorithm type");
        fprintf(stdout, "\n");
    }

    if (!noout && !x509) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_REQ_bio(out, req);
        else if (newhdr)
            i = PEM_write_bio_X509_REQ_NEW(out, req);
        else
            i = PEM_write_bio_X509_REQ(out, req);
        if (!i) {
            BIO_printf(bio_err, "unable to write X509 request\n");
            ctx->errcode = -42;
            goto end;
        }
    }
    if (!noout && x509 && (x509ss != NULL)) {
        if (outformat == FORMAT_ASN1)
            i = i2d_X509_bio(out, x509ss);
        else
            i = PEM_write_bio_X509(out, x509ss);
        if (!i) {
            BIO_printf(bio_err, "unable to write X509 certificate\n");
            ctx->errcode = -43;
            goto end;
        }
    }
    ret = CMS_RET_OK;

    BIO_flush(out);

    return ret;
 
 end:
    BIO_flush(out);
    if (ret) {
        ERR_print_errors(bio_err);
    }
    /*NCONF_free(req_conf);
    NCONF_free(addext_conf);
    BIO_free(addext_bio);
    BIO_free(in);
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(genctx);
    sk_OPENSSL_STRING_free(pkeyopts);
    sk_OPENSSL_STRING_free(sigopts);
    lh_OPENSSL_STRING_doall(addexts, exts_cleanup);
    lh_OPENSSL_STRING_free(addexts);
#ifndef OPENSSL_NO_ENGINE
    //ENGINE_free(gen_eng);
#endif
    OPENSSL_free(keyalgstr);
    X509_REQ_free(req);
    X509_free(x509ss);
    ASN1_INTEGER_free(serial);
    //check: release_engine(e);
    if (passin != nofree_passin)
        OPENSSL_free(passin);
    if (passout != nofree_passout)
        OPENSSL_free(passout); */

    //return ret;
    return ctx->errcode;
}


static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, char *subj, int multirdn, int attribs, unsigned long chtype, char *req_section) {
    int ret = 0, i;
    char no_prompt = 0;
    STACK_OF(CONF_VALUE) *dn_sk, *attr_sk = NULL;
    char *tmp, *dn_sect, *attr_sect;

    //tmp = NCONF_get_string(req_conf, SECTION, PROMPT);
    tmp = NCONF_get_string(req_conf, req_section, PROMPT);

    if (tmp == NULL)
        ERR_clear_error();
    if ((tmp != NULL) && strcmp(tmp, "no") == 0)
        no_prompt = 1;

    no_prompt = 1;
    //dn_sect = NCONF_get_string(req_conf, SECTION, DISTINGUISHED_NAME);
    dn_sect = NCONF_get_string(req_conf, req_section, DISTINGUISHED_NAME);

    //IF_VERBOSE fprintf(stderr, "debug:make_REQ():dn_sect:%s, SECTION=%s, DISTINGUISHED_NAME=%s\n", dn_sect, SECTION, DISTINGUISHED_NAME);
    IF_VERBOSE fprintf(stderr, "debug:make_REQ():dn_sect:%s, SECTION=%s, DISTINGUISHED_NAME=%s\n", dn_sect, req_section, DISTINGUISHED_NAME);

    if (dn_sect == NULL) {
        IF_VERBOSE fprintf(stderr, ERR_TAG"unable to find DN config - "color_yellow_b"%s"color_reset"\n", DISTINGUISHED_NAME);
        goto err;
    }

    dn_sk = NCONF_get_section(req_conf, dn_sect);
    if (dn_sk == NULL) {
        IF_VERBOSE fprintf(stderr, ERR_TAG"unable to get '%s' section\n", dn_sect);
        goto err;
    }

    //attr_sect = NCONF_get_string(req_conf, SECTION, ATTRIBUTES);
    attr_sect = NCONF_get_string(req_conf, req_section, ATTRIBUTES);
    printf("debug:make_REQ():attr_sect:%s\n", attr_sect);
    if (attr_sect == NULL) {
        ERR_clear_error();
        attr_sk = NULL;
        printf("attr_sk = NULL!\n");
    } else {
        attr_sk = NCONF_get_section(req_conf, attr_sect);
        if (attr_sk == NULL) {
            BIO_printf(bio_err, "unable to get '%s' section\n", attr_sect);
            goto err;
        }
    }

    /* setup version number */
    if (!X509_REQ_set_version(req, 0L))
        goto err; /* version 1 */

    if (subj) {
        X509_NAME *n;
        CONF_VALUE *v;
        if ((n = (X509_NAME *)parse_name(subj, chtype, multirdn)) == NULL)
            return 0;
        if (!X509_REQ_set_subject_name(req, n)) {
            X509_NAME_free(n);
            return 0;
        }
        X509_NAME_free(n);
        int cnt = 0;
        cnt = sk_CONF_VALUE_num(attr_sk);
                           printf("CNT: %d\n", cnt);

        if (attribs) {
            for (i = 0; i < cnt; i++)
            {
                v = sk_CONF_VALUE_value(attr_sk, i);
                printf("info: v/name/value: [%s], [%s]\n", v->name, (char *)v->value);
            #if 1
                X509_REQ_add1_attr_by_txt(req, v->name, chtype, (unsigned char *)v->value, -1);
            #else
                if (!X509_REQ_add1_attr_by_txt(req, v->name, chtype, (unsigned char *)v->value, -1))
                {
                    printf("error: v/name/value: [%s], [%s]\n", v->name, (char *)v->value);

                    i = 0;
                    goto err;
                }
            #endif
            }
        }
    }
    else if (no_prompt) {
        i = auto_info(req, dn_sk, attr_sk, attribs, chtype);
        IF_VERBOSE fprintf(stderr, "debug:make_request():auto_info():i=[%d]\n",  i);
    }
    else {
        i = prompt_info(req, dn_sk, dn_sect, attr_sk, attr_sect, attribs, chtype);
        IF_VERBOSE fprintf(stderr, "debug:make_request():prompt_info():i=[%d]\n",  i);
    }
    if (!i)
        goto err;

    if (!X509_REQ_set_pubkey(req, pkey))
        goto err;

    ret = 1;
 err:
    return ret;
}

static int prompt_info(X509_REQ *req,
                       STACK_OF(CONF_VALUE) *dn_sk, const char *dn_sect,
                       STACK_OF(CONF_VALUE) *attr_sk, const char *attr_sect,
                       int attribs, unsigned long chtype)
{
    int i;
    char *p, *q;
    char buf[100];
    int nid, mval;
    long n_min, n_max;
    char *type, *value;
    const char *def;
    CONF_VALUE *v;
    X509_NAME *subj;
    subj = X509_REQ_get_subject_name(req);

    if (!batch) {
        //BIO_printf(bio_err, "You are about to be asked to enter information that will be incorporated\n");
        //BIO_printf(bio_err, "into your certificate request.\n");
        //BIO_printf(bio_err, "What you are about to enter is what is called a Distinguished Name or a DN.\n");
        //BIO_printf(bio_err, "There are quite a few fields but you can leave some blank\n");
        //BIO_printf(bio_err, "For some fields there will be a default value,\n");
        //BIO_printf(bio_err, "If you enter '.', the field will be left blank.\n");
        //BIO_printf(bio_err, "-----\n");
    }

    if (sk_CONF_VALUE_num(dn_sk)) {
        i = -1;
 start:
        for ( ; ; ) {
            i++;
            if (sk_CONF_VALUE_num(dn_sk) <= i)
                break;

            v = sk_CONF_VALUE_value(dn_sk, i);
            p = q = NULL;
            type = v->name;
            if (!check_end(type, "_min") || !check_end(type, "_max") ||
                !check_end(type, "_default") || !check_end(type, "_value"))
                continue;
            /*
             * Skip past any leading X. X: X, etc to allow for multiple
             * instances
             */
            for (p = v->name; *p; p++)
                if ((*p == ':') || (*p == ',') || (*p == '.')) {
                    p++;
                    if (*p)
                        type = p;
                    break;
                }
            if (*type == '+') {
                mval = -1;
                type++;
            } else {
                mval = 0;
            }
            /* If OBJ not recognised ignore it */
            if ((nid = OBJ_txt2nid(type)) == NID_undef)
                goto start;
            if (!join(buf, sizeof(buf), v->name, "_default", "Name"))
                return 0;
            if ((def = NCONF_get_string(req_conf, dn_sect, buf)) == NULL) {
                ERR_clear_error();
                def = "";
            }

            if (!join(buf, sizeof(buf), v->name, "_value", "Name"))
                return 0;
            if ((value = NCONF_get_string(req_conf, dn_sect, buf)) == NULL) {
                ERR_clear_error();
                value = NULL;
            }

            if (!join(buf, sizeof(buf), v->name, "_min", "Name"))
                return 0;
            if (!NCONF_get_number(req_conf, dn_sect, buf, &n_min)) {
                ERR_clear_error();
                n_min = -1;
            }


            if (!join(buf, sizeof(buf), v->name, "_max", "Name"))
                return 0;
            if (!NCONF_get_number(req_conf, dn_sect, buf, &n_max)) {
                ERR_clear_error();
                n_max = -1;
            }

            if (!add_DN_object(subj, v->value, def, value, nid, n_min, n_max, chtype, mval))
                return 0;
        }
        if (X509_NAME_entry_count(subj) == 0) {
            BIO_printf(bio_err, "error, no objects specified in config file\n");
            return 0;
        }

        if (attribs) {
            if ((attr_sk != NULL) && (sk_CONF_VALUE_num(attr_sk) > 0) && (!batch)) {
                BIO_printf(bio_err, "\nPlease enter the following 'extra' attributes\n");
                BIO_printf(bio_err, "to be sent with your certificate request\n");
            }

            i = -1;
 start2:
            for ( ; ; ) {
                i++;
                if ((attr_sk == NULL) || (sk_CONF_VALUE_num(attr_sk) <= i))
                    break;

                v = sk_CONF_VALUE_value(attr_sk, i);
                type = v->name;
                if ((nid = OBJ_txt2nid(type)) == NID_undef)
                    goto start2;

                if (!join(buf, sizeof(buf), type, "_default", "Name"))
                    return 0;
                if ((def = NCONF_get_string(req_conf, attr_sect, buf)) == NULL) {
                    ERR_clear_error();
                    def = "";
                }

                if (!join(buf, sizeof(buf), type, "_value", "Name"))
                    return 0;
                if ((value = NCONF_get_string(req_conf, attr_sect, buf)) == NULL) {
                    ERR_clear_error();
                    value = NULL;
                }

                if (!join(buf, sizeof(buf), type,"_min", "Name"))
                    return 0;
                if (!NCONF_get_number(req_conf, attr_sect, buf, &n_min)) {
                    ERR_clear_error();
                    n_min = -1;
                }

                if (!join(buf, sizeof(buf), type, "_max", "Name"))
                    return 0;
                if (!NCONF_get_number(req_conf, attr_sect, buf, &n_max)) {
                    ERR_clear_error();
                    n_max = -1;
                }

                if (!add_attribute_object(req, v->value, def, value, nid, n_min, n_max, chtype))
                    return 0;
            }
        }
    } else {
        BIO_printf(bio_err, "No template, please set one up.\n");
        return 0;
    }

    return 1;

}


static int gzpki_auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *attr_sk, int attribs, unsigned long chtype)
{
    int i, spec_char, plus_char;
    char *p, *q;
    char *type;
    CONF_VALUE *v;

    X509_NAME *subj;
    subj = X509_REQ_get_subject_name(req);

    int cnt = X509_NAME_entry_count(subj);
    if (!cnt) {
        fprintf(stderr, "error: no name objects specified in config file\n");
        return 0;
    }

    if (attribs) {
        for (i = 0; i < sk_CONF_VALUE_num(attr_sk); i++) {
            v = sk_CONF_VALUE_value(attr_sk, i);
            IF_VERBOSE fprintf(stderr, "info:name=[%s], value=[%s]\n", v->name, (char *)v->value);
#if 1
            if (!X509_REQ_add1_attr_by_txt(req, v->name, chtype, (unsigned char *)v->value, -1)) {
                IF_VERBOSE fprintf(stderr, ERR_TAG"name=[%s], value=[%s]\n", v->name, (char *)v->value);
                return 0;
            }
#endif
        }
    }
    return 1;
}



static int auto_info(X509_REQ *req, STACK_OF(CONF_VALUE) *dn_sk,
                     STACK_OF(CONF_VALUE) *attr_sk, int attribs,
                     unsigned long chtype)
{
    int i, spec_char, plus_char;
    char *p, *q, *type;
    CONF_VALUE *v;
    X509_NAME *subj;

    subj = X509_REQ_get_subject_name(req);

    for (i = 0; i < sk_CONF_VALUE_num(dn_sk); i++) {
        int mval;
        v = sk_CONF_VALUE_value(dn_sk, i);
        p = q = NULL;
        type = v->name;
        /*
         * Skip past any leading X. X: X, etc to allow for multiple instances
         */
        for (p = v->name; *p; p++) {
#ifndef CHARSET_EBCDIC
            spec_char = ((*p == ':') || (*p == ',') || (*p == '.'));
#else
            spec_char = ((*p == os_toascii[':']) || (*p == os_toascii[','])
                    || (*p == os_toascii['.']));
#endif
            if (spec_char) {
                p++;
                if (*p)
                    type = p;
                break;
            }
        }
#ifndef CHARSET_EBCDIC
        plus_char = (*type == '+');
#else
        plus_char = (*type == os_toascii['+']);
#endif
        if (plus_char) {
            type++;
            mval = -1;
        } else {
            mval = 0;
        }

#if 1
        X509_NAME_add_entry_by_txt(subj, type, chtype, (unsigned char *)v->value, -1, -1, mval);
#else
        if (!X509_NAME_add_entry_by_txt(subj, type, chtype, (unsigned char *)v->value, -1, -1, mval)) 
            return 0;
#endif
    }

    if (!X509_NAME_entry_count(subj)) {
        BIO_printf(bio_err, "error, no objects specified in config file\n");
        return 0;
    }
    int r=0;
    if (attribs) {
        for (i = 0; i < sk_CONF_VALUE_num(attr_sk); i++) {
            v = sk_CONF_VALUE_value(attr_sk, i);
            r = X509_REQ_add1_attr_by_txt(req, v->name, chtype, (unsigned char *)v->value, -1);
            IF_VERBOSE fprintf(stderr, "debug:auto_info:name=[%s], value=[%s]\n", v->name, (char *)v->value);
            if (!r) {
                printf("error: auto_info: r = %d\n", r);
                //return 0;
            }
        }
    }
    return 1;
}



static int build_data(char *text, const char *def, char *value, int n_min, int n_max, char *buf, const int buf_size, const char *desc1, const char *desc2)
{
    int i;
start:
    if (!batch)
        BIO_printf(bio_err, "%s [%s]:", text, def);
    (void)BIO_flush(bio_err);
    if (value != NULL) {
        if (!join(buf, buf_size, value, "\n", desc1))
            return 0;
        BIO_printf(bio_err, "%s\n", value);
    } else {
        buf[0] = '\0';
        if (!batch) {
            if (!fgets(buf, buf_size, stdin))
                return 0;
        } else {
            buf[0] = '\n';
            buf[1] = '\0';
        }
    }

    if (buf[0] == '\0')
        return 0;
    if (buf[0] == '\n') {
        if ((def == NULL) || (def[0] == '\0'))
            return 1;
        if (!join(buf, buf_size, def, "\n", desc2))
            return 0;
    } else if ((buf[0] == '.') && (buf[1] == '\n')) {
        return 1;
    }

    i = strlen(buf);
    if (buf[i - 1] != '\n') {
        BIO_printf(bio_err, "weird input :-(\n");
        return 0;
    }
    buf[--i] = '\0';
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(buf, buf, i);
#endif
    if (!req_check_len(i, n_min, n_max)) {
        if (batch || value)
            return 0;
        goto start;
    }
    return 2;
}

static int add_attribute_object(X509_REQ *req, char *text, const char *def,
                                char *value, int nid, int n_min,
                                int n_max, unsigned long chtype)
{
    int ret = 0;
    char buf[1024];

    ret = build_data(text, def, value, n_min, n_max, buf, sizeof(buf), "Attribute value", "Attribute default");
    if ((ret == 0) || (ret == 1))
        return ret;
    ret = 1;

    if (!X509_REQ_add1_attr_by_NID(req, nid, chtype, (unsigned char *)buf, -1)) {
        BIO_printf(bio_err, "Error adding attribute\n");
        ERR_print_errors(bio_err);
        ret = 0;
    }

    return ret;
}



static int req_check_len(int len, int n_min, int n_max)
{
    if ((n_min > 0) && (len < n_min)) {
        BIO_printf(bio_err,
                   "string is too short, it needs to be at least %d bytes long\n",
                   n_min);
        return 0;
    }
    if ((n_max >= 0) && (len > n_max)) {
        BIO_printf(bio_err,
                   "string is too long, it needs to be no more than %d bytes long\n",
                   n_max);
        return 0;
    }
    return 1;
}

/* Check if the end of a string matches 'end' */
static int check_end(const char *str, const char *end)
{
    size_t elen, slen;
    const char *tmp;

    elen = strlen(end);
    slen = strlen(str);
    if (elen > slen)
        return 1;
    tmp = str + slen - elen;
    return strcmp(tmp, end);
}

static int add_DN_object(X509_NAME *n, char *text, const char *def,
                         char *value, int nid, int n_min, int n_max,
                         unsigned long chtype, int mval)
{
    int ret = 0;
    char buf[1024];

    ret = build_data(text, def, value, n_min, n_max, buf, sizeof(buf), "DN value", "DN default");
    if ((ret == 0) || (ret == 1))
        return ret;
    ret = 1;

    if (!X509_NAME_add_entry_by_NID(n, nid, chtype, (unsigned char *)buf, -1, -1, mval))
        ret = 0;

    return ret;
}


/*
 * Merge the two strings together into the result buffer checking for
 * overflow and producing an error message if there is.
 */
static int join(char buf[], size_t buf_size, const char *name, const char *tail, const char *desc)  {
    const size_t name_len = strlen(name), tail_len = strlen(tail);

    if (name_len + tail_len + 1 > buf_size) {
        BIO_printf(bio_err, "%s '%s' too long\n", desc, name);
        return 0;
    }
    memcpy(buf, name, name_len);
    memcpy(buf + name_len, tail, tail_len + 1);
    return 1;
}




static EVP_PKEY_CTX *set_keygen_ctx(const char *gstr,
                                    int *pkey_type, long *pkeylen,
                                    char **palgnam, ENGINE *keygen_engine)
{
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *param = NULL;
    long keylen = -1;
    BIO *pbio = NULL;
    const char *paramfile = NULL;

    if (gstr == NULL) {
        *pkey_type = EVP_PKEY_RSA;
        keylen = *pkeylen;
    } else if (gstr[0] >= '0' && gstr[0] <= '9') {
        *pkey_type = EVP_PKEY_RSA;
        keylen = atol(gstr);
        *pkeylen = keylen;
    } else if (strncmp(gstr, "param:", 6) == 0) {
        paramfile = gstr + 6;
    } else {
        const char *p = strchr(gstr, ':');
        int len;
        ENGINE *tmpeng;
        const EVP_PKEY_ASN1_METHOD *ameth;

        if (p != NULL)
            len = p - gstr;
        else
            len = strlen(gstr);
        /*
         * The lookup of a the string will cover all engines so keep a note
         * of the implementation.
         */

        ameth = EVP_PKEY_asn1_find_str(&tmpeng, gstr, len);

        if (ameth == NULL) {
            BIO_printf(bio_err, "Unknown algorithm %.*s\n", len, gstr);
            return NULL;
        }

        EVP_PKEY_asn1_get0_info(NULL, pkey_type, NULL, NULL, NULL, ameth);
#ifndef OPENSSL_NO_ENGINE
        //ENGINE_finish(tmpeng);
#endif
        if (*pkey_type == EVP_PKEY_RSA) {
            if (p != NULL) {
                keylen = atol(p + 1);
                *pkeylen = keylen;
            } else {
                keylen = *pkeylen;
            }
        } else if (p != NULL) {
            paramfile = p + 1;
        }
    }

    if (paramfile != NULL) {
        pbio = BIO_new_file(paramfile, "r");
        if (pbio == NULL) {
            BIO_printf(bio_err, "Can't open parameter file %s\n", paramfile);
            return NULL;
        }
        param = PEM_read_bio_Parameters(pbio, NULL);

        if (param == NULL) {
            X509 *x;

            (void)BIO_reset(pbio);
            x = PEM_read_bio_X509(pbio, NULL, NULL, NULL);
            if (x != NULL) {
                param = X509_get_pubkey(x);
                X509_free(x);
            }
        }

        BIO_free(pbio);

        if (param == NULL) {
            BIO_printf(bio_err, "Error reading parameter file %s\n", paramfile);
            return NULL;
        }
        if (*pkey_type == -1) {
            *pkey_type = EVP_PKEY_id(param);
        } else if (*pkey_type != EVP_PKEY_base_id(param)) {
            BIO_printf(bio_err, "Key Type does not match parameters\n");
            EVP_PKEY_free(param);
            return NULL;
        }
    }

    if (palgnam != NULL) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        ENGINE *tmpeng;
        const char *anam;

        ameth = EVP_PKEY_asn1_find(&tmpeng, *pkey_type);
        if (ameth == NULL) {
            BIO_puts(bio_err, "Internal error: can't find key algorithm\n");
            return NULL;
        }
        EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, &anam, ameth);
        *palgnam = OPENSSL_strdup(anam);
#ifndef OPENSSL_NO_ENGINE
        //ENGINE_finish(tmpeng);
#endif
    }

    if (param != NULL) {
        gctx = EVP_PKEY_CTX_new(param, keygen_engine);
        *pkeylen = EVP_PKEY_bits(param);
        EVP_PKEY_free(param);
    } else {
        gctx = EVP_PKEY_CTX_new_id(*pkey_type, keygen_engine);
    }

    if (gctx == NULL) {
        BIO_puts(bio_err, "Error allocating keygen context\n");
        ERR_print_errors(bio_err);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(gctx) <= 0) {
        BIO_puts(bio_err, "Error initializing keygen context\n");
        ERR_print_errors(bio_err);
        EVP_PKEY_CTX_free(gctx);
        return NULL;
    }
#ifndef OPENSSL_NO_RSA
    if ((*pkey_type == EVP_PKEY_RSA) && (keylen != -1)) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, keylen) <= 0) {
            BIO_puts(bio_err, "Error setting RSA keysize\n");
            ERR_print_errors(bio_err);
            EVP_PKEY_CTX_free(gctx);
            return NULL;
        }
    }
#endif

    return gctx;
}

static int genpkey_cb(EVP_PKEY_CTX *ctx)
{
    char c = '*';
    BIO *b = EVP_PKEY_CTX_get_app_data(ctx);
    int p;
    p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
    if (p == 0)
        c = '.';
    if (p == 1)
        c = '+';
    if (p == 2)
        c = '*';
    if (p == 3)
        c = '\n';
    BIO_write(b, &c, 1);
    (void)BIO_flush(b);
    return 1;
}
