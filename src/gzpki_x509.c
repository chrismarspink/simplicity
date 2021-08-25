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

# include "gzpki_types.h"
# include "gzpki_common.h"
# include "gzpki_x509.h"

static int callb(int ok, X509_STORE_CTX *x509_store_ctx);
static int print_x509v3_exts(BIO *bio, X509 *x, const char *ext_names);
static int purpose_print(BIO *bio, X509 *cert, X509_PURPOSE *pt);
static int parse_ext_names(char *names, const char **result);
static int sign(X509 *x, EVP_PKEY *pkey, int days, int opt_clrext,const EVP_MD *digest, CONF *conf, const char *section, int opt_preserve_dates);
static int x509_certify(X509_STORE *x509_store_ctx, const char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts,
                        const char *serialfile, int create,
                        int days, int opt_clrext, CONF *conf, const char *section,
                        ASN1_INTEGER *sno, int opt_reqfile, int opt_preserve_dates);

//--------------------------------------------------
// RENAME
// ctx -> x509_store_ctx
// ctx2 -> x509_store_ctx2
// serial -> opt_serial
// next_serial -> opt_next_serial
// email -> opt_email
// modulus  -> opt_modulus
//--------------------------------------------------

//int x509_main(int argc, char **argv)
int GZPKI_do_X509(GZPKI_CTX *ctx)
{
    ASN1_INTEGER *sno = NULL;
    ASN1_OBJECT *objtmp = NULL;
    BIO *out = NULL;
    CONF *extconf = NULL;
    EVP_PKEY *Upkey = NULL, *CApkey = NULL, *fkey = NULL;
    STACK_OF(ASN1_OBJECT) *trust = NULL, *reject = NULL;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    X509 *x = NULL, *xca = NULL;
    X509_REQ *req = NULL, *rq = NULL;
    X509_STORE *x509_store_ctx = NULL;
    const EVP_MD *digest = NULL;
    char *CAkeyfile = NULL, *CAserial = NULL, *fkeyfile = NULL, *alias = NULL;
    char *checkhost = NULL, *checkemail = NULL, *checkip = NULL, *exts = NULL;
    char *extsect = NULL, *extfile = NULL, *passin = NULL, *passinarg = NULL;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL, *CAfile = NULL;
    //char *prog;
    int opt_x509req = 0, days = DEF_DAYS, opt_modulus = 0, opt_pubkey = 0, opt_pprint = 0;
    int C = 0, CAformat = FORMAT_PEM, CAkeyformat = FORMAT_PEM;
    int opt_fingerprint = 0, opt_reqfile = 0, opt_checkend = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, keyformat = FORMAT_PEM;
    int opt_next_serial = 0, opt_subject_hash = 0, opt_issuer_hash = 0, opt_ocspid = 0;
    int opt_serial = 0;
    int opt_noout = 0, opt_sign_flag = 0;
    int opt_CA_flag = 0; //to GZPKI_CTX
    int opt_CA_createserial = 0;
    int opt_email = 0;
    int opt_ocsp_uri = 0, opt_trustout = 0, opt_clrtrust = 0, opt_clrreject = 0, opt_aliasout = 0;
    int ret = 1, i, num = 0, opt_badsig = 0, opt_clrext = 0, opt_nocert = 0;
    int opt_text = 0, opt_subject = 0, opt_issuer = 0, opt_startdate = 0, opt_ext = 0;
    int opt_enddate = 0;
    time_t checkoffset = 0;
    unsigned long certflag = 0;
    int opt_preserve_dates = 0;
    //OPTION_CHOICE o;
    ENGINE *e = NULL;
    char *randfile = NULL; //added by jkkim
    char *addtrust = NULL; //added by jkkim
    int opt_get_field_all = 0;

    char *tmp = NULL; //jkkim: to get serial

#ifndef OPENSSL_NO_MD5
    int opt_subject_hash_old = 0, opt_issuer_hash_old = 0;
#endif

    x509_store_ctx = X509_STORE_new();
    if (ctx == NULL)
        goto end;
    X509_STORE_set_verify_cb(x509_store_ctx, callb);

    //prog = opt_init(argc, argv, x509_options);
    informat    = ctx->informat;
    infile      = ctx->infile;
    outformat   = ctx->outformat;
    keyformat   = ctx->keyformat;

    outfile     = ctx->outfile;
    opt_reqfile = ctx->opt_reqfile;
    days        = ctx->days;
    passinarg   = ctx->passinarg;
    extfile     = ctx->extfile;
    extsect     = ctx->extsect;

    keyfile     = ctx->keyfile;

    
    //case OPT_SIGNKEY: keyfile = opt_arg(); sign_flag = ++num;  break;
    CAkeyfile   = ctx->CAkeyfile; 
    CAkeyformat = ctx->CAkeyformat;

    CAserial    = ctx->CAserial; 
    randfile    = ctx->randfile; 

    fkeyfile    = ctx->fkeyfile; 
    opt_trustout    
                = ctx->opt_trustout; 
    //addtrust    = ctx->addtrust; 
    ///addreject   = ctx->addreject; 
    alias       = ctx->alias; 
    certflag    = ctx->certflag;  //GZPKI_set_certflag() 외부 call
    //nmflag      = ctx->nmflag;     //GZPKI_set_nameflag() 
    e           = ctx->e; //GZPKI_setup_engine() setup_engine(opt_arg(), 0);
    

    if(ctx->opt_sign_flag == 1 && ctx->keyfile) {
        opt_sign_flag   = ++num; 
        keyfile = ctx->keyfile;
    }
    
    if(ctx->opt_CA_flag == 1 && ctx->CAfile) {
        opt_CA_flag = ++num;
        CAfile = ctx->CAfile; 
    }

    opt_get_field_all = ctx->opt_get_field_all;
    if(opt_get_field_all == 1) {
        opt_email = ++num; 
        opt_serial = ++num; 
        opt_next_serial = ++num; 
        opt_modulus = ++num; 
        opt_pubkey = ++num; 
        opt_x509req = ++num; 
        opt_text = ++num; 
        opt_subject = ++num; 
        opt_issuer = ++num; 
        opt_fingerprint = ++num; 
        opt_subject_hash = ++num; 
        opt_subject_hash_old = ++num; 
        opt_subject_hash_old = ++num; 
        opt_issuer_hash = ++num; 
        opt_issuer_hash_old = ++num; 
        opt_pprint = ++num; 
        opt_startdate = ++num; 
        opt_enddate = ++num; 
        opt_noout = ++num; 
        opt_ext = ++num; 
        opt_clrtrust = ++num; 
        opt_clrreject = ++num; 
        opt_aliasout = ++num; 
        opt_CA_createserial = ++num; 
        opt_ocspid = ++num; 
    }
    else {
        if(1 == ctx->opt_email)             opt_email = ++num; 
        if(1 == ctx->opt_ocsp_uri)          opt_ocsp_uri = ++num; 
        if(1 == ctx->opt_serial)            opt_serial = ++num; 
        if(1 == ctx->opt_next_serial)       opt_next_serial = ++num; 
        if(1 == ctx->opt_modulus)           opt_modulus = ++num; 
        if(1 == ctx->opt_pubkey)            opt_pubkey = ++num; 
        if(1 == ctx->opt_x509req)           opt_x509req = ++num; 
        if(1 == ctx->opt_text)              opt_text = ++num; 
        if(1 == ctx->opt_subject)           opt_subject = ++num; 
        if(1 == ctx->opt_issuer)            opt_issuer = ++num; 
        if(1 == ctx->opt_fingerprint)       opt_fingerprint = ++num; 
        if(1 == ctx->opt_subject_hash)      opt_subject_hash = ++num; 
        if(1 == ctx->opt_subject_hash_old)  opt_subject_hash_old = ++num; 
        //if(1 == ctx->opt_subject_hash_old)  opt_subject_hash_old = ++num; 
        if(1 == ctx->opt_issuer_hash)       opt_issuer_hash = ++num; 
        if(1 == ctx->opt_issuer_hash_old)   opt_issuer_hash_old = ++num; 
        if(1 == ctx->opt_pprint)            opt_pprint = ++num; 
        if(1 == ctx->opt_startdate)         opt_startdate = ++num; 
        if(1 == ctx->opt_enddate)           opt_enddate = ++num; 
        if(1 == ctx->opt_noout)             opt_noout = ++num; 
        if(1 == ctx->opt_ext)               opt_ext = ++num; 
        if(1 == ctx->opt_clrtrust)          opt_clrtrust = ++num; 
        if(1 == ctx->opt_clrreject)         opt_clrreject = ++num; 
        if(1 == ctx->opt_aliasout)          opt_aliasout = ++num; 
        if(1 == ctx->opt_CA_createserial)   opt_CA_createserial = ++num; 
        if(1 == ctx->opt_ocspid)            opt_ocspid = ++num; 
    }

    opt_nocert      = ctx->opt_nocert;
    opt_clrext      = ctx->opt_clrext;
    opt_badsig      = ctx->opt_badsig;
    opt_checkend    = ctx->opt_checkend;
    checkhost       = ctx->checkhost;
    checkip         = ctx->checkip;
    opt_preserve_dates  = ctx->opt_preserve_dates;
    digest          = ctx->digest;

    passin = ctx->passin;


    set_nameopt_v(GZPKI_DEFAULT_NAME_OPT);
    
    //inserial을 이용하여 serial 번호 지정 openssl ca -set_serial inserial
    if(ctx->inserial)
        if((sno = s2i_ASN1_INTEGER(NULL, ctx->inserial)) == NULL) {
            //TODO: set errstr[]
            return CMS_RET_OK;
        }

    if(ctx->addtrust) {
        if ((objtmp = OBJ_txt2obj(ctx->addtrust, 0)) == NULL) { 
            BIO_printf(bio_err, "gzpki: Invalid trust object value %s\n", ctx->addtrust); 
            goto end; 
        }
        if (trust == NULL && (trust = sk_ASN1_OBJECT_new_null()) == NULL) 
            goto end;
        sk_ASN1_OBJECT_push(trust, objtmp);
        objtmp = NULL; 
        opt_trustout = 1; 
    }

    if(ctx->addreject) {
            if ((objtmp = OBJ_txt2obj(ctx->addreject, 0)) == NULL) { 
                BIO_printf(bio_err, "gzpki: Invalid reject object value %s\n", ctx->addreject); 
                goto end; 
            }
            if (reject == NULL && (reject = sk_ASN1_OBJECT_new_null()) == NULL) 
                goto end;
            sk_ASN1_OBJECT_push(reject, objtmp);
            objtmp = NULL; 
            opt_trustout = 1;
    }


#if 0    
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        //case OPT_INFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &informat)) goto opthelp; break;
        //case OPT_IN: infile = opt_arg(); break;
        //case OPT_OUTFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &outformat)) goto opthelp; break;
        //case OPT_KEYFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &keyformat)) goto opthelp; break;
        //case OPT_CAFORM: if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &CAformat)) goto opthelp; break;
        //case OPT_CAKEYFORM: if (!opt_format(opt_arg(), OPT_FMT_ANY, &CAkeyformat)) goto opthelp; break;
        //case OPT_OUT:  outfile = opt_arg(); break; 
        //case OPT_REQ: reqfile = 1; break;
        //case OPT_DAYS: if (preserve_dates) goto opthelp; days = atoi(opt_arg()); break;
        case OPT_SIGOPT:
            if (!sigopts) sigopts = sk_OPENSSL_STRING_new_null(); 
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, opt_arg())) goto opthelp; break;
        
        //case OPT_PASSIN: passinarg = opt_arg(); break; 
        //case OPT_EXTFILE: extfile = opt_arg(); break;
        case OPT_R_CASES: if (!opt_rand(o)) goto end; break;
        //case OPT_EXTENSIONS: extsect = opt_arg(); break;
        //case OPT_SIGNKEY: keyfile = opt_arg(); sign_flag = ++num;  break;
        //case OPT_CA: CAfile = opt_arg(); CA_flag = ++num; break;
        //case OPT_CAKEY: CAkeyfile = opt_arg(); break;
        //case OPT_CASERIAL: CAserial = opt_arg(); break;
        //case OPT_SET_SERIAL: if (sno != NULL) { BIO_printf(bio_err, "Serial number supplied twice\n"); goto opthelp; }
            //if ((sno = s2i_ASN1_INTEGER(NULL, opt_arg())) == NULL) goto opthelp; break;
        //case OPT_FORCE_PUBKEY: fkeyfile = opt_arg(); break;
        case OPT_ADDTRUST:
            if ((objtmp = OBJ_txt2obj(opt_arg(), 0)) == NULL) { BIO_printf(bio_err, "%s: Invalid trust object value %s\n", prog, opt_arg()); goto opthelp; }
            if (trust == NULL && (trust = sk_ASN1_OBJECT_new_null()) == NULL) goto end;
            sk_ASN1_OBJECT_push(trust, objtmp);
            objtmp = NULL; opt_trustout  //int = 1; break;
        case OPT_ADDREJECT:
            if ((objtmp = OBJ_txt2obj(opt_arg(), 0)) == NULL) { BIO_printf(bio_err, "%s: Invalid reject object value %s\n", prog, opt_arg()); goto opthelp; }
            if (reject == NULL && (reject = sk_ASN1_OBJECT_new_null()) == NULL) goto end;
            sk_ASN1_OBJECT_push(reject, objtmp);
            objtmp = NULL; opt_trustout  //int = 1; break;
        //case OPT_SETALIAS: alias = opt_arg(); opt_trustout  //int = 1; break;
        //case OPT_CERTOPT: if (!set_cert_ex(&certflag, opt_arg())) goto opthelp; break;
        //case OPT_NAMEOPT: if (!set_nameopt(opt_arg())) goto opthelp; break;
        //case OPT_ENGINE: e = setup_engine(opt_arg(), 0); break;
        //case OPT_C: C = ++num; break; ## C 코드 출력, 사용하지 않는다. 
        case OPT_EMAIL: opt_email = ++num; break;
        case OPT_OCSP_URI: opt_ocsp_uri = ++num; break;
        case OPT_SERIAL:
            opt_serial = ++num;
            break;
        case OPT_NEXT_SERIAL:
            opt_next_serial = ++num;
            break;
        case OPT_MODULUS:
            opt_modulus = ++num;
            break;
        case OPT_PUBKEY:
            opt_pubkey = ++num;
            break;
        case OPT_X509TOREQ:
            opt_x509req = ++num;
            break;
        case OPT_TEXT:
            opt_text = ++num;
            break;
        case OPT_SUBJECT:
            opt_subject = ++num;
            break;
        case OPT_ISSUER:
            opt_issuer = ++num;
            break;
        case OPT_FINGERPRINT:
            opt_fingerprint = ++num;
            break;
        case OPT_HASH:
            opt_subject_hash = ++num;
            break;
        case OPT_ISSUER_HASH:
            opt_issuer_hash = ++num;
            break;
        case OPT_PURPOSE:
            opt_pprint = ++num;
            break;
        case OPT_STARTDATE:
            opt_startdate = ++num;
            break;
        case OPT_ENDDATE:
            opt_enddate = ++num;
            break;
        case OPT_NOOUT:
            opt_noout = ++num;
            break;
        case OPT_EXT:
            opt_ext = ++num;
            exts = opt_arg();
            break;
        case OPT_NOCERT:
            opt_nocert = 1;
            break;
        case OPT_TRUSTOUT:
            opt_trustout  //int = 1;
            break;
        case OPT_CLRTRUST:
            opt_clrtrust = ++num;
            break;
        case OPT_CLRREJECT:
            opt_clrreject = ++num;
            break;
        case OPT_ALIAS:
            opt_aliasout = ++num;
            break;
        case OPT_CACREATESERIAL:
            opt_CA_createserial = ++num;
            break;
        case OPT_CLREXT:
            opt_clrext = 1;
            break;
        case OPT_OCSPID:
            opt_ocspid = ++num;
            break;
        case OPT_BADSIG:
            opt_badsig = 1;
            break;
#ifndef OPENSSL_NO_MD5
        case OPT_SUBJECT_HASH_OLD:
            opt_subject_hash_old = ++num;
            break;
        case OPT_ISSUER_HASH_OLD:
            opt_issuer_hash_old = ++num;
            break;
#else
        case OPT_SUBJECT_HASH_OLD:
        case OPT_ISSUER_HASH_OLD:
            break;
#endif
        case OPT_DATES:
            opt_startdate = ++num;
            opt_enddate = ++num;
            break;
        case OPT_CHECKEND:
            opt_checkend = 1;
            {
                intmax_t temp = 0;
                if (!opt_imax(opt_arg(), &temp))
                    goto opthelp;
                checkoffset = (time_t)temp;
                if ((intmax_t)checkoffset != temp) {
                    BIO_printf(bio_err, "%s: checkend time out of range %s\n",
                               prog, opt_arg());
                    goto opthelp;
                }
            }
            break;
        case OPT_CHECKHOST:
            checkhost = opt_arg();
            break;
        case OPT_CHECKEMAIL:
            checkemail = opt_arg();
            break;
        case OPT_CHECKIP:
            checkip = opt_arg();
            break;
        case OPT_PRESERVE_DATES:
            if (days != DEF_DAYS)
                goto opthelp;
            opt_preserve_dates = 1;
            break;
        case OPT_MD:
            if (!opt_md(opt_unknown(), &digest))
                goto opthelp;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();
    if (argc != 0) {
        BIO_printf(bio_err, "%s: Unknown parameter %s\n", prog, argv[0]);
        goto opthelp;
    }
#endif


    if (!app_passwd(passinarg, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password\n");
        goto end;
    }

    if (!X509_STORE_set_default_paths(x509_store_ctx)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (fkeyfile != NULL) {
        fkey = load_pubkey(fkeyfile, keyformat, 0, NULL, e, "Forced key");
        if (fkey == NULL)
            goto end;
    }

    if ((CAkeyfile == NULL) && (opt_CA_flag) && (CAformat == FORMAT_PEM)) {
        CAkeyfile = CAfile;
    } else if ((opt_CA_flag) && (CAkeyfile == NULL)) {
        BIO_printf(bio_err, "need to specify a CAkey if using the CA command\n");
        goto end;
    }

    if (extfile != NULL) {
        X509V3_CTX x509_store_ctx2;
        if ((extconf = app_load_config(extfile)) == NULL)
            goto end;
        if (extsect == NULL) {
            extsect = NCONF_get_string(extconf, "default", "extensions");
            if (extsect == NULL) {
                ERR_clear_error();
                extsect = "default";
            }
        }
        X509V3_set_ctx_test(&x509_store_ctx2);
        X509V3_set_nconf(&x509_store_ctx2, extconf);
        if (!X509V3_EXT_add_nconf(extconf, &x509_store_ctx2, extsect, NULL)) {
            BIO_printf(bio_err, "Error Loading extension section %s\n", extsect);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (opt_reqfile) {
        EVP_PKEY *pkey;
        BIO *in;

        if (!opt_sign_flag && !opt_CA_flag) {
            BIO_printf(bio_err, "We need a private key to sign with\n");
            goto end;
        }
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL)
            goto end;
        req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
        BIO_free(in);

        if (req == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }

        if ((pkey = X509_REQ_get0_pubkey(req)) == NULL) {
            BIO_printf(bio_err, "error unpacking public key\n");
            goto end;
        }
        i = X509_REQ_verify(req, pkey);
        if (i < 0) {
            BIO_printf(bio_err, "Signature verification error\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (i == 0) {
            BIO_printf(bio_err, "Signature did not match the certificate request\n");
            goto end;
        } else {
            BIO_printf(bio_err, "Signature ok\n");
        }

        print_name(bio_err, "subject=", X509_REQ_get_subject_name(req), get_nameopt());
        str_append(&ctx->req_field_subject, "%s", X509_NAME_oneline(X509_REQ_get_subject_name(req), 0, 0) );

        if ((x = X509_new()) == NULL)
            goto end;

        if (sno == NULL) {
            sno = ASN1_INTEGER_new();
            if (sno == NULL || !rand_serial(NULL, sno))
                goto end;
            if (!X509_set_serialNumber(x, sno))
                goto end;
            ASN1_INTEGER_free(sno);
            sno = NULL;
        } else if (!X509_set_serialNumber(x, sno)) {
            goto end;
        }

        if (!X509_set_issuer_name(x, X509_REQ_get_subject_name(req)))
            goto end;
        if (!X509_set_subject_name(x, X509_REQ_get_subject_name(req)))
            goto end;
        if (!set_cert_times(x, NULL, NULL, days))
            goto end;

        if (fkey != NULL) {
            X509_set_pubkey(x, fkey);
        } else {
            pkey = X509_REQ_get0_pubkey(req);
            X509_set_pubkey(x, pkey);
        }
    } else {
        x = load_cert(infile, informat, "Certificate");
    }

    if (x == NULL)
        goto end;
    if (opt_CA_flag) {
        xca = load_cert(CAfile, CAformat, "CA Certificate");
        if (xca == NULL)
            goto end;
    }

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

    if (!opt_noout || opt_text || opt_next_serial)
        OBJ_create("2.99999.3", "SET.ex3", "SET x509v3 extension 3");

    if (alias)
        X509_alias_set1(x, (unsigned char *)alias, -1);

    if (opt_clrtrust)
        X509_trust_clear(x);
    if (opt_clrreject)
        X509_reject_clear(x);

    if (trust != NULL) {
        for (i = 0; i < sk_ASN1_OBJECT_num(trust); i++) {
            objtmp = sk_ASN1_OBJECT_value(trust, i);
            X509_add1_trust_object(x, objtmp);
        }
        objtmp = NULL;
    }

    if (reject != NULL) {
        for (i = 0; i < sk_ASN1_OBJECT_num(reject); i++) {
            objtmp = sk_ASN1_OBJECT_value(reject, i);
            X509_add1_reject_object(x, objtmp);
        }
        objtmp = NULL;
    }

    if (opt_badsig) {
        const ASN1_BIT_STRING *signature;

        X509_get0_signature(&signature, NULL, x);
        corrupt_signature(signature);
    }

    if (num) {
        for (i = 1; i <= num; i++) {
            if (opt_issuer == i) {
                print_name(out, "issuer=", X509_get_issuer_name(x), get_nameopt());
                str_append(&ctx->x509_field_issuer, "%s", X509_NAME_oneline(X509_get_issuer_name(x), 0, 0) );

            } else if (opt_subject == i) {
                print_name(out, "subject=", X509_get_subject_name(x), get_nameopt());
                ctx->x509_field_subject = GZPKI_strdup(X509_NAME_oneline(X509_get_subject_name(x), 0, 0));
            } else if (opt_serial == i) {
                BIO_printf(out, "serial=");
                i2a_ASN1_INTEGER(out, X509_get_serialNumber(x));
                BIO_printf(out, "\n");
                
                BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x), NULL);
                tmp = BN_bn2dec(bn);
                str_append(&ctx->x509_field_serial, "%s", tmp);
                
            } else if (opt_next_serial == i) {
                ASN1_INTEGER *ser = X509_get_serialNumber(x);
                BIGNUM *bnser = ASN1_INTEGER_to_BN(ser, NULL);

                if (!bnser)
                    goto end;
                if (!BN_add_word(bnser, 1))
                    goto end;
                ser = BN_to_ASN1_INTEGER(bnser, NULL);
                if (!ser)
                    goto end;
                BN_free(bnser);
                i2a_ASN1_INTEGER(out, ser);

                BIGNUM *bn = ASN1_INTEGER_to_BN(ser, NULL);
                char *tmp = BN_bn2dec(bn);
                str_append(&ctx->x509_field_next_serial, "%s", tmp);

                ASN1_INTEGER_free(ser);
                BIO_puts(out, "\n");
            } else if ((opt_email == i) || (opt_ocsp_uri == i)) {
                int j, cnt;
                STACK_OF(OPENSSL_STRING) *emlst;
                if (opt_email == i)
                    emlst = X509_get1_email(x);
                else
                    emlst = X509_get1_ocsp(x);

                cnt = sk_OPENSSL_STRING_num(emlst);
                for (j = 0; j < cnt; j++) {
                    if(opt_email == i) {
                        BIO_printf(out, "%s\n", sk_OPENSSL_STRING_value(emlst, j));
                        str_append(&ctx->x509_field_email, "%s", sk_OPENSSL_STRING_value(emlst, j));
                    }
                    else {
                        BIO_printf(out, "%s\n", sk_OPENSSL_STRING_value(emlst, j));
                        str_append(&ctx->x509_field_ocsp_uri, "%s", sk_OPENSSL_STRING_value(emlst, j));
                    }
                }
                X509_email_free(emlst);
            } else if (opt_aliasout == i) {
                unsigned char *alstr;
                alstr = X509_alias_get0(x, NULL);
                if (alstr) {
                    BIO_printf(out, "%s\n", alstr);
                    str_append(&ctx->x509_field_aliasout, "%s", alstr);
                }
                else {
                    BIO_puts(out, "<No Alias>\n");
                    str_append(&ctx->x509_field_aliasout, "%s", "<No Alias>");
                }
            } else if (opt_subject_hash == i) {
                BIO_printf(out, "%08lx\n", X509_subject_name_hash(x));
                str_append(&ctx->x509_field_subject_hash, "%08lx", X509_subject_name_hash(x));
            }
#ifndef OPENSSL_NO_MD5
            else if (opt_subject_hash_old == i) {
                BIO_printf(out, "%08lx\n", X509_subject_name_hash_old(x));
            }
#endif
            else if (opt_issuer_hash == i) {
                BIO_printf(out, "%08lx\n", X509_issuer_name_hash(x));
                str_append(&ctx->x509_field_issuer_hash, "%08lx", X509_issuer_name_hash(x));
            }
#ifndef OPENSSL_NO_MD5
            else if (opt_issuer_hash_old == i) {
                BIO_printf(out, "%08lx\n", X509_issuer_name_hash_old(x));
            }
#endif
            else if (opt_pprint == i) {
                X509_PURPOSE *ptmp;
                BIO *tmpbio = BIO_new(BIO_s_mem());
                BUF_MEM *bptr;
                int j;
                BIO_printf(out, "Certificate purposes:\n");
                for (j = 0; j < X509_PURPOSE_get_count(); j++) {
                    ptmp = X509_PURPOSE_get0(j);
                    purpose_print(out, x, ptmp);
                    purpose_print(tmpbio, x, ptmp);
                }

                BIO_get_mem_ptr( tmpbio, &bptr); 
                str_append(&ctx->x509_field_pprint, "%s", bptr->data);
                ctx->x509_field_pprint[bptr->length -1] = 0;

            } else if (opt_modulus == i) {
                EVP_PKEY *pkey;
                BIO *tmpbio = BIO_new(BIO_s_mem());
                BUF_MEM *bptr;

                pkey = X509_get0_pubkey(x);
                if (pkey == NULL) {
                    BIO_printf(bio_err, "Modulus=unavailable\n");
                    ERR_print_errors(bio_err);
                    goto end;
                }
                BIO_printf(out, "Modulus=");
#ifndef OPENSSL_NO_RSA
                if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
                    const BIGNUM *n;
                    RSA_get0_key(EVP_PKEY_get0_RSA(pkey), &n, NULL, NULL);
                    BN_print(out, n);
                    BN_print(tmpbio, n);
                } else
#endif
#ifndef OPENSSL_NO_DSA
                if (EVP_PKEY_id(pkey) == EVP_PKEY_DSA) {
                    const BIGNUM *dsapub = NULL;
                    DSA_get0_key(EVP_PKEY_get0_DSA(pkey), &dsapub, NULL);
                    BN_print(out, dsapub);
                    BN_print(tmpbio, dsapub);
                } else
#endif
                {
                    BIO_printf(out, "Wrong Algorithm type");
                    BIO_printf(tmpbio,"Wrong Algorithm type");
                }

                BIO_printf(out, "\n");

                BIO_get_mem_ptr( tmpbio, &bptr); 
                str_append(&ctx->x509_field_modulus, "%s", bptr->data);
                ctx->x509_field_modulus[bptr->length -1] = 0;

            } else if (opt_pubkey == i) {
                EVP_PKEY *pkey;

                pkey = X509_get0_pubkey(x);
                if (pkey == NULL) {
                    BIO_printf(bio_err, "Error getting public key\n");
                    ERR_print_errors(bio_err);
                    goto end;
                }
                PEM_write_bio_PUBKEY(out, pkey);
                
                BIO *tmpbio = BIO_new(BIO_s_mem());
                BUF_MEM *bptr;
                PEM_write_bio_PUBKEY(tmpbio, pkey);
                BIO_get_mem_ptr( tmpbio, &bptr); 

                str_append(&ctx->x509_field_pubkey, "%s", bptr->data);
                ctx->x509_field_pubkey[bptr->length -1] = 0;
            } else if (C == i) {
                unsigned char *d;
                char *m;
                int len;

                print_name(out, "/*\n"
                                " * Subject: ", X509_get_subject_name(x), get_nameopt());
                print_name(out, " * Issuer:  ", X509_get_issuer_name(x), get_nameopt());
                BIO_puts(out, " */\n");

                len = i2d_X509(x, NULL);
                m = app_malloc(len, "x509 name buffer");
                d = (unsigned char *)m;
                len = i2d_X509_NAME(X509_get_subject_name(x), &d);
                print_array(out, "the_subject_name", len, (unsigned char *)m);
                d = (unsigned char *)m;
                len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &d);
                print_array(out, "the_public_key", len, (unsigned char *)m);
                d = (unsigned char *)m;
                len = i2d_X509(x, &d);
                print_array(out, "the_certificate", len, (unsigned char *)m);
                OPENSSL_free(m);

            } else if (opt_text == i) {
                BIO *tmpbio = BIO_new(BIO_s_mem());
                BUF_MEM *bptr;

                X509_print_ex(out,    x, get_nameopt(), certflag);
                X509_print_ex(tmpbio, x, get_nameopt(), certflag);
                
                BIO_get_mem_ptr( tmpbio, &bptr); 
                str_append(&ctx->x509_field_text, "%s", bptr->data);
                ctx->x509_field_text[bptr->length-1] = 0;

            } else if (opt_startdate == i) {
                BIO_puts(out, "notBefore=");
                ASN1_TIME_print(out, X509_get0_notBefore(x));
                BIO_puts(out, "\n");

                BIO *tmpbio = BIO_new(BIO_s_mem());
                BUF_MEM *bptr;
                ASN1_TIME_print(tmpbio, X509_get0_notBefore(x));
                BIO_get_mem_ptr( tmpbio, &bptr); 
                str_append(&ctx->x509_field_startdate, "%s", bptr->data);
                ctx->x509_field_startdate[bptr->length] = 0;

            } else if (opt_enddate == i) {
                BIO_puts(out, "notAfter=");
                ASN1_TIME_print(out, X509_get0_notAfter(x));
                BIO_puts(out, "\n");

                BIO *tmpbio = BIO_new(BIO_s_mem());
                BUF_MEM *bptr;
                ASN1_TIME_print(tmpbio, X509_get0_notAfter(x));
                BIO_get_mem_ptr( tmpbio, &bptr); 
                str_append(&ctx->x509_field_enddate, "%s", bptr->data);
                ctx->x509_field_enddate[bptr->length] = 0; // length-1로 설정한 경우 GMT -> GM까지만 출력된다. 

            } else if (opt_fingerprint == i) {
                int j;
                unsigned int n;
                unsigned char md[EVP_MAX_MD_SIZE];
                const EVP_MD *fdig = digest;

                if (fdig == NULL)
                    fdig = EVP_sha1();

                if (!X509_digest(x, fdig, md, &n)) {
                    BIO_printf(bio_err, "out of memory\n");
                    goto end;
                }
                BIO_printf(out, "%s Fingerprint=", OBJ_nid2sn(EVP_MD_type(fdig)));
                for (j = 0; j < (int)n; j++) {
                    BIO_printf(out, "%02X%c", md[j], (j + 1 == (int)n) ? '\n' : ':');
                }

                BIO *tmpbio = BIO_new(BIO_s_mem());
                BUF_MEM *bptr;
                for (j = 0; j < (int)n; j++) {
                    BIO_printf(tmpbio, "%02X%c", md[j], (j + 1 == (int)n) ? '\n' : ':');
                }
                BIO_get_mem_ptr( tmpbio, &bptr); 

                str_append(&ctx->x509_field_fingerprint, "%s", bptr->data);
                ctx->x509_field_fingerprint[bptr->length -1] = 0;

            }

            /* should be in the library */
            else if ((opt_sign_flag == i) && (opt_x509req == 0)) {
                BIO_printf(bio_err, "Getting Private key\n");
                if (Upkey == NULL) {
                    Upkey = load_key(keyfile, keyformat, 0, passin, e, "Private key");
                    if (Upkey == NULL)
                        goto end;
                }

                if (!sign(x, Upkey, days, opt_clrext, digest, extconf, extsect, opt_preserve_dates))
                    goto end;
            } else if (opt_CA_flag == i) {
                BIO_printf(bio_err, "Getting CA Private Key\n");
                if (CAkeyfile != NULL) {
                    CApkey = load_key(CAkeyfile, CAkeyformat, 0, passin, e, "CA Private Key");
                    if (CApkey == NULL)
                        goto end;
                }

                if (!x509_certify(x509_store_ctx, CAfile, digest, x, xca,
                                  CApkey, sigopts,
                                  CAserial, opt_CA_createserial, days, opt_clrext,
                                  extconf, extsect, sno, opt_reqfile, opt_preserve_dates))
                    goto end;

            } else if (opt_x509req == i) {
                EVP_PKEY *pk;

                BIO_printf(bio_err, "Getting request Private Key\n");
                if (keyfile == NULL) {
                    BIO_printf(bio_err, "no request key file specified\n");
                    //goto end;
                    continue;
                } else {
                    pk = load_key(keyfile, keyformat, 0, passin, e, "request key");
                    if (pk == NULL)
                        //goto end;
                        continue;
                }

                BIO_printf(bio_err, "Generating certificate request\n");

                rq = X509_to_X509_REQ(x, pk, digest);
                EVP_PKEY_free(pk);
                if (rq == NULL) {
                    ERR_print_errors(bio_err);
                    goto end;
                }
                if (!opt_noout) {
                    X509_REQ_print_ex(out, rq, get_nameopt(), X509_FLAG_COMPAT);
                    PEM_write_bio_X509_REQ(out, rq);
                }
                opt_noout = 1;
            } else if (opt_ocspid == i) {
                X509_ocspid_print(out, x);
            } else if (opt_ext == i) {
                print_x509v3_exts(out, x, exts);
            }
        }
    }

    if (opt_checkend) {
        time_t tcheck = time(NULL) + checkoffset;

        if (X509_cmp_time(X509_get0_notAfter(x), &tcheck) < 0) {
            BIO_printf(out, "Certificate will expire\n");
            ret = 1;
        } else {
            BIO_printf(out, "Certificate will not expire\n");
            ret = 0;
        }
        goto end;
    }

    print_cert_checks(out, x, checkhost, checkemail, checkip);

    if (opt_noout || opt_nocert) {
        ret = 0;
        goto end;
    }

    if (outformat == FORMAT_ASN1) {
        i = i2d_X509_bio(out, x);
    } else if (outformat == FORMAT_PEM) {
        if (opt_trustout)
            i = PEM_write_bio_X509_AUX(out, x);
        else
            i = PEM_write_bio_X509(out, x);
    } else {
        BIO_printf(bio_err, "bad output format specified for outfile\n");
        goto end;
    }
    if (!i) {
        BIO_printf(bio_err, "unable to write certificate\n");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    NCONF_free(extconf);
    //BIO_free_all(out); --> free_context
    BIO_flush(out);
    X509_STORE_free(x509_store_ctx);
    X509_REQ_free(req);
    X509_free(x);
    X509_free(xca);
    EVP_PKEY_free(Upkey);
    EVP_PKEY_free(CApkey);
    EVP_PKEY_free(fkey);
    sk_OPENSSL_STRING_free(sigopts);
    X509_REQ_free(rq);
    ASN1_INTEGER_free(sno);
    sk_ASN1_OBJECT_pop_free(trust, ASN1_OBJECT_free);
    sk_ASN1_OBJECT_pop_free(reject, ASN1_OBJECT_free);
    ASN1_OBJECT_free(objtmp);
//    release_engine(e);
    OPENSSL_free(passin);
    return ret;
}

static ASN1_INTEGER *x509_load_serial(const char *CAfile,
                                      const char *serialfile, int create)
{
    char *buf = NULL;
    ASN1_INTEGER *bs = NULL;
    BIGNUM *serial = NULL;

    if (serialfile == NULL) {
        const char *p = strrchr(CAfile, '.');
        size_t len = p != NULL ? (size_t)(p - CAfile) : strlen(CAfile);

        buf = app_malloc(len + sizeof(POSTFIX), "serial# buffer");
        memcpy(buf, CAfile, len);
        memcpy(buf + len, POSTFIX, sizeof(POSTFIX));
        serialfile = buf;
    }

    serial = load_serial(serialfile, create, NULL);
    if (serial == NULL)
        goto end;

    if (!BN_add_word(serial, 1)) {
        BIO_printf(bio_err, "add_word failure\n");
        goto end;
    }

    if (!save_serial(serialfile, NULL, serial, &bs))
        goto end;

 end:
    OPENSSL_free(buf);
    BN_free(serial);
    return bs;
}

static int x509_certify(X509_STORE *x509_store_ctx, const char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts,
                        const char *serialfile, int create,
                        int days, int opt_clrext, CONF *conf, const char *section,
                        ASN1_INTEGER *sno, int opt_reqfile, int opt_preserve_dates)
{
    int ret = 0;
    ASN1_INTEGER *bs = NULL;
    X509_STORE_CTX *xsc = NULL;
    EVP_PKEY *upkey;

    upkey = X509_get0_pubkey(xca);
    if (upkey == NULL) {
        BIO_printf(bio_err, "Error obtaining CA X509 public key\n");
        goto end;
    }
    EVP_PKEY_copy_parameters(upkey, pkey);

    xsc = X509_STORE_CTX_new();
    if (xsc == NULL || !X509_STORE_CTX_init(xsc, x509_store_ctx, x, NULL)) {
        BIO_printf(bio_err, "Error initialising X509 store\n");
        goto end;
    }
    if (sno)
        bs = sno;
    else if ((bs = x509_load_serial(CAfile, serialfile, create)) == NULL)
        goto end;

    /*
     * NOTE: this certificate can/should be self signed, unless it was a
     * certificate request in which case it is not.
     */
    X509_STORE_CTX_set_cert(xsc, x);
    X509_STORE_CTX_set_flags(xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!opt_reqfile && X509_verify_cert(xsc) <= 0)
        goto end;

    if (!X509_check_private_key(xca, pkey)) {
        BIO_printf(bio_err,
                   "CA certificate and CA private key do not match\n");
        goto end;
    }

    if (!X509_set_issuer_name(x, X509_get_subject_name(xca)))
        goto end;
    if (!X509_set_serialNumber(x, bs))
        goto end;

    if (!opt_preserve_dates && !set_cert_times(x, NULL, NULL, days))
        goto end;

    if (opt_clrext) {
        while (X509_get_ext_count(x) > 0)
            X509_delete_ext(x, 0);
    }

    if (conf != NULL) {
        X509V3_CTX x509_store_ctx2;
        X509_set_version(x, 2); /* version 3 certificate */
        X509V3_set_ctx(&x509_store_ctx2, xca, x, NULL, NULL, 0);
        X509V3_set_nconf(&x509_store_ctx2, conf);
        if (!X509V3_EXT_add_nconf(conf, &x509_store_ctx2, section, x))
            goto end;
    }

    if (!do_X509_sign(x, pkey, digest, sigopts))
        goto end;
    ret = 1;
 end:
    X509_STORE_CTX_free(xsc);
    if (!ret)
        ERR_print_errors(bio_err);
    if (!sno)
        ASN1_INTEGER_free(bs);
    return ret;
}

static int callb(int ok, X509_STORE_CTX *x509_store_ctx)
{
    int err;
    X509 *err_cert;

    /*
     * it is ok to use a self signed certificate This case will catch both
     * the initial ok == 0 and the final ok == 1 calls to this function
     */
    err = X509_STORE_CTX_get_error(x509_store_ctx);
    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        return 1;

    /*
     * BAD we should have gotten an error.  Normally if everything worked
     * X509_STORE_CTX_get_error(ctx) will still be set to
     * DEPTH_ZERO_SELF_....
     */
    if (ok) {
        BIO_printf(bio_err,
                   "error with certificate to be certified - should be self signed\n");
        return 0;
    } else {
        err_cert = X509_STORE_CTX_get_current_cert(x509_store_ctx);
        print_name(bio_err, NULL, X509_get_subject_name(err_cert), 0);
        BIO_printf(bio_err,
                   "error with certificate - error %d at depth %d\n%s\n", err,
                   X509_STORE_CTX_get_error_depth(x509_store_ctx),
                   X509_verify_cert_error_string(err));
        return 1;
    }
}

/* self sign */
static int sign(X509 *x, EVP_PKEY *pkey, int days, int opt_clrext,
                const EVP_MD *digest, CONF *conf, const char *section,
                int opt_preserve_dates)
{

    if (!X509_set_issuer_name(x, X509_get_subject_name(x)))
        goto err;
    if (!opt_preserve_dates && !set_cert_times(x, NULL, NULL, days))
        goto err;
    if (!X509_set_pubkey(x, pkey))
        goto err;
    if (opt_clrext) {
        while (X509_get_ext_count(x) > 0)
            X509_delete_ext(x, 0);
    }
    if (conf != NULL) {
        X509V3_CTX x509_store_ctx;
        X509_set_version(x, 2); /* version 3 certificate */
        X509V3_set_ctx(&x509_store_ctx, x, x, NULL, NULL, 0);
        X509V3_set_nconf(&x509_store_ctx, conf);
        if (!X509V3_EXT_add_nconf(conf, &x509_store_ctx, section, x))
            goto err;
    }
    if (!X509_sign(x, pkey, digest))
        goto err;
    return 1;
 err:
    ERR_print_errors(bio_err);
    return 0;
}

static int purpose_print(BIO *bio, X509 *cert, X509_PURPOSE *pt)
{
    int id, i, idret;
    const char *pname;
    id = X509_PURPOSE_get_id(pt);
    pname = X509_PURPOSE_get0_name(pt);
    for (i = 0; i < 2; i++) {
        idret = X509_check_purpose(cert, id, i);
        BIO_printf(bio, "%s%s : ", pname, i ? " CA" : "");
        if (idret == 1)
            BIO_printf(bio, "Yes\n");
        else if (idret == 0)
            BIO_printf(bio, "No\n");
        else
            BIO_printf(bio, "Yes (WARNING code=%d)\n", idret);
    }
    return 1;
}

static int parse_ext_names(char *names, const char **result)
{
    char *p, *q;
    int cnt = 0, len = 0;

    p = q = names;
    len = strlen(names);

    while (q - names <= len) {
        if (*q != ',' && *q != '\0') {
            q++;
            continue;
        }
        if (p != q) {
            /* found */
            if (result != NULL) {
                result[cnt] = p;
                *q = '\0';
            }
            cnt++;
        }
        p = ++q;
    }

    return cnt;
}

static int print_x509v3_exts(BIO *bio, X509 *x, const char *ext_names)
{
    const STACK_OF(X509_EXTENSION) *exts = NULL;
    STACK_OF(X509_EXTENSION) *exts2 = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OBJECT *obj;
    int i, j, ret = 0, num, nn = 0;
    const char *sn, **names = NULL;
    char *tmp_ext_names = NULL;

    exts = X509_get0_extensions(x);
    if ((num = sk_X509_EXTENSION_num(exts)) <= 0) {
        BIO_printf(bio, "No extensions in certificate\n");
        ret = 1;
        goto end;
    }

    /* parse comma separated ext name string */
    if ((tmp_ext_names = OPENSSL_strdup(ext_names)) == NULL)
        goto end;
    if ((nn = parse_ext_names(tmp_ext_names, NULL)) == 0) {
        BIO_printf(bio, "Invalid extension names: %s\n", ext_names);
        goto end;
    }
    if ((names = OPENSSL_malloc(sizeof(char *) * nn)) == NULL)
        goto end;
    parse_ext_names(tmp_ext_names, names);

    for (i = 0; i < num; i++) {
        ext = sk_X509_EXTENSION_value(exts, i);

        /* check if this ext is what we want */
        obj = X509_EXTENSION_get_object(ext);
        sn = OBJ_nid2sn(OBJ_obj2nid(obj));
        if (sn == NULL || strcmp(sn, "UNDEF") == 0)
            continue;

        for (j = 0; j < nn; j++) {
            if (strcmp(sn, names[j]) == 0) {
                /* push the extension into a new stack */
                if (exts2 == NULL
                    && (exts2 = sk_X509_EXTENSION_new_null()) == NULL)
                    goto end;
                if (!sk_X509_EXTENSION_push(exts2, ext))
                    goto end;
            }
        }
    }

    if (!sk_X509_EXTENSION_num(exts2)) {
        BIO_printf(bio, "No extensions matched with %s\n", ext_names);
        ret = 1;
        goto end;
    }

    ret = X509V3_extensions_print(bio, NULL, exts2, 0, 0);
 end:
    sk_X509_EXTENSION_free(exts2);
    OPENSSL_free(names);
    OPENSSL_free(tmp_ext_names);
    return ret;
}
