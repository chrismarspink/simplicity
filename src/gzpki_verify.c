
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
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "apps.h"
//#include "progs.h"
//#include <openssl/bio.h>
//#include <openssl/err.h>
//#include <openssl/x509.h>
//#include <openssl/x509v3.h>
//#include <openssl/pem.h>

static int cb(int ok, X509_STORE_CTX *ctx); //org
static int x509_verify_callback(int ok, X509_STORE_CTX *ctx); //modified
static int check(X509_STORE *ctx, const char *file,
                 STACK_OF(X509) *uchain, STACK_OF(X509) *tchain,
                 STACK_OF(X509_CRL) *crls, int show_chain);

static int v_verbose = 0, vflags = 0;

/*typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_ENGINE, OPT_CAPATH, OPT_CAFILE, OPT_NOCAPATH, OPT_NOCAFILE,
    OPT_UNTRUSTED, OPT_TRUSTED, OPT_CRLFILE, OPT_CRL_DOWNLOAD, OPT_SHOW_CHAIN,
    OPT_V_ENUM, OPT_NAMEOPT,
    OPT_VERBOSE
} OPTION_CHOICE;*/

/*const OPTIONS verify_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] cert.pem...\n"},
    {OPT_HELP_STR, 1, '-', "Valid options are:\n"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"verbose", OPT_VERBOSE, '-', "Print extra information about the operations being performed."},
    {"CApath", OPT_CAPATH, '/', "A directory of trusted certificates"},
    {"CAfile", OPT_CAFILE, '<', "A file of trusted certificates"},
    {"no-CAfile", OPT_NOCAFILE, '-', "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-', "Do not load certificates from the default certificates directory"},
    {"untrusted", OPT_UNTRUSTED, '<', "A file of untrusted certificates"},
    {"trusted", OPT_TRUSTED, '<', "A file of trusted certificates"},
    {"CRLfile", OPT_CRLFILE, '<', "File containing one or more CRL's (in PEM format) to load"},
    {"crl_download", OPT_CRL_DOWNLOAD, '-', "Attempt to download CRL information for this certificate"},
    {"show_chain", OPT_SHOW_CHAIN, '-', "Display information about the certificate chain"},
    {"nameopt", OPT_NAMEOPT, 's', "Various certificate name options"},
    OPT_V_OPTIONS,
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {NULL}
};*/

//int verify_main(int argc, char **argv)
int GZPKI_do_VERIFY(GZPKI_CTX *ctx)
{
    ENGINE *e = NULL;
    STACK_OF(X509) *untrusted = NULL, *trusted = NULL;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    const char *prog = "GZPKI_do_VERIFY";
    char *CApath = NULL;
    char *CAfile = NULL;
    int noCApath = 0, noCAfile = 0;
    int vpmtouched = 0, crl_download = 0, show_chain = 0, i = 0, ret = 1;
    //OPTION_CHOICE o;

    //in opt_verify
    ASN1_OBJECT *otmp;
    X509_PURPOSE *xptmp;
    const X509_VERIFY_PARAM *vtmp;

    char *verify_opts = NULL;
    
    if(ctx->verify_opts)
        verify_opts = GZPKI_strdup(ctx->verify_opts);

    if ((vpm = X509_VERIFY_PARAM_new()) == NULL)
        goto end;


    //prog = opt_init(argc, argv, verify_options);
    //while ((o = opt_next()) != OPT_EOF) {
    if(1) {
        CApath = ctx->CApath;
        CAfile = ctx->CAfile;
        noCApath = ctx->noCApath;
        noCAfile = ctx->noCAfile;

        if(ctx->trusted_certfile) 
        {
            noCAfile = noCApath = 1;
            if (!load_certs(ctx->trusted_certfile, &trusted, FORMAT_PEM, NULL, "trusted certificates"))
                goto end;
        }

        if(ctx->untrusted_certfile) 
        {
            if (!load_certs(ctx->untrusted_certfile, &untrusted, FORMAT_PEM, NULL, "untrusted certificates"))
                goto end;
        }

        if(ctx->crlfile) 
         {
            if (!load_crls(ctx->crlfile, &crls, FORMAT_PEM, NULL, "other CRLs"))
                goto end;
        }

        //opt_verify_crl_download
        //opt_verify_show_chain

        set_nameopt_v(ctx->opt_nameopt);

        if(ctx->verbose == 1)
            v_verbose = 1;

        /*
         * notice: verify option은 OPT_V_OPTIONS 참조(vericy.c, apps.h)
         */

        //OPT_V_POLICY
        if(ctx->verify_add_policy && strlen(ctx->verify_add_policy) >= 1) {
            
            otmp = OBJ_txt2obj(ctx->verify_add_policy, 0);
            if (otmp == NULL) {
                printf("error:%s:invalid policy:%s\n", prog, ctx->verify_add_policy);
                return 0;
            }
            X509_VERIFY_PARAM_add0_policy(vpm, otmp);
            vpmtouched++;
        }

        //OPT_V_PURPOSE
        if(ctx->verify_purpose) {
            i = X509_PURPOSE_get_by_sname(ctx->verify_purpose);
            if (i < 0) {
                printf("error:%s:invalid purpose:%s\n", prog, ctx->verify_purpose);
                return 0;
            }
            xptmp = X509_PURPOSE_get0(i); /* purpose index -> purpose object */

            i = X509_PURPOSE_get_id(xptmp); /* purpose object -> purpose value */

            if (!X509_VERIFY_PARAM_set_purpose(vpm, i)) {
                printf("error:%s:internal error setting purpose:%s\n", prog, ctx->verify_purpose);
                    return 0;
            }
            vpmtouched++;
        }

        //OPT_V_VERIFY_NAME
        if(ctx->verify_name) {
            vtmp = X509_VERIFY_PARAM_lookup(ctx->verify_name);
            if (vtmp == NULL) {
                printf("error:%s: Invalid verify name %s\n", prog, ctx->verify_name);
                return 0;
            }
            X509_VERIFY_PARAM_set1(vpm, vtmp);
            vpmtouched++;
        }

        //OPT_V_VERIFY_DEPTH
        if(ctx->verify_depth && i >= ctx->verify_depth) {
            X509_VERIFY_PARAM_set_depth(vpm, i);
            vpmtouched++;
        }

        //OPT_V_VERIFY_AUTH_LEVEL
        if(ctx->verify_auth_level && i >= ctx->verify_auth_level) {
            X509_VERIFY_PARAM_set_auth_level(vpm, i);
            vpmtouched++;
        }
#if 0 //TODO: OPT_V_ATTIME
        if(ctx->verify_epoch_time) {
            if (!opt_imax(ctx->verify_epoch_time, &t))
                return 0;
            if (t != (time_t)t) {
                printf("error:%s: epoch time out of range:%s\n", prog, ctx->verify_epoch_time);
                return 0;
            }
            X509_VERIFY_PARAM_set_time(vpm, (time_t)t);
            vpmtouched++;
        }
#endif

        //OPT_V_VERIFY_HOSTNAME
        if(ctx->verify_host_name) {
            if (!X509_VERIFY_PARAM_set1_host(vpm, ctx->verify_host_name, 0))
                return 0;
            vpmtouched++;
        }

        //OPT_V_VERIFY_EMAIL
        if(ctx->verify_email) {
            if (!X509_VERIFY_PARAM_set1_email(vpm, ctx->verify_email, 0))
                return 0;
            vpmtouched++;
        }

        //case OPT_V_VERIFY_IP:
        if(ctx->verify_ip) {
            if (!X509_VERIFY_PARAM_set1_ip_asc(vpm, ctx->verify_ip))
                return 0;
            vpmtouched++;
        }

        if(verify_opts) {
            if(strstr(verify_opts, "ignore_critical"))  { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_IGNORE_CRITICAL); vpmtouched++; }
            if(strstr(verify_opts, "issuer_checks"))    { /*deprecated*/ }
            if(strstr(verify_opts, "crl_check"))        { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK); vpmtouched++; }
            if(strstr(verify_opts, "crl_check_all"))    { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL); vpmtouched++; }
            if(strstr(verify_opts, "explicit_policy"))  { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_EXPLICIT_POLICY); vpmtouched++; }
            if(strstr(verify_opts, "inhibit_any"))      { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_INHIBIT_ANY); vpmtouched++; }
            if(strstr(verify_opts, "inhibit_map"))      { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_INHIBIT_MAP); vpmtouched++; }
            if(strstr(verify_opts, "x509_strict"))      { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_X509_STRICT); vpmtouched++; }
            if(strstr(verify_opts, "extended_crl"))     { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_EXTENDED_CRL_SUPPORT); vpmtouched++; }
            if(strstr(verify_opts, "use_deltas"))       { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_USE_DELTAS); vpmtouched++; }
            if(strstr(verify_opts, "policy_print"))     { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NOTIFY_POLICY); vpmtouched++; }
            if(strstr(verify_opts, "check_ss_sig"))     { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CHECK_SS_SIGNATURE); vpmtouched++; }
            if(strstr(verify_opts, "trusted_first"))    { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_TRUSTED_FIRST); vpmtouched++; }
            //"suiteB_128_only" ==> "suiteB_only_128"
            if(strstr(verify_opts, "suiteB_only_128"))  { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_128_LOS_ONLY); vpmtouched++; }
            if(strstr(verify_opts, "suiteB_128"))       { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_128_LOS); vpmtouched++; }
            if(strstr(verify_opts, "suiteB_192"))       { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_SUITEB_192_LOS); vpmtouched++; }
            if(strstr(verify_opts, "partial_chain"))    { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN); vpmtouched++; }
            if(strstr(verify_opts, "no_alt_chains"))    { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NO_ALT_CHAINS); vpmtouched++; }
            if(strstr(verify_opts, "no_check_time"))    { X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NO_CHECK_TIME); vpmtouched++; }
            if(strstr(verify_opts, "allow_proxy_certs")){ X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_ALLOW_PROXY_CERTS); vpmtouched++; }
        }

    }


    //argc = opt_num_rest();
    //argv = opt_rest();
    if (trusted != NULL && (CAfile || CApath)) {
        printf("error:%s: Cannot use -trusted with -CAfile or -CApath\n", prog);
        goto end;
    }

    if ((store = setup_verify(CAfile, CApath, noCAfile, noCApath)) == NULL)
        goto end;

    X509_STORE_set_verify_cb(store, x509_verify_callback);

    if (vpmtouched)
        X509_STORE_set1_param(store, vpm);

    ERR_clear_error();

    if (crl_download)
        store_setup_crl_download(store);

    //ret = 0;
    ret = CMS_RET_OK;
    
    if (0) //(argc < 1) {
    {
        if (check(store, NULL, untrusted, trusted, crls, show_chain) != 1)
            ret = -1;
    
    } 
    else 
    {
        if(ctx->infile)
            if (check(store, ctx->infile, untrusted, trusted, crls, show_chain) != 1)
                ret = -1;
    }
    

 end:
    X509_VERIFY_PARAM_free(vpm);
    X509_STORE_free(ctx->store);
    sk_X509_pop_free(untrusted, X509_free);
    sk_X509_pop_free(trusted, X509_free);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
    release_engine(e);
    //return (ret < 0 ? 2 : ret);
    return CMS_RET_ERROR;
}



static int x509_verify_callback(int ok, X509_STORE_CTX *ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    if (!ok) {
        if (current_cert != NULL) {
            X509_NAME_print_ex(bio_err, X509_get_subject_name(current_cert), 0, get_nameopt());
            BIO_printf(bio_err, "\n");
        }
        BIO_printf(bio_err, "%serror %d at %d depth lookup: %s\n",
               X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] " : "",
               cert_error,
               X509_STORE_CTX_get_error_depth(ctx),
               X509_verify_cert_error_string(cert_error));

        IF_VERBOSE {
            printf("%serror %d at %d depth lookup: %s\n",
               X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] " : "",
               cert_error,
               X509_STORE_CTX_get_error_depth(ctx),
               X509_verify_cert_error_string(cert_error));               
        }
        switch (cert_error) {
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            policies_print(ctx);
            /* fall thru */
        case X509_V_ERR_CERT_HAS_EXPIRED:

            /*
             * since we are just checking the certificates, it is ok if they
             * are self signed. But we should still warn the user.
             */
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            /* Continue after extension errors too */
        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_INVALID_NON_CA:
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        case X509_V_ERR_INVALID_PURPOSE:
        case X509_V_ERR_CRL_HAS_EXPIRED:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            ok = 1;
        }

        return ok;

    }
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(ctx);
    if (!v_verbose)
        ERR_clear_error();
    return ok;
}


static int check(X509_STORE *ctx, 
                 const char *file,
                 STACK_OF(X509) *uchain, 
                 STACK_OF(X509) *tchain,
                 STACK_OF(X509_CRL) *crls, 
                 int show_chain)
{
    X509 *x = NULL;
    int i = 0, ret = 0;
    X509_STORE_CTX *csc;
    STACK_OF(X509) *chain = NULL;
    int num_untrusted;

printf("debug: check: %s\n", file);
    x = load_cert(file, FORMAT_PEM, "certificate file");
    if (x == NULL)
        goto end;

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        printf("error %s: X.509 store context allocation failed\n", (file == NULL) ? "stdin" : file);
        goto end;
    }

    X509_STORE_set_flags(ctx, vflags);
    if (!X509_STORE_CTX_init(csc, ctx, x, uchain)) {
        X509_STORE_CTX_free(csc);
        printf("error %s: X.509 store context initialization failed\n", (file == NULL) ? "stdin" : file);
        goto end;
    }
    if (tchain != NULL)
        X509_STORE_CTX_set0_trusted_stack(csc, tchain);
    if (crls != NULL)
        X509_STORE_CTX_set0_crls(csc, crls);
    i = X509_verify_cert(csc);
    if (i > 0 && X509_STORE_CTX_get_error(csc) == X509_V_OK) {
        printf("%s: OK\n", (file == NULL) ? "stdin" : file);
        ret = 1;
        if (show_chain) {
            int j;

            chain = X509_STORE_CTX_get1_chain(csc);
            num_untrusted = X509_STORE_CTX_get_num_untrusted(csc);
            printf("Chain:\n");
            for (j = 0; j < sk_X509_num(chain); j++) {
                X509 *cert = sk_X509_value(chain, j);
                printf("depth=%d: ", j);
                X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, get_nameopt());
                if (j < num_untrusted)
                    printf(" (untrusted)");
                printf("\n");
            }
            sk_X509_pop_free(chain, X509_free);
        }
    } else {
        printf("error %s: verification failed\n", (file == NULL) ? "stdin" : file);
    }
    X509_STORE_CTX_free(csc);

 end:
    if (i <= 0)
        ERR_print_errors(bio_err);
    X509_free(x);

    return ret;
}

static int cb(int ok, X509_STORE_CTX *ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    if (!ok) {
        if (current_cert != NULL) {
            X509_NAME_print_ex(bio_err, X509_get_subject_name(current_cert), 0, get_nameopt());
            BIO_printf(bio_err, "\n");
        }
        BIO_printf(bio_err, "%serror %d at %d depth lookup: %s\n",
               X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] " : "",
               cert_error,
               X509_STORE_CTX_get_error_depth(ctx),
               X509_verify_cert_error_string(cert_error));
        switch (cert_error) {
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            policies_print(ctx);
            /* fall thru */
        case X509_V_ERR_CERT_HAS_EXPIRED:

            /*
             * since we are just checking the certificates, it is ok if they
             * are self signed. But we should still warn the user.
             */
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            /* Continue after extension errors too */
        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_INVALID_NON_CA:
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        case X509_V_ERR_INVALID_PURPOSE:
        case X509_V_ERR_CRL_HAS_EXPIRED:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            ok = 1;
        }

        return ok;

    }
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(ctx);
    if (!v_verbose)
        ERR_clear_error();
    return ok;
}
