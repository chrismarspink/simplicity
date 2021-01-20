#include <stdio.h>
#include <string.h>

# include <openssl/crypto.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/x509_vfy.h>
# include <openssl/x509v3.h>
# include <openssl/cms.h>
# include <openssl/evp.h>
# include <openssl/ui.h>

# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include <assert.h>
//# include "progs.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/obj_mac.h>


#include "gzpki_types.h"
#include "gzpki_common.h"
#include "gzpki_ecc.h"


//커브 종류만을 출력
//필드에서는 불필요함 함수
int print_ecdsa_curves(int add_comment)
{
    
    EC_builtin_curve *curves = NULL;
    size_t crv_len = EC_get_builtin_curves(NULL, 0);
    size_t n;
    int ret = CMS_RET_UNDEF;


    curves = app_malloc((int)sizeof(*curves) * crv_len, "list curves");
    if (!EC_get_builtin_curves(curves, crv_len)) {
        OPENSSL_free(curves);
        goto end;
    }

    for (n = 0; n < crv_len; n++) {
        const char *comment;
        const char *sname;
        comment = curves[n].comment;
        sname = OBJ_nid2sn(curves[n].nid);
        if (comment == NULL)
            comment = "CURVE DESCRIPTION NOT AVAILABLE";
        if (sname == NULL)
            sname = "";

        if(strcmp(sname, "Oakley-EC2N-3") && strcmp(sname, "Oakley-EC2N-4")) {
            if(add_comment==1) {
                printf("%-10s: ", sname);
                printf("%s\n", comment);
            }
            else {
                printf("%s\n", sname);                
            }
        }
        
    }

    OPENSSL_free(curves);
    ret = 0;
    goto end;

    return CMS_RET_OK;    

end:
    #if 0
        BN_free(ec_p);
        BN_free(ec_a);
        BN_free(ec_b);
        BN_free(ec_gen);
        BN_free(ec_order);
        BN_free(ec_cofactor);
        OPENSSL_free(buffer);
        EC_GROUP_free(group);
        release_engine(e);
        BIO_free(in);
        BIO_free_all(out);
    #endif
    
    return CMS_RET_ERROR;    
}

int ECPARAM_init_ctx(GZPKI_CTX *ctx)
{
#if 1
    gzpki_common_context_init(ctx);
#else
    ctx->form  = POINT_CONVERSION_UNCOMPRESSED;
    ctx->asn1_flag = OPENSSL_EC_NAMED_CURVE;
    ctx->new_asn1_flag = 0;
    ctx->informat = ctx->outformat = FORMAT_PEM;
    ctx->noout = ctx->C = ctx->new_asn1_flag = 0;
    ctx->ret = 1;
    ctx->private = ctx->no_seed = ctx->check = ctx->new_form = ctx->text = ctx->genkey = 0;
    ctx->curve_name = NULL;
    ctx->ec_gen = ctx->ec_order = ctx->ec_cofactor = NULL;
    ctx->ec_p = ctx->ec_a = ctx->ec_b = NULL;
    ctx->infile = ctx->outfile = NULL;

    ctx->outtype = FORMAT_FILE;
    ctx->intype = FORMAT_FILE;  
#endif    
}

#if 0 //DELETE
int init_eccparam_ctx(GZPKI_CTX *ctx)
{
    //========================================
    //init context
    //========================================
    ctx->form  = POINT_CONVERSION_UNCOMPRESSED;
    ctx->asn1_flag = OPENSSL_EC_NAMED_CURVE;
    ctx->new_asn1_flag = 0;
    ctx->informat = ctx->outformat = FORMAT_PEM;
    ctx->noout = ctx->C = ctx->new_asn1_flag = 0;
    ctx->ret = 1;
    ctx->private = ctx->no_seed = ctx->check = ctx->new_form = ctx->text = ctx->genkey = 0;
    ctx->curve_name = NULL;
    ctx->ec_gen = ctx->ec_order = ctx->ec_cofactor = NULL;
    ctx->ec_p = ctx->ec_a = ctx->ec_b = NULL;
    ctx->infile = ctx->outfile = NULL;

    ctx->outtype = FORMAT_FILE;
    ctx->intype = FORMAT_FILE;
    
    //ctx->noout = 1;
}
#endif

//int set_eccparam_curve_name(GZPKI_CTX *ctx, char *curve_name);

int ECPARAM_set_curve_name(GZPKI_CTX *ctx, char *curve_name)
{
    ctx->curve_name = GZPKI_strdup(curve_name);
    if(ctx->curve_name)
        return CMS_RET_OK;

    return CMS_RET_ERROR;
}


#if 0
int set_eccparam_infile(GZPKI_CTX *ctx, char *infile, int informat)
{
    if(infile == NULL) {
        return CMS_RET_ERROR;
    }
    
    ctx->infile = GZPKI_strdup(infile);
    ctx->informat = informat;

    ctx->in = bio_open_default(ctx->infile, 'r', ctx->informat);
    if (ctx->in == NULL) {
        return CMS_RET_ERROR;
    }
    return CMS_RET_OK;
}

int set_eccparam_inbuffer(GZPKI_CTX *ctx, char *inbuffer, int inbuffer_size)
{
    if(inbuffer == NULL || inbuffer_size < 1) {
        CMS_RET_ERROR;
    }
    
    ctx->in = BIO_new(BIO_s_mem());
    ctx->outtype = FORMAT_MEM;
    
    if(ctx->informat == FORMAT_SMIME || ctx->informat == FORMAT_PEM) {
        ctx->in = BIO_new_mem_buf(ctx->inbuffer, -1);
    }
    else if(ctx->informat == FORMAT_ASN1) {
        ctx->in = BIO_new_mem_buf(ctx->inbuffer, ctx->inbuffer_size);
    }
    
    return CMS_RET_OK;
}

int set_eccparam_outfile(GZPKI_CTX *ctx, char *outfile, int outformat) {
    
    if(outfile == NULL) {
        ctx->outtype = FORMAT_MEM;
        ctx->outformat = outformat;
        ctx->out = BIO_new(BIO_s_mem());
        return CMS_RET_OK;
    }

    ctx->outfile = GZPKI_strdup(outfile);
    ctx->outformat = outformat;

    ctx->out = bio_open_owner(ctx->outfile, ctx->outformat, ctx->private);
    if (ctx->out == NULL) {
        return CMS_RET_ERROR;
    }
    ctx->outtype = FORMAT_FILE;
    return CMS_RET_OK;
}
#endif






#if 1
int GZPKI_do_ECPARAM(GZPKI_CTX *ctx)
{
    int ret = CMS_RET_ERROR;
    int i = 0;
    EC_GROUP *group = NULL;

    ctx->private = ctx->genkey ? 1 : 0;

    IF_VERBOSE fprintf(stderr, "GZPKI_do_ECPARAM(): %s\n", ctx->curve_name);
    
    if (ctx->curve_name != NULL) {
        int nid;
        if (strcmp(ctx->curve_name, "secp192r1") == 0) {
            sprintf(ctx->errstr, "using curve name prime192v1 instead of secp192r1");
            nid = NID_X9_62_prime192v1;
        } else if (strcmp(ctx->curve_name, "secp256r1") == 0) {
            sprintf(ctx->errstr, "using curve name prime256v1 instead of secp256r1");
            nid = NID_X9_62_prime256v1;
        } else {
            nid = OBJ_sn2nid(ctx->curve_name);
        }

        if (nid == 0)
            nid = EC_curve_nist2nid(ctx->curve_name);

        if (nid == 0) {
            sprintf(ctx->errstr, "unknown curve name (%s)", ctx->curve_name);
            ctx->errcode = 100;
            ret = CMS_RET_ERROR;
            goto end;
        }

        ctx->group = EC_GROUP_new_by_curve_name(nid);

        if (ctx->group == NULL) {
            sprintf(ctx->errstr, "unable to create curve (%s)", ctx->curve_name);
            ctx->errcode = 101;
            ret = CMS_RET_ERROR;
            goto end;
        }
        
        EC_GROUP_set_asn1_flag(ctx->group, ctx->asn1_flag); //OPENSSL_EC_NAMED_CURVE
        EC_GROUP_set_point_conversion_form(ctx->group, ctx->form);
    } else if (ctx->informat == FORMAT_ASN1) {
        ctx->group = d2i_ECPKParameters_bio(ctx->in, NULL);
    } else {
        ctx->group = PEM_read_bio_ECPKParameters(ctx->in, NULL, NULL, NULL);
    }
    if (ctx->group == NULL) {
        sprintf(ctx->errstr, "unable to load elliptic curve parameters");
        //ERR_print_errors(bio_err);
        ctx->errcode = 102;
        ret = CMS_RET_ERROR;
        goto end;
    }

    if (ctx->new_form)
        EC_GROUP_set_point_conversion_form(ctx->group, ctx->form);

    if (ctx->new_asn1_flag)
        EC_GROUP_set_asn1_flag(ctx->group, ctx->asn1_flag);

    if (ctx->no_seed) {
        EC_GROUP_set_seed(ctx->group, NULL, 0);
    }

    if (ctx->text) {
        if (!ECPKParameters_print(ctx->out, ctx->group, 0)) {
            ctx->errcode = 103;
            ret = CMS_RET_ERROR;
            goto end;
        }
    }

    if (ctx->check) {
        if (!EC_GROUP_check(ctx->group, NULL)) {
            ctx->errcode = 104;
            sprintf(ctx->errstr, "%d:checking elliptic curve parameters: failed", ctx->errcode);
            //ERR_print_errors(bio_err);
            ret = CMS_RET_ERROR;
            goto end;
        }
        sprintf(ctx->errstr, "checking elliptic curve parameters: ok");
    }

    if (ctx->outformat == FORMAT_ASN1 && ctx->genkey)
        ctx->noout = 1;

    if (!ctx->noout) {
        if (ctx->outformat == FORMAT_ASN1) {
            i = i2d_ECPKParameters_bio(ctx->out, ctx->group);
        }
        else {
            i = PEM_write_bio_ECPKParameters(ctx->out, ctx->group);
        }
        if (!i) {
            sprintf(ctx->errstr, "unable to write elliptic curve parameters");
            //ERR_print_errors(bio_err);
            ctx->errcode = 105;
            ret = CMS_RET_ERROR;
            goto end;
        }
    }

    if (ctx->genkey) {
        EC_KEY *eckey = EC_KEY_new();

        if (eckey == NULL) {
            sprintf(ctx->errstr, "fail to generate EC key");
            ctx->errcode = 106;
            ret = CMS_RET_ERROR;
            goto end;
        }

        if (EC_KEY_set_group(eckey, ctx->group) == 0) {
            sprintf(ctx->errstr, "unable to set group when generating key\n");
            EC_KEY_free(eckey);
            //ERR_print_errors(bio_err);
            ctx->errcode = 107;
            ret = CMS_RET_ERROR;
            goto end;
        }

        if (ctx->new_form)
            EC_KEY_set_conv_form(eckey, ctx->form);

        if (!EC_KEY_generate_key(eckey)) {
            sprintf(ctx->errstr, "unable to generate key\n");
            EC_KEY_free(eckey);
            //ERR_print_errors(bio_err);
            ctx->errcode = 108;
            ret = CMS_RET_ERROR;
            goto end;
        }
        assert(ctx->private);
        if (ctx->outformat == FORMAT_ASN1) {
            //printf("ctx->outformat == FORMAT_ASN1\n");
            i = i2d_ECPrivateKey_bio(ctx->out, eckey);
        }
//add jkkim
        else if(ctx->cipher && ctx->passout)
        {
            //printf("PEM_write_bio_ECPrivateKey: passout: [%s]\n", ctx->passout);
            i = PEM_write_bio_ECPrivateKey(ctx->out, eckey, ctx->cipher, NULL, 0, NULL, ctx->passout);
        }
//add end
        else {
            //printf("PEM_write_bio_ECPrivateKey\n");
            i = PEM_write_bio_ECPrivateKey(ctx->out, eckey, NULL, NULL, 0, NULL, NULL);
        }
        EC_KEY_free(eckey);
    }

    ret = CMS_RET_OK;
 end:
    BIO_flush(ctx->out);
    
    return ret;
}
#endif  //generate_ecparam


#if 0 //DELETE
int ecparam_context_free(GZPKI_CTX *ctx)
{
    BN_free(ctx->ec_p);
    BN_free(ctx->ec_a);
    BN_free(ctx->ec_b);
    BN_free(ctx->ec_gen);
    BN_free(ctx->ec_order);
    BN_free(ctx->ec_cofactor);
    //OPENSSL_free(ctx->buffer);
    EC_GROUP_free(ctx->group);
    //gzpki: no engine : release_engine(e);
    if(ctx->in) BIO_free(ctx->in);
    if(ctx->out) BIO_free_all(ctx->out);
    }
#endif 

//====================================
// APPSC : ADDED
//====================================

void print_bignum_var(BIO *out, const BIGNUM *in, const char *var, int len, unsigned char *buffer) {
    BIO_printf(out, "    static unsigned char %s_%d[] = {", var, len);
    if (BN_is_zero(in)) {
        BIO_printf(out, "\n        0x00");
    } else {
        int i, l;

        l = BN_bn2bin(in, buffer);
        for (i = 0; i < l; i++) {
            BIO_printf(out, (i % 10) == 0 ? "\n        " : " ");
            if (i < l - 1)
                BIO_printf(out, "0x%02X,", buffer[i]);
            else
                BIO_printf(out, "0x%02X", buffer[i]);
        }
    }
    BIO_printf(out, "\n    };\n");
}

BIO *bio_open_owner(const char *filename, int format, int private)
{
    FILE *fp = NULL;
    BIO *b = NULL;
    int fd = -1, bflags, mode, textmode;

    if (!private || filename == NULL || strcmp(filename, "-") == 0)
        return bio_open_default(filename, 'w', format);

    mode = O_WRONLY;
#ifdef O_CREAT
    mode |= O_CREAT;
#endif
#ifdef O_TRUNC
    mode |= O_TRUNC;
#endif
    textmode = istext(format);
    if (!textmode) {
#ifdef O_BINARY
        mode |= O_BINARY;
#elif defined(_O_BINARY)
        mode |= _O_BINARY;
#endif
    }

#ifdef OPENSSL_SYS_VMS
    /* VMS doesn't have O_BINARY, it just doesn't make sense.  But,
     * it still needs to know that we're going binary, or fdopen()
     * will fail with "invalid argument"...  so we tell VMS what the
     * context is.
     */
    if (!textmode)
        fd = open(filename, mode, 0600, "ctx=bin");
    else
#endif
        fd = open(filename, mode, 0600);
    if (fd < 0)
        goto err;
    fp = fdopen(fd, modestr('w', format));
    if (fp == NULL)
        goto err;
    bflags = BIO_CLOSE;
    if (textmode)
        bflags |= BIO_FP_TEXT;
    b = BIO_new_fp(fp, bflags);
    if (b)
        return b;

 err:
    printf("error: Can't open \"%s\" for writing, %s\n", filename, strerror(errno));
    //ERR_print_errors(bio_err);
    /* If we have fp, then fdopen took over fd, so don't close both. */
    if (fp)
        fclose(fp);
    else if (fd >= 0)
        close(fd);
    return NULL;
}



#if 0
int gzec_context_free(GZECC_CTX *ctx) {

    if(ctx->in) BIO_free(ctx->in);
    if(ctx->out) BIO_free_all(ctx->out);
    //if(ctx->eckey) EC_KEY_free(ctx->eckey);
    //release_engine(e);
    //if(ctx->passin) OPENSSL_free(ctx->passin);
    //if(ctx->passout) OPENSSL_free(ctx->passout);
}
#endif

#if 0 //DELETE
int gzec_context_init(GZECC_CTX *ctx) {

    ctx->in = NULL;
    ctx->out = NULL;
    ctx->infile = NULL;
    ctx->outfile = NULL;
    ctx->informat = FORMAT_PEM;
    ctx->outformat = FORMAT_PEM;
    ctx->noout = CMS_OPT_OFF;
    ctx->text = CMS_OPT_OFF;
    ctx->param_out = CMS_OPT_OFF;
    ctx->pubin = CMS_OPT_OFF;
    ctx->pubout = CMS_OPT_OFF;
    ctx->passinarg = NULL;
    ctx->passoutarg = NULL;
    ctx->passin = NULL;
    ctx->passout = NULL;
    ctx->no_public = CMS_OPT_OFF;
    ctx->name = "aes128";
    ctx->enc = EVP_get_cipherbyname(ctx->name); 
    ctx->check = CMS_OPT_OFF;
    ctx->private = CMS_OPT_OFF;  //TODO
    ctx->form = POINT_CONVERSION_UNCOMPRESSED;
    ctx->asn1_flag = OPENSSL_EC_NAMED_CURVE;
    ctx->new_form = CMS_OPT_OFF;
    ctx->new_asn1_flag = CMS_OPT_OFF;

    ctx->intype = FORMAT_FILE;
    ctx->outtype = FORMAT_FILE; //or FORMAT_MEM;

    return CMS_RET_OK;
}
#endif

int GZPKI_do_ECC(GZPKI_CTX *ctx)
{
    int ret = CMS_RET_UNDEF;
    BIO *in = NULL, *out = NULL;
    //ENGINE *e = NULL;
    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    const EVP_CIPHER *enc = NULL;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    char *infile = NULL, *outfile = NULL;
    char *passin = NULL, *passout = NULL, *passinarg = NULL, *passoutarg = NULL;
    //OPTION_CHOICE o;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE, new_form = 0, new_asn1_flag = 0;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM, text = 0, noout = 0;
    int pubin = 0, pubout = 0, param_out = 0, i, /*ret = 1,*/ private = 0;
    int no_public = 0, check = 0;
    int intype, outtype;

    intype = ctx->intype;
    outtype = ctx->outtype;

    infile = ctx->infile;
    outfile = ctx->outfile;

    asn1_flag = ctx->asn1_flag;
    new_form = ctx->new_form;
    new_asn1_flag = ctx->new_asn1_flag;
    informat = ctx->informat;
    outformat = ctx->informat;
    in = ctx->in;
    out = ctx->out;
    noout = ctx->noout;
    text = ctx->text;
    param_out = ctx->param_out;
    pubin = ctx->pubin;
    pubout =  ctx->pubout;

    passin = ctx->passin;
    passout = ctx->passout;
    passinarg = ctx->passinarg;
    passoutarg = ctx->passoutarg;

    enc = EVP_get_cipherbyname(ctx->name); //opt_cipher(opt_unknown(), &enc)
    no_public = ctx->no_public;
    check = ctx->check;
    private = ctx->private = 0;  //TODO
    
            
#if 0
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONV_FORM:
            if (!opt_pair(opt_arg(), conv_forms, &i)) goto opthelp;
            new_form = form = i;
            break;
        case OPT_PARAM_ENC:
            if (!opt_pair(opt_arg(), param_enc, &i)) goto opthelp;
            new_asn1_flag = asn1_flag = i;
            break;
        ...
    }
#endif    
    private = ctx->param_out || ctx->pubin || ctx->pubout ? 0 : 1;
    if (ctx->text && !ctx->pubin)
        private = 1;

    if (!app_passwd(ctx->passinarg, ctx->passoutarg, &ctx->passin, &ctx->passout)) {
        printf("Error getting passwords\n");
        ret = CMS_RET_ERROR;
        goto end;
    }


#if 1
    //GZPKI_set_infile(GZPKI_CTX *ctx, char *infile, char *inbuffer, int inbuffer_size, int informat);
    //을 사전에 수행한다. 

#else
    if (intype == FORMAT_FILE) {
        in = bio_open_default(infile, 'r', informat);
        if (in == NULL){
            ret = CMS_RET_ERROR;
            goto end;
        }
    }
    else if(intype == FORMAT_FILE) {
        // code ....
    }
#endif 

    IF_VERBOSE fprintf(stdout, "EC key reading...\n");
    if (informat == FORMAT_ASN1) {
        if (pubin)
            eckey = d2i_EC_PUBKEY_bio(in, NULL);
        else
            eckey = d2i_ECPrivateKey_bio(in, NULL);
    
    } 
#if 0    
    else if (informat == FORMAT_ENGINE) {
        EVP_PKEY *pkey;
        if (pubin)
            pkey = load_pubkey(infile, informat, 1, passin, e, "Public Key");
        else
            pkey = load_key(infile, informat, 1, passin, e, "Private Key");
        if (pkey != NULL) {
            eckey = EVP_PKEY_get1_EC_KEY(pkey);
            EVP_PKEY_free(pkey);
        }
    } 
#endif    
    else {
        if (pubin)
            eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL);
        else
            eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, passin);
    }
    if (eckey == NULL) {
        printf("unable to load Key\n");
        //ERR_print_errors(bio_err);
        ret = CMS_RET_ERROR;
        goto end;
    }

    out = bio_open_owner(outfile, outformat, private);
    if (out == NULL) {
        ret = CMS_RET_ERROR;
        goto end;
    }

    group = EC_KEY_get0_group(eckey);

    if (new_form)
        EC_KEY_set_conv_form(eckey, form);

    if (new_asn1_flag)
        EC_KEY_set_asn1_flag(eckey, asn1_flag);

    if (no_public)
        EC_KEY_set_enc_flags(eckey, EC_PKEY_NO_PUBKEY);

    if (text) {
        assert(pubin || private);
        if (!EC_KEY_print(out, eckey, 0)) {
            perror(outfile);
            //ERR_print_errors(bio_err);
            ctx->errcode = -1000;
            ret = CMS_RET_ERROR;
            goto end;
        }
    }

    if (check) {
        if (EC_KEY_check_key(eckey) == 1) {
            printf("EC Key valid.\n");
        } else {
            ctx->errcode = -1001;
            printf("EC Key Invalid!\n");
            //ERR_print_errors(bio_err);
        }
    }

    if (noout) {
        ctx->errcode = -1002;
        //ret = 0;
        ret = CMS_RET_ERROR;
        goto end;
    }

    printf("writing EC key\n");
    if (outformat == FORMAT_ASN1) {
        if (param_out) {
            i = i2d_ECPKParameters_bio(out, group);
        } else if (pubin || pubout) {
            i = i2d_EC_PUBKEY_bio(out, eckey);
        } else {
            assert(private);
            i = i2d_ECPrivateKey_bio(out, eckey);
        }
    } else {
        if (param_out) {
            i = PEM_write_bio_ECPKParameters(out, group);
        } else if (pubin || pubout) {
            i = PEM_write_bio_EC_PUBKEY(out, eckey);
        } else {
            assert(private);
            i = PEM_write_bio_ECPrivateKey(out, eckey, enc, NULL, 0, NULL, passout);
        }
    }

    if (!i) {
        ctx->errcode = -1003;
        ret = CMS_RET_ERROR;
        printf("unable to write private key\n");
        //ERR_print_errors(bio_err);
    } else {
        ret = CMS_RET_OK;
    }

 end:
    BIO_flush(out);
    /*
    EC_KEY_free(eckey);
    

    //check below
    BIO_free(in);
    BIO_free_all(out);
    
    //release_engine(e);
    OPENSSL_free(passin);
    OPENSSL_free(passout);
    */
    return ret;
}




//--------------------------------------------------------------------------------
//SM2_enrypt() new version for GZCMM
//--------------------------------------------------------------------------------

#if 1

/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/sm2.h"
#include "crypto/sm2err.h"
#include "crypto/ec.h" /* ecdh_KDF_X9_63() */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>

#if 1
    typedef struct CMMP1_Ciphertext_st CMMP1_Ciphertext;
    DECLARE_ASN1_FUNCTIONS(CMMP1_Ciphertext)

    struct CMMP1_Ciphertext_st {
        BIGNUM *C1x;
        BIGNUM *C1y;
        ASN1_OCTET_STRING *C2;
    };

    ASN1_SEQUENCE(CMMP1_Ciphertext) = {
        ASN1_SIMPLE(CMMP1_Ciphertext, C1x, BIGNUM),
        ASN1_SIMPLE(CMMP1_Ciphertext, C1y, BIGNUM),
        ASN1_SIMPLE(CMMP1_Ciphertext, C2, ASN1_OCTET_STRING),
    } ASN1_SEQUENCE_END(CMMP1_Ciphertext)

    IMPLEMENT_ASN1_FUNCTIONS(CMMP1_Ciphertext)
#endif

#if 1
    typedef struct CMM_Ciphertext_st CMM_Ciphertext;
    DECLARE_ASN1_FUNCTIONS(CMM_Ciphertext)

    struct CMM_Ciphertext_st {
        ASN1_OCTET_STRING *C2;
    };

    ASN1_SEQUENCE(CMM_Ciphertext) = {
        ASN1_SIMPLE(CMM_Ciphertext, C2, ASN1_OCTET_STRING),
    } ASN1_SEQUENCE_END(CMM_Ciphertext)

    IMPLEMENT_ASN1_FUNCTIONS(CMM_Ciphertext)
#endif 

static size_t ec_field_size(const EC_GROUP *group)
{
    /* Is there some simpler way to do this? */
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    size_t field_size = 0;

    if (p == NULL || a == NULL || b == NULL)
       goto done;

    if (!EC_GROUP_get_curve(group, p, a, b, NULL))
        goto done;
    field_size = (BN_num_bits(p) + 7) / 8;

 done:
    BN_free(p);
    BN_free(a);
    BN_free(b);

    return field_size;
}


int CMM_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len, size_t *pt_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t overhead;

	
	IF_VERBOSE fprintf(stderr, "plain text size = %ld\n", msg_len);
	IF_VERBOSE fprintf(stderr, "ecc field size = %ld\n", field_size);
	

    if (md_size < 0) {
        printf("CMMP2(CMMP2_F_CMMP2_PLAINTEXT_SIZE, CMMP2_R_INVALID_DIGEST)\n");
        return 0;
    }
    
    if (field_size == 0) {
        printf("CMMP2err(CMMP2_F_CMMP2_PLAINTEXT_SIZE, CMMP2_R_INVALID_FIELD)\n");
        return 0;
    }
	//printf("NOTICE: CMM_plaintext_size(): msg_len=%d\n", msg_len);
	
    //overhead = 10 + 2 * field_size + (size_t)md_size;
    overhead = 10 + 2 * field_size /*+ (size_t)md_size*/;
	
	IF_VERBOSE fprintf(stderr, "cmm plain text size: overhead=%ld\n", overhead);
	
    if (msg_len <= overhead) {
        printf("CMMP2err(CMMP2_F_CMMP2_PLAINTEXT_SIZE, CMMP2_F_CMMP2_PLAINTEXT_SIZE)\n");
        //printf("msg_len: %ld <= ", msg_len);
        //printf("overhead: %ld\n", overhead);
        return 0;
    }

    *pt_size = msg_len - overhead;
	IF_VERBOSE printf("*pt_size=%ld\n", *pt_size);
    return 1;
}



int CMM_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len, size_t *ct_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t sz;

    if (field_size == 0 )
        return 0;

    printf("CMM_ciphertext_size()...\n");

    /* Integer and string are simple type; set constructed = 0, means primitive and definite length encoding. */
    sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
	    //+ ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
         + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
    /* Sequence is structured type; set constructed = 1, means constructed and definite length encoding. */
    *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);
    IF_VERBOSE printf("CMM cipher text size: %ld\n", *ct_size);

    return 1;
}


//check and remove
#if 0

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------

int CMM01_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len, uint8_t *ciphertext_buf, size_t *ciphertext_len)
{
    int rc = 0, ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    struct SM2_Ciphertext_st ctext_struct;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *C3 = NULL;
    size_t field_size;
    const int C3_size = EVP_MD_size(digest);

    /* NULL these before any "goto done" */
    ctext_struct.C2 = NULL;
    ctext_struct.C3 = NULL;

    if (hash == NULL || C3_size <= 0) {
    //if (hash == NULL) {
	    printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    field_size = ec_field_size(group);
    
    if (field_size == 0) {
		printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_BN_LIB);
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    C3 = OPENSSL_zalloc(C3_size);

    if (x2y2 == NULL || C3 == NULL) {
    //if (x2y2 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memset(ciphertext_buf, 0, *ciphertext_len);

	//BN_rand_range() generates a cryptographically strong pseudo-random number rnd in the range 0 <= rnd < range.	
	//BN_priv_rand() and BN_priv_rand_range() have the same semantics as BN_rand() and BN_rand_range() respectively. 
	//They are intended to be used for generating values that should remain private, 
	//and mirror the same difference between RAND_bytes(3) and RAND_priv_bytes(3).
    if (!BN_priv_rand_range(k, order)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    //--------------------------------------------------
    // k를 fix
    // BIGNUM *k = NULL;
    //--------------------------------------------------
    //int len = 0;
    //len = BN_num_bits(order);
    //printf("random bit generator: ORDER ["color_blue_b"%d"color_reset"] BITS\n", len);
    //len = BN_bn2bin()

	//int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
	///EC_POINT_mul calculates the value generator * n + q * m 
	// and stores the result in r. 
	//The value n may be NULL in which case the result is just q * m.
    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0 || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    if (EVP_DigestInit(hash, digest) == 0
            || EVP_DigestUpdate(hash, x2y2, field_size) == 0
            || EVP_DigestUpdate(hash, msg, msg_len) == 0
            || EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0
            || EVP_DigestFinal(hash, C3, NULL) == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    //x1, y1 remove
    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;
    ctext_struct.C3 = ASN1_OCTET_STRING_new();
    ctext_struct.C2 = ASN1_OCTET_STRING_new();

    //x1과 y1을 BN으로 따로 뺀다.
    //int len_x1 = BN_bn2bin(x1);
    printf("CMM_encrypt(): x1 = [%s]\n", BN_bn2hex(x1));
    
    //int len_x2 = BN_bn2bin(x2);
    printf("CMM_encrypt(): x2 = [%s]\n", BN_bn2hex(x2));

    if (ctext_struct.C3 == NULL || ctext_struct.C2 == NULL) {

       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
    }

	//fix only this
    //if (!ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size) || !ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
    if (!ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);
    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    rc = 1;

 done:
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(C3);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}
#endif


#if 0
//modified version for GZCMM
//take ciphertext without hash
int CMM01_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len)
{
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct SM2_Ciphertext_st *sm2_ctext = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const int hash_size = EVP_MD_size(digest);
    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;

#if 0 //from encrypt
	BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
#endif 	

    if (field_size == 0 || hash_size <= 0)
       goto done;

    printf("CMM_decrypt: field_size = %d\n", field_size);
    printf("CMM_decrypt: hash_size = %d\n", hash_size);
    printf("CMM_decrypt: *ptext_len = %d\n", *ptext_len);
    
    memset(ptext_buf, 0xFF, *ptext_len);
    
    printf("d2i_SM2_Ciphertext BEGIN\n");

    printf("CMM_decrypt: ciphertext_len = %d\n", ciphertext_len);

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

    printf("d2i_SM2_Ciphertext END\n");
    

    if (sm2_ctext == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_ASN1_ERROR);
        goto done;
    }

    /*
    if (sm2_ctext->C3->length != hash_size) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_ENCODING);
        goto done;
    }*/

    C2 = sm2_ctext->C2->data;
    C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_BN_LIB);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    //computed_C3 = OPENSSL_zalloc(hash_size);

    //if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL) {
    if (msg_mask == NULL || x2y2 == NULL ) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x, sm2_ctext->C1y, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

	/*
    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, x2y2, field_size)
            || !EVP_DigestUpdate(hash, ptext_buf, msg_len)
            || !EVP_DigestUpdate(hash, x2y2 + field_size, field_size)
            || !EVP_DigestFinal(hash, computed_C3, NULL)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EVP_LIB);
        goto done;
    }
    */
	
	/*
    if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_DIGEST);
        goto done;
    }*/

    rc = 1;
    *ptext_len = msg_len;

 done:
    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    //OPENSSL_free(computed_C3);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    SM2_Ciphertext_free(sm2_ctext);
    //EVP_MD_CTX_free(hash);

    return rc;
}

#endif 

//============================
#if 1


#if 0

int CMM_P2_generate_secret(const EC_KEY *key,  char *share_k, char *share_x1, char *share_x2)
{
    int rc = 0, ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    struct SM2_Ciphertext_st ctext_struct;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *C3 = NULL;
    size_t field_size;
    
    printf("CMM_asymm_gen_secret. BEGIN\n");

    field_size = ec_field_size(group);
    
    if (field_size == 0) {
		printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_BN_LIB);
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    
    if (x2y2 == NULL) {
        printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE)\n");
        goto done;
    }

    if (!BN_priv_rand_range(k, order)) {
        printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }
    printf("k: %s\n", BN_bn2hex(k) );
    memset(sharedK, 0, sizeof(sharedK));
    sprintf(sharedK, "%s",  BN_bn2hex(k)  );

    
    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        printf("ERROR: SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB)\n");
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0 || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }

    
    printf("X1: %s \n", BN_bn2hex(x1) );
    printf("X1: %s \n", BN_bn2hex(y1) );
    

    
    sprintf(&sharedX1, "%s", BN_bn2hex(x1) );
    sprintf(&sharedY1, "%s", BN_bn2hex(y1) );
    

    
 done:
    //ASN1_OCTET_STRING_free(ctext_struct.C2);
    //ASN1_OCTET_STRING_free(ctext_struct.C3);
    //OPENSSL_free(msg_mask);
    //OPENSSL_free(x2y2);
    //OPENSSL_free(C3);
    //EVP_MD_CTX_free(hash);
    //BN_CTX_free(ctx);
    //EC_POINT_free(kG);
    //EC_POINT_free(kP);

    printf("BYE...\n");
    return rc;
}
#else


//#define CMM_P1_SAVE_X1      0
//#define CMM_P1_SAVE_Y1      1
//#define CMM_P1_SAVE_KE      2


int CMM_P2_save_secret(char *path, int opt)
{
	int r = 0;
    FILE *fp = NULL;
    char *mode = "wb";
    
    char filename[256];
    
    if(!path)
        return -1;
	struct stat st = {0};

    IF_VERBOSE fprintf(stderr, "CMM_P2_save_secret: dir=[%s]\n", path);
    if (stat(path, &st) == -1) {
        fprintf(stderr, "error:%d:%s", errno, strerror(errno) );
        return -1;
    }

    memset(filename, 0, sizeof(filename));
    
    if(opt == CMM_P1_SAVE_X1) {
        sprintf(filename, "%s/secret.x1", path);
    }
    else if(opt == CMM_P1_SAVE_Y1) {
        sprintf(filename, "%s/secret.y1", path);
    }
    else if(opt == CMM_P1_SAVE_KE) {
        sprintf(filename, "%s/secret.ke", path);
    }
    else {
        fprintf(stderr, "invalid save option: %d\n", opt);
    }
    
    fp = fopen(filename, "wb");
    if( fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", filename, strerror(errno));
        return -1;
    }

    if(opt == CMM_P1_SAVE_X1) {
        fwrite(sharedX1,sizeof(sharedX1),1,fp);
    }
    else if(opt == CMM_P1_SAVE_Y1) {
        fwrite(sharedY1,sizeof(sharedY1),1,fp);
    }
    else if(opt == CMM_P1_SAVE_KE) {
        fwrite(sharedK,sizeof(sharedK),1,fp);
    }
    else {
        fprintf(stderr, "invalid option: %d\n", opt);
    }

    fclose(fp);

    IF_VERBOSE fprintf(stderr, "cmm.p2.parameter:file: %s\n", filename);

	return 0;
}


#if 0
int CMM_P2_save_peer_secret(char *path, int opt, unsigned char *value, int length)
{
	int r = 0;
    FILE *fp = NULL;
    char mode = "wb";
    size_t size = -1;
    
    char filename[256];
    
    if(!path)
        return -1;
	struct stat st = {0};

    fprintf(stderr, "CMM_P2_save_secret: dir=[%s]\n", path);

    if (stat(path, &st) == -1) {
        fprintf(stderr, "error:%d:%s", errno, strerror(errno) );
        return -1;
    }

    memset(filename, 0, sizeof(filename));
    
    if(opt == CMM_P1_SAVE_X1) {
        sprintf(filename, "%s/secret.x1", path);
    }
    else if(opt == CMM_P1_SAVE_Y1) {
        sprintf(filename, "%s/secret.y1", path);
    }
    //K value never delivered
    //else if(opt == CMM_P1_SAVE_KE) {
    //    sprintf(filename, "%s/secret.ke", path);
    //}
    else {
        fprintf(stderr, "invalid save option: %d\n", opt);
    }
    
    fp = fopen(filename, "wb");
    if( fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:mkdir:%s, %s\n", filename, strerror(errno));
        return -1;
    }

    size = fwrite(value, length,1,fp);
    if(size < 1) {
        fprintf(stderr, "error:fail to write secret value: opt=%d\n", opt);
    }
    fclose(fp);

    fprintf(stdout, "cmm.p2.parameter: %s\n", filename);

	return 0;
}
#endif


int CMM_P2_read_secret(char *path, int opt)
{
	int r = 0;
    FILE *fp = NULL;
    char *mode = "wb";
    
    char filename[256];
    
    if(!path)
        return -1;
	struct stat st = {0};

    IF_VERBOSE fprintf(stderr, "CMM_P2_read_secret: dir=[%s]\n", path);

    if (stat(path, &st) == -1) {
        fprintf(stderr, "error:%d:%s", errno, strerror(errno) );
        return -1;
    }

    memset(filename, 0, sizeof(filename));
    
    if(opt == CMM_P1_SAVE_X1) {
        sprintf(filename, "%s/secret.x1", path);
    }
    else if(opt == CMM_P1_SAVE_Y1) {
        sprintf(filename, "%s/secret.y1", path);
    }
    else if(opt == CMM_P1_SAVE_KE) {
        sprintf(filename, "%s/secret.ke", path);
    }
    else {
        fprintf(stderr, "invalid save option: %d\n", opt);
    }
    
    //READ FROM FILE
    fp = fopen(filename, "rb");
    if( fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:mkdir:%s, %s\n", filename, strerror(errno));
        return -1;
    }

    if(opt == CMM_P1_SAVE_X1) {
        memset(sharedX1, 0, sizeof(sharedX1));
        fread(&sharedX1,sizeof(sharedX1),1,fp);
    }
    else if(opt == CMM_P1_SAVE_Y1) {
        memset(sharedY1, 0, sizeof(sharedY1));
        fread(&sharedY1,sizeof(sharedY1),1,fp);
    }
    else if(opt == CMM_P1_SAVE_KE) {
        memset(sharedK, 0, sizeof(sharedK));
        fread(&sharedK,sizeof(sharedK),1,fp);
    }
    else {
        fprintf(stderr, "invalid option: %d\n", opt);
    }

    fclose(fp);

    //fprintf(stdout, "read:cmm.p2.parameter: %s\n", filename);
    IF_VERBOSE {
        if(opt == CMM_P1_SAVE_X1) {
            fprintf(stderr, "X1:%s\n", sharedX1);
        }
        else if(opt == CMM_P1_SAVE_Y1) {
            fprintf(stderr, "Y1:%s\n", sharedY1);
        }
        else if(opt == CMM_P1_SAVE_KE) {
            fprintf(stderr, "K:%s\n", sharedK);
        }
    }

	return 0;
}


int CMM_P2_generate_secret(const EC_KEY *key,  char *share_k, char *share_x1, char *share_x2, char *path, int opt_save)
{
    int rc = 0;
    //int ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    
    struct CMM_Ciphertext_st ctext_struct;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    //uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;
    //uint8_t *C3 = NULL;
    size_t field_size;
    
    IF_VERBOSE printf("BEGIN:CMM_P2_generate_secret()\n");

    field_size = ec_field_size(group);
    if (field_size == 0) {
		printf("CMMP2err(CMMP2_F_CMMP2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        printf("ERROR: CMMPerr(CMMP2_F_CMMP2_ENCRYPT, ERR_R_MALLOC_FAILURE)\n");
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        printf("ERROR: CMMP2err(CMMP2_F_CMMP2_ENCRYPT, ERR_R_BN_LIB)\n");
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    
    if (x2y2 == NULL) {
        printf("ERROR: CMMP2err(CMMP2_F_CMMP2_ENCRYPT, ERR_R_MALLOC_FAILURE)\n");
        goto done;
    }

    if (!BN_priv_rand_range(k, order)) {
        printf("ERROR: CMMP2err(CMMP2_F_CMMP2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }
    fprintf(stdout, "KE: %s\n", BN_bn2hex(k) );
    
    memset(sharedK, 0, sizeof(sharedK));
    sprintf(sharedK, "%s",  BN_bn2hex(k));
    
    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        printf("ERROR: CMMP2err(CMMP2_F_SM2_ENCRYPT, ERR_R_EC_LIB)\n");
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0 || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        printf("ERROR: CMMP2err(CMMP2_F_CMMP2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }

    fprintf(stdout, "X1: %s \n", BN_bn2hex(x1) );
    fprintf(stdout, "X1: %s \n", BN_bn2hex(y1) );
    
    //sharedX1, sharedY1 -> global
    sprintf(sharedX1, "%s", BN_bn2hex(x1) );
    sprintf(sharedY1, "%s", BN_bn2hex(y1) );

    if(path) {
        //--------------------------------------------------
        //TODO check dir exists
        //--------------------------------------------------
        if(opt_save == CMM_P1_SAVE_X1 || opt_save == CMM_P1_SAVE_X1Y1 || opt_save == CMM_P1_SAVE_X1Y1KE )
            CMM_P2_save_secret(path, CMM_P1_SAVE_X1);
        if(opt_save == CMM_P1_SAVE_Y1 || opt_save == CMM_P1_SAVE_X1Y1 || opt_save == CMM_P1_SAVE_X1Y1KE )
            CMM_P2_save_secret(path, CMM_P1_SAVE_Y1);
        if(opt_save == CMM_P1_SAVE_KE || opt_save == CMM_P1_SAVE_X1Y1KE )
            CMM_P2_save_secret(path, CMM_P1_SAVE_KE);
    }
    

    
 done:
    
    OPENSSL_free(x2y2);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);

    IF_VERBOSE fprintf(stderr, "CMM_P2_generate_secret(): done.\n");
    return rc;
}
    

#endif



int CMM_P2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                //const uint8_t *msg,
                unsigned char *msg,
                int msg_len, unsigned char *ciphertext_buf, int *ciphertext_len)
{
    int rc = 0, ciphertext_leni;
    size_t i;
    int r = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    
    struct CMM_Ciphertext_st ctext_struct;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *C3 = NULL;
    size_t field_size;
    const int C3_size = EVP_MD_size(digest);
    

    /* NULL these before any "goto done" */
    ctext_struct.C2 = NULL;
    //ctext_struct.C3 = NULL;

    //if (hash == NULL || C3_size <= 0) {
    if (hash == NULL) {
	    printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    //fprintf(stderr, "BEGIN: CMM_P2_encrypt()...\n");

    field_size = ec_field_size(group);
    
    if (field_size == 0) {
		printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_BN_LIB);
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    //C3 = OPENSSL_zalloc(C3_size);

    //if (x2y2 == NULL || C3 == NULL) {
    if (x2y2 == NULL ) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memset(ciphertext_buf, 0, *ciphertext_len);

    r = BN_hex2bn(&k, sharedK);
    IF_VERBOSE printf("P2(K): "color_green"%s"color_reset"\n", BN_bn2hex(k));


    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB);
        goto done;
    }


    if (BN_bn2binpad(x2, x2y2, field_size) < 0 || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];
    
    ctext_struct.C2 = ASN1_OCTET_STRING_new();

    //x1과 y1을 BN으로 따로 뺀다.
    //int len_x1 = BN_bn2bin(x1);
    IF_VERBOSE printf("CMM_P2_encrypt(x1): "color_yellow"%s"color_reset"\n", BN_bn2hex(x1));
    IF_VERBOSE printf("CMM_P2_encrypt(y1): "color_blue"%s"color_reset"\n", BN_bn2hex(y1));

    //if (ctext_struct.C3 == NULL || ctext_struct.C2 == NULL) {
    if ( ctext_struct.C2 == NULL) {
       printf("SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE)\n");
       goto done;
    }

	//fix only this
    //if (!ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size) || !ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
    if (!ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        printf("SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR\n");
        goto done;
    }

    ciphertext_leni = i2d_CMM_Ciphertext(&ctext_struct, &ciphertext_buf);
    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        printf("SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR\n");
        goto done;
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    IF_VERBOSE printf("CMM_P2_encrypt(): ciphertext length = %d\n", *ciphertext_len);

    rc = 1;

 done:
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    //ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    //OPENSSL_free(C3);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}




//modified version for GZCMM
//take ciphertext without hash
int CMM_P2_decrypt(const EC_KEY *key, 
                //const EVP_MD *digest,
                //const uint8_t *ciphertext,
                const unsigned char *ciphertext, unsigned long ciphertext_len, 
                unsigned char *ptext_buf, int *ptext_len)
{
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct CMM_Ciphertext_st *sm2_ctext = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const EVP_MD *digest = EVP_sha256();
    //const int hash_size = EVP_MD_size(digest);
    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;

    //if (field_size == 0 || hash_size <= 0)
    if (field_size == 0)
       goto done;

    //IF_VERBOSE printf("__CMM_P2_decrypt: field_size = %ld\n", field_size);
    //IF_VERBOSE printf("__CMM_P2_decrypt: *ptext_len = %d\n", *ptext_len);
    memset(ptext_buf, 0xFF, *ptext_len);
    
    //IF_VERBOSE printf("d2i_CMM_Ciphertext BEGIN\n");
    //IF_VERBOSE printf("CMM_decrypt: ciphertext_len = %ld\n", ciphertext_len);
    sm2_ctext = d2i_CMM_Ciphertext(NULL, &ciphertext, (long)ciphertext_len);

    IF_VERBOSE printf("d2i_CMM_Ciphertext END\n");
    
    if (sm2_ctext == NULL) {
        fprintf(stderr,"CMMerr(SM2_F_SM2_DECRYPT, SM2_R_ASN1_ERROR)\n");
        goto done;
    }

    /*
    if (sm2_ctext->C3->length != hash_size) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_ENCODING);
        goto done;
    }*/

    C2 = sm2_ctext->C2->data;
    //C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;

    IF_VERBOSE printf("cmm_ctext->C2->length: %d\n", msg_len);
    

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        printf("CMMP2err(CMMP2_F_CMMP2_DECRYPT, ERR_R_MALLOC_FAILURE)\n");
        goto done;
    }

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_BN_LIB);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    //computed_C3 = OPENSSL_zalloc(hash_size);

    //if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL) {
    if (msg_mask == NULL || x2y2 == NULL ) {
        //printf("CMMP2err(CMMP2_F_CMMP2_DECRYPT, ERR_R_MALLOC_FAILURE)\n");
        printf("CMM_P2_ERR(DECRYPT, MALLOC): %s: %d\n", __FILE__, __LINE__);
        goto done;
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        printf("CMM_P2_ERR(EC_POINT_new): %s: %d\n", __FILE__, __LINE__);
        goto done;
    }

    BIGNUM *recoverX1 = NULL;
    BIGNUM *recoverY1 = NULL;
     
    BN_hex2bn(&recoverX1, sharedX1);
    BN_hex2bn(&recoverY1, sharedY1);

    //if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x, sm2_ctext->C1y, ctx)
    if (!EC_POINT_set_affine_coordinates(group, C1, recoverX1, recoverY1, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        printf("CMM_P2_ERR(EC_POINT_set_affine_coordinates): %s: %d\n", __FILE__, __LINE__);
        ERR_print_errors_fp(stderr);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)) {
        //SM2err(SM2_F_SM2_DECRYPT, ERR_R_INTERNAL_ERROR);
        printf("CMM_P2_ERR(BN_bn2binpad): %s: %d\n", __FILE__, __LINE__);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    IF_VERBOSE printf("ptext: %s\n", ptext_buf);

    rc = 1;
    *ptext_len = msg_len;

 done:
    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    //OPENSSL_free(computed_C3);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    CMM_Ciphertext_free(sm2_ctext);
    //EVP_MD_CTX_free(hash);

    return rc;
}


int CMM_P2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, int msg_len, int *pt_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    //const int md_size = EVP_MD_size(digest);
    size_t overhead;

	
	IF_VERBOSE printf("CMM_P2_plaintext_size: input(cipher) length = %d\n", msg_len);
	IF_VERBOSE printf("ecc field_size=%ld\n", field_size);
	
    overhead = 4  /*+ (size_t)md_size*/;
	
	IF_VERBOSE printf("cipher text overhead = [%ld]\n", overhead);
	
    if (msg_len <= overhead) {
        fprintf(stderr, "error:CMMP2:plaintext_size:invalid encoding: #message=%d, #overhead=%ld\n", msg_len, overhead);
        return -1;
    }

    *pt_size = msg_len - overhead;
	IF_VERBOSE fprintf(stderr, "return plaintext_size: "color_red_b"%d"color_reset"\n", *pt_size);
    return 1;
}



int CMM_P2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, int msg_len, int *ct_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t sz;

    if (field_size == 0 )
        return 0;

    sz = //2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
	    //+ ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
         + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
    /* Sequence is structured type; set constructed = 1, means constructed and definite length encoding. */
    *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);
    IF_VERBOSE printf("CMM_P2_ciphertext_size: cipher text size: %d\n", *ct_size);

    return 1;
}

#endif


int CMM_P1_plaintext_size(const EC_KEY *key, const EVP_MD *digest, int msg_len, int *pt_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t overhead;

    if (field_size == 0) {
        fprintf(stderr, "error:CMM_P1_plaintext_size:invalid field size.\n");
        return -1;
    }

    overhead = 4 + 2 * field_size /*+ (size_t)md_size*/;
	
#ifdef DEBUG_MODE
	fprintf(stderr, "CMM_P1_plaintext_size: #overhead=%ld\n", overhead);
#endif    
	
    if (msg_len <= overhead) {
        printf("error:CMM_P1_plaintext_size:invalid encoding.\n");
        return -1;
    }

    *pt_size = msg_len - overhead;
	printf("CMM_P1_plaintext_size: %d\n", *pt_size);
    return 1;
}


int CMM_P1_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, int msg_len, int *ct_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t sz;

    if (field_size == 0 )
        return 0;

    //+ ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
    sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
         + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
   
    *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

    return 1;
}



int CMM_P1_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                unsigned char  *msg,
                int msg_len, unsigned char *ciphertext_buf, int *ciphertext_len)
{
    int rc = 0, ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    
    BIGNUM *k = NULL, *x1 = NULL, *y1 = NULL, *x2 = NULL, *y2 = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    struct CMMP1_Ciphertext_st ctext_struct;
    
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);

    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;

    size_t field_size;
    
    ctext_struct.C2 = NULL;
    
    if (hash == NULL) {
	    printf("CMMP1err(CMMP1_F_CMMP1_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }

    field_size = ec_field_size(group);
    if (field_size == 0) {
		printf("CMMP1err(CMMP1_F_CMMP1_ENCRYPT, ERR_R_INTERNAL_ERROR)\n");
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_MALLOC_FAILURE\n");
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_BN_LIB\n");
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    //C3 = OPENSSL_zalloc(C3_size);

    //if (x2y2 == NULL || C3 == NULL) {
    if (x2y2 == NULL) {
        printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_MALLOC_FAILURE\n");
        goto done;
    }

    if (!BN_priv_rand_range(k, order)) {
        printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_INTERNAL_ERROR\n");
        goto done;
    }

    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0 || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_INTERNAL_ERROR\n");
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
       printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_MALLOC_FAILURE\n");
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)) {
        printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_EVP_LIB\n");
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;

    ctext_struct.C2 = ASN1_OCTET_STRING_new();

    if (ctext_struct.C2 == NULL) {        

       printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_MALLOC_FAILURE\n");
       goto done;
    }

	//fix only this
    //if (!ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size) || !ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
    if (!ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_INTERNAL_ERROR\n");
        goto done;
    }

    ciphertext_leni = i2d_CMMP1_Ciphertext(&ctext_struct, &ciphertext_buf);
    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        printf("CMMP1_F_CMMP1_ENCRYPT, ERR_R_INTERNAL_ERROR\n");
        goto done;
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    rc = 1;

 done:
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    //ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    //OPENSSL_free(C3);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}




//modified version for GZCMM
//take ciphertext without hash
int CMM_P1_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const unsigned char *ciphertext,
                unsigned long ciphertext_len, unsigned char *ptext_buf, int *ptext_len)
{
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct CMMP1_Ciphertext_st *sm2_ctext = NULL;
    
    BIGNUM *x2 = NULL,  *y2 = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const int hash_size = EVP_MD_size(digest);
    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;

    if (field_size == 0 || hash_size <= 0)
       goto done;

    sm2_ctext = d2i_CMMP1_Ciphertext(NULL, &ciphertext, ciphertext_len);

    if (sm2_ctext == NULL) {
        printf("error:CMM_P1_decrypt: DECRYPT, ASN1_ERROR\n");
        goto done;
    }

    /*if (sm2_ctext->C3->length != hash_size) { fprintf(stderr, "SM2_F_SM2_DECRYPT, SM2_R_INVALID_ENCODING\n"); goto done; }*/
    C2 = sm2_ctext->C2->data; //C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        printf("error:CMM_P1_decrypt: DECRYPT, MALLOC_FAILURE]\n");
        goto done;
    }

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        printf("error:CMM_P1_decrypt: DECRYPT, BN_LIB\n");
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    //computed_C3 = OPENSSL_zalloc(hash_size);

    if (msg_mask == NULL || x2y2 == NULL /*|| computed_C3 == NULL*/) {
        printf("error:CMM_P1_decrypt: DECRYPT, MALLOC_FAILURE\n");
        goto done;
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        printf("error:CMM_P1_decrypt: DECRYPT, MALLOC_FAILURE)\n");
        goto done;
    }

    if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x, sm2_ctext->C1y, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        printf("error:CMM_P1_decrypt: DECRYPT, ERR_R_EC_LIB\n");
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)) {
        printf("error:CMM_P1_decrypt: DECRYPT, INTERNAL_ERROR\n");
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    IF_VERBOSE printf("==================================================\n");
    IF_VERBOSE printf("DEC_P1_(PLAIN TEXT) : %x %x %x %x %x\n", ptext_buf[0], ptext_buf[1], ptext_buf[2], ptext_buf[3], ptext_buf[4]);
    IF_VERBOSE printf("==================================================\n");

    rc = 1;
    *ptext_len = msg_len;

 done:
    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    //OPENSSL_free(computed_C3);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    CMMP1_Ciphertext_free(sm2_ctext);
    //EVP_MD_CTX_free(hash);

    return rc;
}





//---------- ---------- ---------- ---------- ---------- 
int CMM_P1_encrypt_file(char *infile, char *certin, char *outfile, int opt_secret) 
{

    char *message = NULL;
    unsigned char plaintext[CMM_P1_PLAINTEXT_LEN];
    unsigned char ciphertext[CMM_P1_PLAINTEXT_LEN+128];

    FILE *fpin = NULL;
    FILE *fpout = NULL;

    int size = 0;
    int ciphertext_len = -1;

    memset(plaintext, 0, sizeof(plaintext));
    memset(ciphertext, 0, sizeof(ciphertext));

    //--------------------------------------------------
    // 1. Encrypt Key : get public key from certificate
    //--------------------------------------------------
    X509 *cert = NULL;
    cert = load_cert(certin, FORMAT_PEM, "certificate file");
    if(!cert) {
        printf("\n");
        return 0;
    }
    EVP_PKEY *pkey = NULL;
    pkey = X509_get_pubkey(cert);
    if(!pkey) {
        printf("fail to read EVP_PKEY...\n");
        return 0;
    }
    EC_KEY *ec_encrypt_key = NULL;
    ec_encrypt_key = EVP_PKEY_get1_EC_KEY(pkey);
    if(!ec_encrypt_key) {
        printf("fail to read public key...\n");
        return 0;
    }

    if(!infile) {
        fprintf(stderr, "CMM_P1_encrypt_file: no out file specified.\n");
        return -1;
    }

    fpin = fopen(infile, "rb");
    if(!fpin) {
        fprintf(stderr, "error:fail to open file: %s\n", infile);
        return -1;
    }

    size_t rsize = -1;
    
    fseek(fpin, 0, SEEK_END);    // 파일 포인터를 파일의 끝으로 이동시킴
    size = ftell(fpin);

#ifdef DEBUG_MODE
    IF_VERBOSE fprintf(stderr, "CMM_P1_encrypt_file:read:%s:size=%d\n", infile, size );
#endif    

    //rsize = fread( plaintext, size, 1, fpin);
    fseek(fpin, 0, SEEK_SET);  
    rsize = fread( plaintext, sizeof(char), size, fpin);

    plaintext[size] = 0;

#if 0 //def DEBUG_MODE
    fprintf(stderr, "PLAIN: %c %c %c %c %c ...\n", plaintext[0], plaintext[1], plaintext[2], plaintext[3], plaintext[4]);
#endif

    if(rsize<0) {
        fprintf(stderr, "error: fail to read plain text, rsize=%ld\n", rsize);
        IF_VERBOSE fprintf(stderr, "source: [%s]\n", plaintext);
        return -1;
    }
    fclose(fpin);

    //--------------------------------------------------
    // Encrypt
    //--------------------------------------------------
    //CMM_P2_read_secret(".", CMM_P1_SAVE_KE);
    //IF_VERBOSE fprintf(stderr, "Read KEE : "color_red_b"%s"color_reset"\n", sharedK);
    
    memset(ciphertext, 0, sizeof(ciphertext));
    message = (char *)plaintext;
    //CMM_P2_ENCRYPT(message, size, certin, 0, ciphertext, &ciphertext_len);
    //TODO: Remove
    const EVP_MD *digest = EVP_sha256();
    CMM_P1_encrypt(ec_encrypt_key, digest, (unsigned char *)message, size, ciphertext, &ciphertext_len);


    ciphertext[ciphertext_len] = 0;
    
    IF_VERBOSE printf("==================================================\n");
    IF_VERBOSE printf("P1 ENC(CIPHER): %x %x %x %x %x\n", ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3], ciphertext[4]);
    IF_VERBOSE printf("==================================================\n");
    
    //printf("encrypted: "color_red_b"0x%x"color_reset"\n", ciphertext);
    IF_VERBOSE fprintf(stderr, "TEST: "color_blue_b"Clear shared secret..."color_reset"\n");
    
    //--------------------------------------------------
    // Save Ciper Text
    //--------------------------------------------------
    if(!outfile) {
        fprintf(stderr, "CMM_P1_encrypt_file: no out file specified.\n");
        return -1;
    }

    fpout = fopen(outfile, "wb");
    if( fpout == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", outfile, strerror(errno));
        return -1;
    }

    fwrite(ciphertext, ciphertext_len,1,fpout);
    fclose(fpout);
    
    IF_VERBOSE fprintf(stderr, "file encrypt: end.\n");

    return 1;
}



int CMM_P1_decrypt_file(char *infile, char *keyin, char *passin, char *outfile, int opt_secret) 
{
    
    unsigned char ciphertext[CMM_P1_PLAINTEXT_LEN];
    size_t ciphertext_len = -1;
    FILE *fp = NULL;
    FILE *fpin = NULL;
    int size = 0;

    if(!outfile) {
        fprintf(stderr, "CMM_P2_decrypt_file: no out file specified.\n");
        return -1;
    }
    //IF_VERBOSE fprintf(stderr, "CMM_P2_decrypt_file: "color_blue_b"Read shared secret from file."color_reset"\n");

    //memset(plaintext, 0, sizeof(plaintext));
    memset(ciphertext, 0, sizeof(ciphertext));

    //--------------------------------------------------
    //Read Cipher Text from File
    //--------------------------------------------------
    fpin = fopen(infile, "rb");
    if(!fpin) {
        fprintf(stderr, "error:fail to open file: %s\n", infile);
        return -1;
    }

    fseek(fpin, 0, SEEK_END);    // 파일 포인터를 파일의 끝으로 이동시킴
    size = ftell(fpin);

    //fprintf(stderr, "read(%s): size=%d\n", infile, size);

    size_t rsize = -1;
    fseek(fpin, 0, SEEK_SET);
    rsize = fread( ciphertext, sizeof(char), size, fpin);
    if(rsize<0) {
        IF_VERBOSE fprintf(stderr, "error: fail to read plain text\n");
        return -1;
    }
    IF_VERBOSE fprintf(stderr, "fread(): %ld\n", rsize);
    IF_VERBOSE fprintf(stderr, "input file(%s), size=[%d]\n", infile, size);
    fclose(fpin);

    IF_VERBOSE printf("==================================================\n");
    IF_VERBOSE printf("DEC(CIPHER TEXT) : %x %x %x %x %x\n", ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3], ciphertext[4]);
    IF_VERBOSE printf("==================================================\n");
 
    //--------------------------------------------------
    // Decrypt
    //--------------------------------------------------
    char *keyfile = keyin;
    EVP_PKEY * private_key = NULL;
    EC_KEY *ec_decrypt_key = NULL;
    private_key = load_key(keyin, FORMAT_PEM, 0, passin, NULL, "key");
    ec_decrypt_key = EVP_PKEY_get1_EC_KEY(private_key);
    if(!ec_decrypt_key) {
        fprintf(stderr, "error:read private...\n");
        return -1;
    }

    //memset(sharedX1, 0, sizeof(sharedX1));
    //memset(sharedY1, 0, sizeof(sharedY1));
    //CMM_P2_read_secret(".", CMM_P1_SAVE_X1);
    //CMM_P2_read_secret(".", CMM_P1_SAVE_Y1);

    //--------------------------------------------------
    // Recover : Decryption
    //--------------------------------------------------
    unsigned char recovered[CMM_P1_PLAINTEXT_LEN];
    ciphertext_len = size;
    int recovered_len = -1;
    
    IF_VERBOSE fprintf(stderr, "Decrypting...\n");
    //printf("cipher text length = %d\n", (int)ciphertext_len);

    //char *passin = NULL;
    //passin = GZPKI_get_master_password_one(keyfile, "password:");

    //IF_VERBOSE printf("==================================================\n");
    //IF_VERBOSE printf("DEC:(PASSIN): [%s]\n", passin);
    //IF_VERBOSE printf("==================================================\n");

    memset(recovered, 0, sizeof(recovered));
    const EVP_MD *digest = EVP_sha256();
    //CMM_P1_decrypt(ciphertext, ciphertext_len, keyfile, 0, recovered, &recovered_len);
    CMM_P1_decrypt(ec_decrypt_key, digest, ciphertext, ciphertext_len, recovered, &recovered_len);
    


    //recovered[recovered_len] = 0;
    //IF_VERBOSE printf("recovered = ["color_red_b"%s"color_reset"]", recovered);

    fp = fopen(outfile, "wb");

    if( fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", outfile, strerror(errno));
        return -1;
    }

    fwrite(recovered, recovered_len, 1, fp);
    fclose(fp);
    
   
    return 1;
}


//new api for gzpki_eccp1_XXX
#if 1

#define ERR_DONE(code) rc = code; goto done

int decrypt_buffer_with_eckey(const EC_KEY *key, 
                const unsigned char *ciphertext, 
                unsigned long ciphertext_len, 
                unsigned char *ptext_buf, 
                int *ptext_len,
                char *ecpk, char *ecpx, char *ecpy, 
                int opt)

{
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct CMM_Ciphertext_st *sm2_ctext = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const EVP_MD *digest = EVP_sha256();

    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;

    if (field_size == 0) {
        ERR_DONE(1);
    }

    //memset(ptext_buf, 0xFF, *ptext_len);
    sm2_ctext = d2i_CMM_Ciphertext(NULL, &ciphertext, (long)ciphertext_len);
    
    if (sm2_ctext == NULL) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d d2i_CMM_Ciphertext() failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(2);
    }

    C2 = sm2_ctext->C2->data;
    msg_len = sm2_ctext->C2->length;

    D_printf("cmm_ctext->C2->length: %d\n", msg_len);
    
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d BIGNUM() geneation failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(3);
    }

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d y2 point generation failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(4);
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);

    if (msg_mask == NULL || x2y2 == NULL ) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d malloc failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(5);
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d ec point C1 generation failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(6);
    }

    BIGNUM *recoverX1 = NULL;
    BIGNUM *recoverY1 = NULL;
     
    BN_hex2bn(&recoverX1, ecpx);
    BN_hex2bn(&recoverY1, ecpy);

    if (!EC_POINT_set_affine_coordinates(group, C1, recoverX1, recoverY1, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d ec point set affine coordinates failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_print_errors_fp(stderr);
        ERR_DONE(7);
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d ec diffie-hellman kdf x9.63 failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(8);
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    ptext_buf[msg_len] = 0;
    
    *ptext_len = msg_len;

    rc = 0;

 done:

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    CMM_Ciphertext_free(sm2_ctext);
    //EVP_MD_CTX_free(hash);

    return rc;
}


int encrypt_buffer_with_eckey(
    const EC_KEY *key,
    const EVP_MD *digest_in,
    unsigned char *msg,
    int msg_len, 
    unsigned char *ciphertext_buf, 
    int *ciphertext_len,
    char *ecpk, char *ecpx, char *ecpy, int opt)
{
    int rc = 0, ciphertext_leni, r = 0;
    
    size_t i, field_size;

    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL, *x1 = NULL, *y1 = NULL, *x2 = NULL, *y2 = NULL;
    
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    
    struct CMM_Ciphertext_st ctext_struct;
    
    const EVP_MD *digest = EVP_sha256();
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    const int C3_size = EVP_MD_size(digest); //sha256 --> 32 bytes

    EC_POINT *kG = NULL, *kP = NULL;

    uint8_t *msg_mask = NULL, *x2y2 = NULL, *C3 = NULL;
    
    IF_VERBOSE printf("encrypt with eckey: opt=%d, msg=[%s]\n", opt, msg);
    /* NULL these before any "goto done" */
    ctext_struct.C2 = NULL;

    //field_size = ec_field_size(group);
    if (0 == (field_size = ec_field_size(group))) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d fail to get FIELD SIZE from EC GROUP.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(10);
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d fail to generate EC POINT - kG, kP\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(11);
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d null ec point y2\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(12);
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    if (x2y2 == NULL ) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d null ec point x2 * y2\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(13);
    }

    //2020.10.19
    //shared value 'sharedK' --> 'ecpk'로 변경
    r = BN_hex2bn(&k, ecpk);
    D_printf("K: "color_green"%s"color_reset"\n", BN_bn2hex(k));

    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d ec point affine coordinates failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(14);
    }


    if (BN_bn2binpad(x2, x2y2, field_size) < 0 || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d ec point operation failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(15);
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d null message mask.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(16);
    }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest)) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d ECDH-KDF-X9.63 operation failed.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(17);
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];
    
    ctext_struct.C2 = ASN1_OCTET_STRING_new();

    //디버깅용:
    //x, y1은 k값에서 추출된다. 
    //복호화하는 측은 x1, y1을 메시지에서 출력하거나, 미리 저장되어 있는 x1, y1값을 사용한다. 
    D_printf("x1: "color_yellow"%s"color_reset"\n", BN_bn2hex(x1));
    D_printf("y1: "color_blue"%s"color_reset"\n", BN_bn2hex(y1));

    if ( ctext_struct.C2 == NULL) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d null C2 field.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(20);
    }

    if (!ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d fail to set C2 masking.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(21);
    }

    ciphertext_leni = i2d_CMM_Ciphertext(&ctext_struct, &ciphertext_buf);
    if (ciphertext_leni < 0) {
        IF_VERBOSE fprintf(stderr,"%s:%s:%d Invalid cipher length.\n", __FILE__, __FUNCTION__, __LINE__);
        ERR_DONE(22);
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    D_printf("cipher text length: "color_red"%d"color_reset"\n", *ciphertext_len);

    rc = 0;

 done:
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    //ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    //OPENSSL_free(C3);
    //EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}


int gzpki_eccp2_read_secret(char *filename, char *secret, unsigned int *datalen, int opt)
{
	int r = 0;
    FILE *fp = NULL;
    //char *mode = "rb";
    size_t rsize = -1, len = -1;

    if( NULL == (fp = fopen(filename, "rb")) ) {
        IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", filename, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_END);    // 파일 포인터를 파일의 끝으로 이동시킴
    rsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);  
   
    D_printf("get file size(rsize)=%d\n", rsize);

    len = fread( &secret[0], 1, rsize, fp);
    *datalen = rsize;
    fclose(fp);
    return 0;
}

#if 1
int gzpki_eccp2_read_file(char *filename, char *data, unsigned int *datalen, int opt)
{
	int r = 0;
    BIO *fp = NULL;
    char tmp[4096];
    //char *mode = "rb";
    size_t rsize = -1, len = -1;

    fp = bio_open_default(filename, 'r', FORMAT_BINARY);
    if (fp == NULL)  {
        return NULL;
    }

    rsize = BIO_read(fp, tmp, sizeof(tmp));
    
    memcpy(&data[0], tmp, rsize);
    
    //len = fread( &data[0], 1, rsize, fp);
    data[rsize] = 0;
        
    *datalen = rsize;

    IF_VERBOSE fprintf(stderr, "%s:%d:read data size=[%d], fread()=%d\n", __FILE__, __LINE__, rsize, len);
    IF_VERBOSE fprintf(stderr, "%s:%d:read data [%s]\n", __FILE__, __LINE__, data);

    BIO_free(fp);

    return 0;
}

#else
int gzpki_eccp2_read_file(char *filename, char *data, unsigned int *datalen, int opt)
{
	int r = 0;
    FILE *fp = NULL;
    char *mode = "rb";
    size_t rsize = -1, len = -1;

    if( NULL == (fp = fopen(filename, mode)) ) {
        IF_VERBOSE fprintf(stderr, "%s:%d:error:fopen():%s, %s\n",  __FILE__, __LINE__, filename, strerror(errno));
        return -1;
    }

    fseek(fp, 0, SEEK_END);    // 파일 포인터를 파일의 끝으로 이동시킴
    rsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);  
   
    IF_VERBOSE fprintf(stderr, "%s:%d:file(%s):size=[%d]\n", __FILE__, __LINE__, filename,rsize);
    
    len = fread( &data[0], 1, rsize, fp);
        
    *datalen = rsize;

    IF_VERBOSE fprintf(stderr, "%s:%d:read data size=[%d], fread()=%d\n", __FILE__, __LINE__, rsize, len);
    IF_VERBOSE fprintf(stderr, "%s:%d:read data [%s]\n", __FILE__, __LINE__, data);

    fclose(fp);

    return 0;
}
#endif

int gzpki_eccp2_save_secret(char *filename, char *value, int len, int opt)
{
    FILE *fp = NULL;
    char *mode = "wb";
    
    IF_VERBOSE fprintf(stderr, "gzpki_eccp2_save_secret: file=[%s]\n", filename);
    
    fp = fopen(filename, mode);
    if( fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:fopen(%s): %s\n", filename, strerror(errno));
        return -1;
    }
    //fwrite(value, sizeof(value), 1, fp);
    fwrite(value, len, 1, fp);
    fclose(fp);

    IF_VERBOSE fprintf(stderr, "success:save file=[%s], len=[%d], value=[%s]\n", filename, len, value);
	return 0;
}



int gzpki_eccp2_read_secret_from_certfile(char *filename, char *header, char *secret, unsigned int *datalen, int opt)
{
	int r = -1;
    FILE *fp = NULL;
    char *line = NULL;
    ssize_t len = 0, rsize = 0;

    if( NULL == (fp = fopen(filename, "r")) ) { //char *mode = "r";
        D_printf("error:fopen(%s): %s\n", filename, strerror(errno));
        return -1;
    }

    while ((rsize = getline(&line, &len, fp)) != -1) {
        if(!strncmp(header, line, strlen(header))) {
            D_printf("match(%s): %s", header, line);
            char* ptr = strtok(line, ":");
            ptr = strtok(NULL, ":");

            sprintf(&secret[0], "%s", ptr);
            *datalen = strlen(ptr);
            //D_printf("  length = %d\n", *datalen);
            if (secret[*datalen-1] == '\r' || secret[*datalen-1] == '\n') 
                secret[*datalen-1] = 0;
        }
        r = 0;
    }

    fclose(fp);

    return r;
}

int gzpki_eccp2_append_secret_to_certfile(char *filename, char *header, char *value, int len, int opt) {
    FILE *fp = NULL;
    char *mode = "a+";
    char data[256];

    if(!value || !header || !filename) {
        D_printf("error:invalid header/value/filename\n");    
        return -1;
    }
        
    memset(data, 0, sizeof(data));
    sprintf(data, "%s%s%s\n", header, ECCP2_HEADER_DELIM,  value);
    int size = strlen(data);
    
    fp = fopen(filename, mode);

    if(fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:fopen(%s): %s\n", filename, strerror(errno));
        return -1;
    }
    fwrite(data, size, 1, fp);
    fclose(fp);

    D_printf("append '%s:%s' to '%s'\n", header, value, filename);

	return 0;
}

/// @brief 공개키 인증서에서 secret(k, x1, y1)을 생성한다. 
//int gzpki_eccp2_generate_secret(char *certfile /*const EC_KEY *key*/,  char **KK, char **XX, char **YY, unsigned int *size, int opt)
int gzpki_eccp2_generate_secret(char *certfile,  char *KK, char *XX, char *YY, unsigned int *size, int opt)
{
    int rc = 0;
    //int ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    
    //struct CMM_Ciphertext_st ctext_struct;
    const EC_GROUP *group;  // = EC_KEY_get0_group(key);
    const BIGNUM *order;    // = EC_GROUP_get0_order(group);
    const EC_POINT *P;      // = EC_KEY_get0_public_key(key);

    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;

    uint8_t *x2y2 = NULL;
    size_t field_size;
    const EC_KEY *key;
    
    //1. 인증서 로딩
    X509 *x509 = NULL;
    x509 = load_cert(certfile, FORMAT_PEM, "certificate file");

    //2. 공개키 추출
    EVP_PKEY *public_key = NULL;
    public_key = X509_get_pubkey(x509);
    if(!public_key) {
        IF_VERBOSE fprintf(stderr, "fail to get public key from %s\n", certfile);
        rc = -1; goto err;
    }

    //3. EC KEY 추출
    key = EVP_PKEY_get1_EC_KEY(public_key);
    if(!key) {
        IF_VERBOSE fprintf(stderr, "fail to get ec key from %s\n", certfile);
        rc = -2; goto err;
    }

    //4. EC KEY로 부터 group 추출
    group = EC_KEY_get0_group(key);
    order = EC_GROUP_get0_order(group);
    P = EC_KEY_get0_public_key(key);

    //5. field size 
    field_size = ec_field_size(group);
    if (field_size == 0) {
		IF_VERBOSE fprintf(stderr, "fail to get field size\n");
        rc = -3; goto err;
    }
    fprintf(stderr, "field size: %d\n", field_size);
    *size = field_size;

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        IF_VERBOSE fprintf(stderr, "fail to create kg, kp contenxt.\n");
        rc = -4; goto err;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        IF_VERBOSE fprintf(stderr, "fail to create y2\n");
        rc = -5; goto err;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    if (x2y2 == NULL) {
        IF_VERBOSE fprintf(stderr, "fail to alloc x2*y2 value\n");
        rc = -6; goto err;
    }

    if (!BN_priv_rand_range(k, order)) {
        IF_VERBOSE fprintf(stderr, "fail to generate random value K\n");
        rc = -7; goto err;
    }

    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        IF_VERBOSE fprintf(stderr, "fail to generate x2, y2 ec point\n");
        rc = -8; goto err;

    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0 || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        printf("fail to convert big number to binary\n");
        rc = -9; goto err;
    }

    int len =  field_size * 2 + 1;
    
    IF_DEBUG  fprintf(stderr, "alloc size: %d\n", len);
    IF_DEBUG  fprintf(stderr, "strlen(k) : %d\n", strlen(BN_bn2hex(k)));

    len = strlen(BN_bn2hex(k));

    IF_VERBOSE {
        fprintf(stderr, "k :  %s \n", BN_bn2hex(k)  );
        fprintf(stderr, "X1:  %s \n", BN_bn2hex(x1) );
        fprintf(stderr, "X1:  %s \n", BN_bn2hex(y1) );
    }
    
    sprintf(&KK[0], "%s", BN_bn2hex(k) );
    sprintf(&XX[0], "%s", BN_bn2hex(x1) );
    sprintf(&YY[0], "%s", BN_bn2hex(y1) );

    IF_VERBOSE {
        fprintf(stderr, "get ec secret from : %s\n", certfile);
        fprintf(stderr, "KK:  %s \n", KK);
        fprintf(stderr, "XX:  %s \n", XX);
        fprintf(stderr, "YY:  %s \n", YY);
    }


    rc = 0;
 
 err:
    
    //OPENSSL_free(x2y2);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);

    IF_VERBOSE fprintf(stderr, "success: generate ec point k, x1, y1.\n");
    return rc;
}
#endif 


#endif
