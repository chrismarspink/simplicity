
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


#include "gzpki_types.h"
#include "gzpki_common.h"
#include "gzpki_ecc.h"
#include "gzpki_enc.h"

#include <openssl/evp.h>


struct doall_enc_ciphers {
    BIO *bio;
    int n;
};


#include <ctype.h>

static void show_ciphers(const OBJ_NAME *name, void *arg)
{
    struct doall_enc_ciphers *dec = (struct doall_enc_ciphers *)arg;
    const EVP_CIPHER *cipher;

    if (!islower((unsigned char )*name->name))
        return;

    /* Filter out ciphers that we cannot use */
    cipher = EVP_get_cipherbyname(name->name);
    if (cipher == NULL ||
            (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0 ||
            EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)
        return;

    BIO_printf(dec->bio, "-%-25s", name->name);
    if (++dec->n == 3) {
        BIO_printf(dec->bio, "\n");
        dec->n = 0;
    } else
        BIO_printf(dec->bio, " ");
}

static int set_hex(const char *in, unsigned char *out, int size)
{
    int i, n;
    unsigned char j;

    i = size * 2;
    n = strlen(in);
    if (n > i) {
        BIO_printf(bio_err, "hex string is too long, ignoring excess\n");
        n = i; /* ignore exceeding part */
    } else if (n < i) {
        BIO_printf(bio_err, "hex string is too short, padding with zero bytes to length\n");
    }

    memset(out, 0, size);
    for (i = 0; i < n; i++) {
        j = (unsigned char)*in++;
        if (!isxdigit(j)) {
            BIO_printf(bio_err, "non-hex digit\n");
            return 0;
        }
        j = (unsigned char)OPENSSL_hexchar2int(j);
        if (i & 1)
            out[i / 2] |= j;
        else
            out[i / 2] = (j << 4);
    }
    return 1;
}
static int cipher_num = 0;
static void show_ciphers2(const OBJ_NAME *name, void *arg)
{
    struct doall_enc_ciphers *dec = (struct doall_enc_ciphers *)arg;
    const EVP_CIPHER *cipher;

    if (!islower((unsigned char)*name->name))
        return;

    /* Filter out ciphers that we cannot use */
    cipher = EVP_get_cipherbyname(name->name);
    if (cipher == NULL || (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0 || EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)
        return;

    if(
         strncmp(name->name, "bf", strlen("bf"))
      && strncmp(name->name, "rc2", strlen("rc2"))
      && strncmp(name->name, "rc4", strlen("rc4"))
      && strncmp(name->name, "sm4", strlen("sm4"))
      && strncmp(name->name, "des", strlen("des"))
      && strncmp(name->name, "cast", strlen("cast"))
      && strncmp(name->name, "camellia", strlen("camellia"))
      && strncmp(name->name, "aria", strlen("aria"))
      && strncmp(name->name, "seed", strlen("seed"))
      && strncmp(name->name, "idea", strlen("idea"))
      && strncmp(name->name, "blowfish", strlen("blowfish"))
      && strncmp(name->name, "id-", strlen("id-"))
      && strncmp(name->name, "aes128-wrap", strlen("aes128-wrap"))
      && strncmp(name->name, "aes192-wrap", strlen("aes192-wrap"))
      && strncmp(name->name, "aes256-wrap", strlen("aes256-wrap"))
    ) {
        BIO_printf(dec->bio, "[%02d] %-25s", ++cipher_num,  name->name);
        if (++dec->n == 1) {
            BIO_printf(dec->bio, "\n");
            dec->n = 0;
        } else
            BIO_printf(dec->bio, " ");
    }
}

static void show_ciphers_all(const OBJ_NAME *name, void *arg)
{
    struct doall_enc_ciphers *dec = (struct doall_enc_ciphers *)arg;
    const EVP_CIPHER *cipher;

    if (!islower((unsigned char)*name->name))
        return;

    /* Filter out ciphers that we cannot use */
    cipher = EVP_get_cipherbyname(name->name);
    if (cipher == NULL || (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0 || EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)
        return;

    if(1) {
        //BIO_printf(dec->bio, "[%02d] %-25s", ++cipher_num,  name->name);
        BIO_printf(dec->bio, "%s",  name->name);
        if (++dec->n == 1) {
            BIO_printf(dec->bio, "\n");
            dec->n = 0;
        } else
            BIO_printf(dec->bio, " ");
    }
}

struct doall_dgst_digests {
    BIO *bio;
    int n;
};

static void show_digests(const OBJ_NAME *name, void *arg)
{
    struct doall_dgst_digests *dec = (struct doall_dgst_digests *)arg;
    const EVP_MD *md = NULL;

    /* Filter out signed digests (a.k.a signature algorithms) */
    if (strstr(name->name, "rsa") != NULL || strstr(name->name, "RSA") != NULL)
        return;

    if (!islower((unsigned char)*name->name))
        return;

    /* Filter out message digests that we cannot use */
    md = EVP_get_digestbyname(name->name);
    if (md == NULL)
        return;

    //BIO_printf(dec->bio, "%s", name->name);
    fprintf(stdout, "%s\n", name->name);
    /*
    if (++dec->n == 3) {
        fprintf(stdout, "\n");
        dec->n = 0;
    } else {
        fprintf(stdout, " ");
    }*/
}


void encrypt(char *infile, char *outfile)
{
  FILE *ifp;
  FILE *ofp;

  ifp = fopen(infile, "rb");//File to be encrypted; plain text
  ofp = fopen(outfile, "wb");//File to be written; cipher text  
  //Get file size
  fseek(ifp, 0L, SEEK_END);
  int fsize = ftell(ifp);
  //set back to normal
  fseek(ifp, 0L, SEEK_SET);

  int outLen1 = 0; int outLen2 = 0;
  unsigned char *indata = malloc(fsize);
  unsigned char *outdata = malloc(fsize*2);
  unsigned char ckey[] =  "thiskeyisverybad";
  unsigned char ivec[] = "dontusethisinput";

  //Read File
  fread(indata,sizeof(char),fsize, ifp);//Read Entire File

  //Set up encryption
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit(ctx,EVP_aes_256_cbc(),ckey,ivec);
  EVP_EncryptUpdate(ctx,outdata,&outLen1,indata,fsize);
  EVP_EncryptFinal(ctx,outdata,&outLen2);
  fwrite(outdata,sizeof(char),fsize,ofp);

  fclose(ifp);
  fclose(ofp);
}

void decrypt(char *infile, char *outfile)
{
  FILE *ifp;
  FILE *ofp;
  ifp = fopen(infile, "rb");//File to be encrypted; plain text
  ofp = fopen(outfile, "wb");//File to be written; cipher text  
  //Get file size
  fseek(ifp, 0L, SEEK_END);
  int fsize = ftell(ifp);
  //set back to normal
  fseek(ifp, 0L, SEEK_SET);

  int outLen1 = 0; int outLen2 = 0;
  unsigned char *indata = malloc(fsize);
  unsigned char *outdata = malloc(fsize*2);
  unsigned char ckey[] =  "thiskeyisverybad";
  unsigned char ivec[] = "dontusethisinput";

  //Read File
  fread(indata,sizeof(char),fsize, ifp);//Read Entire File

  //setup decryption
  //EVP_CIPHER_CTX ctxx;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit(ctx,EVP_aes_256_cbc(),ckey,ivec);
  EVP_DecryptUpdate(ctx,outdata,&outLen1,indata,fsize);
  EVP_DecryptFinal(ctx,outdata,&outLen2);
  fwrite(outdata,sizeof(char),fsize,ofp);
  fclose(ifp);
  fclose(ofp);
}


int GZPKI_do_ENC(GZPKI_CTX *ctx) {

    static char buf[128];
    static const char magic[] = "Salted__";
    ENGINE *e = NULL;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio = NULL, *wbio = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    const EVP_CIPHER *cipher = NULL, *c;
    const EVP_MD *dgst = NULL;
    char *hkey = NULL, *hiv = NULL, *hsalt = NULL, *p;
    char *infile = NULL, *outfile = NULL, *prog = "gzpki";
    char *str = NULL, *passarg = NULL, *pass = NULL, *strbuf = NULL;
    char mbuf[sizeof(magic) - 1];
    //OPTION_CHOICE o;
    int bsize = BSIZE, verbose = 0, debug = 0, olb64 = 0, nosalt = 0;
    int enc = 1, printkey = 0, i, k;
    int base64 = 0, informat = FORMAT_BINARY, outformat = FORMAT_BINARY;
    int ret = 1, inl, nopad = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char *buff = NULL, salt[PKCS5_SALT_LEN];
    int pbkdf2 = 0;
    int iter = 0;
    long n;
    struct doall_enc_ciphers dec;

    /* first check the program name */
    prog = "gzpki";
    base64 = ctx->base64;

    if(ctx->cipher_name) {
        cipher = EVP_get_cipherbyname(ctx->cipher_name);

        if (cipher == NULL ){
            BIO_printf(bio_err, "error:known cipher:%s\n", ctx->cipher_name);
            goto end;
        } else {
            IF_VERBOSE fprintf(stderr, DEBUG_TAG"cipher name: ["color_yellow_b"%s"color_reset"]\n", ctx->cipher_name);
        }
    }
    
    if(ctx->operation == GZPKI_ENCRYPT)
        enc = 1;

    if(ctx->operation == GZPKI_DECRYPT)
        enc = 0;

    if(ctx->operation == GZPKI_CIPHER_LIST || ctx->operation == GZPKI_CIPHER_LIST_ALL || ctx->operation == GZPKI_CIPHER_LIST_COMPAT) {
        ctx->cipher_list = 1;
    }
    else if(ctx->operation == GZPKI_DIGEST_LIST) {
        ctx->cipher_list = 2;
    }


    if(ctx->cipher_list==1) {
        BIO_printf(ctx->bio_out, color_yellow_b"cipher list:"color_reset"\n");
        //fprintf(stdout, "Supported ciphers:\n");
        dec.bio = ctx->bio_out;
        //dec.bio = stdout;
        dec.n = 0;
        if(ctx->operation == GZPKI_CIPHER_LIST )
            OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, show_ciphers2, &dec);
        else if(ctx->operation == GZPKI_CIPHER_LIST_ALL )
            OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, show_ciphers_all, &dec);
        else if(ctx->operation == GZPKI_CIPHER_LIST_COMPAT )
            OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, show_ciphers, &dec);

        BIO_printf(ctx->bio_out, "\n");
        ret = 0;
        goto end;
    }

    else if(ctx->cipher_list==2) {
        BIO_printf(bio_out, "digest list:\n");
        dec.bio = bio_out;
        dec.n = 0;
        OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, show_digests, &dec);
        BIO_printf(bio_out, "\n");
        ret = 0;
        goto end;
    }

    
    infile = ctx->infile;
    outfile = ctx->outfile;
    //passarg = ctx->passarg;
    passarg = ctx->passargin;

    printkey = ctx->printkey; //1, 2
        //::case OPT_UPPER_P: printkey = 2;
        //::case OPT_P: printkey = 1;
    verbose = ctx->verbose;
    nopad = ctx->nopad;
    nosalt = ctx->nosalt; //0;

    olb64 = ctx->olb64;//case OPT_UPPER_A: olb64 = 1;

    pbkdf2 = ctx->pbkdf2;
    if(pbkdf2==1 && iter == 0) {   /* do not overwrite a chosen value */
        iter = 10000;
    }

        //::passphrase
    if(ctx->passphrase  != NULL) {
        str = ctx->passphrase; //case OPT_K: str = opt_arg(); break;
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"ctx->passphrase:str: [%s]\n", str);
    }

    if(ctx->passphrase_file != NULL) {
        in = bio_open_default(ctx->passphrase_file, 'r', FORMAT_TEXT);
        if (in == NULL)
            goto end;
        i = BIO_gets(in, buf, sizeof(buf));
        BIO_free(in);
        in = NULL;
        if (i <= 0) {
            BIO_printf(bio_err, "%s Can't read key from %s\n", prog, ctx->infile);
            goto end;
        }
        while (--i > 0 && (buf[i] == '\r' || buf[i] == '\n'))
            buf[i] = '\0';
        if (i <= 0) {
            BIO_printf(bio_err, "%s: zero length password\n", prog);
            goto end;
        }
        str = buf;
    }

    

    if(ctx->rawkey_hex != NULL) {
        hkey = ctx->rawkey_hex; // case OPT_UPPER_K: hkey = opt_arg(); break;
    }

    if(ctx->salt_hex != NULL) {
        hsalt = ctx->salt_hex; //case OPT_UPPER_S: hsalt = opt_arg(); break;
    }

    if(ctx->iv_hex != NULL) {
        hiv = ctx->iv_hex; //case OPT_IV: hiv = opt_arg(); break;
    }

    if(ctx->dgst_name != NULL) {
        dgst = EVP_get_digestbyname(ctx->dgst_name); //case OPT_MD: if (!opt_md(opt_arg(), &dgst)) goto opthelp; break;
    }
  
    if(ctx->iter != 0) {
        iter = ctx->iter;
        pbkdf2 = 1; // case OPT_ITER: if (!opt_int(opt_arg(), &iter)) goto opthelp; pbkdf2 = 1; break;
    }
        
    if (cipher && EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
        BIO_printf(bio_err, "%s: AEAD ciphers not supported\n", prog);
        goto end;
    }

    if (cipher && (EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)) {
        BIO_printf(bio_err, "%s XTS ciphers not supported\n", prog);
        goto end;
    }

    if (dgst == NULL)
        dgst = EVP_sha256();

    if (iter == 0) iter = 1;

    /* It must be large enough for a base64 encoded line */
    if (base64 && bsize < 80) bsize = 80;

    if (verbose) BIO_printf(bio_err, "bufsize=%d\n", bsize);

        if (base64) {
            if (enc)
                outformat = FORMAT_BASE64;
            else
                informat = FORMAT_BASE64;
        }

    strbuf = app_malloc(SIZE, "strbuf");
    buff = app_malloc(EVP_ENCODE_LENGTH(bsize), "evp buffer");

#if 1
    if (ctx->in != NULL) {
        //IF_VERBOSE fprintf(stderr, DEBUG_TAG"get bio(in) from outside\n");
        in = ctx->in;
    }
    else
#endif 
    if (infile == NULL) {
        //IF_VERBOSE fprintf(stderr, DEBUG_TAG"get bio(in) by duplicate.\n");
        in = dup_bio_in(informat);
    } else {
        //IF_VERBOSE fprintf(stderr, DEBUG_TAG"get bio(in) from file:%s\n", infile);
        in = bio_open_default(infile, 'r', informat);
    }
    if (in == NULL)
        goto end;

    if (str == NULL && passarg != NULL) {
        if (!app_passwd(passarg, NULL, &pass, NULL)) {
            BIO_printf(bio_err, "Error getting password\n");
            goto end;
        }
        str = pass;
    }

    if ((str == NULL) && (cipher != NULL) && (hkey == NULL)) {
        if (1) {
#ifndef OPENSSL_NO_UI_CONSOLE
            for (;;) {
                char prompt[200];

                BIO_snprintf(prompt, sizeof(prompt), "enter %s %s password:", OBJ_nid2ln(EVP_CIPHER_nid(cipher)), (enc) ? "encryption" : "decryption");
                strbuf[0] = '\0';
                i = EVP_read_pw_string((char *)strbuf, SIZE, prompt, enc);
                if (i == 0) {
                    if (strbuf[0] == '\0') {
                        ret = 1;
                        goto end;
                    }
                    str = strbuf;
                    break;
                }
                if (i < 0) {
                    BIO_printf(bio_err, "bad password read\n");
                    goto end;
                }
            }
        } else {
#endif
            BIO_printf(bio_err, "password required\n");
            goto end;
        }
    }

    if(!out && outfile) {
        IF_VERBOSE {
            fprintf(stderr, DEBUG_TAG"open:outfile: %s\n", outfile);
        }
        out = bio_open_default(outfile, 'w', outformat);
        if (out == NULL)
            goto end;
    }
    else {
        IF_VERBOSE {
            fprintf(stderr, DEBUG_TAG"get bio(out) from gzpki context.\n");
        }
        out = ctx->out;
    }

    if (debug) {
        BIO_set_callback(in, BIO_debug_callback);
        BIO_set_callback(out, BIO_debug_callback);
        BIO_set_callback_arg(in, (char *)bio_err);
        BIO_set_callback_arg(out, (char *)bio_err);
    }

    rbio = in;
    wbio = out;

    if (base64) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL)
            goto end;
        if (debug) {
            BIO_set_callback(b64, BIO_debug_callback);
            BIO_set_callback_arg(b64, (char *)bio_err);
        }
        if (olb64)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        if (enc)
            wbio = BIO_push(b64, wbio);
        else
            rbio = BIO_push(b64, rbio);
    }

    if (cipher != NULL) {
        /* * Note that str is NULL if a key was passed on the command line, so * we get no salt in that case. Is this a bug? */
        if (str != NULL) {
            /* * Salt handling: if encrypting generate a salt and write to output BIO. If decrypting read salt from input BIO. */
            unsigned char *sptr;
            size_t str_len = strlen(str);

            if (nosalt) {
                sptr = NULL;
            } else {
                if (enc) {
                    if (hsalt) {
                        if (!set_hex(hsalt, salt, sizeof(salt))) {
                            BIO_printf(bio_err, "invalid hex salt value\n");
                            goto end;
                        }
                    } else if (RAND_bytes(salt, sizeof(salt)) <= 0) {
                        goto end;
                    }
                    /*
                     * If -P option then don't bother writing
                     */
                    if ((printkey != 2) && (BIO_write(wbio, magic,sizeof(magic) - 1) != sizeof(magic) - 1 || BIO_write(wbio, (char *)salt, sizeof(salt)) != sizeof(salt))) {
                        BIO_printf(bio_err, "error writing output file\n");
                        goto end;
                    }
                } 
                else if (BIO_read(rbio, mbuf, sizeof(mbuf)) != sizeof(mbuf) || BIO_read(rbio, (unsigned char *)salt, sizeof(salt)) != sizeof(salt)) 
                {
                    BIO_printf(bio_err, "error reading input file\n");
                    goto end;
                } 
                else if (memcmp(mbuf, magic, sizeof(magic) - 1)) 
                {
                    BIO_printf(bio_err, "bad magic number\n");
                    goto end;
                }
                sptr = salt;
            }

            if (pbkdf2 == 1) {
                /*
                * derive key and default iv
                * concatenated into a temporary buffer
                */
                unsigned char tmpkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];
                int iklen = EVP_CIPHER_key_length(cipher);
                int ivlen = EVP_CIPHER_iv_length(cipher);
                /* not needed if HASH_UPDATE() is fixed : */
                int islen = (sptr != NULL ? sizeof(salt) : 0);
                if (!PKCS5_PBKDF2_HMAC(str, str_len, sptr, islen, iter, dgst, iklen+ivlen, tmpkeyiv)) {
                    BIO_printf(bio_err, "PKCS5_PBKDF2_HMAC failed\n");
                    goto end;
                }
                /* split and move data back to global buffer */
                memcpy(key, tmpkeyiv, iklen);
                memcpy(iv, tmpkeyiv+iklen, ivlen);
            } else {
                BIO_printf(bio_err, "*** WARNING : deprecated key derivation used.\nUsing -iter or -pbkdf2 would be better.\n");
                if (!EVP_BytesToKey(cipher, dgst, sptr, (unsigned char *)str, str_len, 1, key, iv)) {
                    BIO_printf(bio_err, "EVP_BytesToKey failed\n");
                    goto end;
                }
            }
            /*
             * zero the complete buffer or the string passed from the command
             * line.
             */
            if (str == strbuf)
                OPENSSL_cleanse(str, SIZE);
            else
                OPENSSL_cleanse(str, str_len);
        }
        if (hiv != NULL) {
            int siz = EVP_CIPHER_iv_length(cipher);
            if (siz == 0) {
                BIO_printf(bio_err, "warning: iv not used by this cipher\n");
            } else if (!set_hex(hiv, iv, siz)) {
                BIO_printf(bio_err, "invalid hex iv value\n");
                goto end;
            }
        }
        if ((hiv == NULL) && (str == NULL)
            && EVP_CIPHER_iv_length(cipher) != 0) {
            /*
             * No IV was explicitly set and no IV was generated.
             * Hence the IV is undefined, making correct decryption impossible.
             */
            BIO_printf(bio_err, "iv undefined\n");
            goto end;
        }
        if (hkey != NULL) {
            if (!set_hex(hkey, key, EVP_CIPHER_key_length(cipher))) {
                BIO_printf(bio_err, "invalid hex key value\n");
                goto end;
            }
            /* wiping secret data as we no longer need it */
            OPENSSL_cleanse(hkey, strlen(hkey));
        }

        if ((benc = BIO_new(BIO_f_cipher())) == NULL)
            goto end;

        /*
         * Since we may be changing parameters work on the encryption context
         * rather than calling BIO_set_cipher().
         */

        BIO_get_cipher_ctx(benc, &cipher_ctx);

        if (!EVP_CipherInit_ex(cipher_ctx, cipher, NULL, NULL, NULL, enc)) {
            BIO_printf(bio_err, "Error setting cipher %s\n", EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

        if (nopad)
            EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);

        if (!EVP_CipherInit_ex(cipher_ctx, NULL, NULL, key, iv, enc)) {
            BIO_printf(bio_err, "Error setting cipher %s\n", EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

        if (debug) {
            BIO_set_callback(benc, BIO_debug_callback);
            BIO_set_callback_arg(benc, (char *)bio_err);
        }

        if (printkey) {
            if (!nosalt) {
                printf("salt=");
                for (i = 0; i < (int)sizeof(salt); i++)
                    printf("%02X", salt[i]);
                printf("\n");
            }
            if (EVP_CIPHER_key_length(cipher) > 0) {
                printf("key=");
                for (i = 0; i < EVP_CIPHER_key_length(cipher); i++)
                    printf("%02X", key[i]);
                printf("\n");
            }
            if (EVP_CIPHER_iv_length(cipher) > 0) {
                printf("iv =");
                for (i = 0; i < EVP_CIPHER_iv_length(cipher); i++)
                    printf("%02X", iv[i]);
                printf("\n");
            }
            if (printkey == 2) {
                ret = 0;
                goto end;
            }
        }
    }

    /* Only encrypt/decrypt as we write the file */
    if (benc != NULL)
        wbio = BIO_push(benc, wbio);

    while (BIO_pending(rbio) || !BIO_eof(rbio)) {
        inl = BIO_read(rbio, (char *)buff, bsize);
        if (inl <= 0)
            break;
        if (BIO_write(wbio, (char *)buff, inl) != inl) {
            BIO_printf(bio_err, "error writing output file\n");
            goto end;
        }
    }
    if (!BIO_flush(wbio)) {
        BIO_printf(bio_err, "bad decrypt\n");
        fprintf(stderr, "bad decrypt\n");
        goto end;
    }

    //BIO_flush(out);

    ret = 0;
    if (1) {
        BIO_printf(bio_err, "bytes read   : %8ju\n", BIO_number_read(in));
        BIO_printf(bio_err, "bytes written: %8ju\n", BIO_number_written(out));
    }
#if 1    
    ERR_print_errors(bio_err);
    OPENSSL_free(strbuf);
    OPENSSL_free(buff);
    //BIO_free(in);
    //BIO_free_all(out);
    BIO_free(benc);
    BIO_free(b64);
    OPENSSL_free(pass);
    
    return CMS_RET_OK;
#endif

 end:
    ERR_print_errors(bio_err);
    OPENSSL_free(strbuf);
    OPENSSL_free(buff);
    //BIO_free(in);
    //BIO_free_all(out);
    BIO_free(benc);
    BIO_free(b64);

    OPENSSL_free(pass);
    //return ret;
    return CMS_RET_ERROR;
}



