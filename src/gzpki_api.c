# include <stdio.h>
# include <string.h>

# include <openssl/crypto.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/x509_vfy.h>
# include <openssl/x509v3.h>
# include <openssl/cms.h>
# include <openssl/evp.h>

# include "gzpki_common.h"
# include "gzpki_ecc.h"
# include "gzpki_cms.h"
# include "gzpki_req.h"
# include "gzpki_keypass.h"
# include "gzpki_enc.h"

#include "gzpki_api.h"


int GZPKI_base64_encode(const char* message, char** buffer) { //Encodes a string to base64
  BIO *bio, *b64;
  FILE* stream;
  int encodedSize = 4*ceil((double)strlen(message)/3);
  *buffer = (char *)malloc(encodedSize+1);

  stream = fmemopen(*buffer, encodedSize+1, "w");
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  BIO_write(bio, message, strlen(message));
  BIO_flush(bio);
  BIO_free_all(bio);
  fclose(stream);

  return (0); //success
}
int GZPKI_base64_endecode_file(char *infile, char *outfile, int operation) {
    unsigned char *p = NULL;

    GZPKI_CTX C;
    int len;
    int r = -1;
    
    GZPKI_init_ctx(&C);
    C.operation = operation; //GZPKI_DECRYPT;
    C.cipher_name = NULL;
    C.passargin = NULL;
    
    C.verbose = 1;
    C.base64 = 1;
    C.pbkdf2 = 0;
                
    GZPKI_set_infile(&C, infile, (char *)NULL, 0, FORMAT_PEM);
    GZPKI_set_outfile(&C, outfile, FORMAT_PEM);
    r = GZPKI_do_ENC(&C);
    if(r == CMS_RET_OK) {
        fprintf(stderr, "success base64 processing\n");
    }
    else {
        fprintf(stderr, "error:GZPKI_base64_endecode_file.\n");
    }

    GZPKI_free_ctx(&C);

    return r;
}

int gzpki_set_debug_mode(int flag) {
    return api_debug_mode = flag;
}

# define get_config_str(_SECTION_, _NAME_) NCONF_get_string(conf, _SECTION_, _NAME_)       
# define get_config_int(_SECTION_, _NAME_) atoi(NCONF_get_string(conf, _SECTION_, _NAME_))

# define ERR_RETURN(code) {ret=code; goto encrypt_error;}


#define SET_TK_CONF_PARAM_VALUE(_target_, _section_, _value_, _param_, _tag_, _retval_) \
        if(opt_use_token==1) { \
            _target_ = tk.server_certfile; \
            D_printf("GET VALUE(%s) FROM TOKEN: %s\n", _tag_, _target_); \
        } else if(opt_use_config == 1) { /*} else if(opt_use_token != 1 && conf) {*/ \
            _target_ = get_config_str(_section_, _value_); \
            D_printf("GET VALUE(%s) FROM CONFIG: %s\n", _tag_, _target_); \
        } else if(_param_) {\
            _target_ = _param_; \
            D_printf("GET VALUE(%s) FROM PARAM: %s\n", _tag_, _target_); \
        } else { \
            printf("error: fail to get %s\n", _tag_); \
            ERR_RETURN(_retval_); \
        }

#define SET_TK_CONF_PARAM_VALUE2(_target_, _section1_, _value1_, _section2_, _value2_, _param_, _tag_, _retval_) \
        if(opt_use_token==1) { \
            _target_ = get_config_str(_section1_, _value1_); \
            D_printf("GET VALUE(%s) FROM TOKEN: %s\n", _tag_, _target_); \
        } else if(opt_use_config == 1) { \
            _target_ = get_config_str(_section2_, _value2_); \
            D_printf("GET VALUE(%s) FROM CONFIG: %s\n", _tag_, _target_); \
        } else if(_param_) {\
            _target_ = _param_; \
            D_printf("GET VALUE(%s) FROM PARAM: %s\n", _tag_, _target_); \
        } else { \
            printf("error: fail to get %s\n", _tag_); \
            ERR_RETURN(_retval_); \
        }

#define SET_TK_CONF_PARAM_VALUE3(_target_, _token_value_, _section_, _value_, _param_, _tag_, _retval_) \
        if(opt_use_token==1) { \
            _target_ = _token_value_; \
            D_printf("GET VALUE(%s) FROM TOKEN: %s\n", _tag_, _target_); \
        } else if(opt_use_config == 1) { /*} else if(opt_use_token != 1 && conf) {*/ \
            _target_ = get_config_str(_section_, _value_); \
            D_printf("GET VALUE(%s) FROM CONFIG: %s\n", _tag_, _target_); \
        } else if(_param_) {\
            _target_ = _param_; \
            D_printf("GET VALUE(%s) FROM PARAM: %s\n", _tag_, _target_); \
        } else { \
            printf("error: fail to get %s\n", _tag_); \
            ERR_RETURN(_retval_); \
        }        

#define SET_ENCRYPT_CERTIFICATE     SET_TK_CONF_PARAM_VALUE
#define SET_DECRYPT_PRIVATE_KEY     SET_TK_CONF_PARAM_VALUE
#define SET_CA_CERTIFICATE          SET_TK_CONF_PARAM_VALUE

#define SET_SIGN_PRIVATE_KEY        SET_TK_CONF_PARAM_VALUE3
#define SET_SIGN_CERTIFICATE        SET_TK_CONF_PARAM_VALUE3

#define SET_CIPHERS                 SET_TK_CONF_PARAM_VALUE2

#define CONF_NO_TOKEN opt_use_config == 1 && opt_use_token != 1

/*int CMM_P2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                //const uint8_t *msg,
                unsigned char *msg,
                int msg_len, unsigned char *ciphertext_buf, int *ciphertext_len)
*/         
//int CMM_P2_encrypt_file(char *infile, char *certin, char *outfile, char *x1, char *y1, char *ke, int opt_secret) 
#if 0
int __ECCP2_ENCRYPTOR(char *config,char *infile, char *certin, char *outfile, char *x1, char *y1, char *ke, int opt_secret) 
{
    char *message = NULL;
    unsigned char plaintext[4096];
    unsigned char ciphertext[4096+128];
    size_t ciphertext_len = -1;
    FILE *fpin = NULL;
    FILE *fp = NULL;
    int size = 0;

    memset(plaintext, 0, sizeof(plaintext));
    memset(ciphertext, 0, sizeof(ciphertext));

    if(!infile) {
        fprintf(stderr, "CMM_P2_encrypt_file: no out file specified.\n");
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

    fprintf(stderr, "read(%s): size=[%d]\n", infile, size );

    //rsize = fread( plaintext, size, 1, fpin);
    fseek(fpin, 0, SEEK_SET);  
    rsize = fread( plaintext, sizeof(char), size, fpin);

    plaintext[size] = 0;

    IF_VERBOSE printf("==================================================\n");
    IF_VERBOSE printf("PLAIN TEXT: %s\n", bin2hex(plaintext, size));
    IF_VERBOSE printf("==================================================\n");

    if(rsize<0) {
        fprintf(stderr, "error: fail to read plain text, rsize=%ld\n", rsize);
        IF_VERBOSE fprintf(stderr, "source: [%s]\n", plaintext);
        return -1;
    }
    IF_VERBOSE fprintf(stderr, "plain text, size=[%ld]\n", rsize);
    IF_VERBOSE fprintf(stderr, "plain text: [\n%s\n]\n", plaintext);
    fclose(fpin);

    //--------------------------------------------------
    // Encrypt
    //--------------------------------------------------
    CMM_P2_read_secret(".", CMM_P1_SAVE_KE);
    IF_VERBOSE fprintf(stderr, "Read KEE : "color_red_b"%s"color_reset"\n", sharedK);
    
    memset(ciphertext, 0, sizeof(ciphertext));
    message = (char *)plaintext;
    CMM_P2_ENCRYPT(message, size, certin, 0, ciphertext, &ciphertext_len);

    ciphertext[ciphertext_len] = 0;
    
    IF_VERBOSE printf("==================================================\n");
    IF_VERBOSE printf("ENC(CIPHER): %s\n", bin2hex(ciphertext, ciphertext_len));
    IF_VERBOSE printf("==================================================\n");
    
    //printf("encrypted: "color_red_b"0x%x"color_reset"\n", ciphertext);
    IF_VERBOSE fprintf(stderr, "TEST: "color_blue_b"Clear shared secret..."color_reset"\n");
    
    //--------------------------------------------------
    // Save Ciper Text
    //--------------------------------------------------
    if(!outfile) {
        fprintf(stderr, "CMM_P2_encrypt_file: no out file specified.\n");
        return -1;
    }

    fp = fopen(outfile, "wb");
    if( fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", outfile, strerror(errno));
        return -1;
    }

    fwrite(ciphertext, ciphertext_len,1,fp);
    fclose(fp);
    
    IF_VERBOSE fprintf(stderr, "CMM_P2_encrypt_file: completed.\n");

    return 1;
}       

#endif


int PKI_ENCRYPOR (
    int is_cms_mode,  /*불필요한지 확인*/
    char *configfile, 
    char *default_section,  
    int operation, 
    int intype, 
    int outtype, 
    char *infile, 
    char *outfile, 
    char *inbuffer, 
    unsigned int inbuffer_len, 
    char **outbuffer,
    unsigned int *outbuffer_len, 
    char *certfile, 
    char *keyfile, 
    char *passin,
    char *cafile, 
    char *cipher_algs,
    char *digest_algs, 
    int opt) 
{
    static CONF *conf = NULL;
    TOKEN_CTX tk;

    char *L_certfile = NULL;
    char *L_keyfile = NULL;
    char *L_cafile = NULL;

    char *L_cipher_algs = NULL;
    char *L_digest_algs = NULL;
    
    int opt_use_token = 0;
    int opt_use_config = 0;
    
    char *L_section = NULL;
    char *L_default_section = NULL;
    char *L_token_section = NULL;
    char *L_token_dir = NULL;
    char *L_encrypt_section = NULL;
    char *L_decrypt_section = NULL;
    char *L_sign_section = NULL;
    char *L_verify_section = NULL;
    char *tmp = NULL;

    char *L_passin = NULL;

    int ret = 0;
    int r = CMS_RET_OK;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM;
    
    GZPKI_CTX ctx ;
    GZPKI_init_ctx(&ctx);

    //1. config check
    D_printf("config: %s\n", configfile);
    if_D {
        D_printf("operation: %d, ", operation); 
        print_operation_str(operation);
        printf("\n"); 
    }
    
    
    //D_printf("input section: %s\n", default_section==NULL?"NULL":default_section);        

    if(configfile != NULL) {
        conf = app_load_config(configfile);
        if(conf == NULL) {
            fprintf(stderr, "fail to load config: %s\n");
            ERR_RETURN(-1);
        }    
        else 
            opt_use_config = 1;
    }
    else 
        opt_use_config = 0;

    //TBD
    IF_DEBUG printf("config used: %d\n", opt_use_config);

    if(opt_use_config == 1) {
        if(default_section==NULL) {
            L_default_section = get_config_str(NULL, "default_section");
        }
        else {
            L_default_section = default_section;
        }
        //D_printf("GET default_section name: %s\n", L_default_section);

        opt_use_token = get_config_int(L_default_section, "use_token");
        D_printf("opt_use_token: %d\n", opt_use_token);

        if(opt_use_token == 1) {
            //L_token_section = get_config_str(L_default_section, "token_section");
            L_token_section = get_config_str(L_default_section, "section");
            D_printf("%d: token_section: %s\n", __LINE__, L_token_section);
            
            L_token_dir = get_config_str(L_token_section, "token_dir");
            D_printf("token_dir: %s\n", L_token_dir);
            
            GZPKI_init_token(&tk, L_token_dir);
            
            D_printf("device certfile: %s\n", tk.device_certfile);
            D_printf("server certfile: %s\n", tk.server_certfile);
            D_printf("ca certfile: %s\n", tk.ca_certfile);
        }
    } 
    else {
        D_printf("no config file specified.\n"); //not error
        opt_use_config = 0;
    }

    if(operation == SMIME_ENCRYPT || operation == SMIME_DECRYPT || operation == SMIME_SIGN || operation == SMIME_VERIFY ) 
    {    
        ctx.outtype = outtype;
        ctx.intype = intype;

        GZPKI_set_operation(&ctx, operation);
    }

    //--------------------------------------------------------------------------------
    // input data for CMS
    //--------------------------------------------------------------------------------
    if(FORMAT_FILE == intype) {

#if 0
        if((0 != opt) && (0 == (opt % ECCP2_BASE64_IN))) 
        {
            char inputdata[ECCP2_MAX_INPUT_SIZE];
            char *indata = NULL;
            unsigned int indata_len = -1;
            char out[4096];
            char out_len = -1;
            int len=0;
        
            gzpki_eccp2_read_file(infile, inputdata, &indata_len, 0);
            len = indata_len;

            IF_VERBOSE printf("INPUT_DATA: [%s], len=%d\n", inputdata, indata_len);

            //IF_VERBOSE printf("OPT: %d, opt mod ECCP2_BASE64_IN=%d\n",  opt, opt % ECCP2_BASE64_IN);
            //IF_VERBOSE printf("OPT: %d, opt mod ECCP2_BASE64_OUT=%d\n", opt, opt % ECCP2_BASE64_OUT);

            if ( (inputdata[indata_len-1]=='\n') || (inputdata[indata_len-1]=='\r') ) {
				inputdata[indata_len]=0 ;
				indata_len-- ;
		    }

            
            IF_VERBOSE printf("INPUT_DATA: len  =%d\n", len);
            IF_VERBOSE printf("INPUT_DATA: indata_len=%d\n", indata_len);

        
            IF_VERBOSE printf("cms base64 in mode with ecc p2 encrypt, indatalen=%d\n", indata_len);
            IF_VERBOSE printf(" -- input data=[%s]\n", inputdata);
            int decode_len = indata_len / 4 * 3;

            indata = (unsigned char *)decode64((unsigned char *)inputdata, indata_len);
            indata_len = decode_len;
            IF_VERBOSE printf("CMS base64 decode, indata=[%s],  decode length=[%d]\n", bin2hex(indata, indata_len), decode_len);
            IF_VERBOSE printf("CMSbase64 decode, indata=[%s],  decode length=[%d]\n", indata, decode_len);
                
            if(NULL == indata) {
                IF_VERBOSE fprintf(stderr, "error:null input data(Base64 decoded).\n");   
                ERR_RETURN(-12);
            }
            informat = FORMAT_MEM;

            IF_VERBOSE printf("CMS indata[%s], length=[%d], strlen(indata)=%d\n", indata, indata_len, strlen(indata));
            GZPKI_set_infile(&ctx, NULL, indata, indata_len, informat);

        }
        else
#endif        
        {
            if(!is_file_exists(infile)) {
                IF_VERBOSE fprintf(stderr, "error:no input file: %s\n", infile);   
                ERR_RETURN(-11);
            }
            IF_VERBOSE fprintf(stderr, "input file: %s\n", infile);   
            GZPKI_set_infile(&ctx, infile, NULL, 0, informat);
        }
        

        
    }
    else if(FORMAT_MEM == intype) {
        
        char *indata = NULL;
        unsigned int indata_len = -1;

#if 0 
        if(1) 
        {
            if((0 != opt) && (0 == (opt % ECCP2_BASE64_IN))) 
            {
                //IF_VERBOSE 
                printf("base64(buffer) in mode with cms encrypt...\n");
                int decode_len = inbuffer_len / 4 * 3;
                indata = (unsigned char *)decode64(inbuffer, inbuffer_len);
                indata_len = decode_len;
                //IF_VERBOSE 
                printf("base64(buffer) indata=[%s],  decode length=[%d]\n", indata, decode_len);
            }
            else 
            { 
                indata = inbuffer;
                indata_len = inbuffer_len;
            }
        }

        if(NULL == indata) {
            IF_VERBOSE fprintf(stderr, "error:null input data(Base64 decoded).\n");   
            ERR_RETURN(-12);
        }
        GZPKI_set_infile(&ctx, NULL, indata, indata_len, informat);
#endif                    

        if(NULL == inbuffer) {
            IF_VERBOSE fprintf(stderr, "error:null input buffer.\n");   
            ERR_RETURN(-12);
        }
        GZPKI_set_infile(&ctx, NULL, inbuffer, inbuffer_len, informat);
        
    } else {
        IF_VERBOSE fprintf(stderr, "error:invalid input data type: %d\n", intype);   
        ERR_RETURN(-13);
    }
    //--------------------------------------------------------------------------------
    // TODO
    // output data
    // if(operation == SMIME_ENCRYPT || operation == SMIME_DECRYPT)  구문 내로 이동 
    //--------------------------------------------------------------------------------
    if(FORMAT_FILE == outtype) {
        ctx.outtype = FORMAT_FILE;
        GZPKI_set_outfile(&ctx, outfile, outformat);
    }
    else if(FORMAT_MEM == outtype) {

        ctx.outtype = FORMAT_MEM;
        GZPKI_set_outfile(&ctx, NULL, outformat);
    } else {
        IF_VERBOSE fprintf(stderr, "error:invalid output data type: %d\n", outtype);   
        ERR_RETURN(-14);
    }

    if(operation == SMIME_ENCRYPT || operation == SMIME_DECRYPT || operation == SMIME_SIGN || operation == SMIME_VERIFY) 
    {
        if(operation == SMIME_ENCRYPT) {
            //설정파일(config의 encrypt 섹션) 정보를 이용하여 암호 알고리즘 설정
            if(CONF_NO_TOKEN) L_encrypt_section = get_config_str(L_default_section, "encrypt");
        
            SET_CIPHERS(L_cipher_algs, L_token_section, "ciphers", L_encrypt_section, "ciphers",cipher_algs, "encrypt:ciphers", -4 );
            r = GZPKI_set_cipher(&ctx, L_cipher_algs?L_cipher_algs:DEFAULT_CMS_ENCRYPT_CIPHERS);
            if(CMS_RET_OK != r) {
                IF_VERBOSE fprintf(stderr, "error: fail to set cipher for encryption: %s\n", ctx.errstr);   
                ERR_RETURN(-8);
            }
        
            //config의 token 정보 --> config encrypt 섹션 --> certfile 순으로 인증서 정보를 찾는다.
            SET_ENCRYPT_CERTIFICATE(L_certfile, L_encrypt_section, "certificate", certfile, "encrypt:certificate", -5 );
            if(!L_certfile) {
                IF_VERBOSE fprintf(stderr, "error:fail to get certificate for CMS encryption, encrypt section=[%s]\n", L_encrypt_section);   
                ERR_RETURN(-6);
            }
            r = GZPKI_set_encerts(&ctx, L_certfile);
            if(CMS_RET_OK != r) {
                IF_VERBOSE fprintf(stderr, "error: fail to set certificate for encryption: %s\n", ctx.errstr);   
                ERR_RETURN(-8);
            }
        }
        else if(operation == SMIME_DECRYPT) {
            //복호화 관련 설정 세션명
            if(CONF_NO_TOKEN) L_decrypt_section = get_config_str(L_default_section, "decrypt");
        
            //config의 token 정보 --> config decrypt 섹션 --> certfile 순으로 인증서 정보를 찾는다.
            SET_DECRYPT_PRIVATE_KEY(L_keyfile, L_decrypt_section, "key", keyfile, "decrypt:key", -5 );
            if(!L_keyfile) {
                IF_VERBOSE fprintf(stderr, "error:fail to get private key for CMS decryption, section=[%s]\n", L_decrypt_section);   
                ERR_RETURN(-6);
            }

            if(1 == opt_use_token) {
                GZPKI_generate_device_password(&ctx, NULL, tk.device_certfile);
                L_passin =  ctx.device_password;
            } else {
                L_passin = passin;
            }
            r = GZPKI_set_keyfile(&ctx, L_keyfile, L_passin, 0);
            if(r != CMS_RET_OK) {
                IF_VERBOSE fprintf(stderr, "error:fail to set private key: %s\n", L_keyfile);   
                ERR_RETURN(-6);
            }
        } 
        else if(operation == SMIME_SIGN) {
            //복호화 관련 설정 세션명
            if(CONF_NO_TOKEN) L_sign_section = get_config_str(L_default_section, "sign");
        
            //config의 token 정보 --> config sign 섹션 --> key 순으로 인증서 정보를 찾는다.
            SET_SIGN_PRIVATE_KEY(L_keyfile, tk.device_keyfile, L_sign_section, "key", keyfile, "sign:key", -5 );
            if(!L_keyfile) {
                IF_VERBOSE fprintf(stderr, "error:fail to get private key for CMS signing, section=[%s]\n", L_sign_section);   
                ERR_RETURN(-6);
            }
            
            SET_SIGN_CERTIFICATE(L_certfile, tk.device_certfile, L_sign_section, "certificate", certfile, "sign:certificate", -5 );
            if(!L_certfile) {
                IF_VERBOSE fprintf(stderr, "error:fail to get certificate for CMS signing, section=[%s]\n", L_sign_section);   
                ERR_RETURN(-6);
            }

            if(1 == opt_use_token) {
                GZPKI_generate_device_password(&ctx, NULL, tk.device_certfile);
                L_passin =  ctx.device_password;
            }
            else {
                L_passin = passin;
            }
            
            r = GZPKI_set_signer(&ctx, L_certfile, L_keyfile, L_passin);
            if(r != CMS_RET_OK) {
                IF_VERBOSE fprintf(stderr, "error:fail to set private key: %s\n", L_keyfile);   
                ERR_RETURN(-6);
            }
        }
        else if(operation == SMIME_VERIFY) {
            //복호화 관련 설정 세션명
            if(CONF_NO_TOKEN) L_verify_section = get_config_str(L_default_section, "verify");
        
            SET_ENCRYPT_CERTIFICATE(L_cafile, L_verify_section, "cacert", cafile, "verify:ca", -5 );
            if(!L_cafile) {
                IF_VERBOSE fprintf(stderr, "error:fail to get certificate for CMS signing, section=[%s]\n", L_verify_section);   
                ERR_RETURN(-6);
            }

            GZPKI_set_CAfile(&ctx, L_cafile);  
            if(r != CMS_RET_OK) {
                IF_VERBOSE fprintf(stderr, "error:fail to set ca certificate: %s\n", L_cafile);   
                ERR_RETURN(-6);
            }

            //SignedData내부에 포함된 사용자의 인증서를 certfile로 저장한다. 
            //config 파일을 사용하지 않고 직접 파라메터를 입력히는 경우에만 해당
            if(opt_use_config == 0) {
                GZPKI_set_signerfile(&ctx, certfile);
            }
        }
        
        //--------------------------------------------------------------------------------
        // 암호화 수행, BUFFER는 PEM 데이터이므로 string으로 간주 가능함
        // 이후 부분은 ENCRYPT / DECRYPT 공통 처리
        //-------------------------------------------------------------------------------- 
        r = GZPKI_do_CMS(&ctx);
        if(r == CMS_RET_OK) {
            if(operation == SMIME_VERIFY) {
                int show_text = 0;
                if( CMS_VERIFY_OK == ctx.verify_result) {
                    printf("Verification successful\n");
                }
                else if( CMS_VERIFY_FAIL == ctx.verify_result) {
                    printf("Verification failure: %s\n", ctx.errstr);
                }

                if      (opt_use_token == 1) show_text = get_config_int(L_token_section, "show_text");
                else if (opt_use_config == 1)  show_text = get_config_int(L_verify_section, "show_text");
                else if (opt & CMS_VERIFY_SHOW_TEXT) show_text = 1;

                if(show_text == 1)
                    fprintf(stderr, "%s", GZPKI_get_mem(&ctx) );

                //TODO if (opt & CMS_VERIFY_SAVE_USER_CERT)) {
                //TODO     D_printf("User Certificate: %s\n", usercert_file);
                //TODO }
            }
            else {
                if(ctx.outtype == FORMAT_MEM) {
                    int len = GZPKI_get_mem_length(&ctx);
                    *outbuffer_len = len;
                    
                    *outbuffer = (char *)malloc(len * 2);
                    //snprintf(outbuffer[0], len, "%s", GZPKI_get_mem(&ctx));
                    memcpy(outbuffer[0], GZPKI_get_mem(&ctx), len);
                    outbuffer[0][len] = 0;
                }
                else if(ctx.outtype == FORMAT_FILE) {

                    IF_VERBOSE fprintf(stdout, "success:%s\n", (char *)ctx.outfile);
   #if 0                 
                    if((0!= opt) && (0 == (opt % ECCP2_BASE64_OUT))) {
                        IF_VERBOSE fprintf(stdout, "out type is FILE, and BASE64_OUT mode detected\n");
                        /*FILE *fp = fopen(ctx.outfile, "wb");
                        if( fp == NULL )     {
                            IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", outfile, strerror(errno));
                            return -1;
                        }*/
                        char inputdata[ECCP2_MAX_INPUT_SIZE];

                        char *indata = NULL;
                        unsigned int indata_len = -1;

                        char out[4096];
                        char out_len = -1;
        
                        gzpki_eccp2_read_file(ctx.outfile, inputdata, &indata_len, 0);

                        IF_VERBOSE fprintf(stderr, "* read:%s, len=%d\n", ctx.outfile, indata_len);

                        out_len = indata_len;
                        IF_VERBOSE fprintf(stderr, "FORMAT_FILE:base64 out option\n");
                        int encode_len = 4 * ((out_len + 2) / 3);
                        
                        IF_VERBOSE printf("CMS out file/base64_out, out len=%d\n", out_len, encode_len);

                        unsigned char *outdata = (unsigned char *)base64(out, out_len);
                        
                        //fwrite(outdata, encode_len,1,fp);
                        printf("base64 encoded:");
                        printf("%s\n", outdata);
                    }
#endif
                }
                else 
                {
                    IF_VERBOSE fprintf(stderr, "error:invalid output type %d\n", ctx.outtype);
                    ERR_RETURN(-9);
                }
            }
        } 
        else {
            IF_VERBOSE printf("error:fail to CMS operation: %d:%s\n", ctx.errcode, ctx.errstr);  
            ERR_RETURN(-10); 
        }
        
    } 
    else if(operation == ECCP2_ENCRYPT || operation == ECCP2_DECRYPT) {

        char secretfile_k[256];
        char secretfile_x[256];
        char secretfile_y[256];

        char inputdata[ECCP2_MAX_INPUT_SIZE];

        char *indata = NULL;
        unsigned int indata_len = -1;

        char out[4096];
        char out_len = -1;
        char ecpk[128];
        unsigned int ecpk_len = -1;
        char ecpx[128];
        unsigned int ecpx_len = -1;
        char ecpy[128];
        unsigned int ecpy_len = -1;

        if(intype == FORMAT_FILE) {
            
            gzpki_eccp2_read_file(infile, inputdata, &indata_len, 0);

            if((0 != opt) && (0 == (opt % ECCP2_BASE64_IN))) {    
                int decode_len = indata_len / 4 * 3;

                indata = (unsigned char *)decode64((unsigned char *)inputdata, indata_len);
                indata_len = decode_len;
            }
            else { 
                indata = inputdata;
                indata_len = indata_len;
            }
        }
        else if(intype == FORMAT_MEM) {

            if((0 != opt) && (0 == (opt % ECCP2_BASE64_IN))) {
                int decode_len = inbuffer_len / 4 * 3;

                indata = (unsigned char *)decode64(inbuffer, inbuffer_len);
                indata_len = decode_len;
            }
            else { 
                indata = inbuffer;
                indata_len = inbuffer_len;
            }

        }
        else {
            D_printf("error: invalid input type");
            ERR_RETURN(-200);
        }

        if(operation == ECCP2_ENCRYPT) {
            if(CONF_NO_TOKEN) L_encrypt_section = get_config_str(L_default_section, "encrypt");
            //암호화를 위한 설정
            //1. 암호화용 인증서
            //2. 암호화를 위해 사용되는 EC.K
            SET_ENCRYPT_CERTIFICATE(L_certfile, L_encrypt_section, "certificate", certfile, "encrypt:certificate", -5 );
            if(!L_certfile) {
                IF_VERBOSE fprintf(stderr, "certfile: %s\n", L_certfile);   
                IF_VERBOSE fprintf(stderr, "encrypt_section: %s\n", L_encrypt_section);   
                IF_VERBOSE fprintf(stderr, "param:certfile: %s\n", certfile);   
                IF_VERBOSE fprintf(stderr, "error:fail to get certificate for ECC P2 encryption, encrypt section=[%s]\n", L_encrypt_section);   
                ERR_RETURN(-6);
            }
            
            X509 *x509 = load_cert(L_certfile, FORMAT_PEM, "certificate file");
            if(!x509) {
                IF_VERBOSE fprintf(stderr, "fail to read certificate: '%s'\n", certfile);
                ERR_RETURN(-201);
            }

            EVP_PKEY *public_key = X509_get_pubkey(x509);
            if(!public_key) {
                IF_VERBOSE printf("fail to read public key from %s\n", certfile);
                ERR_RETURN(-202);
            }

            EC_KEY *ec_encrypt_key = EVP_PKEY_get1_EC_KEY(public_key);
            if(!ec_encrypt_key) {
                IF_VERBOSE printf("fail to get EC POINT from %s\n", certfile);
                ERR_RETURN(-202);
            }
            
     
            memset(ecpk, 0, sizeof(ecpk));
            //SECRET 값이 인증서 파일에 포함되어 있음
            if(0 == (opt % ECCP2_SECRET_FROM_CERTFILE )) {
                
                r = gzpki_eccp2_read_secret_from_certfile(L_certfile, ECCP2_HEADER_K, ecpk, &ecpk_len, 0);
                IF_VERBOSE printf("K from certfile: %s\n K:\n", ecpk);
            }
            //SECRET 값을 별도 파일(인증서파일명.eck)에서 읽는다. 
            else if(0 == (opt % ECCP2_SECRET_FROM_SECRET_FILE)) {
                sprintf(secretfile_k, "%s.%s", L_certfile, ECCP2_EXT_K);
                r = gzpki_eccp2_read_secret(secretfile_k, ecpk, &ecpk_len, 0);
                IF_VERBOSE printf("K from secret file: %s\n  K: %s\n", secretfile_k, ecpk);
            }
            else if(keyfile) {
                sprintf(secretfile_k, "%s", keyfile);
                r = gzpki_eccp2_read_secret(secretfile_k, ecpk, &ecpk_len, 0);
                IF_VERBOSE printf("K from key/param file: %s\n  K: %s\n", secretfile_k, ecpk);
            }
            else {
                r = gzpki_eccp2_read_secret_from_certfile(L_certfile, ECCP2_HEADER_K, ecpk, &ecpk_len, 0);
                IF_VERBOSE printf("default: K from certfile: %s\n K:\n", ecpk); 
            }

            r = encrypt_buffer_with_eckey(
                ec_encrypt_key,
                NULL,
                indata,
                indata_len, 
                out, 
                &out_len,
                ecpk, NULL, NULL/*ecpx*/, opt);

            if(r == 0) {
                printf("\n");

                //IF_VERBOSE printf("outbuffer length = %d\n", out_len);
                //IF_VERBOSE printf("==================================================\n");
                //IF_VERBOSE printf("CIPHER TEXT: %s\n", bin2hex(out, out_len));
                //IF_VERBOSE printf("==================================================\n");
            }
            else {
                printf("%s:%d:error: fail to eccp2 encryption(r=%d)\n", __FILE__, __LINE__, r);
            }


            if(r == 0 ) {
                if(outtype == FORMAT_FILE) {
                    //outfile에 outbuffer, outbuffer_len을 쓴다 
                    FILE *fp = fopen(outfile, "wb");
                    if( fp == NULL )     {
                        IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", outfile, strerror(errno));
                        return -1;
                    }

                    //if(0 == (opt % ECCP2_BASE64_OUT)) {
                    if((0!= opt) && (0 == (opt % ECCP2_BASE64_OUT))) 
                    {
                        int encode_len = 4 * ((out_len + 2) / 3);
                        unsigned char *outdata = (unsigned char *)base64(out, out_len);
                        fwrite(outdata, encode_len,1,fp);
                    }
                    else 
                    { 
                        fwrite(out, out_len,1,fp);
                    }
                    fclose(fp);
                }
                else if(outtype == FORMAT_MEM) {
        
                    out[out_len] = 0;

                    *outbuffer_len = out_len;
                    //if(0==(opt % ECCP2_BASE64_OUT)) {
                    if((0 != opt) && (0 == (opt % ECCP2_BASE64_OUT))) {
                        int encode_len = 4 * ((out_len + 2) / 3);
                        unsigned char *outdata = (unsigned char *)base64(out, out_len);
                       
                        *outbuffer = (char *)malloc(encode_len);
                        memcpy(outbuffer[0], outdata, encode_len);
                    }
                    else { 
                        *outbuffer = (char *)malloc(out_len);
                        memcpy(outbuffer[0], out, out_len);
                    }
                }
                else {
                    printf("error:invalid output type(FORMAT_PEM/FORMAT_FILE)\n");
                }
            }
            else {
                printf("%s:%d:error:fail to encrypt\n", __FILE__, __LINE__);
            }
            
        }
        
        //END of ECCP2 Encryption
        else if (operation==ECCP2_DECRYPT) {
            if(CONF_NO_TOKEN) L_decrypt_section = get_config_str(L_default_section, "decrypt");

            SET_ENCRYPT_CERTIFICATE(L_certfile, L_decrypt_section, "certificate", certfile, "decrypt:certificate", -5 );
            if(!L_certfile) {
                IF_VERBOSE fprintf(stderr, "L_certfile: %s\n", L_certfile);   
                IF_VERBOSE fprintf(stderr, "L_encrypt_section: %s\n", L_encrypt_section);   
                IF_VERBOSE fprintf(stderr, "param:certfile: %s\n", certfile);   
                IF_VERBOSE fprintf(stderr, "error:fail to get certificate for ECC P2 encryption, encrypt section=[%s]\n", L_encrypt_section);   
                ERR_RETURN(-6);
            }

            //복호화를 위한 설정
            //1. 암호화용 개인키
            //2. 암호화를 위해 사용되는 EC.X, EC.Y
            //SET_DECRYPT_PRIVATE_KEY(L_certfile, L_encrypt_section, "certificate", certfile, "encrypt:certificate", -5 );
            SET_DECRYPT_PRIVATE_KEY(L_keyfile, L_decrypt_section, "key", keyfile, "decrypt:key", -5 );
            if(!L_keyfile) {
                IF_VERBOSE fprintf(stderr, "L_keyfile: %s\n", L_keyfile);   
                IF_VERBOSE fprintf(stderr, "L_decrypt_section: %s\n", L_decrypt_section);   
                IF_VERBOSE fprintf(stderr, "param:key: %s\n", keyfile);   
                IF_VERBOSE fprintf(stderr, "error:fail to get private key ECC P2 encryption, encrypt section=[%s]\n", L_decrypt_section);   
                ERR_RETURN(-6);
            }
            
            EVP_PKEY * private_key = NULL;
            EC_KEY *ec_decrypt_key = NULL;
            private_key = load_key(L_keyfile, FORMAT_PEM, 0, passin, NULL, "key");
            ec_decrypt_key = EVP_PKEY_get1_EC_KEY(private_key);
            if(!ec_decrypt_key) {
                fprintf(stderr, "error:read private...\n");
                return -1;
            }

            // 파라메터를 통해  ecpk파일을 직접 지정할 수 있도록 한다.
            if(opt_use_config != 1 && keyfile) {
                sprintf(secretfile_k, "%s", keyfile);
            }
            else {
                sprintf(secretfile_k, "%s.%s", L_certfile, ECCP2_EXT_K);
            }
            IF_VERBOSE printf("ec point k file: %s\n", secretfile_k);

            memset(ecpk, 0, sizeof(ecpk));
            //SECRET 값이 인증서 파일에 포함되어 있음
            if(0 == (opt % ECCP2_SECRET_FROM_CERTFILE)) {
                r = gzpki_eccp2_read_secret_from_certfile(L_certfile, ECCP2_HEADER_X, ecpx, &ecpx_len, 0);
                r = gzpki_eccp2_read_secret_from_certfile(L_certfile, ECCP2_HEADER_Y, ecpy, &ecpy_len, 0);
                IF_VERBOSE printf("ECC.X from %s: %s\n K:\n", L_certfile,ecpx);
                IF_VERBOSE printf("ECC.Y from %s: %s\n K:\n", L_certfile,ecpy);
            }
            //SECRET 값을 별도 파일(인증서파일명.eck)에서 읽는다. 
            else {
                r = gzpki_eccp2_read_secret(secretfile_x, ecpx, &ecpx_len, 0);
                IF_VERBOSE printf("read X value from file: %s\n  K: %s\n", secretfile_x, ecpx);

                r = gzpki_eccp2_read_secret(secretfile_x, ecpx, &ecpx_len, 0);
                IF_VERBOSE printf("read X value from file: %s\n  K: %s\n", secretfile_y, ecpy);
            }

            r = decrypt_buffer_with_eckey(ec_decrypt_key, 
                indata, 
                indata_len, 
                out, 
                &out_len,
                NULL, ecpx, ecpy, 
                0);


            if(r == 0) {
                printf("success: eccp2 decryption\n");

                IF_VERBOSE printf("    outbuffer length = %d\n", out_len);
                
                IF_VERBOSE printf("==================================================\n");
                IF_VERBOSE printf("ORIGINAL/PLAIN TEXT\n");
                IF_VERBOSE printf(color_blue"%s"color_reset, out);
                IF_VERBOSE printf("==================================================\n");
            }
            else {
                printf("failed: eccp2 decryption\n", outfile);
            }

        
           if(r == 0 ) {
                if(outtype == FORMAT_FILE) {
                    //outfile에 outbuffer, outbuffer_len을 쓴다 
                    FILE *fp = fopen(outfile, "wb");
                    if( fp == NULL )     {
                        IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", outfile, strerror(errno));
                        return -1;
                    }

                    //if(0 == (opt % ECCP2_BASE64_OUT)) {
                    if((0 != opt) && (0 == (opt % ECCP2_BASE64_OUT))) {
                        int encode_len = 4 * ((out_len + 2) / 3);
                        
                        IF_VERBOSE printf("eccp2 2file, base64_out, out len=%d\n", out_len, encode_len);

                        unsigned char *outdata = (unsigned char *)base64(out, out_len);
                        //ndata_len = encode_len;
                        fwrite(outdata, encode_len,1,fp);
                    }
                    else 
                    { 
                        fwrite(out, out_len,1,fp);
                    }
        
                    fclose(fp);
                }
                else if(outtype == FORMAT_MEM) {
        
                    out[out_len] = 0;

                    *outbuffer_len = out_len;
                    //if(0 == (opt % ECCP2_BASE64_OUT)) {
                    if((0 != opt) && (0 == (opt % ECCP2_BASE64_OUT))) {
                        int encode_len = 4 * ((out_len + 2) / 3);
                        unsigned char *outdata = (unsigned char *)base64(out, out_len);
                       
                        *outbuffer = (char *)malloc(encode_len);
                        memcpy(outbuffer[0], outdata, encode_len);
                    }
                    else { 
                        *outbuffer = (char *)malloc(out_len);
                        memcpy(outbuffer[0], out, out_len);
                    }
                }
                else {
                    printf("error:invalid output type(FORMAT_PEM/FORMAT_FILE)\n");
                }
            } else 
                printf("error:fail to decrypt file:%s", infile);
             
        }
        ////END of ECCP2 Decryption
        else {
            printf("unsupported operation: %d\n", operation);
            ERR_RETURN(-40); 
        }

        return 0;
    } 
       
encrypt_error:
    NCONF_free(conf);
    GZPKI_free_ctx(&ctx);
    return ret;

        
}


//CLIENT
int gzpki_cms_encrypt_file(char *config, char *infile, char *outfile, char *certfile, char *ciphers, int opt)  {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_ENCRYPT,  FORMAT_FILE,  FORMAT_FILE, 
        infile, outfile, 
        NULL, 0/*inbuffer len*/, NULL, 0/*outbuffer len*/, 
        certfile, NULL/*no need private key*/, NULL, NULL /*cafile*/,
        ciphers/*cipher_algs*/, NULL /*digest_algs*/, opt) ;
};


int gzpki_cms_decrypt_file(char *config, char *infile, char *outfile, char *keyfile, char *pass, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_DECRYPT,  FORMAT_FILE,  FORMAT_FILE, 
        infile, outfile, 
        NULL, 0/*inbuffer len*/, NULL, 0/*outbuffer len*/, 
        NULL/*certfile*/, keyfile/*no need private key*/, pass, NULL /*cafile*/,
        NULL/*cipher_algs*/, NULL /*digest_algs*/, opt) ;
};

//SERVER
int gzpki_cms_encrypt_buffer(char *config, 
        char *inbuffer, unsigned int inbuffer_len, 
        char **outbuffer, unsigned int *outbuffer_len, 
        char *certfile, char *ciphers, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_ENCRYPT, FORMAT_MEM, FORMAT_MEM, 
        NULL, NULL, 
        inbuffer, inbuffer_len/*inbuffer len*/, outbuffer, outbuffer_len/*outbuffer len*/, 
        certfile, NULL/*no need private key*/, NULL, NULL /*cafile*/,
        ciphers, NULL /*digest_algs*/, opt) ;
};

int gzpki_cms_decrypt_buffer(char *config, char *inbuffer, unsigned char inbuffer_len, char **outbuffer, unsigned int *outbuffer_len, char *keyfile, char *pass, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_DECRYPT, FORMAT_MEM, FORMAT_MEM, 
        NULL, NULL, 
        inbuffer, inbuffer_len/*inbuffer len*/, outbuffer, outbuffer_len/*outbuffer len*/, 
        NULL, keyfile, pass, NULL /*cafile*/,
        NULL/*ciphers*/, NULL /*digest_algs*/, opt) ;
};

int gzpki_cms_encrypt_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len, char *certfile, char *ciphers, int opt) {
    return PKI_ENCRYPOR ( CMS_ENCRYPT, config, NULL/*default section*/, SMIME_ENCRYPT, FORMAT_FILE, FORMAT_MEM, 
        infile, NULL, 
        NULL, 0/*inbuffer len*/, outbuffer, outbuffer_len/*outbuffer len*/, 
        certfile, NULL/*no need private key*/, NULL, NULL /*cafile*/, ciphers/*cipher_algs*/, NULL /*digest_algs*/, opt) ;
}

int gzpki_cms_decrypt_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, char *keyfile, char *pass, int opt) {
    return PKI_ENCRYPOR ( CMS_ENCRYPT, config, NULL/*default section*/, SMIME_DECRYPT, FORMAT_MEM, FORMAT_FILE, 
        NULL, outfile, 
        inbuffer, inbuffer_len, NULL, 0/*outbuffer len*/, 
        NULL/*certfile*/, keyfile/*no need private key*/, pass, NULL /*cafile*/, NULL/*cipher_algs*/, NULL /*digest_algs*/, opt) ;
}

int gzpki_cms_encrypt_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, char *certfile, char *ciphers, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_ENCRYPT, FORMAT_MEM, FORMAT_FILE, 
        NULL, outfile, 
        inbuffer, inbuffer_len/*inbuffer len*/, NULL, 0/*outbuffer len*/, 
        certfile, NULL/*no need private key*/, NULL, NULL /*cafile*/,
        ciphers, NULL /*digest_algs*/, opt) ;
}


int gzpki_cms_decrypt_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len, char *keyfile, char *passin, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_DECRYPT, FORMAT_FILE, FORMAT_MEM, 
        infile, NULL, 
        NULL, 0/*inbuffer len*/, outbuffer, outbuffer_len, 
        NULL, keyfile, passin, NULL /*cafile*/,
        NULL, NULL /*digest_algs*/, opt) ;
}

int gzpki_cms_sign_file(char *config, char *infile, char *outfile, char *certfile, char *keyfile, char *passin, char *digest_algs, int opt){
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_SIGN, FORMAT_FILE, FORMAT_FILE, 
        infile, outfile, NULL, 0/*inbuffer len*/, NULL, 0, 
        certfile, keyfile, passin, NULL /*cafile*/, NULL, digest_algs, opt) ;
};

int gzpki_cms_verify_file (char *config, char *infile, char *certfile, char *cafile, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_VERIFY, FORMAT_FILE, FORMAT_MEM, 
        infile, NULL, NULL, 0/*inbuffer len*/, NULL, 0, 
        certfile, NULL/*keyfile*/, NULL, cafile, NULL, NULL, opt) ;
};

int gzpki_cms_sign_buffer   (char *config, char *inbuffer, unsigned int inbuffer_len, 
    char **outbuffer, unsigned int *outbuffer_len,  char *certfile, char *keyfile, char *pass, char *digest_algs, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_SIGN, FORMAT_MEM, FORMAT_MEM, 
        NULL, NULL,  inbuffer, inbuffer_len, outbuffer, outbuffer_len, 
        certfile, keyfile, pass, NULL /*cafile*/, NULL, digest_algs, opt) ;
};

int gzpki_cms_verify_buffer (char *config, char *inbuffer, unsigned int inbuffer_len, char *certfile, char *cafile, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_VERIFY, FORMAT_MEM, FORMAT_MEM, 
        NULL, NULL, inbuffer, inbuffer_len, NULL, 0, 
        certfile, NULL, NULL, cafile, NULL, NULL, opt) ;
};

int gzpki_cms_sign_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, char *certfile, char *keyfile, char *pass, char *digest_algs, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_SIGN, FORMAT_MEM, FORMAT_FILE, 
        NULL, outfile, inbuffer, inbuffer_len, NULL, 0, 
        certfile, keyfile, pass, NULL /*cafile*/, NULL, digest_algs, opt) ;
};


int gzpki_cms_sign_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len,  char *certfile, char *keyfile, char *pass, char *digest_algs, int opt) {
    return PKI_ENCRYPOR (CMS_ENCRYPT, config, NULL/*default section*/, SMIME_SIGN, FORMAT_FILE, FORMAT_MEM, 
        infile, NULL,  NULL/*inbuffer*/, 0/*inbuffer_len*/, outbuffer, outbuffer_len, 
        certfile, keyfile, pass, NULL, NULL, NULL, opt) ;
};


/// @brief keyfile은 ecppint k를 저장하는 파일을 의미한다. 따라서 passin은 부재.
int gzpki_eccp2_encrypt_file(char *config, char *infile, char *outfile, char *certfile, char *keyfile, int opt) {
    return PKI_ENCRYPOR (ECDSA_ENCRYPT, config, NULL/*default section*/, ECCP2_ENCRYPT, FORMAT_FILE, FORMAT_FILE, 
        infile, outfile,  NULL/*inbuffer*/, 0/*inbuffer_len*/, NULL, 0, certfile, NULL, NULL, NULL, NULL, NULL, opt) ;
};

int gzpki_eccp2_decrypt_file(char *config, char *infile, char *outfile, char *certfile, char *keyfile, char *passin, int opt) {
    return PKI_ENCRYPOR (ECDSA_ENCRYPT, config, NULL/*default section*/, ECCP2_DECRYPT, FORMAT_FILE, FORMAT_FILE, 
        infile, outfile,  NULL/*inbuffer*/, 0, NULL/*outbuffer*/, 0, certfile, keyfile, passin, NULL, NULL, NULL, opt) ;
};


int gzpki_eccp2_encrypt_buffer(char *config, char *inbuffer, unsigned int inbuffer_len, char *outbuffer, unsigned int *outbuffer_len,
    char *certfile, int opt) {
    return PKI_ENCRYPOR (ECDSA_ENCRYPT, config, NULL, ECCP2_ENCRYPT, FORMAT_MEM, FORMAT_MEM, 
        NULL/*infile*/, NULL/*outfile*/,  inbuffer, inbuffer_len, outbuffer, outbuffer_len, certfile, NULL, NULL, NULL, NULL, NULL, opt) ;
};

int gzpki_eccp2_decrypt_buffer(char *config, char *inbuffer, unsigned int inbuffer_len, char *outbuffer, unsigned int *outbuffer_len,
    char *certfile, char *keyfile, char *passin, int opt) {
    return PKI_ENCRYPOR (ECDSA_ENCRYPT, config, NULL, ECCP2_DECRYPT, FORMAT_MEM, FORMAT_MEM, 
        NULL/*infile*/, NULL/*outfile*/,  inbuffer, inbuffer_len, outbuffer, outbuffer_len, certfile, keyfile, passin, NULL, NULL, NULL, opt) ;
};

/// @brief 
int gzpki_eccp2_encrypt_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len, char *certfile, char *keyfile, int opt) {
    return PKI_ENCRYPOR (ECDSA_ENCRYPT, config, NULL/*default section*/, ECCP2_ENCRYPT, FORMAT_FILE, FORMAT_MEM, 
        infile, NULL,  NULL/*inbuffer*/, 0/*inbuffer_len*/, outbuffer, outbuffer_len, certfile, keyfile, NULL, NULL, NULL, NULL, opt) ;
};

int gzpki_eccp2_decrypt_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, char *certfile, char *keyfile, char *passin, int opt) {
    return PKI_ENCRYPOR (ECDSA_ENCRYPT, config, NULL/*default section*/, ECCP2_DECRYPT, FORMAT_MEM, FORMAT_FILE, 
        NULL, outfile,  inbuffer, inbuffer_len, NULL/*outbuffer*/, 0/*outbuffer_len*/, certfile, keyfile, passin, NULL, NULL, NULL, opt) ;
};


/// @brief 
int gzpki_eccp2_encrypt_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, 
    char *certfile, char *keyfile, char *passin, int opt) {
    return PKI_ENCRYPOR (ECDSA_ENCRYPT, config, NULL/*default section*/, ECCP2_ENCRYPT, FORMAT_MEM, FORMAT_FILE, 
        NULL, outfile,  inbuffer, inbuffer_len, NULL, 0,  certfile, keyfile, passin, NULL, NULL, NULL, opt) ;
};

int gzpki_eccp2_decrypt_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len, 
    char *certfile, char *keyfile, char *passin, int opt) {
    return PKI_ENCRYPOR (ECDSA_ENCRYPT, config, NULL/*default section*/, ECCP2_DECRYPT, FORMAT_FILE, FORMAT_MEM, 
        infile, NULL,  NULL, 0, outbuffer, outbuffer_len, certfile, keyfile, passin, NULL, NULL, NULL, opt) ;
};












