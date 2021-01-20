# ifndef _GZPKI_API_H_
# define _GZPKI_API_H_


#define CMS_ENCRYPT     1
#define ECDSA_ENCRYPT   2

#define ECCP2_MAX_INPUT_SIZE   4096

# define CMS_OP                     0x10
# define CMS_VERIFY_SHOW_TEXT       (1  | CMS_OP)
# define CMS_VERIFY_SAVE_USER_CERT  (2  | CMS_OP)

#define ECCP2_EXT_K "eck"
#define ECCP2_EXT_X "ecx"
#define ECCP2_EXT_Y "ecy"

# define ECCP2_OP                       0x10
# define ECCP2_IN                       0x20
# define ECCP2_OUT                       0x40
# define ECCP2_SECRET_FROM_CERTFILE     2
# define ECCP2_SECRET_FROM_PARAM        3
# define ECCP2_SECRET_FROM_SECRET_FILE  5
# define ECCP2_BASE64_IN                7
# define ECCP2_BASE64_OUT               11




#define DEFAULT_CMS_ENCRYPT_CIPHERS "aes128"
#define DEFAULT_CMS_SIGN_DIGESTS "sha256"

int gzpki_set_debug_mode(int flag);

int PKI_ENCRYPOR (
    int is_cms_mode, 
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
    unsigned int *outuffer_len, 
    char *certfile, 
    char *keyfile, 
    char *passin,
    char *cafile, 
    char *cipher_algs,
    char *digest_algs,
    int opt)  ;
//--------------------
// CMS OPERATION
//--------------------
int gzpki_cms_encrypt_file(char *config, char *infile, char *outfile, char *certfile, char *ciphers, int opt);
int gzpki_cms_decrypt_file(char *config, char *infile, char *outfile, char *keyfile, char *pass, int opt);

int gzpki_cms_encrypt_buffer(char *config, char *inbuffer, unsigned int inbuffer_len, char **outbuffer, unsigned int *outbuffer_len, char *certfile, char *ciphers, int opt);
int gzpki_cms_decrypt_buffer(char *config, char *inbuffer, unsigned char inbuffer_len, char **outbuffer, unsigned int *outbuffer_len, char *keyfile, char *pass, int opt);

int gzpki_cms_encrypt_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len, char *certfile, char *ciphers, int opt);
int gzpki_cms_decrypt_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, char *keyfile, char *pass, int opt);

int gzpki_cms_encrypt_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, char *certfile, char *ciphers, int opt);
int gzpki_cms_decrypt_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len, char *keyfile, char *passin, int opt);


//SIGNING
int gzpki_cms_sign_file   (char *config, char *infile, char *outfile, char *certfile, char *keyfile, char *pass, char *digest_algs, int opt);
int gzpki_cms_verify_file (char *config, char *infile, char *certfile, char *cacertfile, int opt);
int gzpki_cms_sign_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, char *certfile, char *keyfile, char *pass, char *digest_algs, int opt);
int gzpki_cms_sign_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len,  char *certfile, char *keyfile, char *pass, char *digest_algs, int opt);

//VERIFICATION
int gzpki_cms_sign_buffer   (char *config, char *inbuffer, unsigned int inbuffer_len, 
    char **outbuffer, unsigned int *outbuffer_len,  char *certfile, char *keyfile, char *pass, char *digest_algs, int opt);
int gzpki_cms_verify_buffer (char *config, char *inbuffer, unsigned int inbuffer_len, char *certfile, char *cafile, int opt);


int gzpki_eccp2_encrypt_file(char *config, char *infile, char *outfile, char *certfile, char *keyfile, int opt);
int gzpki_eccp2_decrypt_file(char *config, char *infile, char *outfile, char *certfile, char *keyfile, char *passin, int opt);

int gzpki_eccp2_encrypt_buffer(char *config, char *inbuffer, unsigned int inbuffer_len, char *outbuffer, unsigned int *outbuffer_len,
    char *certfile, int opt);
int gzpki_eccp2_decrypt_buffer(char *config, char *inbuffer, unsigned int inbuffer_len, char *outbuffer, unsigned int *outbuffer_len,
    char *certfile, char *keyfile, char *passin, int opt);

int gzpki_eccp2_encrypt_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len, char *certfile, char *keyfile, int opt);
int gzpki_eccp2_encrypt_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, 
    char *certfile, char *keyfile, char *passin, int opt);

int gzpki_eccp2_decrypt_buffer2file(char *config, char *inbuffer, unsigned int inbuffer_len, char *outfile, char *certfile, char *keyfile, char *passin, int opt);
int gzpki_eccp2_decrypt_file2buffer(char *config, char *infile, char **outbuffer, unsigned int *outbuffer_len, 
    char *certfile, char *keyfile, char *passin, int opt);




//--------------------
// ECDSA P2 OPERATION
//--------------------
//int gzpki_eccp2_generate_secret(char *config, char *kval, char *xval, char *yval);
//int gzpki_eccp2_generate_secret_file(char *config, char *kfile, char *xfile, char *yfile);

//int gzpki_eccp2_read_secret_file(char *file, char *val);
//int gzpki_eccp2_read_secret_x(char *config, char **xval);
//int gzpki_eccp2_read_secret_y(char *config, char **yval);
//int gzpki_eccp2_read_secret_k(char *config, char **kval);

int gzpki_ecdsa_encrypt_file(char *config, char *infile, char *outfile, char *certfile, int opt);
int gzpki_ecdsa_decrypt_file(char *config, char *infile, char *outfile, char *certfile, char *keyfile, int opt);

int gzpki_ecdsa_encrypt_buffer(char *config, char *inbuffer, char *outbuffer);
int gzpki_ecdsa_decrypt_buffer(char *config, char *inbuffer, char *outbuffer);



#endif // _GZCMS_API_H_