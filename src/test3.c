
#include <stdio.h>
#include <string.h>

#include "gzpki_api.h"

int main_CMS();
int main_ECC();

int main()
{
    return main_ECC();
    //return main_CMS();
}

int main_ECC() {
    char *config = "./gzcms-cli.config";
    char *infile = "./plain.txt";
    char *outfile = "./plain.txt.ecc";
    char *orgfile = "./plain.txt.ecc.recovered";
    char *certfile = "./test/server.pem";
    char *keyfile = "./test/server.key";
    char *pass = "1234";
    char *ciphers = "aes256";
    char *digests = "sha256";
    int opt = ECCP2_SECRET_FROM_CERTFILE/*=0*/;

    int r = -1;


    //int gzpki_eccp2_encrypt_buffer(char *config, char *inbuffer, unsigned int inbuffer_len, char *outbuffer, unsigned int *outbuffer_len,
    //      char *certfile, int opt);
    //int gzpki_eccp2_decrypt_buffer(char *config, char *inbuffer, unsigned int inbuffer_len, char *outbuffer, unsigned int *outbuffer_len,
    //      char *certfile, char *keyfile, char *passin, int opt);

//BUFFER ENCRYPT/DECRYPT

    char *inbuffer = "Hello GZPKI!";
    char *outbuffer = NULL;
    char *orgbuffer = NULL;
    unsigned int inbuffer_len = strlen(inbuffer);
    unsigned int outbuffer_len = 0;
    unsigned int orgbuffer_len = 0;

    r = gzpki_eccp2_encrypt_buffer(NULL, inbuffer, inbuffer_len, &outbuffer, &outbuffer_len, certfile, opt);
    if(0==r) {
        printf("success encrypt buffer\n");
        printf("IN(%d): %s\n", inbuffer_len, inbuffer);
        printf("OUT(%d)\n", outbuffer_len);
        printf("%s\n", outbuffer);
    }
    else {
        printf("encrypt buffer failed(%d)...\n", r);
    }

    
    r = gzpki_eccp2_decrypt_buffer(NULL, outbuffer, outbuffer_len, &orgbuffer, &orgbuffer_len, certfile, keyfile, pass, 0);

    if(0==r) {
        //orgbuffer[orgbuffer_len] = 0;
        printf("success decrypt buffer: orgbuffer_len=%d\n", orgbuffer_len);
        printf("recovered:\n[%s]\n", orgbuffer);
    }
    else  {
        printf("decrypt buffer failed(%d)...\n", r);
    }

    if(outbuffer) {
        printf("out buffer free-ed...\n", r);
        free(outbuffer);
    }

    if(orgbuffer) {
        printf("org buffer free-ed...\n", r);
        free(orgbuffer);
    }


    return r;
}



// test for ECCP2 modified 
int main_CMS() {
    char *config = "./gzcms-cli.config";
    char *infile = "./plain.txt";
    char *outfile = "./plain.txt.cms";
    char *orgfile = "./plain.txt.recovered";
    char *certfile = "./test/server.pem";
    char *keyfile = "./test/server.key";
    char *pass = "1234";
    char *ciphers = "aes256";
    char *digests = "sha256";
    int opt = ECCP2_SECRET_FROM_CERTFILE/*=0*/;

    int r = -1;

//FILE ENCRYPT/DECRYPT
#if 0
    //certfile, ciphers는 config에서 읽을 수 있다.
    //r = gzpki_cms_encrypt_file(config, infile, outfile, certfile, ciphers, opt);
    r = gzpki_cms_encrypt_file(config, infile, outfile, NULL, NULL, 0);
    if(0==r)
        printf("encrypt: %s to %s\n", infile, outfile);
    else 
        printf("encrypt failed(%d)...\n", r);

    //r = gzpki_cms_decrypt_file(config, outfile, orgfile, keyfile, pass, opt);
    r = gzpki_cms_decrypt_file(config, outfile, orgfile, NULL, pass, opt);
    if(0==r)
        printf("success decrypt: %s to %s\n", outfile, orgfile);
    else 
        printf("decrypt failed(%d)...\n", r);
#endif


//BUFFER ENCRYPT/DECRYPT
#if 1
    char *inbuffer = "Hello GZPKI!";
    char *outbuffer = NULL;
    char *orgbuffer = NULL;
    unsigned int inbuffer_len = strlen(inbuffer);
    unsigned int outbuffer_len = 0;
    unsigned int orgbuffer_len = 0;

    r = gzpki_cms_encrypt_buffer(config, inbuffer, inbuffer_len, &outbuffer, &outbuffer_len, certfile, ciphers, opt);
    if(0==r) {
        printf("success encrypt buffer\n");
        printf("IN(%d): %s\n", inbuffer_len, inbuffer);
        printf("OUT(%d)\n", outbuffer_len);
        printf("%s\n", outbuffer);
    }
    else {
        printf("encrypt buffer failed(%d)...\n", r);
    }

    
    r = gzpki_cms_decrypt_buffer(config, outbuffer, outbuffer_len, &orgbuffer, &orgbuffer_len, NULL, pass, 0);

    if(0==r) {
        //orgbuffer[orgbuffer_len] = 0;
        printf("success decrypt buffer: orgbuffer_len=%d\n", orgbuffer_len);
        printf("recovered:\n[%s]\n", orgbuffer);
    }
    else  {
        printf("decrypt buffer failed(%d)...\n", r);
    }

    if(outbuffer) {
        printf("out buffer free-ed...\n", r);
        free(outbuffer);
    }

    if(orgbuffer) {
        printf("org buffer free-ed...\n", r);
        free(orgbuffer);
    }

#endif

    return r;
}

