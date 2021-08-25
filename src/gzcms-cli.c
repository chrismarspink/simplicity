/*    2020/05/11: 

TODO:
    1. gzcms_conf를 얻는 순간 필요한 항목들을 일괄 수집해둔다.
 */


#include <stdio.h>
#include <string.h>

# include <openssl/crypto.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/x509_vfy.h>
# include <openssl/x509v3.h>
# include <openssl/cms.h>
# include <openssl/evp.h>

#include "gzpki_common.h"
#include "gzpki_ecc.h"
#include "gzpki_cms.h"
#include "gzpki_req.h"
#include "gzpki_keypass.h"
#include "gzpki_enc.h"
#include "gzpki_api.h"

#ifndef _NO_CA_
    #include "sqlite3.h"
    #include "gzpki_ca.h"
#endif

#include <time.h>
clock_t  CLK_START, CLK_STOP;

void   perf_start() { CLK_START = clock(); }
void   perf_stop() { CLK_STOP = clock(); }
double perf_print() { return (double)(CLK_STOP - CLK_START) / CLOCKS_PER_SEC; }


#define DECL_STRING(NAME, SIZE) char NAME[SIZE]; memset(NAME, 0, sizeof(NAME))

#define ERR_RETURN(ARGS, MESSAGE, RET) if(!ARGS) { fprintf(stderr, "error: %s\n", MESSAGE); return RET; }
#define require_args ERR_RETURN

#define ERR_EXIT(ARGS, MESSAGE, RET) if(!ARGS) { fprintf(stderr, "error: %s\n", MESSAGE); exit(RET); }                            

///@mainpage
#include <getopt.h>

#ifdef _WIN32
   #include <io.h>
   #define access    _access_s
#else
   #include <unistd.h>
#endif

static int encrypt_flag = 0;
static int decrypt_flag = 0;
static int sign_flag = 0;
static int verify_flag = 0;


static int eccp2_encrypt_mode = 0;
static int eccp2_decrypt_mode = 0;

static int base64_in = 0;
static int base64_out = 0;

int operation = 0; // 0: NO OPERATION

//dictionary *INI = NULL;
static CONF *gzcms_conf = NULL;
static CONF *cli_conf = NULL;



//TEST mode flag
int do_test = 0;
char *test_args = NULL;

//--------------------------------------------------------------------------------
//LIST ARGS    
//--------------------------------------------------------------------------------
int do_list = 0;    
int use_token = 0;
int use_keypass_db = 0;
int opt_key_import = 0;

char *list_args = NULL;
char *req_args = NULL;
char *req_section_args = NULL;
char *userid_args = NULL;

char *with_cn_args = NULL;
char *with_mac_args = NULL;
char *with_email_args = NULL;
char *keydb_file = NULL;

unsigned char *new_master_secret = NULL;
unsigned char *old_master_secret = NULL;
   
#define DEFAULT_KEYPASS_DB_PATH "/usr/local/gzcmm/CA/keypass/"
#define DEFAULT_KEYPASS_DB_FILE "keypass.db"
#define DEFAULT_KEYPASS_DB      DEFAULT_KEYPASS_DB_PATH DEFAULT_KEYPASS_DB_FILE

#define CA_APP_NAME     "gzpki-cli"
#define CA_APP_VERSION  "1.2"

#define CLI_APP_NAME    "gzcms-cli"
#define CLI_APP_VERSION "2.1"
#define CLI_APP_DATE "2021/03/33"
/**
 * 2.1 --base64_in/--base64_out option added
 **/

#ifndef _NO_CA_
    char *app_name = CA_APP_NAME;
    char *app_version = CA_APP_VERSION;
    char *app_date = CLI_APP_DATE;
#else
    char *app_name = CLI_APP_NAME;
    char *app_version = CLI_APP_VERSION;
    char *app_date = CLI_APP_DATE;
#endif

void help_print_version() {
    printf(color_green"NAME"color_reset"\n"
      "    "color_yellow"%s"color_reset" version "color_yellow"%s"color_reset"\n\n"
      color_green"USAGES"color_reset"\n"
      "    "color_yellow"%s"color_reset" [OPTIONS] ...\n\n", app_name, app_version, app_name);
};

void help_print_cms() {
    printf("\n"
      ANSI_COLOR_GREEN_BOLD"CMS OPTIONS"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    --encrypt [--eccp2] "ANSI_COLOR_RESET"\n"
                          "                         Encrypt input file for given recipient certificates.\n"
                          "                         output file is the enveloped with CMS(PEM) type.\n"
                          "                         --eccp2: ECCP2 alogithm is used not CMS\n"
      ANSI_COLOR_CYAN_BOLD"    --decrypt [--eccp2]  "ANSI_COLOR_RESET"Decrypt enveloped message\n"
                          "                         --eccp2: ECCP2 alogithm is used not CMS\n"
      ANSI_COLOR_CYAN_BOLD"    --sign ...           "ANSI_COLOR_RESET"Generate digital signature message\n"
      ANSI_COLOR_CYAN_BOLD"    --verify ...         "ANSI_COLOR_RESET"Verify signature\n"
      ANSI_COLOR_CYAN_BOLD"    --cmsinfo ...        "ANSI_COLOR_RESET"Print out all fields of ths CMS structure\n"
      ANSI_COLOR_CYAN_BOLD"    --in <filename>      "ANSI_COLOR_RESET"Input file\n"
      ANSI_COLOR_CYAN_BOLD"    --out <filename>     "ANSI_COLOR_RESET"Output file\n"
      ANSI_COLOR_CYAN_BOLD"    --cert <filename>    "ANSI_COLOR_RESET"X.509 certificate file for encryption\n"
      ANSI_COLOR_CYAN_BOLD"    --key <filename>     "ANSI_COLOR_RESET"Private key file name for Decryption/Sign\n"
      ANSI_COLOR_CYAN_BOLD"    --informat  <format> "ANSI_COLOR_RESET"Input file format PEM(default), SMIME or DER\n"
      ANSI_COLOR_CYAN_BOLD"    --outformat <format> "ANSI_COLOR_RESET"Output file format PEM(default), SMIME or DER\n"
      ANSI_COLOR_CYAN_BOLD"    --text               "ANSI_COLOR_RESET"Show plain text if signature verification successful\n"
      ANSI_COLOR_CYAN_BOLD"    --cipher <param>     "ANSI_COLOR_RESET"\n"
                          "                         The encryption algorithm to use. for example, aes128, aes192, aes256.\n"
                          "                         Default is lea128, and lea192, lea256 can also be used\n"
      ANSI_COLOR_CYAN_BOLD"    --digest <param>     "ANSI_COLOR_RESET""ANSI_COLOR_RESET"Message digest algorithm name, default: SHA256(sha256)\n"
      ANSI_COLOR_CYAN_BOLD"    --passin values      "ANSI_COLOR_RESET"Input passphease source:value\n"
      ANSI_COLOR_CYAN_BOLD"    --cacerts <filename> "ANSI_COLOR_RESET"CA certificate files\n"
      ANSI_COLOR_CYAN_BOLD"    --token <usb>        "ANSI_COLOR_RESET"Use certificate/key on USB token. <usb> is token dir\n"
      ANSI_COLOR_CYAN_BOLD"    --signer <filename>  "ANSI_COLOR_RESET"\n"
                          "                         If a message is being verified then \n"
                          "                         the signers certificates will be written to this file\n"
                          "                         if the verification was successful\n"
      ANSI_COLOR_CYAN_BOLD"    --base64_in          "ANSI_COLOR_RESET"\n""Input is base64-decoded and encrypted or decrypted.\n"
      ANSI_COLOR_CYAN_BOLD"    --base64_out         "ANSI_COLOR_RESET"\n""Output is base64 encoded.\n"
    );  
};        

void help_print_list() {
    printf(
      "\n"ANSI_COLOR_GREEN_BOLD"LIST OPTIONS"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    --list {cipher|digest|curve]"ANSI_COLOR_RESET"\n"
                          "                         cipher: show all enryption algorithm.\n"
                          "                         digest: show all message digest algorithm.\n"
                          "                         curve : show all elliptic curve parameter.\n");
}

void help_print_keypass() {
    printf(
    "\n"
      ANSI_COLOR_GREEN_BOLD"KEYPASS OPTIONS:"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    --keypass {init|list|list2|add||rename|revoke|delete|truncate|password}"ANSI_COLOR_RESET"\n"
                          "                         init     create new keypass database\n"
                          "                         list     show keypass entry as formatted form\n"                          
                          "                         list2    show keypass entry as simple form\n"                          
                          "                         new      generate new passphrase\n"
                          "                         add      add attributes to existing entry(eg, file/url/data)\n"                          
                          "                         rename   chameecreate new passphrase\n"                          

                          "                         delete   mark revoked passphrase status as 'deleted'\n"                          
                          "                         truncate remove permanently marked as 'deleted'\n"                          
                          "                         password change master key of keypass database\n"                          
      ANSI_COLOR_CYAN_BOLD"    --keyid <name>       "ANSI_COLOR_RESET"specify key name\n"
      ANSI_COLOR_CYAN_BOLD"    --newkeyid <name>    "ANSI_COLOR_RESET"specify new key name\n"
      ANSI_COLOR_CYAN_BOLD"    --db <file>          "ANSI_COLOR_RESET"keypass database file name\n"
      ANSI_COLOR_CYAN_BOLD"    --keystat <stat>     "ANSI_COLOR_RESET"specify key status for rename\n"
      ANSI_COLOR_CYAN_BOLD"    --content <data>     "ANSI_COLOR_RESET"add attribute to existing data\n"
      ANSI_COLOR_CYAN_BOLD"    --contentin <file>   "ANSI_COLOR_RESET"add file content to existing data\n"
      ANSI_COLOR_CYAN_BOLD"    --keytype <TYPE>     "ANSI_COLOR_RESET"specify passphease type, TYPE is one of <any|pkey|skey|signin>\n"
      ANSI_COLOR_CYAN_BOLD"    --pkid <id>          "ANSI_COLOR_RESET"specify private key identifier\n"
      ANSI_COLOR_CYAN_BOLD"    --loginid <id>       "ANSI_COLOR_RESET"specify login ID(eg, web site, server,...)\n");
}

void help_print_ca() {
    printf("\n"
      ANSI_COLOR_GREEN_BOLD"CA OPTIONS:"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    --ca <newcadir|newca|sign|signcmm|revoke|gencrl>"ANSI_COLOR_RESET"\n"
                          "                           newcadir create new CA directory/template\n"
                          "                           newca    create new CA private key/certificate\n"                          
                          "                           sign     show keypass entry as simple form\n"                          
                          "                           signcmm  sign to request for GZCMM user, CA generate user key/certificate\n"
                          "                           token    generate usb token for GZCMM user/device\n"
                          "                           gentoken same as 'token' option\n"                          
                          "                           revoke   revoke certificate\n"
                          "                           gencrl   generate CRL(Certificate Revocation List)\n" 
                          "                           export   create pfx file include user/ca/server certificate\n"                          
      ANSI_COLOR_CYAN_BOLD"    --config <name         "ANSI_COLOR_RESET"CA config file\n"
      ANSI_COLOR_CYAN_BOLD"    --userid <name>        "ANSI_COLOR_RESET"specify GZCMM user id for issue/revoke certificate\n"
      ANSI_COLOR_CYAN_BOLD"    --db <file>            "ANSI_COLOR_RESET"keypass database file name\n"
      ANSI_COLOR_CYAN_BOLD"    --keyid <ID>           "ANSI_COLOR_RESET"KEYPASS passphrase id using private key encryption\n"
      ANSI_COLOR_CYAN_BOLD"    --revoke_reason <CODE> "ANSI_COLOR_RESET"Revocation reason, one of unspecified, keyCompromise, CACompromise, \n"
      ANSI_COLOR_CYAN_BOLD"                           "ANSI_COLOR_RESET"affiliationChanged, superseded, cessationOfOperation, certificateHold, \n"
      ANSI_COLOR_CYAN_BOLD"                           "ANSI_COLOR_RESET"removeFromCRL. <CODE> is case sensitive.\n"
    );
};



void help_print_req() {
    printf("\n"
      ANSI_COLOR_GREEN_BOLD"REQ OPTIONS:"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    --req <newcmm|newkey|new>"ANSI_COLOR_RESET"\n"
                          "                           newcmm   create new keypair and CSR for GZCMM user\n"
                          "                           newkey   create new key pair\n"
                          "                           new      create new CSR with input private key\n"
      ANSI_COLOR_CYAN_BOLD"    --with_mac <MAC>       "ANSI_COLOR_RESET"MAC address for GZCMM user\n"
      ANSI_COLOR_CYAN_BOLD"    --with_cn <CN>         "ANSI_COLOR_RESET"specify Common Name(CN) for GZCMM user\n");
};


void help_print_ecdsa_p2() {
    printf("\n"
      ANSI_COLOR_GREEN_BOLD"ECDSA Encryption OPTIONS:"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    --ecc_encrypt ..."ANSI_COLOR_RESET"\n"
                          "                          Encrypt input file with ECDSA public key\n"
                          "                          message contain encryption key (x1, y1)\n"
      ANSI_COLOR_CYAN_BOLD"    --ecc_decrypt ..."ANSI_COLOR_RESET"\n"
                          "                          Decrypt input file with ECDSA private key\n"
      ANSI_COLOR_CYAN_BOLD"    --ecc_p2_encrypt [--token <dir>] ..."ANSI_COLOR_RESET"\n"
                          "                          Encrypt input file with ECDSA public key\n"
                          "                          encryption key (x1, y1) should be pre-shared between sender/receiver\n"
      ANSI_COLOR_CYAN_BOLD"    --ecc_p2_decrypt [--token <dir>] ..."ANSI_COLOR_RESET"\n"
                          "                          Decrypt input file with ECDSA private key\n"
      ANSI_COLOR_CYAN_BOLD"    --ecc_p2_secret export --cert <certificate> [--secret_dir <dir>]"ANSI_COLOR_RESET"\n"                          
      "                                              Generate shared secret file on <dir> or .\n"
      ANSI_COLOR_CYAN_BOLD"    --ecc_p2_secret export --cert <certificate> [--token <dir>]"ANSI_COLOR_RESET"\n"                          
      "                                              Generate shared secret file on token\n"
      "                                              file generated on '$TOKEN/gzcms/cert/server' dir\n"
      ANSI_COLOR_CYAN_BOLD"    --ecc_p2_secret export --x1 <file> --y1 <file> --ke <file>"ANSI_COLOR_RESET"\n"
                          "                          Generate shared secret K, X1, Y1 for encryption\n"
                          "                          X1, Y1 should be shared with message receiver\n"
      ANSI_COLOR_CYAN_BOLD"    --x1 <file>"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    --y1 <file>"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    --ke <file>"ANSI_COLOR_RESET"\n"
      "\n");
};

void help_print_cms_example() {
    printf(
      "\n"
      ANSI_COLOR_GREEN_BOLD"CMS EXAMPLES:"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    Encrypt file"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --encrypt --in plain.txt --out plain.txt.enc --cert server.pem\n"
      "      ./gzcms-cli --encrypt --in plain.txt --cert server.pem\n"
      "      ./gzcms-cli --encrypt --token /tmp/usb --in plain.txt\n"
      "      ./gzcms-cli --encrypt --token /tmp/usb --in plain.txt -out plain.txt.enc\n"
      ANSI_COLOR_CYAN_BOLD"    Decrypt file"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --decrypt --in plain.txt.enc --out plain.txt.org --key server.key\n"
      "      ./gzcms-cli --decrypt --in plain.txt.enc --key server.key\n"
      "      ./gzcms-cli --decrypt --in plain.txt.enc --out plain.txt.org --token /tmp/usb\n"
      "      ./gzcms-cli --decrypt --in plain.txt.enc --token /tmp/usb\n"
      ANSI_COLOR_CYAN_BOLD"    Generate Signature"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --sign --in plain.txt --out plain.txt.sig --key device.key --cert device.pem\n"
      "      ./gzcms-cli --sign --in plain.txt --key device.key --cert device.pem\n"
      "      ./gzcms-cli --sign --in plain.txt --out plain.txt.sig --token /tmp/usb\n"
      "      ./gzcms-cli --sign --in plain.txt --token /tmp/usb\n"
      ANSI_COLOR_CYAN_BOLD"    Verify Signature"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --verify --in plain.txt.sig\n"
      "      ./gzcms-cli --verify --in plain.txt.sig -text\n"
      "      ./gzcms-cli --verify --in plain.txt.sig --signer signer.pem\n"
      "      ./gzcms-cli --verify --in plain.txt.sig --cacert ca.pem\n"
      "      ./gzcms-cli --verify --in plain.txt.sig --token /tmp/usb\n"
      "      ./gzcms-cli --verify --in plain.txt.sig --token /tmp/usb --signer signer.pem\n"
      "\n");

}


void help_print_keypass_example() {
    printf("\n"
      ANSI_COLOR_GREEN_BOLD"KEYPASS EXAMPLES:"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    Generate KEYPASS database"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --keypass init --db mypass.db\n"
      ANSI_COLOR_CYAN_BOLD"    View database"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --keypass list --db mypass.db\n"
      "      ./gzcms-cli --keypass list2 --db mypass.db\n"
      ANSI_COLOR_CYAN_BOLD"    Generate new passphrase with <name>"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --keypass new --db mypass.db --keyid <name>\n"
      ANSI_COLOR_CYAN_BOLD"    Add data to existing entry"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --keypass add --db mypass.db --keyid <name> --content 'http://www.greenzonesecu.com' --loginid 'manager'\n"
      "      ./gzcms-cli --keypass add --db mypass.db --keyid <name> --contentin '/usr/local/gz/mycert.pem' --keytype pkey\n"
      "      ./gzcms-cli --keypass add --db mypass.db --keyid <name> --content '/usr/local/gz/plain.txt' --keytype skey\n"
      ANSI_COLOR_CYAN_BOLD"    Rename passphrase name"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --keypass rename --db mypass.db --keyid <old> --newkeyid <new>\n"
      ANSI_COLOR_CYAN_BOLD"    Change status of passphrase"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --keypass revoke --db mypass.db --keyid <name>\n"
      "      ./gzcms-cli --keypass delete --db mypass.db --keyid <name>\n"
      "      ./gzcms-cli --keypass truncate --db mypass.db \n"
      ANSI_COLOR_CYAN_BOLD"    Change master key password"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --keypass password --db mypass.db \n");

}

void help_print_ca_example() {
    printf( "\n"
      ANSI_COLOR_GREEN_BOLD"CA EXAMPLES:"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    Generate NEW CA directory"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --ca newcadir --db mypass.db --caname <NAME> --cadir <DIR>\n"
      "      ./gzcms-cli --ca newcadir --db mypass.db --caname <NAME> --cadir <DIR> --keyid <ID>\n"
      ANSI_COLOR_CYAN_BOLD"    Create CA Private key and Certificate"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --ca newca --config <FILE>\n"
      ANSI_COLOR_CYAN_BOLD"    Sign to GZCMM user' CSR"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --ca signcmm --config <FILE> --userid <ID>\n"
      ANSI_COLOR_CYAN_BOLD"    Revoke user certificate"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --ca revoke --config <FILE> --userid <ID>\n"
      ANSI_COLOR_CYAN_BOLD"    Generate CRL"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --ca gencrl --config <FILE>\n"
      ANSI_COLOR_CYAN_BOLD"    Generate USB token for GZCMM user"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --ca {gentoken|token} --config <FILE> --userid <ID>>\n"
      ANSI_COLOR_CYAN_BOLD"    Export all certificate to pfx file"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --ca export --config <FILE> --userid <ID> --out <FILE> \n"
      ANSI_COLOR_CYAN_BOLD"    Change request status to 'approval' to issue certificate"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --ca approval --config <FILE> --userid <ID> \n"
    );

}

void help_print_req_example() {
    printf( "\n"
      ANSI_COLOR_GREEN_BOLD"REQ EXAMPLES:"ANSI_COLOR_RESET"\n"
      ANSI_COLOR_CYAN_BOLD"    Generate new request for GZCMM user"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --req newcmm --config <FILE> --with_mac <MAC> --with_cn <CN> --userid <ID>\n"
      ANSI_COLOR_CYAN_BOLD"    Generate new private key for GZCMM user"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --req newkey --config <FILE> --keyout <FILE> \n"
      ANSI_COLOR_CYAN_BOLD"    Generate new key/request"ANSI_COLOR_RESET"\n"
      "      ./gzcms-cli --req new --config <FILE> --out <FILE> --keyout <FILE>\n"
    );

}
void help() {
    help_print_version();
    help_print_cms();
    help_print_list();
    help_print_ecdsa_p2();

#ifndef _NO_CA_    
    help_print_keypass();
    help_print_req();
    help_print_ca();
#endif

    help_print_cms_example();

#ifndef _NO_CA_    
    help_print_keypass_example();
    help_print_ca_example();
    help_print_req_example();
#endif

    printf("\n");

    return;
}


char *GZPKI_get_master_password_one(char *keydb_file, char *prompt_args)
{
    char *p = NULL;
    char master_pwd_in[4096];
    char prompt[256];
    
    int pwd_len = 0;

    memset(master_pwd_in, 0, 4096);
    memset(prompt, 0, 256);

    if(prompt_args == NULL) {
        sprintf(prompt, "Enter master password:");
    }
    else {
        sprintf(prompt, "%s", prompt_args);
    }
        
    p =  getpass(prompt);
    sprintf(master_pwd_in, "%s", p);
    if(master_pwd_in==NULL) {
        IF_VERBOSE printf("password null.\n");
        return NULL;
    }

    pwd_len = strlen(master_pwd_in);
    if(pwd_len < 1) {
        IF_VERBOSE printf("password null.\n");
        return NULL;
    }

//TODO    
#if 0
    if(pwd_len < KEY_MASTER_PWD_LEN_MIN)  {
        printf("password too short.\n");
        return NULL;
    } else
#endif    
    //pwd_len = pwd_len1;
    
    return GZPKI_strdup(master_pwd_in);
}


char *GZPKI_get_master_password(char *keydb_file, char *prompt_args)
{
    char *p = NULL;
    char master_pwd_in[4096];
    char master_pwd_in2[4096];
    int pwd_len = 0;
    char prompt[256], prompt2[256];

    memset(master_pwd_in, 0, 4096);
    memset(master_pwd_in2, 0, 4096);
    memset(prompt, 0, 256);
    memset(prompt2, 0, 256);
            
    if(keydb_file == NULL) {
        IF_VERBOSE fprintf(stdout, "master password, key file=null\n");
    }
    else {
        IF_VERBOSE fprintf(stdout, "master password for database %s\n", keydb_file);
    }

    if(prompt_args == NULL) {
        sprintf(prompt, "Enter master password:");
        sprintf(prompt2, "Verifying - Enter master password:");
    }
    else {
        sprintf(prompt, "%s", prompt_args);
        sprintf(prompt2, "Verifying - %s", prompt_args);
    }
    
    p =  getpass(prompt);
    sprintf(master_pwd_in, "%s", p);
        
    p =  getpass(prompt2);
    sprintf(master_pwd_in2, "%s", p);
    
    if(master_pwd_in==NULL || master_pwd_in2==NULL) {
        printf("fail to get master password\n");
        exit(0);
    }

    int pwd_len1 = strlen(master_pwd_in);
    int pwd_len2 = strlen(master_pwd_in2);
    if(pwd_len1 >= pwd_len2) 
        pwd_len = pwd_len1;
    else
        pwd_len = pwd_len2;


    if(0==strncmp(master_pwd_in, master_pwd_in2, pwd_len)) {
        fprintf(stdout, "Password verify ok.\n");
    }
    else {
        fprintf(stderr, "Password verify failure.\n");
        //return NULL;
        exit(0);
    }


    return GZPKI_strdup(master_pwd_in);
}

#ifndef _NO_CA_
char *master_pwd_in = NULL;
char *master_pwd_hash = NULL;

int verify_master_password(char *keydb_file, int verify_digest ) 
{
    int r=0;

    IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "BEGIN GET PWD");
    master_pwd_in = GZPKI_get_master_password(keydb_file, NULL);

    IF_VERBOSE fprintf(stderr, DEBUG_TAG": get master password: %s\n", master_pwd_in);
    if(!master_pwd_in) {
        fprintf(stderr, "error:fail to get master password\n");
        return -1;
    }
            
    //--------------------------------------------------
    //INIT은 DIGEST 검증 불필요
    //--------------------------------------------------
    if( verify_digest == 1 ) {

        if( !is_file_exists(keydb_file)) {
            printf("error: no file exists: verify option=%d, file=%s\n", verify_digest, keydb_file);
            return -1;
        }

        IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "VERIFY MASTER PASSWD");
        IF_VERBOSE fprintf(stderr, "    PWD_IN ["color_yellow_b"%s"color_reset"]\n", master_pwd_in);
        r = GZPKI_keypass_verify_master_pass(keydb_file, master_pwd_in);
        if(r != 0) {
            IF_VERBOSE printf("user    master hash: ["color_yellow_b"%s"color_reset"]\n", master_pwd_hash);
            IF_VERBOSE printf("keypass master hash: ["color_yellow_b"%s"color_reset"]\n", g_digest);
            printf("error: invalid master password for %s\n", keydb_file);
            return -1;
        }
    }
    return 0;
        
}

#endif /*_NO_CA_*/

#define CFG_CA_NAME() NCONF_get_string(gzcms_conf, "ca", "default_ca")       
#define CFG_CA_SECTION_VALUE(ARGS) NCONF_get_string(gzcms_conf, CFG_CA_NAME(), ARGS)       
#define CFG_SECTION_VALUE(SECT, ARGS) NCONF_get_string(gzcms_conf, SECT, ARGS)       

//Client config file => gzcms-cli.config
#define client_config_get_value(_SECTION_, _NAME_) NCONF_get_string(cli_conf, _SECTION_, _NAME_)       


void print_revokeReason() {
    fprintf(stderr, "RevokeReason:\n");
    fprintf(stderr, "    unspecified\n");
    fprintf(stderr, "    keyCompromise\n");
    fprintf(stderr, "    CACompromise:\n");
    fprintf(stderr, "    affiliationChanged\n");
    fprintf(stderr, "    superseded\n");
    fprintf(stderr, "    cessationOfOperation\n");
    fprintf(stderr, "    certificateHold\n");
    fprintf(stderr, "    removeFromCRL\n");
    fprintf(stderr, "    holdInstruction\n");
    fprintf(stderr, "    keyTime\n");
    fprintf(stderr, "    CAkeyTime\n");
    return;
};

#if 0 //#ifndef _NO_NEWT_
#include <newt.h>
int doNewtTest() 
{
    newtInit();
    newtCls();

    newtDrawRootText(0, 0, "Some root text");
    newtDrawRootText(-25, -2, "Root text in the other corner");

    newtPushHelpLine(NULL);
    newtRefresh();
    sleep(1);

    newtPushHelpLine("A help line");
    newtRefresh();
    sleep(1);

    newtPopHelpLine();
    newtRefresh();
    sleep(1);

    newtFinished();

    return 0;
}
#endif // _NO_NEWT_

#include "crypto/sm2.h"
#include "crypto/sm2err.h"
#include "crypto/ec.h" /* ecdh_KDF_X9_63() */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>


struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};


int CMM_P2_SENDER_generate_param(char *certin, char *destdir) 
{
    EC_KEY *ec_encrypt_key = NULL;

    IF_VERBOSE fprintf(stderr, "Load Certificate from '%s'\n", certin);
    char *certfile = certin;   
    X509 *x509 = NULL;
    x509 = load_cert(certfile, FORMAT_PEM, "certificate file");
    if(!x509) {
        printf("fail to read cert...\n");
        return -1;
    }

    IF_VERBOSE fprintf(stderr, "Load PublicKey from certificate...\n");
    EVP_PKEY *public_key = NULL;
    public_key = X509_get_pubkey(x509);
    if(!public_key) {
        printf("fail to read EVP_PKEY...\n");
        return -1;
    }
    ec_encrypt_key = EVP_PKEY_get1_EC_KEY(public_key);
    if(!ec_encrypt_key) {
        printf("fail to read public key...\n");
        return -1;
    }
    printf("Read EC KEY from PublicKey...\n");

    char *shx1 = NULL; //HARED_SECRET_X1;
    char *shy1 = NULL; //SHARED_SECRET_Y1;
    char *shk =  NULL; //SHARED_SECRET_KE;

    char *secret_dir = NULL;

    if(destdir)  {
        //for ex, use_token
        secret_dir = destdir;
    }
    else {
        secret_dir = ".";
    }

    CMM_P2_generate_secret(ec_encrypt_key, shk, shx1, shy1, secret_dir, CMM_P1_SAVE_X1Y1KE);
    

    IF_VERBOSE printf("- ECDSA P2: PARAM KE(%ld): %s\n", strlen(sharedK), sharedK);
    IF_VERBOSE printf("- ECDSA_P2: PARAM X1(%ld): %s\n", strlen(sharedX1), sharedX1);
    IF_VERBOSE printf("- ECDSA_P2: PARAM Y1(%ld): %s\n", strlen(sharedY1), sharedY1);

    printf("Generate Shared secret success.\n");

    return 0;
}



int CMM_P2_ENCRYPT(char *message, int msg_len, char *certin, int opt_base64, unsigned char *cipher_text, size_t *cipher_text_len) {
    
    const EVP_MD *digest = EVP_sha256();

    EC_KEY *ec_encrypt_key = NULL;
        
    unsigned char *ctext = NULL;
    int ctext_len = 0;
    int rc = 0; //size_t ptext_len = 0;

    //char *b64encoded = NULL;
    //int b64encoded_length = 0;
    char *certfile = certin;  

    D_printf("cert file: %s\n", certfile);

    X509 *x509 = NULL;
    x509 = load_cert(certfile, FORMAT_PEM, "certificate file");
    if(!x509) {
        fprintf(stderr, "fail to read certificate: '%s'\n", certfile);
        return -1;
    }

    EVP_PKEY *public_key = NULL;
    public_key = X509_get_pubkey(x509);
    if(!public_key) {
        printf("fail to read EVP_PKEY...\n");
        return 0;
    }

    ec_encrypt_key = EVP_PKEY_get1_EC_KEY(public_key);
    if(!ec_encrypt_key) {
        printf("fail to read public key...\n");
        return 0;
    }
    printf("P2:read public key success.\n");

    CMM_P2_ciphertext_size(ec_encrypt_key, digest, msg_len, &ctext_len);

    IF_VERBOSE printf("P2:ciphertext_size: %d, msg_len=%d\n",ctext_len, msg_len);
    
    ctext = OPENSSL_zalloc(ctext_len);
    //cipher_text = OPENSSL_zalloc(ctext_len);

    IF_VERBOSE printf("P2:encrypt:begin...\n");
    rc = CMM_P2_encrypt(ec_encrypt_key, digest, (unsigned char *)message, msg_len, ctext, &ctext_len);
    //rc = CMM_P2_encrypt(ec_encrypt_key, digest, (const uint8_t *)message, msg_len, cipher_text, &ctext_len);
    if(1 != rc) {
        fprintf(stderr, "CMM_P2_encrypt() failed.\n");
        return -1;
    }

    IF_VERBOSE printf("P2:plaintext: \n["color_red_b"%s"color_reset"]\n", message);
    IF_VERBOSE printf("P2:      len: ["color_red_b"%d"color_reset"] bytes\n", msg_len);
    IF_VERBOSE printf("P2:cipherlen: ["color_red_b"%d"color_reset"] bytes\n", ctext_len);
    IF_VERBOSE printf("P2:cipher   : ["color_red_b"%s"color_reset"] \n", cipher_text);

   
    memcpy(cipher_text, ctext, ctext_len);

    *cipher_text_len = ctext_len;
    return 1;
}



int CMM_P2_DECRYPT(unsigned char *ctext, int ctext_len, char *keyin, char *passin, int opt_base64, unsigned char *plaintext, int *plaintext_len) {
    
    const EVP_MD *digest = EVP_sha256();

    //BIGNUM *priv = NULL;
    
    //size_t ctext_len = 0;
    int ptext_len = 0;
    unsigned char * recovered = NULL;
    int recovered_len = ctext_len;
    //int rc = 0;

    //unsigned char *b64decoded = NULL;
    //int b64decoded_length = 0;

    EVP_PKEY * private_key = NULL;

    //printf("ctext(3): "color_blue_b"0x%x"color_reset"\n", ctext);

    char *keyfile = keyin;   
    private_key = load_key(keyfile, FORMAT_PEM, 0, passin, NULL, "key");
    if(!private_key) {
        fprintf(stderr, "fail to load private key, %s:%d\n", __FILE__, __LINE__);
        return -1;
    }
    
    EC_KEY* ec_decrypt_key = EVP_PKEY_get1_EC_KEY(private_key);
    if(!ec_decrypt_key) {
        printf("fail to get ECC private key for message decryption.\n");
        return -1;
    }
    printf("read private key success\n");

    IF_VERBOSE printf("DECRYPTING: CIPHER TEXT LENGTH : ["color_red_b"%d"color_reset"] bytes\n", ctext_len);

    CMM_P2_plaintext_size(ec_decrypt_key, digest, ctext_len, &ptext_len);

    IF_VERBOSE printf("CMM_P2_plaintext_size: ptext_len : %d\n", ptext_len);
    IF_VERBOSE printf("dec len, cipher=%d, ptext_len=%d, recovered_len=%d\n", ctext_len, ptext_len, recovered_len);

#if 0    
    if(opt_base64 == 1 ) {
        b64decoded_length = ctext_len / 4 * 3;
        b64decoded = OPENSSL_zalloc(b64decoded_length);
        b64decoded = (unsigned char *)decode64(ctext, ctext_len);

        recovered = OPENSSL_zalloc(b64decoded_length);
        CMM_P2_decrypt(ec_decrypt_key, digest, b64decoded, b64decoded_length, recovered, &recovered_len);
    }
    else 
#else    
    {
        IF_VERBOSE printf("recovered  alloc(%d)\n", (int)ptext_len);
        recovered = OPENSSL_zalloc(ptext_len);
        CMM_P2_decrypt(ec_decrypt_key, ctext, ctext_len, recovered, &recovered_len);
    }
#endif


    IF_VERBOSE printf("recovered length: %d\n", recovered_len);

    recovered[recovered_len] =  0;
    memcpy(plaintext, recovered, recovered_len);
    //plaintext = recovered;
    *plaintext_len = recovered_len;
    
    IF_VERBOSE printf("PLAIN = ["color_blue_b"%hhn"color_reset"], length = [%d]\n", recovered, *plaintext_len);
            
        
    return 1;

}


//-------------------- ---------- ---------- -----------
// constraints
// message size < 4K 
// opt_secret
# define FORMAT_FILE    1
# define FORMAT_MEM     2
//---------- ---------- ---------- ---------- ---------- 
int CMM_P2_encrypt_file(char *infile, char *certin, char *outfile, char *x1, char *y1, char *ke, int opt_secret) 
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

    //fprintf(stderr, "read(%s): size=[%d]\n", infile, size );

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

int CMM_P2_decrypt_file(char *infile, char *keyin, char *passin, char *outfile, char *x1, char *x2, char *ke, int opt_secret) 
{
    //unsigned char plaintext[4096];
    unsigned char ciphertext[4096];
    size_t ciphertext_len = -1;
    FILE *fp = NULL;
    FILE *fpin = NULL;
    int size = 0;
    char *decpass=NULL;

    if(!outfile) {
        fprintf(stderr, "CMM_P2_decrypt_file: no out file specified.\n");
        return -1;
    }
    IF_VERBOSE fprintf(stderr, "CMM_P2_decrypt_file: "color_blue_b"Read shared secret from file."color_reset"\n");

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
    //IF_VERBOSE printf("DEC(CIPHER) : %x %x %x %x %x\n", ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3], ciphertext[4]);
    IF_VERBOSE printf("IN(CIPHER): %s\n", bin2hex(ciphertext, size));
    IF_VERBOSE printf("==================================================\n");
 
    //--------------------------------------------------
    // Decrypt
    //--------------------------------------------------
    char *keyfile = keyin;

    memset(sharedX1, 0, sizeof(sharedX1));
    memset(sharedY1, 0, sizeof(sharedY1));
    
    CMM_P2_read_secret(".", CMM_P1_SAVE_X1);
    CMM_P2_read_secret(".", CMM_P1_SAVE_Y1);

    //--------------------------------------------------
    // Recover : Decryption
    //--------------------------------------------------
    unsigned char recovered[4096];
    ciphertext_len = size;
    int recovered_len = -1;
    
    IF_VERBOSE fprintf(stderr, "Decrypting...\n");
    //printf("cipher text length = %d\n", (int)ciphertext_len);

    if(use_token != 1) {
    
        decpass = GZPKI_get_master_password_one(keyfile, "password:");

        IF_VERBOSE printf("==================================================\n");
        IF_VERBOSE printf("DEC:(PASSIN): [%s]\n", decpass);
        IF_VERBOSE printf("==================================================\n");
    }
    else {
        decpass = passin;
        IF_VERBOSE printf("==================================================\n");
        IF_VERBOSE printf("TOKEN:(PASSIN): [%s]\n", decpass);
        IF_VERBOSE printf("==================================================\n");
    }

    memset(recovered, 0, sizeof(recovered));
    //CMM_P2_DECRYPT(ciphertext, ciphertext_len, keyfile, passin, 0, recovered, &recovered_len);
    CMM_P2_DECRYPT(ciphertext, ciphertext_len, keyfile, decpass, 0, recovered, &recovered_len);

    //recovered[recovered_len] = 0;
    //IF_VERBOSE printf("recovered = ["color_red_b"%s"color_reset"]", recovered);

    fp = fopen(outfile, "wb");

    if( fp == NULL )     {
        IF_VERBOSE fprintf(stderr, "error:fopen():%s, %s\n", outfile, strerror(errno));
        return -1;
    }

    fwrite(recovered, recovered_len, 1, fp);

    IF_VERBOSE printf("==================================================\n");
    //IF_VERBOSE printf("DEC(CIPHER) : %x %x %x %x %x\n", ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3], ciphertext[4]);
    IF_VERBOSE printf("RECOVERED(PLAIN): %s\n", bin2hex(recovered, recovered_len));
    IF_VERBOSE printf("==================================================\n");
 
    fclose(fp);
    
    return 1;
}

#define CLI_CONF_FILENAME "./gzcms-cli.config"
int opt_cli_config = 0;
int cms_opt = CMS_VERIFY_SHOW_TEXT;

int main(int argc, char **argv)
{
    int c;
    int verbose = 0;
    int no_signer_cert_verify = 0;
    int informat = FORMAT_PEM;
    int outformat = FORMAT_PEM;
    int intype = FORMAT_FILE;

    char *infile = NULL, *outfile = NULL;
    char *cipher_algs = (char *)"aes256";
    char *digest_algs = (char *)"sha256";

    char *cert_file = NULL;
    char *key_file = NULL;
    char *cacert_file = NULL;
    char *usercert_file = NULL;
    char *passphrase = NULL;
    char *passin = NULL;

    char *token_param = NULL;
    char token_dir[256];

    int do_cmsinfo = 0;
    int do_cmstype = 0;

//--------------------------------------------------------------------------------
// KEY PASS OPTIONs
//--------------------------------------------------------------------------------
    int do_keypass = 0;
    int do_keypass_new = 0;
    int do_keypass_add = 0;
    int do_keypass_delete = 0;
    int do_keypass_password = 0;
    int do_keypass_init = 0;
    int do_keypass_export = 0;
    int do_keypass_list = 0;
    int do_keypass_list2 = 0;
    int do_keypass_revoke = 0;
    int do_keypass_update = 0;
    int do_keypass_rename = 0;
    int do_keypass_truncate = 0; //D 마킹된 모든 항목을 삭제한다. 

//--------------------------------------------------------------------------------
//ECC variables
//--------------------------------------------------------------------------------
    int do_ecc = 0;
    char *ecc_args = NULL;
    char *ecparam_args = NULL;
    char *secretdir_args = NULL;

//--------------------------------------------------------------------------------
//CA variables
//--------------------------------------------------------------------------------
#ifndef _NO_CA_
    int do_ca = 0;
    int do_ca_newca = 0;
    int do_ca_newcadir = 0;
    int do_ca_sign = 0;
    int do_ca_signcmm = 0;
    int do_ca_gentoken = 0;
    int do_ca_revoke = 0;
    int do_ca_gencrl = 0;
    int do_ca_newcmmdb = 0;
    int do_ca_approval = 0;

    char *cadir_args = NULL;
    char *caname_args = NULL;
    char *cakeyfile_args = NULL;
    char *cacertfile_args = NULL;
    char *caconfigfile_args = NULL;
#endif //_NO_CA_    

//--------------------------------------------------------------------------------    
//REQ ARGS    
//--------------------------------------------------------------------------------
    int do_req = 0;
    int do_req_newcmm = 0;
    int do_req_new = 0;
    int do_req_import_csv = 0; // csv format file import

//--------------------------------------------------------------------------------
//ECC Encrypt/ECC_P2 Encrypt
//--------------------------------------------------------------------------------
    int do_ecc_encrypt = 0;
    int do_ecc_decrypt = 0;
    int do_ecc_p2_encrypt = 0;
    int do_ecc_p2_decrypt = 0;
    int do_ecc_p2_secret_export = 0;
    int do_ecc_p2_secret_import = 0;

    char *ecc_p2_secret_args = NULL;


    //--------------------------------------------------
    //DIALOG mode
    //--------------------------------------------------
    //TODO
    //ncurse, or newt
    int dialog = 0;

    //--------------------------------------------------
    //TODO: KEYPASS 암호화 시 salt, iv, key를 출력할지 여부 옵션
    //--------------------------------------------------
    int opt_resource=0;
    int opt_resourcein=0;
    int keytype = KEY_TYPE_ANY;
    int len = 0;
    int keylen = 256;
    int show_text = 0;

    char *cmsopt_args = NULL;
    char *keypass_args = NULL;
    char *keyid_args = NULL;
    char *newkeyid_args = NULL;
    char *keytype_args = NULL;
    char *keystat_args = NULL;
    char *keyresource_args = NULL;

    //--------------------------------------------------
    //CA Arguments    
    //--------------------------------------------------
    char *ca_args = NULL;
    char *config_args = NULL;
    char *token_from_args = NULL;
    char *revoke_reason_args = NULL;
    
    int opt_token_from = 0;

    //--------------------------------------------------
    // SUCCESS CODE를 외부에서 지정
    //--------------------------------------------------
    char *success_args = NULL;
    //DEL int opt_success = 0;

    //"--return "
    char *return_args = NULL;
    int opt_return = 0;

    //"--random #NUM"
    //DEL char *random_args = NULL;
    int opt_random = 0;
    
       

    //keypass:
    //1: old status 무시하고 무조건 new status로 update
    //0: V->R, R->D로만 업데이트
    //TODO : 옵션으로 변경 가능하도록 수정필요
    int keypass_force_update = 0;

    _G_DEBUG_MODE_ = 0;

    GZPKI_CTX ctx;

    TOKEN_CTX token;

    char *outbuffer = NULL;
    unsigned int outbuffer_len = 0;

    IF_DEBUG printf("GZCMS-CLI CONFIG: %s\n", CLI_CONF_FILENAME);
    cli_conf = app_load_config(CLI_CONF_FILENAME);
    if(cli_conf) {
        IF_VERBOSE fprintf(stderr, "no client config file: %s\n", (char *)CLI_CONF_FILENAME);
        opt_cli_config = 0;
    }
    else
        opt_cli_config = 1;

    while (1)
    {    
        static struct option long_options[] =
        {
            {"help",  no_argument, 0, 'H'},
            {"ui",  no_argument, 0, 0}, //dialog or ncurse : TODO
            {"version",  no_argument, 0, 0},
            {"verbose",  no_argument, 0, 'G'},
            {"info",  no_argument, 0, 0},
            {"cmsinfo",  no_argument, 0, 0},
            {"certinfo",  required_argument, 0, 0},
            // long/short option, ex, --encrypt 는 -E와 동일 option
            {"encrypt", no_argument, 0, 'E'},
            {"decrypt", no_argument, 0, 'D'},
            {"sign",    no_argument, 0, 'S'},
            {"verify",  no_argument, 0, 'V'},
            
            {"sign_and_encrypt",    no_argument, 0, 0},
            {"decrypt_and_verify",  no_argument, 0, 0},
//--------------------------------------------------
//BEGIN GZCMM P1 ECDSA Encryption
//--------------------------------------------------
            {"ecc_encrypt", no_argument, 0, 0}, //--in <file> --out <file> --cert <file> + --token <>
            {"ecc_decrypt", no_argument, 0, 0}, //--in <file> --out <file> --key <file>


//--------------------------------------------------
//BEGIN GZCMM P2 ECDSA Encryption
//--------------------------------------------------
            {"ecc_p2_encrypt", no_argument, 0, 0}, //--in <file> --out <file> --cert <file> +  --token <>
            {"ecc_p2_decrypt", no_argument, 0, 0}, ////--in <file> --out <file> --key <file>
            {"ecc_p2_secret", required_argument, 0, 0}, // 1. generate, export -x1 <file> -y1 <file> -ke <file>
                                                        // 2. import -x1 <file> -y1 <file>

            {"in",      required_argument, 0, 'I'},

            {"eccp2", no_argument, 0, 0},
            {"base64_in", no_argument, 0, 0},
            {"base64_out", no_argument, 0, 0},

            ///@todo --in 구현 이후(파일 입/출력) 구현 진행
            {"infile",  required_argument, 0, 0},
            {"indata",  required_argument, 0, 0},

            //output parameters
            {"out",      required_argument, 0, 'O'},
            {"keyout",      required_argument, 0, 'O'},

            ///@todo 추가 구현 : out 옵션과 동일, 없는 경우는 printf 출력
            {"outfile",  required_argument, 0, 0},

            {"cert",     required_argument, 0, 'X'},
            {"key",      required_argument, 0, 'K'},

            //for encrypt/decrypt
            {"encrypt_cert", required_argument, 0, 0},
            {"decrypt_key",  required_argument, 0, 0},

            //for sign/verify
            {"sign_key",     required_argument, 0, 0},
            {"verify_cert",  required_argument, 0, 0},

            //format, in/out data format
            {"informat",  required_argument, 0, 0},
            {"outformat",  required_argument, 0, 0},

            //알고리즘
            {"cipher",  required_argument, 0, 'C'},
            {"digest",  required_argument, 0, 'M'},

            {"cacerts",  required_argument, 0, 'A'},
            {"signer",  required_argument, 0, 'U'},

            {"passin",    required_argument, 0, 'P'},

            {"no_signer_cert_verify", no_argument, 0, 0},

            {"token", required_argument, 0, 'T'},
            {"debug_on", no_argument, 0, 0},
            {"debug_off", no_argument, 0, 0},
            {"debug", required_argument, 0, 0},

            {"privatekey_encrypt", no_argument, 0, 0},
            {"privatekey_decrypt", no_argument, 0, 0},
            {"key_import", no_argument, 0, 0},
            {"key_export", no_argument, 0, 0},
            {"text", no_argument, 0, 0},

//--------------------------------------------------
//LIST ARGUMENTS
//--------------------------------------------------
            {"list", required_argument, 0, 0},            
//--------------------------------------------------
//KEYPASS ARGUMENTS
//--------------------------------------------------
            {"config", required_argument, 0, 0},            
            {"keypass", required_argument, 0, 0},
            {"keyid", required_argument, 0, 0},
            {"newkeyid", required_argument, 0, 0},
            {"keystat", required_argument, 0, 0},
            {"keylen", required_argument, 0, 0},
            {"db", required_argument, 0, 0},
            {"cipher_list", no_argument, 0, 0},
            {"master", no_argument, 0, 0},
            {"keytype", required_argument, 0, 0},
            {"printkey", no_argument, 0, 0},
            {"resource", required_argument, 0, 0},
            {"resourcein", required_argument, 0, 0},
            {"content", required_argument, 0, 0},
            {"contentin", required_argument, 0, 0},
            {"pkid", required_argument, 0, 0},
            {"loginid", required_argument, 0, 0},
//--------------------------------------------------
//CA ARGUMENTS
//--------------------------------------------------
            {"ca", required_argument, 0, 0},
            {"caname", required_argument, 0, 0},
            {"cadir", required_argument, 0, 0},
            {"caconfig", required_argument, 0, 0},
            {"cacert", required_argument, 0, 0},
            {"cakey", required_argument, 0, 0},
            {"token_section", required_argument, 0, 0},
            {"revoke_reason", required_argument, 0, 0},

//--------------------------------------------------            
//REQ ARGUMENTS
//--------------------------------------------------
            {"req", required_argument, 0, 0},
            //{"caname", required_argument, 0, 0},
            //{"caconfig", required_argument, 0, 0},
            {"with_mac", required_argument, 0, 0},
            {"with_cn", required_argument, 0, 0},
            {"req_section", required_argument, 0, 0},
            {"subject", required_argument, 0, 0},
            {"userid", required_argument, 0, 0},

//--------------------------------------------------
//ECC ARGUMENTS
//--------------------------------------------------
            {"ecc", required_argument, 0, 0},
            {"ecparam", required_argument, 0, 0},
            {"secret_dir", required_argument, 0, 0},

//--------------------------------------------------            
//TEST
//--------------------------------------------------
            {"test", no_argument, 0, 0},

//--------------------------------------------------            
//SUCCESS CODE FOR COMMAND
//--------------------------------------------------
            {"success", required_argument, 0, 0},
            {"return", required_argument, 0, 0},
            //RANDOM SESSION GENERATION, 
            //eg) ./gzcms-cli -rsession 16 
            {"random", no_argument, 0, 0}, 
//--------------------------------------------------
//END
//--------------------------------------------------
            {0, 0, 0, 0} // {0,0,0,0}로 옵션 만료
        };

        int option_index = 0;
        c = getopt_long (argc, argv, "GHEDSVA:bbc:d:f:i:O:I:C:K:X:U:T:", long_options, &option_index);

        // getopt_long: getopt()와 동일하게 모든 옵션 파싱을 마치면 -1을 return.
        if (c == -1)
            break;

        #define _args_is_(OPTS) !strcmp(OPTS,long_options[option_index].name )

        switch (c)
        {
            case 0:
                //--------------------------------------------------
                // long name options, ex) sign_and_enrypt, decrypt_and_verify, ...
                //--------------------------------------------------
                if (long_options[option_index].flag != 0)
                    break;

                IF_VERBOSE {
                    if (optarg)
                        fprintf (stderr, "args: %s", optarg);
                }

                if(_args_is_("test")) {
                    test_args = optarg;
                    do_test = 1;
                    printf("test on, var do_test=%d\n", do_test);
                } 

                if(_args_is_("eccp2") || _args_is_("ECCP2")) {
                    eccp2_encrypt_mode = 1;
                    eccp2_decrypt_mode = 1;
                } 
                if(_args_is_("success")) {
                    
                    //DEL opt_success = 1;
                    success_args = optarg;
                } 

                if(_args_is_("base64_in")) {
                    base64_in = 1;
                } 
                
                if(_args_is_("base64_out")) {
                    base64_out = 1;
                } 

                if(_args_is_("return")) {
                    
                    opt_return = 1;
                    return_args = optarg;
                } 

                if(_args_is_("random"))  {
                    opt_random = 1;
                }

                if(_args_is_("ui")) {
                    dialog = 1;
#ifdef DEBUG_MODE                    
                    if(1==dialog) {
                        printf("gzcms-cli, dialog mode.\n");    
                    }
#endif                    
                } 
                
                if(_args_is_("info")) {
                    printf("gzcms-cli %s\n", app_version);
                    printf("Copyright (C) 2019 Greenzone Security, Inc.\n");
                    printf("GZCMS Library Version: %s\n", (char *)GZPKI_lib_get_version());
                    exit(0);
                } 
                /*else*/
                if(_args_is_("cmsinfo")) {
                    cmsopt_args = optarg;
                    IF_VERBOSE fprintf(stderr, "--cmsinfo args: %s\n", (char *)cmsopt_args);
                    do_cmsinfo = 1;
                    operation = SMIME_CMSOUT;
                } 
                
                /*else*/ if(_args_is_("config")) {
                    config_args = optarg;
                    IF_VERBOSE fprintf(stderr, "config file: %s\n", (char *)config_args);
                    if(config_args != NULL) {
			            if(0 != access(config_args, R_OK)) {
				            fprintf(stderr,"fail to access defalut config file : %s\n",config_args);
				            return -1;
			            }
		            }
                    gzcms_conf = app_load_config(config_args);
                    if(!gzcms_conf) {
                        fprintf(stderr, "error: loading config file: %s\n", (char *)config_args);
                        return -1;
                    }
                
                } 

//--------------------------------------------------
//ECC P1
//--------------------------------------------------

                /*else*/
                if(_args_is_("ecc_encrypt")) {
                    printf("ecc_encrypt: operation = ECC_ENCRYPT, do_ecc_encrypt = 1\n");
                    operation = ECC_ENCRYPT;
                    do_ecc_encrypt = 1;
                } 
                /*else*/
                 if(_args_is_("ecc_decrypt")) {
                     printf("ecc_decrypt: operation = ECC_DECRYPT, do_ecc_decrypt = 1\n");
                    operation = ECC_DECRYPT;
                    do_ecc_decrypt = 1;
                } 

//--------------------------------------------------
//ECC P2
//--------------------------------------------------                
                else if(_args_is_("secret_dir")) {
                    //operation = ECCP2_ENCRYPT;
                    secretdir_args = optarg;
                } 
                else if(_args_is_("ecc_p2_encrypt")) {
                    operation = ECCP2_ENCRYPT;
                    do_ecc_p2_encrypt = 1;
                } 
                else if(_args_is_("ecc_p2_decrypt")) {
                    operation = ECCP2_DECRYPT;
                    do_ecc_p2_decrypt = 1;
                } 
                else if(_args_is_("ecc_p2_secret")) {
                    operation = ECCP2_GENERATE_SECRET;
                    ecc_p2_secret_args = optarg;
                    //do_ecc_p2_secret = 1;

                    if(!strcmp(ecc_p2_secret_args, "export")) {
                        do_ecc_p2_secret_export = 1; 
                    }
                    else if(!strcmp(ecc_p2_secret_args, "import")) {
                        do_ecc_p2_secret_import = 1; 
                    }
                    else {
                        fprintf(stderr, "unknown args: %s\n", ecc_p2_secret_args);
                        return -1;
                    }
                    
                } 
//--------------------------------------------------
//ECC
//--------------------------------------------------
                else if(_args_is_("ecc")) {
                    ecc_args = optarg;
                    do_ecc = 1;
                } 
                //else 
                if(_args_is_("ecparam")) {
                     ecparam_args = optarg;
                } 

                //else 
#ifndef _NO_CA_                
                if(_args_is_("caname")) {
                    caname_args = optarg;
                } 
#endif //_NO_CA_                
//--------------------------------------------------
//LIST curve, cipher, digest
//--------------------------------------------------                
                //else
                if(_args_is_("list")) {
                    list_args = optarg;
                    do_list = 1;
                } 
                //else
                if(_args_is_("req_section")) {
                    req_section_args = optarg;
                } 
                //else 
                if(_args_is_("token_section")) {
                    token_from_args = optarg;
                    opt_token_from = 1;
                } 
                else if(_args_is_("userid")) {
                    userid_args = optarg;
                }                 
                /*else if(_args_is_("subject")) {
                    subject_args = optarg;
                } */
                //else 
#ifndef _NO_CA_                
                if(_args_is_("cadir")) {
                    cadir_args = optarg;
                } 
                //else 
                if(_args_is_("caconfig")) {
                    caconfigfile_args = optarg;
                    if(!caconfigfile_args) {
                        fprintf(stderr, "error: invalid CA config filename\n");
                        return -1;
                    }
                    
                } 
                else if(_args_is_("cacert")) {
                    cacertfile_args = optarg;
                    if(!cacertfile_args)
                    {
                        fprintf(stderr, "error: invalid CA certificate filename\n");
                        return -1;
                    }
                } 
                else if(_args_is_("cakey")) {
                    cakeyfile_args = optarg;
                    if(!cakeyfile_args)
                    {
                        fprintf(stderr, "error: invalid CA key filename\n");
                        return -1;
                    }
                } 

                else if(_args_is_("keyid")) {
                    //keyid_args = GZPKI_strdup(optarg);
                    keyid_args = optarg;
                    IF_VERBOSE fprintf(stderr, "keyid: ["color_yellow_b"%s"color_reset"]\n", (char *)keyid_args);
                    if(keyid_args==NULL) {
                        fprintf(stderr, "error: invalid key id\n");
                        return 0;
                    }
                } 
                else if(_args_is_("newkeyid")) {
                    //newkeyid_args = GZPKI_strdup(optarg);
                    newkeyid_args = optarg;
                    IF_VERBOSE fprintf(stderr, "newkeyid: ["color_yellow_b"%s"color_reset"]\n", (char *)newkeyid_args);
                    if(newkeyid_args==NULL) {
                       fprintf(stderr, "error: invalid key id\n");
                        return 0;
                    }
                } 
                
                else if(_args_is_("keystat")) {
                    //keystat_args = GZPKI_strdup(optarg);
                    keystat_args = optarg;
                    IF_VERBOSE fprintf(stderr, "key status: ["color_yellow_b"%s"color_reset"]\n", (char *)keystat_args);
                    if(keystat_args==NULL) {
                       fprintf(stderr, "error: invalid key status.\n");
                        return 0;
                    }
                } 
                else if(_args_is_("resource") || _args_is_("content") ) {
                    //keyresource_args = GZPKI_strdup(optarg);
                    keyresource_args = optarg;
                    IF_VERBOSE fprintf(stderr, "resource: ["color_yellow_b"%s"color_reset"]\n", (char *)keyresource_args);
                    if(!keyresource_args) {
                        fprintf(stderr, "error:invalid resource parameter.\n");
                        return -1;
                    }
                    opt_resource = 1;
                   
                } 
                else if(_args_is_("resourcein") || _args_is_("contentin") ) {
                    //keyresource_args = GZPKI_strdup(optarg);
                    keyresource_args = optarg;
                    IF_VERBOSE fprintf(stderr, "resourcein: ["color_yellow_b"%s"color_reset"]\n", (char *)keyresource_args);
                    if(!keyresource_args) {
                        fprintf(stderr, "error:invalid keyresource_args parameter.\n");
                        return -1;
                    }
                    opt_resourcein = 1;
                } 
                else if(_args_is_("keytype")) {
                    //keytype_args = GZPKI_strdup(optarg);
                    keytype_args = optarg;
                    IF_VERBOSE fprintf(stderr, "key type: ["color_yellow_b"%s"color_reset"]\n", (char *)keytype_args);

                    if(keytype_args == NULL) {
                        fprintf(stderr, "error:invalid key type parameter.\n");
                        return -1;
                    }

                    if(0==strcmp(keytype_args, KEY_TYPE_S_ANY))
                        keytype = KEY_TYPE_ANY;
                    else if(0==strcmp(keytype_args, KEY_TYPE_S_PRIVATE_KEY))
                        keytype = KEY_TYPE_PRIVATE_KEY;
                    else if(0==strcmp(keytype_args, KEY_TYPE_S_SECRET_KEY))
                        keytype = KEY_TYPE_SECRET_KEY;
                    else if(0==strcmp(keytype_args, KEY_TYPE_S_SIGNIN))
                        keytype = KEY_TYPE_SIGNIN;                        
                    else {
                        fprintf(stderr, "error:invalid key type parameter: %s\n", keytype_args);
                        return -1;
                    }
                } 
                else if(_args_is_("keylen")) {
                    keylen = atoi(optarg);
                    IF_VERBOSE fprintf(stderr, "key length: ["color_yellow_b"%d"color_reset"]\n", keylen);
                } 
                /*else if(_args_is_("cipher_list")) {
                    do_cipher_list = 1;
                } */
                else if(_args_is_("with_mac")) {
                    with_mac_args = optarg;
                } 
                else if(_args_is_("with_cn")) {
                    with_cn_args = optarg;
                } 
                else if(_args_is_("with-email")) {
                    with_email_args = optarg;
                } 
                else if(_args_is_("req")) {
                    //req_args = GZPKI_strdup(optarg);
                    req_args = optarg;
                    do_req = 1;
                    fprintf(stderr, "REQ(%s) ", req_args);
                    if(!strcmp(req_args, "newcmm")) {
                        //with-mac, with-cn, ca.config algorithm read
                        do_req_newcmm = 1; 
                        fprintf(stderr, "- generate new keypair and request with MAC/CN\n");
                    }
                    else if(!strcmp(req_args, "new")) {
                        do_req_new = 1; //req, --keyin
                        fprintf(stderr, "- generate new request.\n");
                    }
                    //TODO: add
                    /*
                    else if(!strcmp(req_args, "newkey")) {
                        do_req_newkey = 1; //key + req
                        fprintf(stderr, "- generate new key/request.\n");
                    }
                    */
                    else if(!strcmp(req_args, "importcsv")) {
                        do_req_import_csv = 1; //key + req
                        fprintf(stderr, "- import csv file include certificate request(CN,MAC) \n");
                    }
                    else {
                        fprintf(stderr, "- Unknown options, --req {newcmm|new|newkey} required.\n");
                        return -1;
                    }
                } 
                else if(_args_is_("revoke_reason")) {
                    revoke_reason_args = optarg;
                    if(0!=is_valid_crl_reason(revoke_reason_args)) {
                        fprintf(stderr, "Unknown revoke reason, --revoke_reason $RevokeReason\n");
                        print_revokeReason();
                        return 0;
                    }
                }
#endif                 

#ifndef _NO_CA_ 
                else if(_args_is_("ca")) {
                    ca_args = optarg;
                    do_ca = 1;

                    if(!strcmp(ca_args, "newca")) {
                        do_ca_newca = 1;
                    }
                    /*else if(!strcmp(ca_args, "xsign")) {
                        do_ca_xsign = 1;
                    }*/
                    else if(!strcmp(ca_args, "sign")) {
                        do_ca_sign = 1;
                    }
                    else if(!strcmp(ca_args, "newcadir")) {
                        do_ca_newcadir = 1;
                    }
                    else if(!strcmp(ca_args, "signcmm")) {
                        do_ca_signcmm = 1;
                    }
                                 
                    //TODO
                    /*
                    else if(!strcmp(ca_args, "export")) {
                        //--------------------------------------------------
                        //TODO: PKCS12로 EXPORT
                        //    : not yes implemented
                        //--------------------------------------------------
                        do_ca_export = 1;
                    }
                    */
                    else if(!strcmp(ca_args, "token") || !strcmp(ca_args, "gentoken"))  {
                        //--------------------------------------------------
                        //USB TOKEN 생성 
                        //--------------------------------------------------
                        do_ca_gentoken = 1;
                    }
                    else if(!strcmp(ca_args, "revoke")) {
                        //--------------------------------------------------
                        // Revpke Certi
                        //--------------------------------------------------
                        do_ca_revoke = 1;
                    }
					else if(!strcmp(ca_args, "gencrl")) {
                        do_ca_gencrl = 1;
                    }
                    else if(!strcmp(ca_args, "approval")) {
                        do_ca_approval = 1;
                    }
                    else if(!strcmp(ca_args, "newcmmdb")) {
                        do_ca_newcmmdb = 1;
                    }
                    else {
                        fprintf(stderr, "error: invalid ca parameter.\n");
                        fprintf(stderr, "Usage:\n");
                        fprintf(stderr, "    ./gzcms-cli --ca {newcadir|newca|signcmm|sign} ...\n");
                        return -1;
                    }
                    
                }
#endif //_NO_CA_                       

#ifndef _NO_CA_                       
                else if(_args_is_("keypass")) {

                    keypass_args = GZPKI_strdup(optarg);

                    if(!keypass_args) {
                        fprintf(stderr, "error: no keypass arguments, Use --help options.\n");
                        exit(0);
                    }

                    do_keypass = 1;

                    if(!strcmp(keypass_args, "new")) {
                        do_keypass_new = 1;
                    }
                    else if(!strcmp(keypass_args, "add")) {
                        do_keypass_add = 1;
                    }
                    else if(!strcmp(keypass_args, "list")) {
                        do_keypass_list = 1;
                    }
                    else if(!strcmp(keypass_args, "list2")) {
                        do_keypass_list2 = 1;
                    }
                    else if(!strcmp(keypass_args, "delete")) {
                        do_keypass_delete = 1;
                    }
                    //DEL else if(!strcmp(keypass_args, "change")) {
                    //DEL    do_keypass_change = 1;
                    //DEL }
                    else if(!strcmp(keypass_args, "init")) {
                        do_keypass_init = 1;
                    }
                    //else if(!strcmp(keypass_args, "import")) {
                    //    do_keypass_import = 1;
                    //}
                    else if(!strcmp(keypass_args, "export")) {
                        do_keypass_export = 1;
                    }
                    else if(!strcmp(keypass_args, "revoke")) {
                        do_keypass_revoke = 1;
                    }
                    else if(!strcmp(keypass_args, "update")) {
                        do_keypass_update = 1;
                    }
                    else if(!strcmp(keypass_args, "truncate")) {
                        do_keypass_truncate = 1;
                    }
                    else if(!strcmp(keypass_args, "rename")) {
                        do_keypass_rename = 1;
                    }
                    //----- change master password -----
                    else if(!strcmp(keypass_args, "password") || !strcmp(keypass_args, "passwd")) {
                        do_keypass_password = 1;
                    }
                    
                    else {
                        fprintf(stderr, "error: invalid keypass parameter: "color_yellow_b"%s"color_reset", Use --help options.\n", keypass_args);
                        exit(0);
                    }
                    //exit(0);
                } 
                else if(_args_is_("db")) {
                    //keydb_file = GZPKI_strdup(optarg);
                    keydb_file = optarg;
                    if(!keydb_file) {
                        fprintf(stderr, "error: no key db arguments, Use --help options.\n");
                        exit(0);
                    }

                    use_keypass_db = 1;
                    /* keydb를 생성하는 경우, 사전에 check하면 안됨
                    if(!is_file_exists(keydb_file)) {
                       printf("error: file not exists: %s\n", keydb_file);
                        exit(0);
                    }*/
                } 
#endif //_NO_CA_                                       
                /*else if(_args_is_("printkey")) {
                    opt_printkey = 1;
                } */
                else if(_args_is_("cmstype")) {
                    do_cmsinfo = 1;
                    do_cmstype = 1;
                    operation = SMIME_CMSOUT;
                    //exit(0);
                } 
                else if(_args_is_("text")) {
                    show_text = 1;
                } 
                else if(_args_is_("debug_on")) {
                    _G_DEBUG_MODE_ = 1;
                } 
                else if(_args_is_("debug_off")) {
                    _G_DEBUG_MODE_ = 0;
                } 
                else if(_args_is_("certinfo" )) {
                    fprintf(stderr, DEBUG_TAG"certinfo processing...\n");
                } 
                else if(_args_is_("infile")) {
                    fprintf(stderr, DEBUG_TAG"infile processing...\n"); 
                } 
                else if(_args_is_("indata" )) {
                    fprintf(stderr, DEBUG_TAG"indata processing...\n");
                }
                //==================================================
                // 'X' options, required_argument
                //==================================================
                else if(_args_is_("cert" )) {
                    fprintf(stderr, DEBUG_TAG"--cert/X args option processing...\n");
                }
                else if(!strcmp("encrypt_cert",long_options[option_index].name )) {
                    fprintf(stderr, DEBUG_TAG"ENCRYPT_CERT option processing...\n");
                }
                else if(!strcmp("decrypt_generate_certificate_hashkey",long_options[option_index].name )) {
                    fprintf(stderr, "DECRYPT_KEY option processing...\n");
                }
                else if(!strcmp("verbose",long_options[option_index].name )) {
                    verbose = 1;
                    _G_DEBUG_MODE_= 1;
                    fprintf(stderr, "debug:verbose set\n");
                }
                else if(!strcmp("token",long_options[option_index].name )) {
                    use_token = 1;
                    fprintf(stderr, "SET use_token=[1]\n");
                }
                else if(!strcmp("no_signer_cert_verify",long_options[option_index].name )) {
                    no_signer_cert_verify = 1;
                    fprintf(stderr, DEBUG_TAG"no signer cert verify option: 1\n");
                }
                else if(!strcmp("key_import",long_options[option_index].name )) {
                    opt_key_import=1;
                    IF_VERBOSE fprintf(stderr, DEBUG_TAG"opt_key_import: 1\n");
                }
                break;

            case 'G':  //VERBOSE
                verbose = 1;
                _G_DEBUG_MODE_ = 1;
                _G_VERBOSE_MODE_ = 1;
                fprintf(stderr, "verbose mode: "color_green_b"on"color_reset"\n");
                
                break;
            case 'E':
                encrypt_flag = 1;
                decrypt_flag = 0;
                operation = SMIME_ENCRYPT;
                break;

            case 'D':
                encrypt_flag = 0;
                decrypt_flag = 1;
                operation = SMIME_DECRYPT;
                break;

            case 'S':
                sign_flag = 1;
                verify_flag = 0;
                operation = SMIME_SIGN;
                break;

            case 'V':
                sign_flag = 0;
                verify_flag = 1;
                operation = SMIME_VERIFY;
                break;

            // input data, file type
            case 'I':
                intype = FORMAT_FILE; //default;
                infile = optarg;
                if(infile && !is_file_exists(infile)) {
                    printf("error: file not exists: %s\n", infile);
                    exit(0);
                }
                break;

            // output data, file type
            case 'O':
                ctx.outtype = FORMAT_FILE; //default;
                outfile = (char *)optarg;
                break;

            // cipher algorithm name
            case 'C':
                //optarg가 정상 알고리즘인지 확인
                //cipher_algs = GZPKI_strdup(optarg);
                cipher_algs = optarg;
                if(cipher_algs && !is_valid_cipher(cipher_algs))
                {
                    printf("error: invalid encryption algorithm name: %s\n", cipher_algs);
                    exit(0);
                }
                //printf ("check: cipher algorithm : %s\n", cipher_algs);
                break;

            // message digest algorithm name
            case 'M':
                digest_algs = optarg;
                IF_VERBOSE fprintf (stderr, INFO_TAG"digest algorithm: %s\n", digest_algs);
                break;

            //--------------------------------------------------
            // --cert [X.509 certificate file]
            //--------------------------------------------------
            case 'X':
                cert_file = optarg;
                int r = GZPKI_check_valid_certificate(cert_file, FORMAT_PEM);
                if(r != CMS_RET_OK) {
                    fprintf(stderr, "error:no certificate:%s\n", cert_file);
                    exit(0);
                }
                if(verbose == 1) {
                    IF_VERBOSE fprintf (stderr, INFO_TAG"check file: %s\n", cert_file);
                }
                break;

            // private key
            case 'K':
                key_file = optarg;
                if(key_file && !is_file_exists(key_file)) {
                    printf("error: key file not exists: %s\n", key_file);
                    exit(0);
                }
                if(verbose == 1) printf ("check exists private key file: %s\n", key_file);
                break;

            case 'A':
                cacert_file = optarg;
                if(cacert_file && !is_file_exists(cacert_file)) {
                    printf("error: CA certificate not exists: %s\n", cacert_file);
                    exit(0);
                }
                if(verbose == 1) printf ("check exist CA certificate file: %s\n", cacert_file);
                break;

            case 'U':
                usercert_file = optarg;
                IF_VERBOSE fprintf (stderr, INFO_TAG"usercert file name: %s\n", usercert_file);
                break;

            case 'P':
                passphrase = optarg;
                if(verbose == 1) printf ("debug: passphrase=[%s]\n", passphrase);

                if (!app_passwd(passphrase, NULL, &passin, NULL)) {
                        printf("Error getting password\n");
                        //goto end;
                        exit(0);
                }

                IF_VERBOSE fprintf(stderr, DEBUG_TAG"app_passed(passinarg [%s], passin [%s]\n", passphrase, passin);

                break;
            
            //token 사용
            case 'T':
                token_param = optarg;
                trim(token_param);

                if(token_param) {
                    len = strlen(token_param) - 1;
                    if(token_param[len] == '/')
                        token_param[len] = 0;

                    IF_VERBOSE fprintf(stderr, INFO_TAG"length=[%d]\n", len);
                }
                
                sprintf(token_dir, "%s/gzcms", token_param );
                struct stat st;
                if(stat(token_dir,&st) == 0) {
                    if(st.st_mode & (S_IFDIR != 0)) {
                        use_token = 1;
                        IF_VERBOSE fprintf(stderr, DEBUG_TAG"check directory:[%s] ok.\n", token_dir);
                    }
                }
                else    
                    use_token = 0;
                
                if (use_token != 1) {
                    fprintf(stderr, ERR_TAG"no directory:%s, exit.\n",  token_dir);
                    exit(0);
                }

                break;

            case 'H':
                help();
                exit(0);
                //break;

            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                //abort ();
                printf ("Invalid options...\n");
                break;
        }
    }

    // --encrypt --eccp2 options
    if(operation == SMIME_ENCRYPT && eccp2_encrypt_mode == 1) {
        IF_VERBOSE fprintf(stdout, "operation SMIME_ENCRYPT, mode chanage to ECCP2_ENCRYPT\n");
        operation = ECCP2_ENCRYPT;
        do_ecc_p2_encrypt = 1;
            
    }
    
    // --decrypt --eccp2 options ==> ECCP2_ENCRYPT
    if(operation == SMIME_DECRYPT && eccp2_decrypt_mode == 1) {
        IF_VERBOSE fprintf(stdout, "operation SMIME_DECRYPT, mode chanage to ECCP2_DECRYPT\n");
        operation = ECCP2_DECRYPT;
        do_ecc_p2_decrypt = 1;
            
    }
    //
    //---------- gzcms-cli.config ----------
    //
    char *tmpCfg = NULL;
    //GET: use_token
    if(1 != use_token ) {
        int tmp_use_token = 0;
        tmpCfg = NULL;
        tmpCfg = client_config_get_value("token", "use_token");
        if(tmpCfg) {
            //fprintf(stderr, "client.config:token:use_token = [%s]\n", tmpCfg);
            //fprintf(stderr, "    option(use_token) value are ["color_blue"%d"color_reset"]\n", use_token);
            tmp_use_token = atoi(tmpCfg);
            if(tmp_use_token == 1) {
                use_token = 1;
                //fprintf(stderr, "    option(use_token) set as ["color_red"%d"color_reset"]\n", use_token);
                tmpCfg = NULL;
                tmpCfg = client_config_get_value("token", "token_dir");
                //fprintf(stderr, "%d: client.config:token:token_dir = [%s]\n", __LINE__,  tmpCfg);

                sprintf(token_dir, "%s/gzcms", tmpCfg );
                //fprintf(stderr, "client.config:token:token_dir = [%s]\n", token_dir);
                struct stat st;
                if(stat(token_dir,&st) == 0) {
                    if(st.st_mode & (S_IFDIR != 0)) {
                        IF_VERBOSE fprintf(stderr, "success:check directory:[%s]\n", token_dir);
                    }
                }
                else {
                    use_token = 0;
                    //fprintf(stderr, "error:gzcms-cli.config: no token_dir: %s\n", tmpCfg);
                    //fprintf(stderr, "TODO FIX: %d %s\n", __LINE__, __FILE__);
                }
            }
        }

        
    }

#if 0 //TODO
    tmpCfg = client_config_get_value("token", "token_dir");
    fprintf(stderr, "client.config:token:token_dir = [%s]\n", tmpCfg);
    //client_config_get_value(sect, name)
#endif     

     
    //--------------------------------------------------
    //init context
    //--------------------------------------------------
    int r = CMS_RET_UNDEF;
    
    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;

    char token_device_cert[256];
    char token_device_key[256];
    char token_ca_cert[256];
    char token_device_key_new[256];
    
    GZPKI_init_ctx(&ctx);

    if(opt_return == 1) {
        printf("return.opt = %d\n", opt_return);
        printf("return.val = %s\n", return_args);
    }

    if(opt_random == 1) {
        unsigned char *p = NULL;
        p = GZPKI_gen_random_pass(32);
        printf("%s\n", p);
        return 0;
    }

    //if(opt_key_import == 1 && use_token == 1) {
    if( 1 == use_token ) {
        //실제 파일들이 존재하는지 확인한다. 
        memset(token_device_cert, 0, sizeof(token_device_cert));
        sprintf(token_device_cert, "%s/cert/device/device.pem", token_dir);

        GZPKI_generate_device_password(&ctx, NULL,  token_device_cert);
        
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"device_password: %s\n", ctx.device_password);

        GZPKI_init_token(&token, token_dir);
     
        int bLoadKey = LOAD_DEVICE_KEY;
        GZPKI_get_token_load_key(&token, bLoadKey, NULL);
        
        bLoadKey = LOAD_SERVER_KEY;
        GZPKI_get_token_load_key(&token, bLoadKey, NULL);
    }


    if(opt_key_import == 1 && use_token==1 ) {

        memset(token_device_key, 0, sizeof(token_device_key));
        memset(token_device_cert, 0, sizeof(token_device_cert));

        sprintf(token_device_key, "%s/cert/device/device.key", token_dir);
        sprintf(token_device_cert, "%s/cert/device/device.pem", token_dir);
        sprintf(token_device_key_new, "%s/cert/device/device.key.new", token_dir);
        //TODO: exists?

        GZPKI_set_infile(&ctx, token_device_key, NULL, 0, FORMAT_PEM);
        GZPKI_set_outfile(&ctx, token_device_key_new, FORMAT_PEM);

        char *pwdin = NULL;

        pwdin =  getpass("password for device.key:");

        ctx.passin = GZPKI_strdup(pwdin);
        ctx.passout = GZPKI_strdup((char *)ctx.device_password);

        if(cipher_algs) 
            ctx.name = GZPKI_strdup(cipher_algs);
        else
            ctx.name = "aes256";

        r = GZPKI_do_ECC(&ctx);
        if(CMS_RET_OK!=r) {
            printf("error:do_ecc:failed\n");
            return 0;
        }

        //TODO: DELETE ORIGINAL KEY
        //TODO: MV NEW ORG

        return 0;
        //if(verbose == 1) printf("debug: infile(%s) encrypted with certificate(%s) to outfile(%s)\n", infile, cert_file, outfile);
    }

    if(do_list==1)  {
        if(!strcmp(list_args, "cipher") 
            || !strcmp(list_args, "cipher_all") 
            || !strcmp(list_args, "cipher_compat")
            || !strcmp(list_args, "digest")
            ) {
            //IF_VERBOSE fprintf(stderr, "cipher list\n");
            GZPKI_CTX C;
            GZPKI_init_ctx(&C);
            if(!strcmp(list_args, "cipher2"))
                C.operation = GZPKI_CIPHER_LIST;
            else if(!strcmp(list_args, "cipher"))
                C.operation = GZPKI_CIPHER_LIST_ALL;
            else if(!strcmp(list_args, "cipher_compat"))
                C.operation = GZPKI_CIPHER_LIST_COMPAT;                
            else if(!strcmp(list_args, "digest"))
                C.operation = GZPKI_DIGEST_LIST;                
            GZPKI_do_ENC(&C);
            GZPKI_free_ctx(&C);
            return 0;
        }
        else if(!strcmp(list_args, "rr")) {
            print_revokeReason();
        }
        else if(!strcmp(list_args, "curve")) {
            print_ecdsa_curves(0);
        }

        printf("success\n");
        return 0;
    }

    
    /*
    if(do_cipher_list==1)  {

        IF_VERBOSE fprintf(stderr, "cipher list\n");
        GZPKI_CTX C;
        GZPKI_init_ctx(&C);
        C.operation = GZPKI_CIPHER_LIST;
               
        GZPKI_do_ENC(&C);
        
        GZPKI_free_ctx(&C);
        return 0;
    }
    */

//--------------------------------------------------
// TEST CODE  API_TEST
//--------------------------------------------------

    if(do_test==1) {
    //if(1) {
        
        char *config = "./gzcms-cli.config";
        //char *config = NULL;
        char *section = NULL;
        char *infile = "./test/plain.txt";
        char *outfile = "./test/plain.txt.encrypted";
        char *outfile_ff = "./test/plain.txt.ff.cms";
        char *orgfile_ff = "./test/plain.txt.ff.org";
        char *outfile2 = "./test/plain.txt.2.encrypted";

        char *orgfile_bf = "./test/plain.txt.bf.org";

        char *certfile = "./test/server.pem"; 
        char *keyfile = "./test/server.key";
        char *cafile = "./test/ca.pem";
        char *cipher_algs  = "lea192";
        char *digest_algs = "sha256";
        char *passin = "1234";

        int r = -1;

        char *inbuffer = "welcome, hello, hi, 1234 abcd 가나다라 !@#$!@#$ [] END.";
        char *outbuffer = NULL;
        char *orgbuffer = NULL;
        
        unsigned int inbuffer_len = strlen(inbuffer);
        unsigned int outbuffer_len = 0;
        unsigned int orgbuffer_len = 0;

        char secretfile_k[256], secretfile_x[256], secretfile_y[256];

        memset(secretfile_k, 0, sizeof(secretfile_k));
        memset(secretfile_x, 0, sizeof(secretfile_x));
        memset(secretfile_y, 0, sizeof(secretfile_y));

# define        buffer_clear(A) free(A); A = NULL


//ECCP2 SECRET GEN/WRITE/READ
#if 0
        printf(color_red"========================================\n"color_reset);
        printf(color_red"ECCP2 SECRET GEN/SAVE/READ TEST: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);
        //int gzpki_eccp2_generate_secret(char *certfile /*const EC_KEY *key*/,  char **K, char **X, char **Y, unsigned int *size, int opt)
        int ec_field_size = -1;
        int rc = 0;

        char xx[128], yy[128], kk[128];
        rc = gzpki_eccp2_generate_secret(certfile, kk, xx, yy, &ec_field_size, 0);
        if(rc == 0) {
            printf("gzpki_eccp2_generate_secret() : rc   = %d\n", rc);
            printf("gzpki_eccp2_generate_secret() : size = %d\n", ec_field_size);
            printf("gzpki_eccp2_generate_secret() : kk   = %s\n", kk);
            printf("gzpki_eccp2_generate_secret() : xx   = %s\n", xx);
            printf("gzpki_eccp2_generate_secret() : yy   = %s\n", yy);
        }

       
        sprintf(secretfile_k, "%s.eck", certfile);
        sprintf(secretfile_x, "%s.ecx", certfile);
        sprintf(secretfile_y, "%s.ecy", certfile);
        
        rc =  gzpki_eccp2_save_secret(secretfile_k, kk, ec_field_size*2, 0);
        rc += gzpki_eccp2_save_secret(secretfile_x, xx, ec_field_size*2, 0);
        rc += gzpki_eccp2_save_secret(secretfile_y, yy, ec_field_size*2, 0);

        if(rc == 0) {
            printf("success: save(k, x, y)\n");
        }
        else {
            printf("error: save(k, x, y), rc=%d\n", rc);
        }

        //FREE
        //free(kk); free(xx); free(yy);

        printf(color_yellow"========================================\n"color_reset);
        printf(color_yellow"ECCP2 SECRET READ TEST: config=%s\n"color_reset, config);
        printf(color_yellow"========================================\n"color_reset);

        char rk[128], rx[128], ry[128];
        int rk_len=0, rx_len=0, ry_len=0;

        memset(rk, 0, sizeof(rk));
        memset(rx, 0, sizeof(rx));
        memset(ry, 0, sizeof(ry));

        
        r = gzpki_eccp2_read_secret(secretfile_k, rk, &rk_len, 0);
        r = gzpki_eccp2_read_secret(secretfile_x, rx, &rx_len,0);
        r = gzpki_eccp2_read_secret(secretfile_y, ry, &ry_len,0);

        printf("K: read(%s): %s\n", secretfile_k, rk);
        printf("X: read(%s): %s\n", secretfile_x, rx);
        printf("Y: read(%s): %s\n", secretfile_y, ry);

        //return 0;
#endif


//생성된 secret 파일을 읽고
//암호화를 수행한다. 
#if 0
    {
        
        //gzpki_eccp2_append_secret_to_certfile(certfile, ECCP2_HEADER_K, "E206C901F22E88FDEA96B4BC5BC99EAD4CFC0A17B3AA474F182C7215CD6630AA", 0, 0);
        //gzpki_eccp2_append_secret_to_certfile(certfile, ECCP2_HEADER_X, "44B43F7F6B7E916D7A49A0D94C02E7F61914B99B43DDFABF2083BB1C7E6CEEEF", 0, 0);
        //gzpki_eccp2_append_secret_to_certfile(certfile, ECCP2_HEADER_Y, "6BA714B15966955B59BF22D3524CC1CE96AA5C0D899E03EBC43E426860C28F28", 0, 0);
        
        /*char tmp[1024];
        int len = 0;
        r = gzpki_eccp2_read_secret_from_certfile(certfile, ECCP2_HEADER_K, tmp, &len, 0);

        printf("ECCP2_HEADER_K = [%s]\n", tmp);

        return 0;
        */

        //ENCRYPT ECCP2
        char *infile = "./test/plain.txt";
        char *outfile2 = "./test/plain.txt.enc";
        char *outfile3 = "./test/plain.txt.org";
        r =  gzpki_eccp2_encrypt_file(config, infile, outfile2, certfile, secretfile_k, ECCP2_SECRET_FROM_CERTFILE);
        printf("gzpki_eccp2_encrypt_file(): %d\n", r);

        r = gzpki_eccp2_decrypt_file(config, outfile2, outfile3, certfile, keyfile, passin, ECCP2_SECRET_FROM_CERTFILE);
        printf("gzpki_eccp2_decrypt_file(): %d\n", r);


        return 0;

    }
#endif

#if 0
        printf(color_red"========================================\n"color_reset);
        printf(color_red"ECCP2 ENCRYPT BUFFER TEST: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);

        r = gzpki_eccp2_encrypt_buffer(config, inbuffer, inbuffer_len, &outbuffer, &outbuffer_len, certfile, ECCP2_SECRET_FROM_CERTFILE);
        printf("gzpki_eccp2_encrypt_buffer():"color_blue"%s"color_reset"\n", inbuffer);
        IF_VERBOSE printf("==================================================\n");
        IF_VERBOSE printf("CIPHER TEXT: "color_blue"%s"color_reset"\n", bin2hex(outbuffer, outbuffer_len));
        IF_VERBOSE printf("==================================================\n");

        printf(color_red"========================================\n"color_reset);
        printf(color_red"ECCP2 DECRYPT BUFFER TEST: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);

        r = gzpki_eccp2_decrypt_buffer(config, outbuffer, outbuffer_len, &orgbuffer, &orgbuffer_len, certfile, keyfile, passin, ECCP2_SECRET_FROM_CERTFILE);
        printf("gzpki_eccp2_decrypt_buffer(): \n");
        IF_VERBOSE printf("==================================================\n");
        IF_VERBOSE printf("ORIGINAL TEXT: "color_blue"%s"color_reset"\n", orgbuffer);
        IF_VERBOSE printf("==================================================\n");

        return 0;
#endif

#if 0
        printf(color_red"========================================\n"color_reset);
        printf(color_red"ECCP2 ENCRYPT FILE 2 BUFFER: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);
        //char *infile = "./test/plain.txt";
        //char *outfilep2 = "./test/plain.txt.enc";
        //char *outbuffer = NULL;
        //unsigned int outbuffer_len;
        //r =  gzpki_eccp2_encrypt_file(config, infile, outfilep2, certfile, secretfile_k, ECCP2_SECRET_FROM_CERTFILE);
        r = gzpki_eccp2_encrypt_file2buffer(config, infile, &outbuffer, &outbuffer_len, certfile, NULL, ECCP2_SECRET_FROM_CERTFILE);

        printf("gzpki_eccp2_encrypt_file2buffer(): %d\n", outbuffer_len);
        printf("CIPHER TEXT: "color_blue"%s"color_reset"\n", bin2hex(outbuffer, outbuffer_len));

        printf(color_red"========================================\n"color_reset);
        printf(color_red"ECCP2 DECRYPT BUFFER 2 FILE: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);

        char *outfile10 = "./test/plain.txt.org.10";
        r = gzpki_eccp2_decrypt_buffer2file(config, outbuffer, outbuffer_len, outfile10, certfile, keyfile, passin, ECCP2_SECRET_FROM_CERTFILE);
        
        printf("CIPHER TEXT: "color_blue"%s"color_reset"\n", outfile10);
      
        return 0;

#endif

#if 0
        printf(color_red"========================================\n"color_reset);
        printf(color_red"ECCP2 ENCRYPT BUFFER 2 FILE: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);
        //char *infile = "./test/plain.txt";
        //char *outfilep2 = "./test/plain.txt.enc";
        //char *outbuffer = NULL;
        //unsigned int outbuffer_len;
        //r =  gzpki_eccp2_encrypt_file(config, infile, outfilep2, certfile, secretfile_k, ECCP2_SECRET_FROM_CERTFILE);
        //ECCP2_SECRET_FROM_CERTFILE: 0

        char *outfile11 = "./test/plain.txt.enc.11";
        
        r = gzpki_eccp2_encrypt_buffer2file(config, inbuffer, inbuffer_len, outfile11, certfile, keyfile, passin, 0);

        printf("gzpki_eccp2_encrypt_buffer2file(): "color_blue"%s"color_reset"\n", inbuffer);
        printf("CIPHER FILE: "color_red"%s"color_reset"\n", outfile11);

        printf(color_red"========================================\n"color_reset);
        printf(color_red"ECCP2 DECRYPT FILE 2 BUFFER: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);
      
        r = gzpki_eccp2_decrypt_file2buffer(config, outfile11, &outbuffer, &outbuffer_len, certfile, keyfile, passin, 0);

        printf("gzpki_eccp2_decrypt_file2buffer(): "color_blue"%s"color_reset"\n", outfile11);
        printf("ORIGINAL TEXT: "color_blue"%s"color_reset"\n", outbuffer);
      
        return 0;

#endif

#if 0
    {
        printf(color_yellow"========================================\n"color_reset);
        printf(color_yellow"CMS ENCRYPT FILE TEST: config=%s\n"color_reset, config);
        printf(color_yellow"========================================\n"color_reset);

        r = gzpki_cms_encrypt_file(config, infile, outfile_ff, certfile, cipher_algs, cms_opt);
        if(r != 0) {
            printf("error: gzpki_cms_encrypt_file: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }

        printf(color_yellow"========================================\n"color_reset);
        printf(color_yellow"CMS DECRYPT FILE TEST: config=%s\n"color_reset, config);
        printf(color_yellow"========================================\n"color_reset);
        r = gzpki_cms_decrypt_file(config, outfile_ff, orgfile_ff, keyfile, passin, cms_opt);
        if(r != 0) {
            printf("error: gzpki_cms_decrypt_file: "color_blue"%s"color_reset"\n", outfile_ff);
            return -1;
        }

        return 0;
    }
#endif

       
#if 0
    {
        printf(color_red"========================================\n"color_reset);
        printf(color_red"CMS ENCRYPT BUFFER TEST: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);
        
        r = gzpki_cms_encrypt_buffer(config, inbuffer, inbuffer_len, &outbuffer, &outbuffer_len, certfile, cipher_algs, cms_opt);

        printf("gzpki_cms_encrypt_buffer(%d):\n%s\n", outbuffer_len, outbuffer);
        
        r = gzpki_cms_decrypt_buffer(config, outbuffer, outbuffer_len, &orgbuffer, &orgbuffer_len, keyfile, passin, cms_opt);

        printf("gzpki_cms_decrypt_buffer(%d):\n%s\n", orgbuffer_len, orgbuffer);
        
        if(outbuffer != NULL) {
            buffer_clear(outbuffer);
            printf("free(outbuffer): %s\n", outbuffer==NULL?"NULL":outbuffer);
        }

        if(orgbuffer != NULL) {
            buffer_clear(orgbuffer);
            printf("free(orgbuffer): %s\n", orgbuffer==NULL?"NULL":orgbuffer);
        }

        return 0;
    }
#endif        

#if 0
    {
        printf(color_blue"========================================\n"color_reset);
        printf(color_blue"CMS ENCRYPT FILE --> BUFFER TEST: config=%s\n"color_reset, config);
        printf(color_blue"========================================\n"color_reset);
        r = gzpki_cms_encrypt_file2buffer(config, infile, &outbuffer, &outbuffer_len, certfile, cipher_algs,cms_opt);
        if(r != 0) {
            printf("error: gzpki_cms_encrypt_file2buffer: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }

        printf("gzpki_cms_encrypt_file2buffer(%d):\n"color_blue"%s"color_reset"\n", outbuffer_len, outbuffer);

        r = gzpki_cms_decrypt_buffer2file(config, outbuffer, outbuffer_len, orgfile_bf, keyfile, passin,cms_opt);

        printf("gzpki_cms_decrypt_buffer2file:\n"color_blue"%s"color_reset"\n", orgfile_bf);

        if(outbuffer != NULL) {
            buffer_clear(outbuffer);
            printf("free(outbuffer): %s\n", outbuffer==NULL?"NULL":outbuffer);
        }
        return 0;
    }
#endif 

#if 0
    {
        printf(color_green"========================================\n"color_reset);
        printf(color_green"CMS ENCRYPT BUFFER --> FILE TEST: config=%s\n"color_reset, config);
        printf(color_green"========================================\n"color_reset);
        r = gzpki_cms_encrypt_buffer2file(config, inbuffer, inbuffer_len, outfile2, certfile, cipher_algs,cms_opt);

        printf("gzpki_cms_encrypt_buffer2file(%d):\n"color_blue"%s"color_reset"\n", inbuffer_len, outfile2);

        r = gzpki_cms_decrypt_file2buffer(config,  outfile2, &orgbuffer, &orgbuffer_len, keyfile, passin,cms_opt);

        printf("gzpki_cms_decrypt_file2buffer:\nfile:%s\nlength:%d\n%s\n"color_blue"%s"color_reset"\n", outfile2, orgbuffer_len, orgbuffer);

        if(orgbuffer != NULL) {
            buffer_clear(orgbuffer);
            printf("free(orgbuffer): %s\n", orgbuffer==NULL?"NULL":orgbuffer);
        }
        return 0;
    }
#endif         
        
#if 0
    {
        printf(color_yellow"========================================\n"color_reset);
        printf(color_yellow"CMS SIGN FILE 2 FILET: config=%s\n"color_reset, config);
        printf(color_yellow"========================================\n"color_reset);
        
        char *outfile_signed = "./test/plain.txt.signed";
        char *devpass = "151f92e8be04e9a218ccd11d8fc5fcb0c1a94347";
        r = gzpki_cms_sign_file(config, infile, outfile_signed, certfile, keyfile, passin, digest_algs,cms_opt);
        if(0 != r) {
            printf("error: gzpki_cms_sign_file() failed: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }

        r = gzpki_cms_verify_file (config, outfile_signed, NULL, cafile,cms_opt);
        printf("gzpki_cms_verify_file() : "color_red"%d"color_reset"\n", r);
        if(0 != r) {
            printf("error: gzpki_cms_verify_file() failed: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }
    }
#endif 

#if 0
    {
        printf(color_red"========================================\n"color_reset);
        printf(color_red"CMS SIGN BUFFER 2 BUFFER: config=%s\n"color_reset, config);
        printf(color_red"========================================\n"color_reset);
        
        char *outfile_signed = "./test/plain.txt.signed";
        char *devpass = "151f92e8be04e9a218ccd11d8fc5fcb0c1a94347";
        char *signbuffer = NULL;
        unsigned int signbuffer_len = -1;

        r = gzpki_cms_sign_buffer(config, inbuffer, inbuffer_len, &signbuffer, &signbuffer_len, certfile, keyfile, passin, digest_algs ,cms_opt);

        if(0 != r) {
            printf("error: gzpki_cms_sign_buffer() failed: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }

        r = gzpki_cms_verify_buffer(config, signbuffer, signbuffer_len, certfile, cafile,cms_opt);
        printf("gzpki_cms_verify_buffer() : "color_red"%d"color_reset"\n", r);
        if(0 != r) {
            printf("error: gzpki_cms_verify_buffer() failed: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }
    }
#endif 

#if 0
    {
        printf(color_cyan"========================================\n"color_reset);
        printf(color_cyan"CMS SIGN FILE 2 BUFFER: config=%s\n"color_reset, config);
        printf(color_cyan"========================================\n"color_reset);
        
        char *outfile_signed = "./test/plain.txt.signed";
        char *devpass = "151f92e8be04e9a218ccd11d8fc5fcb0c1a94347";
        char *signbuffer = NULL;
        unsigned int signbuffer_len = -1;
        char *signefile2 = "./test/plain.txt.signed.2";
        
        r = gzpki_cms_sign_buffer2file(config, inbuffer, inbuffer_len, signefile2, certfile, keyfile, passin, digest_algs ,cms_opt);
        if(0 != r) {
            printf("error: gzpki_cms_sign_buffer2file() failed: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }

        r = gzpki_cms_verify_file (config, outfile_signed, NULL, cafile, cms_opt);
        printf("gzpki_cms_verify_file() : "color_red"%d"color_reset"\n", r);
        if(0 != r) {
            printf("error: gzpki_cms_verify_file() failed: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }
    }
#endif 

#if 0
    {
        printf(color_green"========================================\n"color_reset);
        printf(color_green"CMS SIGN BUFFER 2 FILE: config=%s\n"color_reset, config);
        printf(color_green"========================================\n"color_reset);
        
        char *outfile_signed = "./test/plain.txt.signed";
        char *devpass = "151f92e8be04e9a218ccd11d8fc5fcb0c1a94347";
        char *signbuffer = NULL;
        unsigned int signbuffer_len = -1;
        char *signefile2 = "./test/plain.txt.signed.2";
        
        r = gzpki_cms_sign_file2buffer(config, infile, &signbuffer, &signbuffer_len, certfile, keyfile, passin, digest_algs, cms_opt);
        if(0 != r) {
            printf("error: gzpki_cms_sign_file2buffer() failed: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }

        r = gzpki_cms_verify_file (config, outfile_signed, NULL, cafile, cms_opt);
        printf("gzpki_cms_verify_file() : "color_red"%d"color_reset"\n", r);
        if(0 != r) {
            printf("error: gzpki_cms_verify_file() failed: "color_blue"%s"color_reset"\n", infile);
            return -1;
        }
    }
#endif 
        
        return 0;

#if 0
        
        //
        printf(color_red"===== BEGIN TOKEN TEST ====="color_reset"\n");
        TOKEN_CTX tk;
        //DEL int bloadcert = 0;
        //DEL int bloadkey = 0;
        GZPKI_init_token(&tk, "./token");
        //GZPKI_get_token(&tk, bloadcert, bloadkey);
        
        printf("TOKEN: device certfile: %s\n", tk.device_certfile);
        printf("TOKEN: server certfile: %s\n", tk.server_certfile);
        printf("TOKEN: ca     certfile: %s\n", tk.ca_certfile);

        printf(color_red"===== END TOKEN TEST ====="color_reset"\n");


        return 0;


        #ifdef _WIN32
            return printf("'\\'");
        #else

            printf("'\\'");
            printf("\n");
            return printf("'/'");
        #endif
#endif

#if 0
        if(!strcmp(test_args, "sqlite")) {

            GZPKI_CTX CA;
                
            CA.configfile = config_args;
            CA.use_txtdb = 1; 
            CA.use_sqldb = 1;
            CA.opt_ca_index_db_sync = 1;
            CA.opt_ca_load_private_key = 0;
                
            int ret = GZPKI_do_CA(&CA);
            if(CMS_RET_OK==ret) {
                fprintf(stdout, color_yellow_b"success: CA TEST OK."color_reset"\n");     
            }
            else {
                fprintf(stderr, "error:CA_TEST:ret=%d: %d,%s\n", r, ctx.errcode, ctx.errstr);  
            }

            CA.configfile = NULL;
            GZPKI_free_ctx(&CA);
        }
#endif
        return 0;
    }
    //----------
    // END DO TEST
    //---------- 
#if 1

    if(do_ecc_encrypt == 1 || operation == ECC_ENCRYPT ) 
    {
        #if 1

            int opt_secret = 0;
            int r = -1;

            printf("ecc p1 test, infile:%s, outfile:%s\n", infile, outfile);

            require_args(infile, "no input file", -1);
            require_args(outfile, "no output file", -1);
            require_args(cert_file, "no certificate file", -1);


            //--------------------------------------------------
            // config 파일이 없는 경우 
            // ECC_ENCRYPT를 위해 인증서 parameter 필요하다
            //--------------------------------------------------
            if(operation == ECC_ENCRYPT  &&  NULL == config_args ) {
                D_printf("op=%d, config=%s\n", operation, config_args);
                require_args(cert_file, "no certificate file", -1);
            }

            IF_VERBOSE printf("CMM_P1_encrypt_file: in='%s', out='%s', certificate='%s', opt=%d\n", infile, outfile, cert_file, opt_secret);

#if 0 //speed test
            int i;
            char *test_infile = "plain.txt";
            char *test_ecc_outfile = "plain.txt.enc.ecc256";
            char *test_aes_outfile = "plain.txt.enc.aes256";
            char *test_ecc_orgfile = "plain.txt.org.ecc256";
            char *test_aes_orgfile = "plain.txt.org.aes256";

            char fmt_test_ecc_outfile[128];
            char fmt_test_ecc_orgfile[128];

            char fmt_test_aes_outfile[128];
            char fmt_test_aes_orgfile[128];

            char *test_keyfile = "./test/server.key";
            char *test_certfile = "./test/server.pem";
            char *pass = "1111";
            
            int LOOP=1000;
            double elap;
            //ECC ENCRYPT
            perf_start();
            for(i=0;i<LOOP;i++) {
                sprintf(fmt_test_ecc_outfile, "./output/plain.txt.enc_%d.ecc256", i);
                r = CMM_P1_encrypt_file(infile, cert_file, fmt_test_ecc_outfile, opt_secret) ;
                //r = CMM_P1_encrypt_file(infile, cert_file, test_ecc_outfile, opt_secret) ;
            }

            perf_stop();
            elap = perf_print();
            printf("SPEED: ECCP1 ENCRYPT: "color_yellow"%f"color_reset", TPS=%f\n", elap, LOOP / elap );

            //--------------------
            //ECC DECRYPT
            //--------------------
            perf_start();
            for(i=0;i<LOOP;i++){
                sprintf(fmt_test_ecc_outfile, "./output/plain.txt.enc_%d.ecc256", i);
                sprintf(fmt_test_ecc_orgfile, "./output/plain.txt.org_%d.ecc256", i);
                r = CMM_P1_decrypt_file(fmt_test_ecc_outfile, test_keyfile, NULL, fmt_test_ecc_orgfile, opt_secret) ;
                //r = CMM_P1_decrypt_file(infile, key_file, NULL, outfile, opt_secret) ;
            }

            perf_stop();
            elap = perf_print();
            printf("SPEED: ECCP1 DECRYPT: "color_yellow"%f"color_reset", TPS=%f\n", elap, LOOP / elap );

            //----------------------------------------
            //aes encrypt 01
            //----------------------------------------

                                  
            perf_start();
            for(i=0;i<LOOP;i++)
            {
                sprintf(fmt_test_aes_outfile, "./output/plain.txt.enc_%d.aes256", i);
#if 0
                encrypt(infile, test_aes_outfile);
#else                
                GZPKI_CTX C;
                GZPKI_init_ctx(&C);
                C.operation = GZPKI_ENCRYPT;
                C.cipher_name = NULL;
                C.cipher_name = GZPKI_strdup("aes256");
                C.verbose = C.base64 = 0;
                C.pbkdf2 = 0;
                C.printkey = 0;
                C.passphrase = GZPKI_strdup("1111");
                C.iv_hex = GZPKI_strdup("AAAAAAAAAAAA");
                
                
                GZPKI_set_infile(&C, infile, NULL, 0, FORMAT_PEM);
                GZPKI_set_outfile(&C, fmt_test_aes_outfile, FORMAT_FILE);

                if(CMS_RET_OK == GZPKI_do_ENC(&C)) {
                    //printf("GZPKI_do_ENC(GZPKI_DECRYPT): decrypt success.\n");
                }
                else
                    printf("GZPKI_do_ENC(GZPKI_ENCRYPT): enrypt error.\n");
                                
                GZPKI_free_ctx(&C);
#endif                
            }

            

            perf_stop();
            elap = perf_print();
            printf("SPEED: AES256 ENCRYPT: "color_yellow"%f"color_reset", TPS=%f\n", elap, LOOP / elap );

            //----------------------------------------
            //aes decrypt
            //----------------------------------------
            perf_start();
            for(i=0;i<LOOP;i++)
            {
                
                sprintf(fmt_test_aes_outfile, "./output/plain.txt.enc_%d.aes256", i);
                sprintf(fmt_test_aes_orgfile, "./output/plain.txt.org_%d.aes256", i);

#if 0
                decrypt(fmt_test_aes_outfile, fmt_test_aes_orgfile);
#else                
                GZPKI_CTX C;
                GZPKI_init_ctx(&C);
                C.operation = GZPKI_DECRYPT;
                C.cipher_name = NULL;
                C.cipher_name = GZPKI_strdup("aes256");
                C.verbose = C.base64 = 0 ;
                C.pbkdf2 = 0;
                C.printkey = 0;

                C.passphrase = GZPKI_strdup("1111");
                
               
                GZPKI_set_infile(&C, fmt_test_aes_outfile, NULL, 0, FORMAT_PEM);
                GZPKI_set_outfile(&C, fmt_test_aes_orgfile, FORMAT_FILE);

                if(CMS_RET_OK == GZPKI_do_ENC(&C)) {

                    //printf("GZPKI_do_ENC(GZPKI_DECRYPT): decrypt success.\n");
                }
                else
                    printf("GZPKI_do_ENC(GZPKI_DECRYPT): decrypt error.\n");
                                
                GZPKI_free_ctx(&C);
#endif                 
            }
            
            perf_stop();
            elap = perf_print();
            printf("SPEED: AES256 DECRYPT: "color_yellow"%f"color_reset", TPS=%f\n", elap, LOOP / elap );

            
#else            
            r = CMM_P1_encrypt_file(infile, cert_file, outfile, opt_secret) ;
#endif            

            if(opt_return==1)
                printf("success:%s:%s\n", return_args, outfile);
            else 
                printf("success:%s\n", outfile);

            //outfile check
            return r;
        #endif
    }
    
    if(do_ecc_decrypt==1 || operation == ECC_DECRYPT) 
    {
        require_args(infile, "no input file", -1);
        require_args(outfile, "no output file", -1);
        require_args(key_file, "no private key file", -1);

        int opt_secret = 0;
        //int r = 0;

        printf("CMM_P1_decrypt_file: in='%s', out='%s', key='%s', opt=%d\n", infile, outfile, key_file, opt_secret);
        
        r = CMM_P1_decrypt_file(infile, key_file, NULL, outfile, opt_secret) ;

        printf("decrypt file success: "color_red"%s"color_reset"\n", outfile);
        //outfile check
        return 0;
    }
#endif 

    //--------------------------------------------------
    // ECDSA Encryption
    //--------------------------------------------------
    if(1 == do_ecc_p2_encrypt || operation == ECCP2_ENCRYPT) 
    {
        
#if 0
        return gzpki_eccp2_encrypt_file(config_args, infile, outfile, cert_file, NULL, ECCP2_SECRET_FROM_CERTFILE);
#endif 

#if 0
        int opt_secret = 0;
        int r = 0;
        char *str_encert = NULL;
        
        require_args(infile, "no input file", -1);
        require_args(outfile, "no output file", -1);
        //if(use_token != 1) {
        //    require_args(cert_file, "no certificate file", -1);
        //}

        if(use_token==1)
        {
            //memset(token_server_cert, 0, sizeof(token_server_cert));
            //sprintf(token_server_cert, "%s/cert/server/server.pem", token_dir);
            //IF_VERBOSE fprintf(stderr, "certificate for enryption: %s\n", token_server_cert);
            //str_encert = token_server_cert;
            str_encert = token.server_certfile;
        }
        else {
            str_encert = cert_file;
        }

        printf("debug:CMM_P2_encrypt_file:F(%s, %s, %s, %d\n", infile, outfile, str_encert, opt_secret);
        
        r = CMM_P2_encrypt_file(infile, str_encert, outfile, NULL, NULL, NULL, opt_secret) ;

        if(r == 1 ) {
            if(opt_return == 1)
                printf("success:%s:%s\n", return_args, outfile);
            else 
                printf("success:%s\n", outfile);
        }
        else 
            printf("error:fail_to_encrypt_file:%s", infile);

        return 0;
#endif 
    }

    if(1 == do_ecc_p2_decrypt || operation == ECCP2_DECRYPT) 
    {
#if 0
        r = gzpki_eccp2_decrypt_file(config_args, infile, outfile, cert_file, key_file, passin, 0);
#endif 
        
#if 0
        int opt_secret = 0;
        //DEL char *pass = NULL;
        char *str_decpass = NULL;
        char *str_keyfile = NULL;

        require_args(infile, "no input file", -1);
        require_args(outfile, "no output file", -1);

        if(use_token==1)
        {
            //memset(token_server_key, 0, sizeof(token_server_key));
            //sprintf(token_server_key, "%s/cert/server/server.key", token_dir);
            //IF_VERBOSE fprintf(stderr, "private key for decryption: %s\n", token_server_key);
            //passin = GZPKI_strdup((char *)ctx.device_password);
            //IF_VERBOSE printf("debug:CMM_P2_decrypt_file:DEVP(%s)\n", passin);
            //str_keyfile = token_server_key;
            //str_decpass= passin;
            str_keyfile = token.server_keyfile;
            str_decpass= GZPKI_get_token_device_password(&token);
        } else {
            require_args(key_file, "no private key file", -1);
            str_keyfile = key_file;
            str_decpass= NULL;
        }

        IF_VERBOSE printf("debug:CMM_P2_decrypt_file:%s\n", use_token==1?"token":"no token");
        IF_VERBOSE printf("debug:CMM_P2_decrypt_file:F(%s, %s, %s, %d)\n", infile, outfile, str_keyfile, opt_secret);
  
        r = CMM_P2_decrypt_file(infile, str_keyfile, /*pass*/str_decpass, outfile, NULL, NULL, NULL, opt_secret) ;

        if(r == 1) {
            if(opt_return == 1) {
                printf("success:%s:%s\n", return_args, outfile);
            }
            else  {
                printf("success:%s\n", outfile);
            }
        }
        else {
            printf("error:fail_to_decrypt_file:%s\n", infile);
        }

        return 0;
#endif        
    }
    
    if(do_ecc_p2_secret_export==1) 
    {
        int r = 0;
        char target_dir[256];
        memset(target_dir,0,sizeof(target_dir));
        
        if(1==use_token) {
            sprintf(target_dir, "%s/cert/server", token.token_dir);
        }
        else {
            require_args(cert_file, "no certificate file", -1);
            if( !secretdir_args || (app_isdir(secretdir_args) <= 0)) {
               fprintf(stderr, "error:%s is not a directory\n", secretdir_args);
               return -1;
            }
            fprintf(stderr, "ecc secret dir: %s\n", secretdir_args );
            sprintf(target_dir, "%s", secretdir_args);
        }

        r = CMM_P2_SENDER_generate_param(cert_file, target_dir);
        if(r < 0) {
            fprintf(stderr, "error:fail to generate ECC P2 encryption parameter\n");
            return -1;
        }
        else {
            if(opt_return == 1) {
                printf("success:%s:secret export.\n", return_args);
            }
            else {
                printf("success:secret export.\n");
            }
        }
        
        return 0;
    }
    
    if(do_ecc_p2_secret_import==1) 
    {
        printf("do_ecc_p2_secret_import: begin...\n");
        return 0;
    }

#ifndef _NO_CA_
    if(do_ecc == 1) 
    {

        if(!strcmp(ecc_args, "passwd") ) {
            GZPKI_CTX KCTX;
            
            //do_ecc_password = 1;
            require_args(keydb_file, "no key database file", -1);
            require_args(keyid_args, "no keyid", -1);
            require_args(newkeyid_args, "no keyid", -1);
            require_args(infile, "no input file", -1);

            //char *p = NULL;
            char *master_secret = NULL;
            char *master_pwd_in = NULL;
            char *old_key = NULL;
            char *new_key = NULL;

            master_pwd_in = (char *)GZPKI_get_master_password(keydb_file,NULL);
            master_secret = (char *)GZPKI_keypass_get_master_secret(keydb_file, master_pwd_in);

            if(master_secret) {
                old_key = GZPKI_keypass_export(keydb_file,master_secret, keyid_args);
                new_key = GZPKI_keypass_export(keydb_file,master_secret, newkeyid_args);

                IF_VERBOSE {
                    fprintf(stdout, "OLD KEY(%s): %s\n", keyid_args, old_key);
                    fprintf(stdout, "NEW KEY(%s): %s\n", newkeyid_args, new_key);
                }

                if(master_secret) free(master_secret);
            }

            KCTX.passin = old_key;
            KCTX.passout = new_key;

            GZPKI_set_infile(&KCTX, infile, NULL, 0, FORMAT_PEM);
            if(outfile)
                GZPKI_set_outfile(&KCTX, outfile, FORMAT_PEM);
            else 
                GZPKI_set_outfile(&KCTX, NULL, FORMAT_PEM);

            KCTX.passin  = GZPKI_strdup(old_key);
            KCTX.passout = GZPKI_strdup(new_key);

            if(cipher_algs) 
                KCTX.name = GZPKI_strdup(cipher_algs);
            else
                KCTX.name = "aes256";

            r = GZPKI_do_ECC(&KCTX);
            
            if(CMS_RET_OK!=r) {
                printf("error:do_ecc:failed\n");
                return 0;
            }

            GZPKI_free_ctx(&KCTX);

            fprintf(stdout, "success:change password.\n");

            return 0;

        }
        if(!strcmp(ecc_args, "decrypt") ) {
            GZPKI_CTX KCTX;
            
            //do_ecc_password = 1;
            //require_args(keydb_file, "no key database file", -1);
            //require_args(keyid_args, "no keyid", -1);
            //require_args(newkeyid_args, "no keyid", -1);
            require_args(infile, "no input file", -1);

            //char *p = NULL;
            char *master_secret = NULL;
            char *master_pwd_in = NULL;
            char *old_key = NULL;
            char *new_key = NULL;

            master_pwd_in = (char *)GZPKI_get_master_password(keydb_file,NULL);

            master_secret = (char *)GZPKI_keypass_get_master_secret(keydb_file, master_pwd_in);

            if(master_secret) {
                old_key = GZPKI_keypass_export(keydb_file, master_secret, keyid_args);
                new_key = GZPKI_keypass_export(keydb_file, master_secret, newkeyid_args);

                IF_VERBOSE fprintf(stdout, "OLD KEY(%s): %s\n", keyid_args, old_key);
                IF_VERBOSE fprintf(stdout, "NEW KEY(%s): %s\n", newkeyid_args, new_key);

                if(master_secret) free(master_secret);
            }

            KCTX.passin = old_key;
            KCTX.passout = new_key;

            GZPKI_set_infile(&KCTX, infile, NULL, 0, FORMAT_PEM);
            if(outfile)
                GZPKI_set_outfile(&KCTX, outfile, FORMAT_PEM);
            else 
                GZPKI_set_outfile(&KCTX, NULL, FORMAT_PEM);

            //char *pwdin = NULL;
            //pwdin =  getpass("password for device.key:");

            KCTX.passin  = GZPKI_strdup(old_key);
            KCTX.passout = GZPKI_strdup(new_key);

            if(cipher_algs) 
                KCTX.name = GZPKI_strdup(cipher_algs);
            else
                KCTX.name = "aes256";

            r = GZPKI_do_ECC(&KCTX);
            
            if(CMS_RET_OK!=r) {
                printf("error:do_ecc:failed\n");
                return 0;
            }

            GZPKI_free_ctx(&KCTX);

            fprintf(stdout, "success:change password.\n");

            return 0;

        }
        else if(!strcmp(ecc_args, "genkey")) 
        {
            
            //GZPKI_CTX KCTX;
            require_args(outfile, "no output file", -1);
                    
            //KEYPASS DB를 사용하는 경우
            if(use_keypass_db == 1) {
                require_args(keydb_file, "no key database file", -1);
                require_args(keyid_args, "no keyid", -1);
            }
            else {
                //GET PASSWORD
            }

            if(!ecparam_args) ecparam_args = "prime192v3";
            if(!cipher_algs) cipher_algs = "aes256";
            
            int keylen = -1;
            char *pwdin = NULL;
            pwdin =  getpass("Input password:");
            char* keypem = GZPKI_generate_PRIKEY(ecparam_args, pwdin, cipher_algs, &keylen, outfile);

            //28? #"-----BEGIN" + #"-----END" + #"-----" + #"-----"
            if(keypem ) {
                fprintf(stdout, "%s", keypem);
            }
        
            return 0;

        }
        
        return 0;
    }
#endif //#ifnder _NO_CA_

#ifndef _NO_CA_

    if(do_ca == 1) {
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"GZCMS-CLI CA: ARGS=["color_yellow_b"%s"color_reset"]\n", ca_args);

        //--------------------------------------------------
        // CA DIR을 생성한다. 
        // GENERATE: serial, crlserial, certs, newcerts, private, index.txt
        // REQ.DB, X509.DB, REQ.DB.OLD, X509.DB.OLD + TABLE을 생성한다. 
        //--------------------------------------------------
        if(1==do_ca_newcadir) {
            //1. CANAME 존재 여부 확인
            require_args(cadir_args, "no 'cadir' arguments", -1);
            require_args(caname_args, "no CA name arguments, use '--caname' option.", -1);
            
            
            IF_VERBOSE fprintf(stdout, "CA.NEWCADIR, DIR=[%s]\n", cadir_args);

            //2. 기존 디렉토리 있는지 확인 & 생성
            if(0!=generate_dirctory(cadir_args, 0777)){
                fprintf(stderr, "error:fail to generate directory: %s\n", cadir_args);
                return -1;
            }
            else {
                char path[512];
                //fprintf(stderr, "success:generate 'CA_DIR' : %s\n", cadir_args);
                
#define  _GEN_CADIR(__CADIR__, __CASUB__) memset(path, 0, sizeof(path)); \
                sprintf(path, "%s/%s", __CADIR__, __CASUB__); \
                generate_dirctory(path, 0777)
                
                _GEN_CADIR(cadir_args, "certs");
                _GEN_CADIR(cadir_args, "crl");
                _GEN_CADIR(cadir_args, "newcerts");
                _GEN_CADIR(cadir_args, "private");
                _GEN_CADIR(cadir_args, "request");
                //keypairs directory for .req, .key, .mac
                _GEN_CADIR(cadir_args, "keypairs");

                _GEN_CADIR(cadir_args, "token"); //For token generation
                _GEN_CADIR(cadir_args, "token/gzcms"); 
                _GEN_CADIR(cadir_args, "token/gzcms/bin"); 
                _GEN_CADIR(cadir_args, "token/gzcms/docs"); 
                _GEN_CADIR(cadir_args, "token/gzcms/include"); 
                _GEN_CADIR(cadir_args, "token/gzcms/lib"); 
                _GEN_CADIR(cadir_args, "token/gzcms/cert"); 
                _GEN_CADIR(cadir_args, "token/gzcms/cert/server"); 
                _GEN_CADIR(cadir_args, "token/gzcms/cert/ca"); 
                _GEN_CADIR(cadir_args, "token/gzcms/cert/device"); 

                
                memset(path, 0, sizeof(path));
                sprintf(path, "%s/token/gzcms", cadir_args);
                add_file_to_dirctory(path, "version.txt", app_version, "w");

                //GENERATE: cadir 
                //generate_dirctory(cadir_args, 0766);
                add_file_to_dirctory(cadir_args, "crlnumber", "01", "w");
                add_file_to_dirctory(cadir_args, "index.txt", "", "w");
                add_file_to_dirctory(cadir_args, "index.txt.attr", "unique_subject = yes", "w");
                add_file_to_dirctory(cadir_args, "serial", "1000", "w");
            }

            fprintf(stdout, "newca %s created.\n", cadir_args); 

            //3. GENERATE CONFIG
char *FMT_STR = 
"HOME = %s\n"
"ca_default_days = 4015\n"
"\n"
"[ca]\n"
"default_ca = %s\n"
"[%s]\n"
"dir        = $HOME\n"
"certs      = $dir/certs\n"
"keypairs   = $dir/keypairs\n"
"crl_dir    = $dir/crl\n"
"database      = $dir/index.txt\n"
"cmmdb         = $dir/cmm.db\n"
"new_certs_dir = $dir/newcerts\n"
"certificate   = $dir/ca.pem\n"
"csr           = $dir/request/ca.req\n"
"serial        = $dir/serial\n"
"crlnumber     = $dir/crlnumber\n"
"crl           = $dir/crl.pem\n"
"private_key   = $dir/private/ca.key\n"
"RANDFILE      = $dir/private/.rand\n"
"x509_extensions  = usr_cert\n"
"default_days     = 3650\n"
"default_crl_days = 30\n"
"default_md       = sha256\n"
"default_cipher   = aes256\n"
"policy           = policy_anything\n"
"keypass_database = %s\n"
"keypass_keyid    = %s\n"
"token            = usb_token\n"
"\n"
"[ policy_anything ]\n"
"countryName		= optional\n"
"stateOrProvinceName	= optional\n"
"localityName		= optional\n"
"organizationName	= optional\n"
"organizationalUnitName	= optional\n"
"commonName		= supplied\n"
"emailAddress		= optional\n"
"\n"
"[ req ]\n"
"default_curve        = secp521r1 ##CA PRIVATE KEY EC PARAMETER\n"
"default_key_algorithm= EC\n"
"default_keyfile      = privkey.pem\n"
"distinguished_name	  = req_dn\n"
"string_mask = utf8only\n"
"\n"
"[ v3_ca ]\n"
"subjectKeyIdentifier=hash\n"
"authorityKeyIdentifier=keyid:always,issuer\n"
"basicConstraints = critical,CA:true\n"
"\n"
"\n"
"[ usr_cert ]\n"
"subjectKeyIdentifier=hash\n"
"authorityKeyIdentifier=keyid,issuer\n"
"basicConstraints = CA:FALSE\n"
"\n"
"[ server_cert ]\n"
"subjectKeyIdentifier=hash\n"
"authorityKeyIdentifier=keyid,issuer\n"
"basicConstraints = CA:FALSE\n"
"\n"
"[ crl_ext ]\n"
"authorityKeyIdentifier=keyid:always\n"
"\n"
"## CA 인증서 생성을 위한 DN 구성\n"
"## 전체 DN 고정, 필요시 수기 편집해서 사용함\n"
"[ req_dn ]\n"
"C = KR\n"
"ST = DAEGU\n"
"L = SmartCity\n"
"O = Greenzonesecu\n"
"OU = IoT PKI\n"
"CN = GZCMM CA Certificate Class 1\n"
"emailAddress = smartcity@greenzonesecu.com\n"
"\n"
"[ usb_token ]\n"
"device        = /dev/sdb1\n"
"target        = /tmp/usb\n"
"source        = $HOME/token/gzcms\n"
"prefix        = gzcms\n"
"bin_dir       = $HOME/token/$prefix/bin\n"
"bin           = gzcms\n"
"version       = $HOME/token2/$prefix/version.txt\n"
"lib_dir       = $HOME/token/$prefix/lib\n"
"include_dir   = $HOME/token/$prefix/include\n"
"docs_dir      = $HOME/token/$prefix/docs\n"
"server        = $HOME/token/$prefix/cert/server/server.pem\n"
"\n"
"[ usb_token.aarch64 ]\n"
"device        = /dev/sdb1\n"
"target        = /tmp/usb\n"
"source        = $HOME/token/gzcms\n"
"prefix        = gzcms\n"
"bin_dir       = $HOME/token2/$prefix/bin\n"
"bin           = gzcms_aarch64\n"
"version       = $HOME/token2/$prefix/version.txt\n"
"lib_dir       = $HOME/token2/$prefix/lib\n"
"include_dir   = $HOME/token2/$prefix/include\n"
"docs_dir      = $HOME/token2/$prefix/docs\n"
"server        = $HOME/token2/$prefix/cert/server/server.pem\n"
"\n"
"[ req_user ]\n"
"default_curve         = prime256v1\n"
"default_cipher        = aes192\n"
"distinguished_name	   = req_user_dn\n"
"string_mask           = utf8only\n"
"keypairs = $HOME/keypairs\n"
"x509_extensions = usr_cert\n"
"\n"
"[ req_user_dn ]\n"
"C = KR\n"
"ST = DAEGU\n"
"L = SmartCity\n"
"O = PKI\n"
"OU = Device Group\n"
"CN = __commonName__\n"
"emailAddress = __emailAddress__\n"
"\n"
"[ req_server ]\n"
"default_curve         = prime256v1\n"
"default_cipher        = aes192\n"
"distinguished_name	   = req_user_dn\n"
"string_mask           = utf8only\n"
"keypairs = $HOME/keypairs\n"
"x509_extensions = server_cert\n"
"\n"
"[ req_server_dn ]\n"
"C = KR\n"
"ST = DAEGU\n"
"L = SmartCity\n"
"O = PKI Server\n"
"OU = Device Group\n"
"CN = __commonName__\n"
"emailAddress = __emailAddress__\n"
"\n"
"\n"
"\n"
"##END(ca.config)\n";


char *FMT_STR_REQ = 
"## device certificate request template\n"
"HOME = %s\n"
"\n"
"[ req ]\n"
"default_curve         = prime256v1\n"
"default_cipher        = aes192\n"
"distinguished_name    = req_dn\n"
"string_mask           = utf8only\n"
"keypairs              = $HOME/keypairs\n"
"\n"
"[ req_dn ]\n"
"C = KR\n"
"ST = DAEGU\n"
"L = SmartCity\n"
"O = PKI\n"
"OU = Device Group\n"
"CN = __commonName__\n"
"emailAddress = __emailAddress__\n"
"##END(req.config)\n\n";;


char *FMT_STR_REQ_SERVER = 
"HOME = %s\n"
"\n"
"[ req ]\n"
"default_curve         = prime256v1\n"
"default_cipher        = aes256\n"
"distinguished_name    = req_dn\n"
"string_mask           = utf8only\n"
"keypairs              = $HOME/keypairs\n"
"\n"
"[ req_dn ]\n"
"C = KR\n"
"ST = DAEGU\n"
"L = SmartCity\n"
"O = PKI\n"
"OU = Device Group\n"
"CN = __commonName__\n"
"emailAddress = __emailAddress__\n"
"##END(server.config)\n"
"\n"
"[ req_user ]\n"
"default_curve         = prime256v1\n"
"default_cipher        = aes128\n"
"distinguished_name	   = req_user_dn\n"
"string_mask           = utf8only\n"
"keypairs = $HOME/keypairs\n"
"\n"
"[ req_user_dn ]\n"
"C = KR\n"
"ST = DAEGU\n"
"L = SmartCity\n"
"O = PKI\n"
"OU = Device Group\n"
"CN = __commonName__\n"
"emailAddress = __emailAddress__\n"
"\n"
"[ req_server ]\n"
"default_curve         = prime256v1\n"
"default_cipher        = aes192\n"
"distinguished_name	   = req_server_dn\n"
"string_mask           = utf8only\n"
"keypairs = $HOME/keypairs\n"
"\n"
"[ req_server_dn ]\n"
"C = KR\n"
"ST = DAEGU\n"
"L = SmartCity\n"
"O = PKI SERVER\n"
"OU = Device Group\n"
"CN = __commonName__\n"
"emailAddress = __emailAddress__\n";


            char configstr[4096];
            memset(configstr, 0, sizeof(configstr));

            if(!keydb_file || !cadir_args || !caname_args) {
                fprintf(stderr, "--caname, --cadir, --db parameter required.\n");
                return -1;
            }
            sprintf(configstr, FMT_STR,  cadir_args, caname_args, caname_args,keydb_file, caname_args);
            printf("CONFIG_STR:\n%s\n", configstr);

            // 1. CA CONFIG
            fprintf(stdout, "CA confiuguration file generated: "color_yellow_b"%s/ca.config"color_reset"\n", cadir_args);
            add_file_to_dirctory(cadir_args, "ca.config", configstr, "w");

            // 2. REQ CONFIG
            memset(configstr, 0, sizeof(configstr));
            sprintf(configstr, FMT_STR_REQ, cadir_args);
            IF_VERBOSE printf("CONFIG_STR(USER):\n%s\n", configstr);
            add_file_to_dirctory(cadir_args, "req.config", configstr, "w");
            fprintf(stdout, "User request confiuguration file generated: "color_yellow_b"%s/req.config"color_reset"\n", cadir_args);

            // 3. SERVER CONFIG
            memset(configstr, 0, sizeof(configstr));
            sprintf(configstr, FMT_STR_REQ_SERVER, cadir_args);
            printf("CONFIG_STR(SERVER):\n%s\n", configstr);
            add_file_to_dirctory(cadir_args, "server.config", configstr, "w");
            fprintf(stdout, "Server request confiuguration file generated: "color_yellow_b"%s/server.config"color_reset"\n", cadir_args);

            return 0;
        
            
        }
        else if(1==do_ca_signcmm) {

            if( !config_args) {
                fprintf(stderr, "CA:NEWCA: invalid ca config file\n");
                return -1;
            }

            if(!userid_args) {
                fprintf(stderr, "No userid specified, use --userid options.\n");
                return -1;
            }

            
            //--------------------------------------------------------------------------------
            // * BEGIN SIGNCMM 
            // * CMM Rule에 따라 인증서 생성
            // * gzcms-cli --ca signcmm --config $FILE --userid $ID
            //--------------------------------------------------------------------------------

            char export1[256];
            memset(export1, 0, sizeof(export1));

            char *cfg_caname = NCONF_get_string(gzcms_conf, "ca", "default_ca");
            fprintf(stdout, "config:default_ca: "color_red"%s"color_reset"\n", cfg_caname);

            //DEFAULT.KEYPASS DB
            char *cmmdb_file = NCONF_get_string(gzcms_conf, cfg_caname, "cmmdb");
            fprintf(stdout, "config:cmmdb: "color_red"%s"color_reset"\n", cmmdb_file);
            
            if(0 != reqdb_status_comp(cmmdb_file, userid_args, REQ_STATUS_APPROVAL /*"approval"*/)) {
                fprintf(stderr, "error:user %s status is not '%s'\n", userid_args,REQ_STATUS_APPROVAL) ;    
                return -1;
            }


            //DEFAULT.KEYPASS DB
            char *cfg_keypass_db = NCONF_get_string(gzcms_conf, cfg_caname, "keypass_database");
            fprintf(stdout, "config:cfg_keypass_db: "color_red"%s"color_reset"\n", cfg_keypass_db);

            DECL_STRING(user_csrfile, 256);
            DECL_STRING(user_certfile, 256);
            DECL_STRING(user_macfile, 256);
            DECL_STRING(user_keyfile, 256);

            char *keypair_dir = NULL;
            keypair_dir = NCONF_get_string(gzcms_conf, cfg_caname, "keypairs");
            sprintf(user_csrfile, "%s/%s.req", keypair_dir, userid_args);
            sprintf(user_certfile, "%s/%s.cer", keypair_dir, userid_args);
            sprintf(user_macfile, "%s/%s.mac", keypair_dir, userid_args);
            sprintf(user_keyfile, "%s/%s.key", keypair_dir, userid_args);

            fprintf(stderr, "USER CSR  FILENAME: "color_green_b"%s"color_reset"\n", user_csrfile);
            fprintf(stderr, "USER CERT FILENAME: "color_green_b"%s"color_reset"\n", user_certfile);
            fprintf(stderr, "USER MAC  FILENAME: "color_green_b"%s"color_reset"\n", user_macfile);
            fprintf(stderr, "USER KEY  FILENAME: "color_green_b"%s"color_reset"\n", user_keyfile);

            

            if(cfg_keypass_db)
            {
                //직접 입력 우선
                if(keyid_args == NULL) {
                    keyid_args = NCONF_get_string(gzcms_conf, cfg_caname, "keypass_keyid");
                    if(keyid_args == NULL) {
                        fprintf(stderr, "error:fail to get passphrase for CA key.\n");
                        return -1;
                    }
                }
                char *pkeypass = NULL, *master_secret2 = NULL, *master_pwd_in2 = NULL;

                master_pwd_in2 = (char *)GZPKI_get_master_password(cfg_keypass_db,NULL);
                master_secret2 = (char *)GZPKI_keypass_get_master_secret(cfg_keypass_db, master_pwd_in2);

                IF_VERBOSE fprintf(stdout, "GZPKI_keypass_export ...\n");
                if(master_secret2) {
                    pkeypass = GZPKI_keypass_export(cfg_keypass_db ,master_secret2, keyid_args);
                    //if(master_secret2) free(master_secret2);
                }

                if(pkeypass) {
                    IF_VERBOSE fprintf(stdout, "NAME:%s\n", keyid_args);
                    IF_VERBOSE fprintf(stdout, "EXPORT:%s\n", pkeypass);
                    
                    sprintf(export1, "%s", pkeypass);
                    fprintf(stdout, "%s:%s\n", keyid_args, export1);
                    
                    pkeypass = NULL;
                }
                free(pkeypass);
                free(master_secret2);
                free(master_pwd_in2);
            }

            fprintf(stdout, color_yellow_b"Making User certificate ..."color_reset"\n");
            {
                GZPKI_CTX CA;
                GZPKI_set_infile(&CA, user_csrfile, NULL, 0, FORMAT_PEM);
                GZPKI_set_outfile(&CA, user_certfile, FORMAT_PEM);
                //selfsign option for CA Certificate generation.
                //CA.opt_ca_selfsign = 1;
                CA.configfile = GZPKI_strdup(config_args);
                CA.batch = CA.opt_ca_reqin = CA.use_txtdb = CA.ca_request_file_cnt = 1;

                if(cfg_keypass_db)
                    CA.passin = GZPKI_strdup(export1);
                else 
                    CA.passin = GZPKI_strdup(passin);

                CA.opt_ca_load_private_key=1;
                CA.use_sqldb=1;
                CA.reqUUID = userid_args;
                
                int ret = GZPKI_do_CA(&CA);
                if(CMS_RET_OK==ret) {
                    fprintf(stdout, color_yellow_b"success: Generating CA Certificate."color_reset"\n");     
                }
                else {
                    fprintf(stderr, "error:Generating CA Certificate failed, ret:%d, errcode:%d, %s\n", r, ctx.errcode, ctx.errstr);  
                    GZPKI_free_ctx(&CA);
                    return 0;
                }
                GZPKI_free_ctx(&CA);
            }

            //==================================================
            // RE-Encrypt User private key with device password
            //==================================================
            DECL_STRING(device_pwd_old, 256); //MAC만으로 암호화
            DECL_STRING(device_pwd_new, 256); //MAC + CERT로 암호화

            int err=-1;
            size_t f_size = 0;

            //TODO: error 처리 추가
            with_mac_args = dump_file_content(user_macfile, &err, &f_size);
            fprintf(stderr, "MAC: %s\n", with_mac_args);
            {
                GZPKI_CTX ctx; //contaner for ctx.device_password
                GZPKI_generate_device_password(&ctx, with_mac_args, NULL);
                sprintf(device_pwd_old, "%s", ctx.device_password);

                fprintf(stderr, "Device password OLD: %s\n", device_pwd_old);
                
                GZPKI_generate_device_password(&ctx, with_mac_args, user_certfile);
                sprintf(device_pwd_new, "%s", ctx.device_password);

                fprintf(stderr, "Device password NEW: %s\n", device_pwd_new);

                DECL_STRING(newkey_file, 260); //256 + 4
                sprintf(newkey_file, "%s.new", user_keyfile);
        
                GZPKI_set_infile(&ctx, user_keyfile, NULL, 0, FORMAT_PEM);
                GZPKI_set_outfile(&ctx, newkey_file, FORMAT_PEM);

                ctx.passin  = GZPKI_strdup(device_pwd_old);
                ctx.passout = GZPKI_strdup(device_pwd_new);

                char *cipher_alg = NCONF_get_string(gzcms_conf, cfg_caname, "default_cipher");
                if(cipher_alg) 
                    ctx.name = GZPKI_strdup(cipher_algs);
                else
                    ctx.name = GZPKI_strdup("aes256");

                fprintf(stderr, "generate new key file: %s\n", newkey_file);

                int  r = GZPKI_do_ECC(&ctx);
                if(CMS_RET_OK!=r) {
                    fprintf(stderr, "error:do_ecc:private key re-encryption failed: %s\n", user_keyfile);
                    return -1;
                }
                else
                    fprintf(stderr, "success:ecc:private key re-encrypted: %s\n", newkey_file);
                    
            }

            r = reqdb_status_update(cmmdb_file, userid_args, REQ_STATUS_COMPLETED);
            if(0 != r) {
                fprintf(stderr, "error: fail to update REQUEST, userid=%s, stat=%s\n", userid_args, REQ_STATUS_COMPLETED);
                return -1;
            }
            else
                fprintf(stderr, "success: update REQUEST for userid=%s, stat=%s\n", userid_args, REQ_STATUS_COMPLETED);
            
            return 0;

//--------------------------------------------------------------------------------
// * END SIGNCMM 
//--------------------------------------------------------------------------------
        }
        else if(1==do_ca_sign) {

        }
//--------------------------------------------------------------------------------
// BEGIN NEWCA 
//--------------------------------------------------------------------------------        
        else if(1==do_ca_newca) {
            //------------------------------------------------------------
            //CA 인증서와 개인키를 생성한다. 
            // 2. CA KEY PAIR GENERATION, CA.CONFIG만으로 수행 가능
            //------------------------------------------------------------

            if( !config_args) {
                fprintf(stderr, "CA:NEWCA: invalid config file\n");
                return -1;
            }

            //char tmp[256];
            
            //CA.NAME            
            char *cfg_caname = NCONF_get_string(gzcms_conf, "ca", "default_ca");
            fprintf(stdout, "config:default_ca: "color_red"%s"color_reset"\n", cfg_caname);

            //CA.PRIVATE_KEY	        
            char *cfg_cakey_filename = NCONF_get_string(gzcms_conf, cfg_caname, "private_key");
            fprintf(stdout, "config:cakey: "color_red"%s"color_reset"\n", cfg_cakey_filename);

            //CERTIFICATE
            char *cfg_cacert_filename = NCONF_get_string(gzcms_conf, cfg_caname, "certificate");
            fprintf(stdout, "config:cacert: "color_red"%s"color_reset"\n", cfg_cacert_filename);

            //CA.CSR
            char *cfg_csr_filename = NCONF_get_string(gzcms_conf, cfg_caname, "csr");
            fprintf(stdout, "config:csr: "color_red"%s"color_reset"\n", cfg_csr_filename);
            
            //DEFAULT.CURVE            
            char *keygen_param = NCONF_get_string(gzcms_conf, "req", "default_curve");
            fprintf(stdout, "config:default_curve: "color_red"%s"color_reset"\n", keygen_param);

            //DEFAULT.KEYGEN_ALG
            char *keygen_alg = NCONF_get_string(gzcms_conf, "req", "default_key_algorithm");
            fprintf(stdout, "config:default_key_algorithm: "color_red"%s"color_reset"\n", keygen_alg);
            
            //DEFAULT.KEYPASS DB
            char *cfg_keypass_db = NCONF_get_string(gzcms_conf, cfg_caname, "keypass_database");
            fprintf(stdout, "config:cfg_keypass_db: "color_red"%s"color_reset"\n", cfg_keypass_db);


            char *user_keypem = NULL;
            char *user_csr_pem = NULL;

            fprintf(stdout, color_yellow_b"Generating CA key pair ..."color_reset"\n");     

#if 1
            char export1[256];
            //char *cfg_keypass_keyid = NULL;
            
            //직접 입력 우선
            if(keyid_args == NULL) {
                keyid_args = NCONF_get_string(gzcms_conf, cfg_caname, "keypass_keyid");
                if(keyid_args == NULL) {
                    fprintf(stderr, "error:fail to get passphrase for CA key.\n");
                    return -1;
                }
            }
            memset(export1, 0, sizeof(export1));
            {
                char *pkeypass = NULL;
            
                char *master_secret2 = NULL;
                char *master_pwd_in2 = NULL;

                master_pwd_in2 = (char *)GZPKI_get_master_password(cfg_keypass_db,NULL);
                master_secret2 = (char *)GZPKI_keypass_get_master_secret(cfg_keypass_db, master_pwd_in2);

                IF_VERBOSE fprintf(stdout, "GZPKI_keypass_export...\n");
                if(master_secret2) {
                    pkeypass = GZPKI_keypass_export(cfg_keypass_db ,master_secret2, keyid_args);
                    //if(master_secret2) free(master_secret2);
                }

                if(pkeypass) {
                    IF_VERBOSE fprintf(stdout, "NAME:%s\n", keyid_args);
                    IF_VERBOSE fprintf(stdout, "EXPORT:%s\n", pkeypass);
                    
                    sprintf(export1, "%s", pkeypass);
                    fprintf(stdout, "%s:%s\n", keyid_args, export1);
                    free(pkeypass);
                    pkeypass = NULL;
                }
            }
#endif

            //--------------------------------------------------
            // CA.KEY 생성
            //--------------------------------------------------    
            int err=-1;
            size_t f_size=-1;            
            int keylen = 0;  
            {
                user_keypem = GZPKI_generate_PRIKEY(keygen_param, export1,  "aes256", &keylen, cfg_cakey_filename);
                fprintf(stderr, "CAKEY(PEM): %s\n", user_keypem);
                fprintf(stderr, "CAKEY(CONTENTs): "color_green"%s"color_reset"\n", dump_file_content(user_keypem, &err, &f_size));
            }

            //Not Used : int csrlen = 0;  
            //--------------------------------------------------
            // CA.REQ 생성: DN Entry는 모두 ca.config 에서 읽는다.
            //--------------------------------------------------
            fprintf(stdout, color_yellow_b"Generating CA Certificate Signing Request ..."color_reset"\n");     
            user_csr_pem = GZPKI_generate_CSR(NULL/*user_keypem*/, cfg_cakey_filename, export1, config_args, NULL/*CN*/, cfg_csr_filename, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FORMAT_FILE);

            IF_VERBOSE fprintf(stderr, "CSR.PEM:\n%s\n", (char *)user_csr_pem);
            fprintf(stderr, "CSR(CONTENTs): "color_green"%s"color_reset"\n", dump_file_content(user_csr_pem, &err, &f_size));

            //--------------------------------------------------
            // CA.PEM : 인증서 생성
            //--------------------------------------------------            
#if 1
            fprintf(stdout, color_yellow_b"Making CA certificate ..."color_reset"\n");
            {
                int ret = -1;
                char *dayz;
                GZPKI_CTX CA;
                GZPKI_set_infile(&CA, cfg_csr_filename, NULL, 0, FORMAT_PEM);
                GZPKI_set_outfile(&CA, cfg_cacert_filename, FORMAT_PEM);
                CA.opt_ca_selfsign = 1;
                CA.configfile = GZPKI_strdup(config_args);

                CA.batch = 1;
			    CA.opt_ca_reqin = 1;
                CA.use_txtdb = 1;
                CA.passin = GZPKI_strdup(export1);
                
                dayz = CFG_SECTION_VALUE(NULL, "ca_default_days");
                CA.days = atoi(dayz);

                fprintf(stdout, INFO_TAG"NOTICE: check ca validity days(null:ca_default_days): %d\n", CA.days);     

                CA.ca_request_file_cnt = 1;
                CA.opt_ca_load_private_key = 1;
//TEST
//READ IT FROM --EXT_SECTION                
                CA.caconf_entensions_section_name = GZPKI_strdup("v3_ca");

                ret = GZPKI_do_CA(&CA);
                if(CMS_RET_OK==ret) {
                    fprintf(stdout, color_yellow_b"success: Generating CA Certificate."color_reset"\n");     
                }
                else {
                    //fprintf(stdout, color_red_b"error: Fail to generate CA Certificate."color_reset"\n");   
                    fprintf(stderr, "error:sign:ret=%d: %d,%s\n", r, ctx.errcode, ctx.errstr);  
                }
                GZPKI_free_ctx(&CA);
            }
#endif
            return 0;

        }
//--------------------------------------------------------------------------------
// END NEWCA 
//--------------------------------------------------------------------------------

//--------------------------------------------------------------------------------
// BEGIN REVOKE
// : userid를 기반으로 하되 GZPKI_do_CA에는 userid.cer를 전달한다. 
// : index.txt --> TODO(sqlite)
//--------------------------------------------------------------------------------                
        else if(1==do_ca_revoke) {
            
            ERR_RETURN(config_args, "no config file.", -1);
#if 0            
            ERR_RETURN(userid_args, "no user id.", -1);
            ERR_RETURN(infile, "no input file.", -1);
#endif
            DECL_STRING(revfile, 256);
            DECL_STRING(export1, 512);
            
            if(infile != NULL) {
                sprintf(revfile, "%s", infile); 
            } else if(userid_args!=NULL) {
                char *keypair_dir = CFG_CA_SECTION_VALUE("keypairs");
                sprintf(revfile, "%s/%s.cer", keypair_dir, userid_args);
            } else {
                //error
                fprintf(stderr, "error:no revoked filename.\n");
                return -1;
            }

            fprintf(stdout, color_yellow_b"Revoking User certificate ..."color_reset"\n");
            fprintf(stdout, "filename: %s\n", revfile);
            fprintf(stdout, "reason  : %s\n", revoke_reason_args?revoke_reason_args:"NULL");

            {
                char *pkeypass = NULL, *master_secret2 = NULL, *master_pwd_in2 = NULL;
                char *cfg_keypass_db = CFG_CA_SECTION_VALUE("keypass_database");
                char *keyid_args = CFG_CA_SECTION_VALUE("keypass_keyid");

                master_pwd_in2 = GZPKI_get_master_password(cfg_keypass_db,NULL);
                master_secret2 = (char *)GZPKI_keypass_get_master_secret(cfg_keypass_db, master_pwd_in2);

                IF_VERBOSE fprintf(stdout, "GZPKI_keypass_export ...\n");
                if(master_secret2) {
                    pkeypass = GZPKI_keypass_export(cfg_keypass_db ,master_secret2, keyid_args);
                    //if(master_secret2) free(master_secret2);
                }

                if(pkeypass) {
                    IF_VERBOSE fprintf(stdout, "NAME:%s\n", keyid_args);
                    //NEVER USE only for debugging
                    //IF_VERBOSE fprintf(stdout, "EXPORT:%s\n", pkeypass);
                    
                    sprintf(export1, "%s", pkeypass);
                    //NEVER USE only for debugging
                    IF_VERBOSE fprintf(stdout, "%s:%s\n", keyid_args, export1);
                    
                    pkeypass = NULL;
                }
                free(pkeypass);
                free(master_secret2);
                free(master_pwd_in2);
            }
            
            {
                int ret = -1;
                GZPKI_CTX CA;
                //infile: certificate file to revoke
                GZPKI_set_infile(&CA, revfile, NULL, 0, FORMAT_PEM);
                
                CA.configfile = GZPKI_strdup(config_args);

                if(revoke_reason_args) {
                    CA.crl_revoke_reason = GZPKI_strdup(revoke_reason_args);
                    CA.crl_revoke_type = REV_CRL_REASON;
                }
                else {
                    CA.crl_revoke_type = REV_NONE;
                }

                CA.passin = GZPKI_strdup(export1);
			    CA.opt_ca_do_revoke = 1;
                CA.use_txtdb = 1;
                ret = GZPKI_do_CA(&CA);
                if(CMS_RET_OK==ret) {
                    fprintf(stdout, color_yellow_b"success: Revoke user certificate."color_reset"\n");     
                }
                else {
                    //fprintf(stdout, color_red_b"error: Fail to generate CA Certificate."color_reset"\n");   
                    fprintf(stderr, "error(%d):revoke:%s\n", CA.errcode, CA.errstr);  
                }
                CA.configfile = NULL;
                GZPKI_free_ctx(&CA);
    
            }
            
        }
        else if(1==do_ca_approval) 
        {
            
            sqlite3 *db;
            sqlite3_stmt *stmt = NULL;
   	        char *zErrMsg = 0;
   	        int rc;

            require_args(userid_args, "no user id specified...", -1);

            caname_args = CFG_CA_NAME();
            char *file = CFG_CA_SECTION_VALUE("cmmdb");

#if 0
            char *master_pwd_in = NULL;
            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "APPROVAL...");
            master_pwd_in = GZPKI_get_master_password_one(keydb_file, PROMPT_MASTER_PWD);

            char *keydb_file = CFG_CA_SECTION_VALUE("keypass_database");;
            //--------------------------------------------------
            //마스터 패스워드가 맞는지 확인
            //--------------------------------------------------
            r = GZPKI_keypass_verify_master_pass(keydb_file, master_pwd_in);
            if(r != 0) {
                //IF_VERBOSE printf("user    master hash: ["color_yellow_b"%s"color_reset"]\n", master_pwd_hash);
                //IF_VERBOSE printf("keypass master hash: ["color_yellow_b"%s"color_reset"]\n", g_digest);
                printf("error: invalid master password for %s\n", keydb_file);
                return -1;
            }
#endif
            /*
             * 필요값만 FETCH한다 
             */
            int reqid=-1;            
            DECL_STRING(username, 128);
            DECL_STRING(deviceinfo, 128);
            DECL_STRING(reqtype, 16);
            DECL_STRING(extension, 32);

            DECL_STRING(sql, 2048);
            //char sql[1024];
            //memset(sql, 0, 1024);
            sprintf(sql, "SELECT id, status, username, deviceinfo, type, extension FROM reqdb WHERE caname='%s' and id=%s and status='pending'", 
                caname_args, userid_args);
            
            IF_VERBOSE fprintf(stderr, DEBUG_TAG"APPROVAL: FILE: %s\n", file);
            IF_VERBOSE fprintf(stderr, DEBUG_TAG"SQL: %s\n", sql);
            
            rc = sqlite3_open(file, &db);
            if( rc ) {
    	        fprintf(stderr, "error: init gzcmm database %s: %s\n", file, sqlite3_errmsg(db));
      	        return -1;
   	        } 
            rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr,"error:fail to sqlite3_prepare_v2 database: %s\n", file);
                fprintf(stderr,"- sql: %s \n", sql);
                return -1;
            }
            rc = sqlite3_step(stmt);
            int rowCount = 0;
            //int i = 0;

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
            
                        
                        if(0==strcmp(columnName, "username"))   sprintf(username, "%s", valChar);
                        if(0==strcmp(columnName, "deviceinfo")) sprintf(deviceinfo, "%s", valChar);
                        if(0==strcmp(columnName, "type"))       sprintf(reqtype, "%s", valChar);
                        if(0==strcmp(columnName, "extension"))  sprintf(extension, "%s", valChar);
                    }
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

            if(rowCount!=1) {
                fprintf(stderr,"error:no entry user id = [%s]\n", userid_args);
                return -1;
            }

            with_mac_args = deviceinfo;
            with_cn_args = username;

            if(!with_mac_args) {
                fprintf(stderr, "No MAC address specified, use --with-mac options.\n");
                return -1;
            }
            if(!with_cn_args) {
                fprintf(stderr, "No Common Name(CN) specified, use --with-cn options.\n");
                return -1;
            }

            if(!userid_args) {
                fprintf(stderr, "No userid specified, use --userid options.\n");
                return -1;
            }
            
            IF_VERBOSE fprintf(stderr, "ID         : "color_green_b"%d"color_reset"\n", reqid);
            IF_VERBOSE fprintf(stderr, "Device Info: "color_green_b"%s"color_reset"\n", with_mac_args);
            IF_VERBOSE fprintf(stderr, "Common Name: "color_green_b"%s"color_reset"\n", with_cn_args);
            IF_VERBOSE fprintf(stderr, "Type       : "color_green_b"%s"color_reset"\n", reqtype);
            IF_VERBOSE fprintf(stderr, "Extension  : "color_green_b"%s"color_reset"\n", extension!=NULL?extension:"null");

            //==================================================
            // 1.  Key Generation
            // 1.1 Generate Device Password with MAC
            //==================================================

            //int err=-1;
            //size_t f_size=-1;            
            //int keylen = 0;  
            {
                //char *user_key_pem = NULL;
                char *tmp=NULL;
                char export1[512];
                
                int keylen = -1;
                //인증서는 아직 없음
                GZPKI_CTX ctx; //contaner for ctx.device_password
                GZPKI_generate_device_password(&ctx, with_mac_args, NULL);
                
                memset(export1, 0, sizeof(export1));
                sprintf(export1, "%s", ctx.device_password);
                
                fprintf(stderr, "Device password \n");
                fprintf(stderr, "- cn : %s\n", with_cn_args);
                fprintf(stderr, "- pwd: %s\n", export1);
                fprintf(stderr, "- mac: %s\n", with_mac_args);

                char req_section[128];
                memset(req_section, 0, sizeof(req_section));

                if(req_section_args) {
                    IF_VERBOSE fprintf(stderr, "using req section from args: %s\n", req_section_args);
                    sprintf(req_section, "%s", req_section_args);
                    fprintf(stdout, "req_section_args: "color_red"%s"color_reset"\n", req_section);
                }
                else if(extension != NULL) {
                    //caname의 req_user를 사용할 수도 있다
                    //sprintf(req_section, "%s", "req");
                    IF_VERBOSE fprintf(stderr, "using req section from database: %s\n", extension);
                    sprintf(req_section, "%s", extension);
                    fprintf(stdout, "config:DEFAULT_REQ_SECTION: "color_red"%s"color_reset"\n", req_section);
                }
                else {
                    fprintf(stderr, "no req section.\n");
                    return -1;
                }

                
                char keygen_param[128];
                memset(keygen_param, 0, sizeof(keygen_param));
                tmp = NCONF_get_string(gzcms_conf, req_section, "default_curve");
                if(tmp) {
                    sprintf(keygen_param, "%s", tmp);
                    fprintf(stdout, "config:%s:default_curve: "color_yellow_b"%s"color_reset"\n", req_section, keygen_param);
                }
                else {
                    sprintf(keygen_param, "%s", "prime256v1");
                    fprintf(stdout, "config:DEFAULT:default_curve: "color_yellow_b"%s"color_reset"\n", keygen_param);
                }
                
                char default_cipher[128];
                memset(default_cipher, 0, sizeof(default_cipher));
                tmp = NCONF_get_string(gzcms_conf, req_section, "default_cipher");
                
                if(tmp) {
                    IF_VERBOSE fprintf(stderr, "get cipher from %s: %s\n", config_args, tmp);
                    sprintf(default_cipher, "%s", tmp);
                }
                else {
                    IF_VERBOSE fprintf(stderr, "using default cipher AES128\n");
                    sprintf(default_cipher, "%s", "aes128");
                }

                fprintf(stdout, "config:%s:default_cipher: "color_yellow_b"%s"color_reset"\n", req_section, default_cipher);

                char *device_keypem = NULL;

                DECL_STRING(user_keyfile, 256);
                DECL_STRING(user_csrfile, 256);
                DECL_STRING(user_macfile, 256);

                tmp = NCONF_get_string(gzcms_conf, req_section, "keypairs");
                sprintf(user_keyfile, "%s/%s.key", tmp, userid_args);
                sprintf(user_csrfile, "%s/%s.req", tmp, userid_args);
                sprintf(user_macfile, "%s/%s.mac", tmp, userid_args);

                fprintf(stderr, "APPROVAL:KEY FILE: "color_red_b"%s"color_reset"\n", user_keyfile);
                fprintf(stderr, "APPROVAL:CSR FILE: "color_red_b"%s"color_reset"\n", user_csrfile);
                fprintf(stderr, "APPROVAL:MAC FILE: "color_red_b"%s"color_reset"\n", user_macfile);

                //MAC 파일도 저장한다. 
                add_file_to_dirctory(tmp, user_macfile, with_mac_args, "w");

                device_keypem = GZPKI_generate_PRIKEY(keygen_param, export1,  default_cipher, &keylen, user_keyfile);
                fprintf(stderr, "CAKEY(PEM): %s\n", device_keypem);
                fprintf(stdout, color_yellow_b"Generating User Certificate Signing Request ..."color_reset"\n");     

                char *user_csr_pem = NULL;

                DECL_STRING(dn_str, 256);

                char *dn_section = NULL;
                dn_section = NCONF_get_string(gzcms_conf, req_section, "distinguished_name");
                IF_VERBOSE fprintf(stderr, "%s:dn_section = %s\n", req_section, dn_section);

                user_csr_pem = GZPKI_generate_CSR(/*device_keypem*/NULL, 
                    user_keyfile/*NULL*/, 
                    export1, 
                    config_args, 
                    NULL/*dn_str*/, 
                    user_csrfile/*NULL*/, 
                    req_section, 
                    NULL, /*req_exts*/
                    NULL, NULL, NULL, NULL, NULL, 
                    with_cn_args, 
                    with_email_args, 
                    FORMAT_MEM );

                IF_VERBOSE fprintf(stderr, "USER.CSR.PEM:\n%s\n", (char *)user_csr_pem);
                //fprintf(stderr, "USER.CSR(CONTENTs): "color_green"%s"color_reset"\n", dump_file_content(user_csr_pem, &err, &f_size));
            }

            //UPDATE DATABASE
            memset(sql, 0, sizeof(sql));
            sprintf(sql, "UPDATE reqdb SET status='approval' WHERE id=%d", reqid);
            IF_VERBOSE fprintf(stderr, "UPDATE SQL: "color_blue_b"%s"color_reset"\n", sql);

            rc = sqlite3_open(file, &db);
            if( rc ) {
    	        fprintf(stderr, "error:open database %s for approval: %s\n", file, sqlite3_errmsg(db));
      	        return -1;
   	        } 
            
            rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
            if( rc != SQLITE_OK ){
    	        fprintf(stderr, "error:sql:%s\n", zErrMsg);
                sqlite3_free(zErrMsg);  	
   	        } else {
    	        IF_VERBOSE fprintf(stderr, DEBUG_TAG"update table successfully\n");
   	        }

            rc = sqlite3_close(db);
            
            return 0;

        }

        //--------------------------------------------------
        // GENERATE USB TOKEN 4 DEVICE
        //--------------------------------------------------
        else if(1==do_ca_gencrl) {
            //...
            ERR_RETURN(config_args, "no config file.", -1);

            DECL_STRING(export1, 512);

            {
                char *pkeypass = NULL, *master_secret2 = NULL, *master_pwd_in2 = NULL;
                char *cfg_keypass_db = CFG_CA_SECTION_VALUE("keypass_database");
                char *keyid_args = CFG_CA_SECTION_VALUE("keypass_keyid");

                master_pwd_in2 = (char *)GZPKI_get_master_password(cfg_keypass_db,NULL);
                master_secret2 = (char *)GZPKI_keypass_get_master_secret(cfg_keypass_db, master_pwd_in2);

                IF_VERBOSE fprintf(stdout, "GZPKI_keypass_export ...\n");
                if(master_secret2) {
                    pkeypass = GZPKI_keypass_export(cfg_keypass_db ,master_secret2, keyid_args);
                    //if(master_secret2) free(master_secret2);
                }

                if(pkeypass) {
                    IF_VERBOSE fprintf(stdout, "NAME:%s\n", keyid_args);
                    //NEVER USE only for debugging
                    //IF_VERBOSE fprintf(stdout, "EXPORT:%s\n", pkeypass);
                    
                    sprintf(export1, "%s", pkeypass);
                    //NEVER USE only for debugging
                    IF_VERBOSE fprintf(stdout, "%s:%s\n", keyid_args, export1);
                    
                    pkeypass = NULL;
                }
                free(pkeypass);
                free(master_secret2);
                free(master_pwd_in2);
            }


            //--------------------------------------------------
            // 별도의 입력 없이, 
            //--------------------------------------------------
            {
                int ret = -1;
                GZPKI_CTX CA;
                CA.configfile = GZPKI_strdup(config_args);
                CA.passin = GZPKI_strdup(export1);
                CA.opt_ca_generate_crl = 1;
                CA.opt_ca_load_private_key = 1;
                CA.use_txtdb = 1;
                char *outfile = CFG_CA_SECTION_VALUE("crl");
                GZPKI_set_outfile(&CA, outfile, FORMAT_PEM );

                ret = GZPKI_do_CA(&CA);
              
                if(CMS_RET_OK==ret) {
                    fprintf(stdout, "success: crl generation ok\n");     
                }
                else {
                    fprintf(stderr, "error(%d):gencrl:%s\n", CA.errcode, CA.errstr);  
                }

                CA.configfile = NULL;
                if(outfile)
                    free(outfile);
                GZPKI_free_ctx(&CA);
            }

            return 0;


        }
        else if(1==do_ca_newcmmdb) {
            //신규 DB 테이블을 생성한다.

            char *cmmdb_args = CFG_CA_SECTION_VALUE("cmmdb");

            GZPKI_gzcmm_database_init(cmmdb_args);

            return -1;

        }
        else if(1==do_ca_gentoken) {
            
            //char *tmp = NULL;
            int ret = -1;
            
            DECL_STRING(target_dir, 256);
            DECL_STRING(user_certfile, 256);
            DECL_STRING(user_keyfile, 256);
            DECL_STRING(src_dir, 256);
            DECL_STRING(cmd, 512);

            //TOKEN SECTION
            //입력이 없으면 ca.config에서 읽는다
            //--token_from ARGS설정되면 우선 순위는 parameter 지정된 token section
            DECL_STRING(token_section, 64);
            
            ERR_RETURN(userid_args, "no user id.", -1);
            ERR_RETURN(config_args, "no config file.", -1);

            if(opt_token_from==1 && token_from_args) {
                sprintf(token_section, "%s", token_from_args);
            } else {
                sprintf(token_section, "%s", CFG_CA_SECTION_VALUE("token"));
            }
            
            fprintf(stderr, "%s\n", "--------------------------------------------------");    
            fprintf(stderr, "generate usb token for user id: "color_yellow_b"%s"color_reset"\n", userid_args);    
            fprintf(stderr, "token data source: "color_yellow_b"%s"color_reset"\n", token_section);    
            fprintf(stderr, "%s\n", "--------------------------------------------------");    

            
            IF_VERBOSE fprintf(stderr, DEBUG_TAG"default_ca name:%s\n", CFG_CA_NAME());    
            
            
            sprintf(user_certfile, "%s/%s.cer", CFG_CA_SECTION_VALUE("keypairs"), userid_args);
            sprintf(user_keyfile, "%s/%s.key", CFG_CA_SECTION_VALUE("keypairs"), userid_args);
            
            if( !is_file_exists(user_certfile) ) {
                printf("error: no user certificate file, %s\n", user_certfile);
                return -1;
            }
            if( !is_file_exists(user_keyfile) ) {
                printf("error: no user private key file, %s\n", user_certfile);
                return -1;
            }

            //GEN: $TOKEN/$PREFIX 
            sprintf(target_dir, "%s/%s", CFG_SECTION_VALUE(token_section, "target"), CFG_SECTION_VALUE(token_section, "prefix") );
            fprintf(stderr, "generate token home dirctory: "color_yellow_b"%s"color_reset" : ", target_dir);    
            ret = generate_dirctory(target_dir, 0666);
            if(ret < 0) {
                fprintf(stderr, "error: fail to generate token\n"); 
                //TODO: do not return for testing
                //return -1;   
            }

            DECL_STRING(sub_dir, 256);
            
            sprintf(sub_dir, "%s/cert", target_dir );
            fprintf(stderr, "generate: "color_yellow_b"%s"color_reset" : ", sub_dir);    
            generate_dirctory(sub_dir, 0666);

            memset(sub_dir, 0, sizeof(sub_dir));
            sprintf(sub_dir, "%s/bin", target_dir );
            fprintf(stderr, "generate: "color_yellow_b"%s"color_reset" : ", sub_dir);    
            generate_dirctory(sub_dir, 0666);

            memset(sub_dir, 0, sizeof(sub_dir));
            sprintf(sub_dir, "%s/cert/device", target_dir );
            fprintf(stderr, "generate: "color_yellow_b"%s"color_reset" : ", sub_dir);    
            generate_dirctory(sub_dir, 0666);

            memset(sub_dir, 0, sizeof(sub_dir));
            sprintf(sub_dir, "%s/cert/ca", target_dir );
            fprintf(stderr, "generate: "color_yellow_b"%s"color_reset" : ", sub_dir);    
            generate_dirctory(sub_dir, 0666);

            memset(sub_dir, 0, sizeof(sub_dir));
            sprintf(sub_dir, "%s/cert/server", target_dir );
            fprintf(stderr, "generate: "color_yellow_b"%s"color_reset" : ", sub_dir);    
            generate_dirctory(sub_dir, 0666);

            memset(sub_dir, 0, sizeof(sub_dir));
            sprintf(sub_dir, "%s/docs", target_dir );
            fprintf(stderr, "generate: "color_yellow_b"%s"color_reset" : ", sub_dir);    
            generate_dirctory(sub_dir, 0666);

            memset(sub_dir, 0, sizeof(sub_dir));
            sprintf(sub_dir, "%s/include", target_dir );
            fprintf(stderr, "generate: "color_yellow_b"%s"color_reset" : ", sub_dir);    
            generate_dirctory(sub_dir, 0666);

            memset(sub_dir, 0, sizeof(sub_dir));
            sprintf(sub_dir, "%s/lib", target_dir );
            fprintf(stderr, "generate: "color_yellow_b"%s"color_reset" : ", sub_dir);    
            generate_dirctory(sub_dir, 0666);

            //1. device 
            DECL_STRING(target_file, 256);
            //memset(target_file, 0, sizeof(target_file));
            sprintf(target_file, "%s/cert/device/device.pem", target_dir );
            //fprintf(stderr, "copyfile: [%s] to [%s] : ", user_certfile, target_file);   
            fprintf(stderr, "copyfile: %s to "color_yellow_b"%s"color_reset" : ", user_certfile, target_file);  
            ret = copy_file(target_file, user_certfile);
            if(ret==0)
                fprintf(stderr, color_yellow_b"succcess"color_reset"\n");   
            else 
                fprintf(stderr, color_red_b"failed"color_reset"\n");   

            memset(target_file, 0, sizeof(target_file));
            sprintf(target_file, "%s/cert/device/device.key", target_dir );
            fprintf(stderr, "copyfile: %s to "color_yellow_b"%s"color_reset" : ", user_keyfile, target_file);  
            ret = copy_file(target_file, user_keyfile);
            if(ret==0)
                fprintf(stderr, color_yellow_b"succcess"color_reset"\n");   
            else 
                fprintf(stderr, color_red_b"failed"color_reset"\n");   

            //2. ca.pem
            #define CFG_CA_SECTION_VALUE(ARGS) NCONF_get_string(gzcms_conf, CFG_CA_NAME(), ARGS)       
            DECL_STRING(src_file, 256);
            sprintf(src_file, "%s", CFG_CA_SECTION_VALUE("certificate"));

            memset(target_file, 0, sizeof(target_file));
            sprintf(target_file, "%s/cert/ca/ca.pem", target_dir );

            fprintf(stderr, "copyfile: %s to "color_yellow_b"%s"color_reset" : ", src_file, target_file);  
            //fprintf(stderr, "SRC : %s\n", src_file);
            ret = copy_file(target_file, src_file);
            if(ret==0)
                fprintf(stderr, color_yellow_b"succcess"color_reset"\n");   
            else 
                fprintf(stderr, color_red_b"failed"color_reset"\n");   


            //3. server.pem
            //#define CFG_CA_SECTION_VALUE(ARGS) NCONF_get_string(gzcms_conf, CFG_CA_NAME(), ARGS)       
            memset(src_file, 0, sizeof(src_file));
            sprintf(src_file, "%s", CFG_SECTION_VALUE(token_section, "server"));

            memset(target_file, 0, sizeof(target_file));
            sprintf(target_file, "%s/cert/server/server.pem", target_dir );

            fprintf(stderr, "copyfile: %s to "color_yellow_b"%s"color_reset" : ", src_file, target_file);  
            if(ret==0)
                fprintf(stderr, color_yellow_b"succcess"color_reset"\n");   
            else 
                fprintf(stderr, color_red_b"failed"color_reset"\n");   
            

            //4. BIN(GZCMS_CLI)
            memset(src_file, 0, sizeof(src_file));
            sprintf(src_file, "%s/%s", CFG_SECTION_VALUE(token_section, "bin_dir"), CFG_SECTION_VALUE(token_section, "bin"));

            memset(target_file, 0, sizeof(target_file));
            sprintf(target_file, "%s/bin/%s", target_dir, CFG_SECTION_VALUE(token_section, "bin") );

            fprintf(stderr, "copyfile: %s to "color_yellow_b"%s"color_reset" : ", src_file, target_file);  
            if(ret==0)
                fprintf(stderr, color_yellow_b"succcess"color_reset"\n");   
            else 
                fprintf(stderr, color_red_b"failed"color_reset"\n");   

            //4. BIN(GZCMS_CLI)
            memset(src_file, 0, sizeof(src_file));
            sprintf(src_file, "%s", CFG_SECTION_VALUE(token_section, "version"));

            memset(target_file, 0, sizeof(target_file));
            sprintf(target_file, "%s/version.txt", target_dir);

            fprintf(stderr, "copyfile: %s to "color_yellow_b"%s"color_reset" : ", src_file, target_file);  
            if(ret==0)
                fprintf(stderr, color_yellow_b"succcess"color_reset"\n");   
            else 
                fprintf(stderr, color_red_b"failed"color_reset"\n");   

            //- copy directory
            //
            //
            //lib, include, docs
            sprintf(src_dir, "%s", CFG_SECTION_VALUE(token_section, "source"));
            sprintf(target_dir, "%s", CFG_SECTION_VALUE(token_section, "target") );
            sprintf(cmd, "cp -rf %s/ %s", src_dir, target_dir);
            fprintf(stderr, "COMMAND: [%s]\n", cmd);
            ret = system(cmd);
            if(ret < 0) {
                fprintf(stderr, "error:fail to exec command. code=%d\n", ret);
                return -1;
            }

        }
        return 0;
    }



    if(do_req == 1) 
    {
        //config 필수
        if(!config_args) {
            fprintf(stderr, "No Config file specified, use --config options.\n");
            return -1;
        }

        //--------------------------------------------------
        // CMM format의 request file을 import
        //--------------------------------------------------
        if(1==do_req_import_csv) 
        {
            extern char *field[];
            DECL_STRING(sql, 1024);

            caname_args = CFG_CA_NAME();

            //input: csv format file
            require_args(infile, "no input file", -1);

            FILE* stream = fopen(infile, "r");

            int nf;
            int seq = 0;

            // spacer 
            sqlite3 *db;
   	        char *zErrMsg = 0;
   	        int rc;
            //int num = 0;
            //int r = 0;

            char *file = CFG_CA_SECTION_VALUE("cmmdb");
            rc = sqlite3_open(file, &db);

   	
            if( rc ) {
    	        fprintf(stderr, "error: init gzcmm database %s: %s\n", file, sqlite3_errmsg(db));
      	        return -1;
   	        } 

            while ((nf = csvgetline(stream)) != -1) {

                if(strlen(field[0]) < 4 || strlen(field[1]) <  4) {
                    fprintf(stdout, "error:invalid requst(csv) entry, continue...\n");
                    continue;
                }
                
                printf("field[1] = '%s'\n",  field[0]);
                printf("field[2] = '%s'\n",  field[1]);
                sprintf(sql, "INSERT INTO reqdb (status, username, deviceinfo, type, caname, extension, cdate, mdate)"
                " VALUES ('%s', '%s', '%s', '%s', '%s', '%s', DATETIME(\'now\'), DATETIME(\'now\'))"
                , "pending", field[0], field[1], "new", caname_args, req_section_args?req_section_args:"");

                fprintf(stderr,"SQL[%d] : %s\n", seq++, sql);

                rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
                if( rc != SQLITE_OK ){
    	            fprintf(stderr, "error:gzcmm:database:request:init:%s\n", zErrMsg);
                    //sqlite3_free(zErrMsg);  
                    //sqlite3_close(db);
                    return -1;
   	            } else {
    	            fprintf(stdout, "database: add database table, %s, %s.\n", field[0], field[1]);
   	            }
                memset(sql, 0, sizeof(sql));
            }

            fclose(stream);
            sqlite3_close(db);

            if(opt_return == 1)
                fprintf(stdout, "success.%s\n", return_args);

            return 0;

        }
        //--------------------------------------------------
        // NEWCMM: CMM 호환 모드 - 
        // [1] KEY + REQ 모두 생성
        // [2] CN과 MAC을 모두 입력 받는다.
        // [3] USERID가 필요하다 --> K/R의 파일명으로 쓴다. 향후 DBKEY!
        //      - uid.req, uid.key
        //--------------------------------------------------  
        else if(1==do_req_newcmm) 
        {
            if(!with_mac_args) {
                fprintf(stderr, "No MAC address specified, use --with-mac options.\n");
                return -1;
            }
            if(!with_cn_args) {
                fprintf(stderr, "No Common Name(CN) specified, use --with-cn options.\n");
                return -1;
            }


#if 0 //NEWCMM에서 UID는 자동으로 생성한다. 
            if(!userid_args) {
                fprintf(stderr, "No userid specified, use --userid options.\n");
                return -1;
            }
#endif            
            
            //==================================================
            // 1.  Key Generation
            // 1.1 Generate Device Password with MAC
            //==================================================

            //int err=-1;
            //size_t f_size=-1;            
            //int keylen = 0;  
            {
                //char *user_key_pem = NULL;
                char *tmp=NULL;
                char export1[512];
                
                int keylen = -1;
                //인증서는 아직 없음
                GZPKI_CTX ctx; //contaner for ctx.device_password
                GZPKI_generate_device_password(&ctx, with_mac_args, NULL);
                
                memset(export1, 0, sizeof(export1));
                sprintf(export1, "%s", ctx.device_password);
                
                fprintf(stderr, "Device password \n");
                fprintf(stderr, "- cn : %s\n", with_cn_args);
                fprintf(stderr, "- pwd: %s\n", export1);
                fprintf(stderr, "- mac: %s\n", with_mac_args);

                char req_section[128];
                memset(req_section, 0, sizeof(req_section));

                if(req_section_args) {
                    sprintf(req_section, "%s", req_section_args);
                    fprintf(stdout, "req_section_args: "color_red"%s"color_reset"\n", req_section);
                }
                else {
                    //caname의 req_user를 사용할 수도 있다
                    sprintf(req_section, "%s", "req");
                    fprintf(stdout, "config:DEFAULT_REQ_SECTION: "color_red"%s"color_reset"\n", req_section);
                }

                char *file = CFG_CA_SECTION_VALUE("cmmdb");
                //PREPARING 
                {
                    sqlite3 *db;
                    char *zErrMsg = 0;
                    int rc;
                    
                    rc = sqlite3_open(file, &db);

            
                    if( rc ) {
                        fprintf(stderr, "error: init gzcmm database %s: %s\n", file, sqlite3_errmsg(db));
                        return -1;
                    } 

                    //while ((nf = csvgetline(stream)) != -1) {
                    DECL_STRING(sql, 8192);

                    if(!caname_args)
                        caname_args = CFG_CA_NAME();

                    sprintf(sql, "INSERT INTO reqdb (status, username, deviceinfo, type, caname, extension, cdate, mdate)"
                        " VALUES ('%s', '%s', '%s', '%s', '%s', '%s', DATETIME(\'now\'), DATETIME(\'now\'))"
                        , "preparing", with_cn_args, with_mac_args, "new", caname_args, req_section_args?req_section_args:"");

                    fprintf(stderr,"NEWCMM:SQL: %s\n", sql);

                    rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
                    if( rc != SQLITE_OK ){
                            fprintf(stderr, "error:newcmm:database:request:init:%s\n", zErrMsg);
                            sqlite3_free(zErrMsg);  
                            sqlite3_close(db);
                            return -1;
                    } else {
                        fprintf(stderr, "insert data to request database table success.\n");
                    }

                    sqlite3_close(db);
                    //return 0;
                }

                DECL_STRING(tmp_sql, 1024);
                sprintf(tmp_sql, "SELECT id FROM request WHERE status='preparing' AND username='%s' AND deviceinfo = '%s';"
                    , with_cn_args, with_mac_args);

                IF_VERBOSE fprintf(stderr, "SQL:NEWCMM:GET_ID: %s\n", tmp_sql);

                int nUserid = get_request_userid(file, tmp_sql);
                DECL_STRING(str_uid_tmp, 100);
                sprintf(str_uid_tmp, "%d", nUserid);

                IF_VERBOSE fprintf(stderr, "SQL:NEWCMM:ID: %s\n", str_uid_tmp);
                
                if(!userid_args)
                    userid_args = str_uid_tmp;

                IF_VERBOSE fprintf(stderr, "SQL:NEWCMM:userid_args: %s\n", userid_args);
                
                char keygen_param[128];
                memset(keygen_param, 0, sizeof(keygen_param));
                tmp = NCONF_get_string(gzcms_conf, req_section, "default_curve");
                if(tmp) {
                    sprintf(keygen_param, "%s", tmp);
                    fprintf(stdout, "config:%s:default_curve: "color_yellow_b"%s"color_reset"\n", req_section, keygen_param);
                }
                else {
                    sprintf(keygen_param, "%s", "prime256v1");
                    fprintf(stdout, "config:DEFAULT:default_curve: "color_yellow_b"%s"color_reset"\n", keygen_param);
                }
                
                char default_cipher[128];
                memset(default_cipher, 0, sizeof(default_cipher));
                tmp = NCONF_get_string(gzcms_conf, req_section, "default_cipher");
                
                if(tmp) {
                    IF_VERBOSE fprintf(stderr, "get cipher from %s: %s\n", config_args, tmp);
                    sprintf(default_cipher, "%s", tmp);
                }
                else {
                    IF_VERBOSE fprintf(stderr, "using default cipher AES128\n");
                    sprintf(default_cipher, "%s", "aes128");
                }

                fprintf(stdout, "config:%s:default_cipher: "color_yellow_b"%s"color_reset"\n", req_section, default_cipher);

                char *device_keypem = NULL;

                DECL_STRING(user_keyfile, 256);
                DECL_STRING(user_csrfile, 256);
                DECL_STRING(user_macfile, 256);

                //tmp = NCONF_get_string(gzcms_conf, "req", "keypairs");
                
                tmp = NCONF_get_string(gzcms_conf, req_section, "keypairs");
                sprintf(user_keyfile, "%s/%s.key", tmp, userid_args);
                sprintf(user_csrfile, "%s/%s.req", tmp, userid_args);
                sprintf(user_macfile, "%s.mac", userid_args);

                fprintf(stderr, "USER KEY FILENAME: "color_red_b"%s"color_reset"\n", user_keyfile);
                fprintf(stderr, "USER CSR FILENAME: "color_red_b"%s"color_reset"\n", user_csrfile);
                fprintf(stderr, "USER MAC FILENAME: "color_red_b"%s"color_reset"\n", user_macfile);

                //MAC 파일도 저장한다. 
                add_file_to_dirctory(tmp, user_macfile, with_mac_args, "w");

                device_keypem = GZPKI_generate_PRIKEY(keygen_param, export1,  default_cipher, &keylen, user_keyfile);
                fprintf(stderr, "CAKEY(PEM): %s\n", device_keypem);
                fprintf(stdout, color_yellow_b"Generating User Certificate Signing Request ..."color_reset"\n");     

                char *user_csr_pem = NULL;

                DECL_STRING(dn_str, 256);

                char *dn_section = NULL;
                dn_section = NCONF_get_string(gzcms_conf, req_section, "distinguished_name");
                IF_VERBOSE fprintf(stderr, "%s:dn_section = %s\n", req_section, dn_section);
                char *prefix_dn = NULL;
                prefix_dn = NCONF_get_string(gzcms_conf, dn_section, "prefix_dn");
                IF_VERBOSE fprintf(stderr, "%s:prefix = %s\n", dn_section, prefix_dn);

     
                user_csr_pem = GZPKI_generate_CSR(/*device_keypem*/NULL, user_keyfile/*NULL*/, export1, config_args, NULL/*dn_str*/, user_csrfile/*NULL*/, 
                NULL, 
                NULL, NULL, NULL, NULL, NULL, NULL, with_cn_args, with_email_args, FORMAT_MEM );

                IF_VERBOSE fprintf(stderr, "USER.CSR.PEM:\n%s\n", (char *)user_csr_pem);
                //fprintf(stderr, "USER.CSR(CONTENTs): "color_green"%s"color_reset"\n", dump_file_content(user_csr_pem, &err, &f_size));

                ///database update
                if(1)
                {
                    sqlite3 *db;
                    char *zErrMsg = 0;
                    int rc;
                    //int num = 0;
                    //int r = 0;

                    char *file = CFG_CA_SECTION_VALUE("cmmdb");
                    rc = sqlite3_open(file, &db);
            
                    if( rc ) {
                        fprintf(stderr, "error: init gzcmm database %s: %s\n", file, sqlite3_errmsg(db));
                        return -1;
                    } 

                    DECL_STRING(sql, 128);

                    if(!caname_args)
                        caname_args = CFG_CA_NAME();

                    sprintf(sql, "UPDATE request SET status = 'pending' WHERE id = %s", userid_args);

                    fprintf(stderr,"NEWCMM:SQL:UPDATE: %s\n", sql);

                    rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
                    if( rc != SQLITE_OK ){
                            fprintf(stderr, "error:newcmm:database:request:init:%s\n", zErrMsg);
                            sqlite3_free(zErrMsg);  
                            sqlite3_close(db);
                            return -1;
                    } else {
                        fprintf(stderr, "insert data to request database table success.\n");
                    }

                    sqlite3_close(db);
                    //return 0;

                }
            }

            if(opt_return == 1)
                fprintf(stdout, "success.%s\n", return_args );
            
            return 0;

        }
        //do_req_newcmm과 동일한 로직 -> GZCMM에서는 이 로직을 사용한다. 
        //userid는 DB(request) ID
        //userid_args에 해당하는 pending DB 필드를 fetch, KEYPAIR를 생성하고 stat은 approval로 변경
        

        else if(1==do_req_new) {
        }
    }

    if(do_keypass == 1) {
        
        IF_VERBOSE fprintf(stderr, "keypass parameter: "color_yellow_b"%s"color_reset"\n", (char *)keypass_args);
        
        IF_VERBOSE {
            if(1==use_keypass_db)
                fprintf(stderr, "default db: "color_yellow_b"%s"color_reset"\n", (char *)keydb_file);
            else
                fprintf(stderr, "default db: "color_yellow_b"%s"color_reset"\n", (char *)DEFAULT_KEYPASS_DB);
        }
                    
        char *p = NULL;


        //master password 변경
        if(1==do_keypass_password) {

            char *master_pwd_new = NULL;
            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "PASSWORD CHANGE");
            master_pwd_in = GZPKI_get_master_password_one(keydb_file, PROMPT_MASTER_PWD);

            //--------------------------------------------------
            //마스터 패스워드가 맞는지 확인
            //--------------------------------------------------
            r = GZPKI_keypass_verify_master_pass(keydb_file, master_pwd_in);
            if(r != 0) {
                IF_VERBOSE printf("user    master hash: ["color_yellow_b"%s"color_reset"]\n", master_pwd_hash);
                IF_VERBOSE printf("keypass master hash: ["color_yellow_b"%s"color_reset"]\n", g_digest);
                printf("error: invalid master password for %s\n", keydb_file);
                return -1;
            }

            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "GET MASTER SECRET");
            master_pwd_new = GZPKI_get_master_password(keydb_file, PROMPT_MEW_MASTER_PWD);
            
            IF_VERBOSE fprintf(stderr, "master pwd:     %s\n", master_pwd_in);
            IF_VERBOSE fprintf(stderr, "master pwd new: %s\n", master_pwd_new);

            //--------------------------------------------------
            //master password 먼저 업데이트
            //--------------------------------------------------
            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "GET 'OLD' MASTER SECRET");    
            old_master_secret = GZPKI_keypass_get_master_secret(keydb_file, master_pwd_in);
            IF_VERBOSE fprintf(stderr, "old master secret: %s\n", old_master_secret);


            //--------------------------------------------------
            //master password 먼저 업데이트
            //--------------------------------------------------
            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "GENERATE/UPDATE 'NEW' MASTER SECRET");   
            GZPKI_keypass_update_password(keydb_file, -1, NULL, NULL, master_pwd_new, DEFAULT_KEYPASS_MASTER_SEED_LEN, KEY_TYPE_MASTER, 1);

            new_master_secret = (unsigned char *)GZPKI_keypass_get_master_secret(keydb_file, master_pwd_new);
            
            if (new_master_secret) {
                IF_VERBOSE fprintf(stderr, "new master secret: %s\n", new_master_secret);
            }
            else {
                fprintf(stderr, "error:fail to generate new master secret:null\n");
                return -1;
            }
            printf("NEW: %s\n", (char *)new_master_secret);   

            //--------------------------------------------------
            //password가 아닌 SECRET을 이용한다. 
            //--------------------------------------------------
            GZPKI_keypass_update_with_new_master(keydb_file, old_master_secret, new_master_secret );

            printf("GZPKI_keypass_update_with_new_master: OK\n");   

            return 0;

        }
        else if(1==do_keypass_new) 
        {
            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "NEW ENTRY");   
            IF_VERBOSE fprintf(stderr, "    FILE: %s\n", keydb_file);   
            IF_VERBOSE fprintf(stderr, "    KID : %s\n", keyid_args);   
            IF_VERBOSE fprintf(stderr, "    PWD : %s\n", master_pwd_in);   

            if(0!=verify_master_password(keydb_file, 1 )) {
                return -1;
            }

            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "GENERATE NEW PASSWORD");
            char *master_pass = master_pwd_in;
            p = (char *)GZPKI_keypass_generate_password(keydb_file, keyid_args, master_pass, 1024, keytype);
            if(p==NULL) {
                fprintf(stderr, "error:fail to generate password for %s\n", keyid_args);
            }
            IF_VERBOSE fprintf(stderr, DEBUG_TAG"keypass = [%s]\n\n", (char *)p);

            if(p)
                free(p);

            return 0;
        }
        else if(1==do_keypass_add) 
        {
            if(keytype_args == NULL || keyresource_args == NULL|| keyid_args == NULL) {
                fprintf(stderr, "error:no key type or resource specified.\n");
                return -1;
            }

            //key id가 존재하는가?
            int cnt = GZPKI_keypass_get_entry_count(keydb_file, keyid_args, KEY_STATUS_VALID);
            if(cnt < 1) {
                fprintf(stderr, "error:entry %s not exists.\n", keyid_args);
                return -1;
            }
            IF_VERBOSE fprintf(stderr, "%d entry exists.\n", cnt);

            if(opt_resourcein==1 && opt_resource ==1) {
                fprintf(stderr, "error:--resource and --resourcein option is exclusive.\n");
                return -1;
            }
            
            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "READ RESOURCE");   
            IF_VERBOSE fprintf(stderr, "opt_resource: %d\n", opt_resource);   
            IF_VERBOSE fprintf(stderr, "opt_resourcein: %d\n", opt_resourcein);   
            char *res = NULL;
            if(opt_resource == 1) {
                res = keyresource_args;
                IF_VERBOSE fprintf(stderr, "RES: %s\n", res);   
            }
            else if(opt_resourcein == 1) {
                int err;
                size_t f_size = -1;
                //char * f_data = NULL;

                //res = dump_file_content(keyresource_args);
                res = dump_file_content(keyresource_args, &err, &f_size);

                if (err) {
                    if(err==FILE_NOT_EXIST) {
                        fprintf(stderr, "error: file not exists, %s\n", keyresource_args);
                    }   
                    else if(err==FILE_TO_LARGE) {
                        fprintf(stderr, "error: file too large, %s\n", keyresource_args);
                    }
                    else if(err==FILE_READ_ERROR) {
                        fprintf(stderr, "error: file read error, %s\n", keyresource_args);
                    }
                    else {
                        fprintf(stderr, "error: unknown error, %s\n", keyresource_args);
                    }
                    if(res) free(res);
                    return -1;
                }
                
                
                IF_VERBOSE fprintf(stderr, "-----BEGIN DATA------\n"color_blue"%s"color_reset"\n-----END DATA-----\n", res);  
                IF_VERBOSE fprintf(stderr, "dump(2) file content: read(%ld)\n", f_size);
            }

            if(0!=verify_master_password(keydb_file, 1 )) {
                fprintf(stderr, "error:--resource and --resourcein option is exclusive.\n");
                return -1;
            }

            int ret = 0;
            ret =  GZPKI_keypass_add_data(keydb_file, keyid_args, keytype, res, NULL, NULL);
            if(ret != 0) {
                fprintf(stderr, "error:keypass:fail to add data on '%s'.\n", keyid_args);
                return -1;
            }
            //int ret = GZPKI_keypass_add_data(keydb_file, keyid_args, keytype, res);
            


            return 0;
        }
        else if(1==do_keypass_rename) {
            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "RENAME ENTRY");   
            IF_VERBOSE fprintf(stderr, "KEY ID  : %s\n", keyid_args);   
            IF_VERBOSE fprintf(stderr, "NEW ID  : %s\n", newkeyid_args);   
            IF_VERBOSE fprintf(stderr, "KEY STAT: %s\n", keystat_args);   

            if(keyid_args==NULL || newkeyid_args==NULL)
            {
                fprintf(stderr, "error: invalid key id or  new key id\n");   
                return -1;
            }
            if(keystat_args == NULL) 
                keystat_args = KEY_STATUS_VALID;
            
            if(0!=verify_master_password(keydb_file, 1 )) {
                return -1;
            }
            GZPKI_keypass_rename(keydb_file, keyid_args, keystat_args, newkeyid_args);

            return 0;
        }

        else if(1==do_keypass_init) {
            
            if(is_file_exists(keydb_file)) {
                printf("error: file already exists: %s\n", keydb_file);
                exit(0);
            }

            //MASTER HASH 생성 전이므로 digest verify는 하지 않는다. 
            if(0!=verify_master_password(keydb_file, 0)) {
                return -1;
            }

            if(0 != GZPKI_keypass_init(keydb_file, master_pwd_in)) {
                fprintf(stderr, "error: fail to create keypass database: %s\n", keydb_file);
            }
            
            return 0;
        }
        else if(1==do_keypass_revoke || 1==do_keypass_delete) {
            if(keyid_args == NULL) {
                fprintf(stderr, "error: no key id arguments.\n");
                return -1;
            }

            if(0!=verify_master_password(keydb_file, 1)) {
                return -1;
            }

            if(1==do_keypass_revoke) {
                r = GZPKI_keypass_revoke(keydb_file, keyid_args, keypass_force_update);
            }
            else if(1==do_keypass_delete) {
                r = GZPKI_keypass_delete(keydb_file, keyid_args, keypass_force_update);
            }

            if(r!=0) {
                fprintf(stderr, "error: fail to change status of %s\n", keyid_args);
                return -1;
            }

            return 0;
        }
        else if(1==do_keypass_update) 
        {
            if(0!=verify_master_password(keydb_file, 1)) {
                return -1;
            }

            r = GZPKI_keypass_update(keydb_file);
            if(r!=0) {
                fprintf(stderr, "error: fail to update database\n");
                return -1;
            }

            return 0;
        }
        else if(1==do_keypass_truncate) {
            
            if(0!=verify_master_password(keydb_file, 1)) {
                return -1;
            }
            
            r = GZPKI_keypass_truncate(keydb_file);
            if(r!=0) {
                fprintf(stderr, "error: fail to truncate database: %s\n", keydb_file);
                return -1;
            }

            return 0;
        }
        //new/add와 동일함
        else if(1==do_keypass_list) {
            GZPKI_keypass_list(keydb_file, 1);
        }
        else if(1==do_keypass_list2) {
            GZPKI_keypass_list(keydb_file, 0);
        }
        else if(1==do_keypass_export) {
            char *p = NULL;
            char *master_secret = NULL;
            char *master_pwd_in = NULL;

            master_pwd_in = GZPKI_get_master_password(keydb_file,NULL);

            master_secret = (char *)GZPKI_keypass_get_master_secret(keydb_file, master_pwd_in);

            if(master_secret) {
                p = GZPKI_keypass_export(keydb_file,master_secret, keyid_args);
                if(master_secret) free(master_secret);
            }

            if(p) {
                IF_VERBOSE fprintf(stdout, "NAME:%s\n", keyid_args);
                IF_VERBOSE fprintf(stdout, "EXPORT:%s\n", p);
                fprintf(stdout, "%s:%s\n", keyid_args, p);
                
            }
            free(p);
            
        }

        operation = GZPKI_KEYPASS;

        exit(0);
    } //DO_KEYPASS

#endif // _NO_CA_

    //--------------------------------------------------
    //check parameter
    //--------------------------------------------------
    if(operation == SMIME_ENCRYPT) {
        if(intype == FORMAT_FILE && !infile) {
            printf("error: no input file.\n");
            exit(0);
        }
        if(verbose == 1) printf("debug: infile(%s) encrypted with certificate(%s) to outfile(%s)\n", infile, cert_file, outfile);
    }

    if(no_signer_cert_verify == 1)
        GZPKI_add_flags(&ctx, CMS_NO_SIGNER_CERT_VERIFY );

#if 1
    if(operation == SMIME_ENCRYPT || operation == SMIME_DECRYPT) {
        
        if(opt_cli_config==1) {
            char *default_section = NULL;
            default_section = NCONF_get_string(gzcms_conf, NULL, "default_section");
        
            char *encrypt_type = NULL;
            encrypt_type = NCONF_get_string(gzcms_conf, default_section, "encrypt_type");

            char *decrypt_type = NULL;
            decrypt_type = NCONF_get_string(gzcms_conf, default_section, "encrypt_type");

            if(encrypt_type || operation == SMIME_ENCRYPT) {
                if(!strcmp(encrypt_type, "ECCP2") || !strcmp(decrypt_type, "eccp2")) {
                    IF_VERBOSE fprintf(stderr, "operation(SMIME_ENCRYPT:%d) --> [ECCP2_ENCRYPT]\n", SMIME_ENCRYPT);
                    operation = ECCP2_ENCRYPT;
                    IF_VERBOSE fprintf(stderr, "operation changed: %d\n", operation);
                }   
            }
            else if(decrypt_type || operation == SMIME_DECRYPT) {
                IF_VERBOSE printf("operation: %d, decrypt_type=%s\n", operation, decrypt_type);
                //make_uppercase(decrypt_type);
                IF_VERBOSE printf("encrypt_type=%s\n", decrypt_type);
                if(!strcmp(decrypt_type, "ECCP2") || !strcmp(decrypt_type, "eccp2")) {
                    IF_VERBOSE printf("operation(SMIME_DECRYPT:%d) --> [ECCP2_DECRYPT]\n", SMIME_DECRYPT);
                    operation = ECCP2_DECRYPT;
                    IF_VERBOSE printf("operation changed: %d\n", operation);
                }
            }
        }
    }        
#endif
    

    //--------------------------------------------------
    //operation과 무관한 services
    //--------------------------------------------------
    if(operation == SMIME_CMSOUT && do_cmsinfo == 1)
    {
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"operation: CMSOUT/CMSINFO\n");
        //todo: 다른 informat도 허용
        informat = FORMAT_PEM;
        
        GZPKI_set_operation(&ctx, SMIME_CMSOUT);
        GZPKI_set_infile(&ctx, infile, NULL, 0, informat);
        GZPKI_set_outfile(&ctx, NULL, informat);
        GZPKI_set_noout(&ctx, 1);
        GZPKI_set_print(&ctx, 1);

        r = GZPKI_do_CMS(&ctx);

        if(CMS_RET_OK == r) {
            if(do_cmstype==1) {
                printf("ContentType: %s", GZPKI_get_mem(&ctx));
            }
            else {
                printf("%s", GZPKI_get_mem(&ctx));
                printf("\n");
            }
        }
        else {
            fprintf(stderr, "error: fail to get cms:file=[%s]\n", infile);
        }
    }
    //envelopedData 생성
    else if(operation == SMIME_ENCRYPT) {
        int cms_opt = 0;
        char infile_b64[256];
        char *tmpfilename = tempnam("./", "tmp__");
        memset(infile_b64, 0, sizeof(infile_b64));
        if(base64_in == 1) 
        {
            if(cms_opt <= 0) 
                cms_opt = ECCP2_BASE64_IN;
            else 
                cms_opt *= ECCP2_BASE64_IN;
            
            sprintf(infile_b64, "%s", tmpfilename);
            GZPKI_base64_endecode_file(infile, infile_b64, GZPKI_DECRYPT);
        }
        else {
            sprintf(infile_b64, "%s", infile);
        }

        if(outfile == NULL) {
            gzpki_cms_encrypt_file2buffer(config_args, infile_b64, &outbuffer, &outbuffer_len, cert_file, cipher_algs, cms_opt);
            fprintf(stdout, "%s\n", outbuffer);
        }
        else {
            gzpki_cms_encrypt_file(config_args, infile_b64, outfile, cert_file, cipher_algs, cms_opt);
        }

        //TODO: remove tempfile
#if 0
        if(base64_in == 1)  {
            int nResult = remove( infile_b64 );

	        if( nResult == 0 ) {
		        printf( "success to remove: %s\n", infile_b64 );
	        }
	        else if( nResult == -1 ){
		        printf( "fail to remove: %s\n", infile_b64 );
	        }
        }
#endif
         
#if 0        
        if(base64_out == 1) {
            if(cms_opt <= 0) cms_opt = ECCP2_BASE64_OUT;
            else cms_opt *= ECCP2_BASE64_OUT;
            IF_VERBOSE printf("operation CMS_ENCRYPT(base64_out=1): cms_opt=%d\n", cms_opt);
        }
        return  gzpki_cms_encrypt_file(config_args, infile, outfile, cert_file, cipher_algs,cms_opt);
#endif        
    }
    //envelopedData 복호화
    else if(operation == SMIME_DECRYPT) {
        int cms_opt = 0;
        if(base64_in == 1) {
            if(cms_opt <= 0) cms_opt = ECCP2_BASE64_IN;
            else cms_opt *= ECCP2_BASE64_IN;
            IF_VERBOSE printf("operation CMS_DECRYPT(base64_in=1): cms_opt=%d\n", cms_opt);
        }
        
        if(base64_out == 1) {
            if(cms_opt <= 0) cms_opt = ECCP2_BASE64_OUT;
            else cms_opt *= ECCP2_BASE64_OUT;
            IF_VERBOSE printf("operation CMS_ENCRYPT(base64_out=1): cms_opt=%d\n", cms_opt);
        }
        
        
        char outfile_b64[256];
        memset(outfile_b64, 0, sizeof(outfile_b64));

        if(outfile == NULL) {
            gzpki_cms_decrypt_file2buffer(config_args, infile, &outbuffer, &outbuffer_len, key_file, passin, cms_opt);
            if(base64_out == 1 ) {
                const char *message = outbuffer;
                char *buffer = NULL;
                GZPKI_base64_encode(message, &buffer); //Encodes a string to base64
                fprintf(stdout, "%s\n", buffer);
            } else {
                fprintf(stdout, "%s\n", outbuffer);
            }
        }
        else {
            gzpki_cms_decrypt_file(config_args, infile, outfile, key_file, passin ,cms_opt);
        
            if(base64_out == 1 ) {
                char *tmpfilename = tempnam("./", "tmp__");
                sprintf(outfile_b64, "%s", tmpfilename);
                GZPKI_base64_endecode_file(outfile, outfile_b64, GZPKI_ENCRYPT);

                char str[1024];
                FILE * file;
                file = fopen( outfile_b64 , "r");
                if (file) {
                    while (fscanf(file, "%s", str)!=EOF)
                        printf("%s",str);
                    fclose(file);
                }

                //TODO: remove tempfile
                #if 0
            
                    int nResult = remove( tmpfilename );

	                if( nResult == 0 ) {
		                printf( "success to remove: %s\n", tmpfilename );
	                }
	                else if( nResult == -1 ){
		                printf( "fail to remove: %s\n", tmpfilename );
        	        }

                #endif
            }
        }
            
    }
    //SignedData 생성
    else if(operation == SMIME_SIGN) {
        return gzpki_cms_sign_file(config_args, infile, outfile, cert_file, key_file, passin, digest_algs, cms_opt);
    }
    //서명검증
    else if(operation == SMIME_VERIFY) {
        return gzpki_cms_verify_file (config_args, infile, usercert_file, cacert_file, cms_opt);
    }
    //ECC P2 암호화
    else if(operation == ECCP2_ENCRYPT) {
        //return gzpki_eccp2_encrypt_file(config_args, infile, outfile, cert_file, NULL, 0);
        int opt = ECCP2_SECRET_FROM_CERTFILE;
        IF_VERBOSE printf("operation ECCP2_ENCRYPT: opt=0x%x, base64_in=%d, base64_out=%d\n", opt, base64_in, base64_out);
        if(base64_in == 1) {
            
            opt *= ECCP2_BASE64_IN;
            IF_VERBOSE printf("operation ECCP2_ENCRYPT(base64_in=1): opt=%d\n", opt);
        }
        
        if(base64_out == 1) {
            opt *= ECCP2_BASE64_OUT;
            IF_VERBOSE printf("operation ECCP2_ENCRYPT(base64_out=1): opt=%d\n", opt);
        }
        return gzpki_eccp2_encrypt_file(config_args, infile, outfile, cert_file, NULL, opt);
    }
    else if(operation == ECCP2_DECRYPT) {
        int opt = ECCP2_SECRET_FROM_CERTFILE;
        if(base64_in == 1) {
            opt *= ECCP2_BASE64_IN;
        }
        
        if(base64_out == 1) {
            opt *= ECCP2_BASE64_OUT;
        }
        r = gzpki_eccp2_decrypt_file(config_args, infile, outfile, cert_file, key_file, passin, opt);
    }
    //ECC P2 복호화


end:
    
    //if(INI)
	//	iniparser_freedict(INI);
    GZPKI_free_ctx(&ctx);

    return 0;
}


