#ifndef _GZPKI_KEYPASS_H_
#define _GZPKI_KEYPASS_H_


# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include <assert.h>

# include "gzpki_types.h"
# include "gzpki_common.h"

#if 1
    typedef struct __keypass_item {
        int id;
        char name[128];
        char secret[128];
        char cdate[32];
        char digest[32];
        int type;
        char status[4];
    } KEYPASS_ENRTY;
#endif

#define KEY_TYPE_ANY            0
#define KEY_TYPE_PRIVATE_KEY    1
#define KEY_TYPE_SECRET_KEY     2
#define KEY_TYPE_MASTER         3
#define KEY_TYPE_SIGNIN         4

#define KEY_TYPE_S_ANY            "any"
#define KEY_TYPE_S_PRIVATE_KEY    "pkey"
#define KEY_TYPE_S_SECRET_KEY     "skey"
#define KEY_TYPE_S_MASTER         "master"
#define KEY_TYPE_S_SIGNIN         "signin"

#define DEFAULT_KEYPASS_SEED_LEN            1024
#define DEFAULT_KEYPASS_MASTER_SEED_LEN     2048
#define DEFAULT_KEYPASS_MASTER_NAME         "master"

#define KEY_STATUS_VALID        "V"
#define KEY_STATUS_REVOKED      "R"
#define KEY_STATUS_EXPIRED      "E"
#define KEY_STATUS_DELETED      "D"

#define KEY_MASTER_PWD_LEN_MIN   8
#define KEY_MASTER_PWD_LEN_MAX   64

#define KEYPASS_TABLE           "keydb"   

#define KEYPASS_MASTER_PWD_VERIFIED 1000


//TODO: char *로 변경, 사용 시 free/malloc
char g_secret[1024];
char g_digest[1024];


#define PROMPT_MASTER_PWD "Enter master password:"
#define PROMPT_MEW_MASTER_PWD "Enter new master password:"
#define PROMPT_OLD_MASTER_PWD "Enter old master password:"


unsigned char *GZPKI_keypass_generate_password(char *dbfile, char *id, char *master_pass, int nbytes, int type);

//check master password correct
int GZPKI_keypass_verify_master_pass(char *keydb_file, char *master_pass_in);

int GZPKI_keypass_init(char *dbfile, char *master_pwd_in);
int GZPKI_keypass_change_status(char *keydb_file, char *keyid, int force_update, char *old_state, char *new_status);
int GZPKI_keypass_revoke(char *keydb_file, char *keyid, int force_update);
int GZPKI_keypass_delete(char *keydb_file, char *keyid, int force_update);
int GZPKI_keypass_update(char *keydb_file);
int GZPKI_keypass_truncate(char *keydb_file);
int GZPKI_keypass_list(char *dbfile, int form);
int GZPKI_get_entry_all(char *file, char *query);
unsigned char *GZPKI_password_decrypt(unsigned char *secret, int secret_len, char *master_pass);
unsigned char *GZPKI_password_encrypt(unsigned char *secret, int secret_len, char *master_pass);
int GZPKI_keypass_rename(char *dbfile, char *name, char *status, char *new_name);
int GZPKI_keypass_add_data(char *keydb_file, char *keyid, int keytype, char *data, char *pkid, char *loginid);
int GZPKI_keypass_get_secret(char *dbfile, char *name, char *status);
unsigned char *GZPKI_keypass_get_master_secret(char *dbfile, char *master_pass);
char *GZPKI_keypass_export(char *keydb_file, char* master, char* keyid);

unsigned char *GZPKI_keypass_update_password(char *dbfile, int real_id, char *secret, char *old_pass, char *new_pass, int nbytes, int type, int newgen);
int GZPKI_keypass_update_with_new_master(char *file, unsigned char *old_pass, unsigned char *new_pass );
int GZPKI_keypass_get_entry_count(char *file, char *name, char *status);




#endif