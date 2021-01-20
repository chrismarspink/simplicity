

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
#include "gzpki_keypass.h"
#include "gzpki_enc.h"


#include <sqlite3.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      IF_VERBOSE printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}



int GZPKI_get_entry_count(char *file, char *type) {
    int rc;
    char query[128];
    memset(query, 0, 128);
    if(type == NULL) {
        sprintf(query, "SELECT count(*) FROM %s WHERE name IS NOT 'master';", KEYPASS_TABLE);
    }
    else {
        sprintf(query, "SELECT count(*) FROM %s WHERE name IS NOT 'master' AND status = '%s';", KEYPASS_TABLE, type);
    }

    IF_VERBOSE printf("get cnt SQL: %s\n", query);

    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int rowcount;

    rc = sqlite3_open(file, &db);
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    //printf("prepare status for count : %d\n", rc);
    if (rc != SQLITE_OK) {
        // error handling -> statement not prepared
        fprintf(stderr,"error:fail to open database: %s\n", file);
        return -1;
    }
    rc = sqlite3_step(stmt);
    
    //
    //rowcount = sqlite3_column_int(stmt, 0);
    //rc = sqlite3_step(stmt);

    
    int colCount = sqlite3_column_count(stmt);

    const char * columnName = sqlite3_column_name(stmt, 0);
    rowcount = sqlite3_column_int(stmt, 0);

    IF_VERBOSE fprintf(stderr, "get_entry_cnt: %s: %d\n",columnName, rowcount);

    rc = sqlite3_finalize(stmt);
    rc = sqlite3_close(db);

    return rowcount;
}


int GZPKI_get_entry_all(char *file, char *query) {
    int rc;
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int rowcount;

    rc = sqlite3_open(file, &db);
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        // error handling -> statement not prepared
        fprintf(stderr,"error:fail to open database: %s\n", file);
        return -1;
    }
    rc = sqlite3_step(stmt);
    
    int rowCount = 0;
    while (rc != SQLITE_DONE && rc != SQLITE_OK) {
        rowCount++; 
        printf("rowCount: %d\n", rowCount);
        
        int colCount = sqlite3_column_count(stmt);
        printf("  colCount: %d\n", colCount);

        for (int colIndex = 0; colIndex < colCount; colIndex++) {
            int type = sqlite3_column_type(stmt, colIndex);
            
            //printf("  Type of colIndex:"color_yellow_b"%d"color_reset" is "color_cyan_b"%d"color_reset"\n", colIndex, type);

            const char * columnName = sqlite3_column_name(stmt, colIndex);
            if (type == SQLITE_INTEGER)
            {
                int valInt = sqlite3_column_int(stmt, colIndex);
                printf("    columnName = %s, Integer val = %d\n", columnName, valInt);
            }
            else if (type == SQLITE_FLOAT)
            {
                double valDouble = sqlite3_column_double(stmt, colIndex);
                printf("    columnName = %s,Double val = %f\n", columnName, valDouble);
            }
            else if (type == SQLITE_TEXT)
            {
                const unsigned char * valChar = NULL;
                valChar = sqlite3_column_text(stmt, colIndex);
                printf("    columnName = %s,Text val = %s\n", columnName, valChar);
                //if(valChar) free(valChar);
            }
            else if (type == SQLITE_BLOB)
            {
                printf("    columnName = %s,BLOB\n", columnName);
            }
            else if (type == SQLITE_NULL)
            {
                printf("    columnName = %s,NULL\n", columnName);
            }
        }
        printf("Line %d, rowCount = %d\n", rowCount, colCount);

        rc = sqlite3_step(stmt);
    }
    
    rc = sqlite3_finalize(stmt);

    rc = sqlite3_close(db);
    return rc;

}



//--------------------------------------------------
// key pass DB file generate.
//--------------------------------------------------
int GZPKI_keypass_init(char *dbfile, char *master_pwd_in)
{
	sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int r = 0;

    //set filename
    char *filename = NULL;
    if(dbfile == NULL) 
        filename = "keypass.db";
    else    
        filename = dbfile;

    rc = sqlite3_open(filename, &db);
   	
    if( rc ) {
    	fprintf(stderr, "error: init database %s: %s\n", filename, sqlite3_errmsg(db));
      	return -1;
   	} 
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"Open database(%s) successfully.\n", filename);
   	
    //1. KEY_TYPE_SECRET_KEY
    //      단순 password(eg, 파일 암호화용) --> url에 파일 위치 기술
    //      /etc/passwd를 암호화하는데 사용하는 키는 url : /etc/passwd가 된다.
    //2. KEY_TYPE_SIGNIN
    //      로그인 password(eg, 사이트 아이디) -
    //      미지원
    //       loginid/secret + url에 로그인 주소
    //3. KEY_TYPE_PRIVATE_KEY
    //      개인키 password(eg, 파일 암호화용) 
    //      개인키 암호화 용
    //      이름으로 식별하거나 PKID로 식별 --> match되는 공개키나 인증서를 입력하면 개인키 passphrase를 검색
    //4. KEY_TYPE_MASTER
    //      마스터 secret용 passphrase

	char *sql = "CREATE TABLE keydb ("  \
        "id      INTEGER    PRIMARY KEY   AUTOINCREMENT," \
        "name    CHAR(128)  NOT NULL," \
        "secret  TEXT       NOT NULL," \
        "status  CHAR(16)   NOT NULL," \
        "cdate   DATETIME," \
        "mdate   DATETIME," \
        "digest  TEXT    ," \
        "type    INTEGER ," \
        "data    TEXT    ," \
        "pkid    TEXT    ," \
        "loginid TEXT    ," \
        "UNIQUE(name, status)  );";


	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:init:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  
        r = -1;	
        goto end;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"keypass table created successfully\n");
   	}

    //--------------------------------------------------
    // 3. master secret을 암호화하여 저장
    //--------------------------------------------------
    char *p = NULL; //sha256 hash string
    p = GZPKI_keypass_generate_password(filename, DEFAULT_KEYPASS_MASTER_NAME, master_pwd_in, DEFAULT_KEYPASS_MASTER_SEED_LEN, KEY_TYPE_MASTER);
    if(!p) {
        r = -1;
        goto end;
    }
    IF_VERBOSE printf("KEY_TYPE_MASTER: keypass = [%s]\n\n", (char *)p);

end:
    if(p != NULL) free(p);
   	sqlite3_close(db);
	return r;
}


#define LIST_FMT_HDR "%4s | %22s | %19s | %19s | %4s | %4s | %s\n"
#define LIST_FMT     "%4s | "color_yellow_b"%22s"color_reset" | %19s | %19s | %4s | %4s | %s...\n"
int listCallback(void *pArg, int argc, char **argv, char **columnNames)
{
    int i;
    
    char id[16];
    char name[32];
    char cdate[64];
    char mdate[64];
    char stat[16];
    char type[16];
    char secret[128];

    memset(id, 0, sizeof(id));
    memset(name, 0, sizeof(name));
    memset(cdate, 0, sizeof(cdate));
    memset(mdate, 0, sizeof(mdate));
    memset(stat, 0, sizeof(stat));
    memset(type, 0, sizeof(type));
    memset(secret, 0, sizeof(secret));

    for (i = 0; i < argc; i++)
    {
        //printf("argv[%d, %s] = %s\n", i, columnNames[i], argv[i]);
        if(i==0) {
            sprintf(id, "%s", argv[i]);
            //printf("id: %s\n", id);
        }
        if(i==1) {
            sprintf(name, "%s", argv[i]);
            //printf("name : %s\n", name);
        }
        if(i==2) {
            sprintf(cdate, "%s", argv[i]);
            //printf("validity: %s\n", validity);
        }
        if(i==3) {
            sprintf(mdate, "%s", argv[i]==NULL?"null":argv[i]);
            //printf("validity: %s\n", validity);
        }
        if(i==4) {
            sprintf(stat, "%s", argv[i]);
            //printf("stat: %s\n", stat);
        }
        if(i==5) {
            sprintf(type, "%s", argv[i]);
            //printf("type: %s\n", type);
        }
        if(i==6) {
            //snprintf(secret, 32, "%s", argv[i]);
            snprintf(secret, 32, "%s", argv[i]);
            //printf("secret: %s\n", secret);
        }

        //printf("= name:%s, %s\n", i, columnNames[i], argv[i]);
    }
    
    printf(LIST_FMT, id, name, cdate, mdate, stat, type, secret);
    //printf("\n");
    //printf("--------------------------------------------------------------------------------\n");
    return 0;
}



int listCallback2(void *pArg, int argc, char **argv, char **columnNames)
{
    int i;
    char temp[128];

      
    for (i = 0; i < argc; i++)
    {
        //int colCount = sqlite3_column_count(stmt);

        if(0==strcmp(columnNames[i], "secret") && argv[i]!=NULL) {
            memset(temp, 0, 128);
            sprintf(temp, "%s", argv[i]);
            
            int len =  strlen(argv[i])-1;
            if(temp[len] == '\n')
                temp[len] = 0;

            printf("[%04d] %-8s : %s\n", i, columnNames[i], temp);

        }
        else
            printf("[%04d] %-8s : %s\n", i, columnNames[i], argv[i]==NULL?"NULL":argv[i]);
        
    }
    printf(color_yellow_b"----------------------------------------------------------------------------------"color_reset"\n");
    
    return 0;
}



int GZPKI_keypass_list(char *dbfile, int form)
{
	sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;

    char *filename = dbfile;

    //파일이 없으면 오류 return 
    if(!is_file_exists(dbfile)) {
        fprintf(stderr, "no database file: %s\n", dbfile);
        return 0;
    }
    
    rc = sqlite3_open(filename, &db);
   	
    if( rc ) {
    	fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(db));
      	return -1;;
   	} else {
    	IF_VERBOSE fprintf(stderr, "keypass database open successfully.\n");
   	}

	//char *sql = "SELECT id, name, secret, status, validity, type FROM keydb";
    char *sql = "SELECT id, name, cdate, mdate, status, type, secret, digest, data, pkid, loginid FROM keydb";

    if(form==1)
    {
        printf("----------------------------------------------------------------------------------------------------------------------------\n");
        printf(LIST_FMT_HDR, "NO", "PASSID", "CDATE", "MDATE", "STAT", "TYPE", "SECRET(32)");
        printf("----------------------------------------------------------------------------------------------------------------------------\n");

	    rc = sqlite3_exec(db, sql, listCallback, 0, &zErrMsg);

        printf("----------------------------------------------------------------------------------------------------------------------------\n");
        printf("STAT("color_green_b"V"color_reset"alid, "color_red_b"R"color_reset"evoked, "color_red"E"color_reset"xpired), TYPE("color_green_b"3"color_reset":MASTER, 2:SECRET, 1:PRIKEY, 0:ANY)\n");
    }
    else {
        printf(color_yellow_b"----------------------------------------------------------------------------------"color_reset"\n");
        printf("["color_yellow_b"%-4s"color_reset"] "color_yellow_b"%-8s"color_reset" : "color_yellow_b"%-11s"color_reset"\n", "Col.", "Name", "Value");
        printf(color_yellow_b"----------------------------------------------------------------------------------"color_reset"\n");

        rc = sqlite3_exec(db, sql, listCallback2, 0, &zErrMsg);
    }
    
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  	
   	} 
    else {
    	IF_VERBOSE  fprintf(stdout, "keypass:list successfully\n");
   	}

   	sqlite3_close(db);
	return 0;
}

int GZPKI_keypass_verify_master_pass(char *keydb_file, char *master_pass_in) {
    int r = 0;
    char *master_pwd_hash = NULL;
    //check master password hash

    IF_VERBOSE fprintf(stderr, DEBUG_TAG"BEGIN: GZPKI_keypass_verify_master_pass("color_cyan"%s"color_reset")\n", keydb_file);

    master_pwd_hash = GZPKI_ripemd160_hash(master_pass_in, strlen(master_pass_in));

    IF_VERBOSE fprintf(stderr, DEBUG_TAG"master_pwd_hash: %s\n", master_pwd_hash);

    r = GZPKI_keypass_get_secret(keydb_file, KEY_TYPE_S_MASTER, KEY_STATUS_VALID);
    if(r<0) {
        printf("error: fail to get master secret and digest: %s\n", keydb_file);
        return -1;
    }
    
    if(g_secret == NULL || g_digest == NULL) {
        fprintf(stderr, "error:fail to get master digest\n");
        return -1;
    }
    
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"GZPKI_keypass_verify_master_pass(DIGEST): %s\n", g_digest);

            
    if(0 != strcmp(master_pwd_hash, g_digest)) {
        IF_VERBOSE printf("user    master hash: ["color_yellow_b"%s"color_reset"]\n", master_pwd_hash);
        IF_VERBOSE printf("keypass master hash: ["color_yellow_b"%s"color_reset"]\n", g_digest);
        printf("error: invalid master password for %s\n", keydb_file);
        return -1;
    }

    IF_VERBOSE fprintf(stderr, DEBUG_TAG"END: GZPKI_keypass_verify_master_pass("color_cyan"%s"color_reset")\n", keydb_file);
    return 0;
}


static int getSecretCallback(void *NU, int argc, char **argv, char **azColName)
{
    int i;
    for (i = 0; i < argc; i++)
    {
        IF_VERBOSE printf ("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        if(0 == strcmp(azColName[i], "secret") && argv[i] != NULL) {
            memset(g_secret, 0, sizeof(g_secret));
            sprintf(g_secret, "%s", argv[i]);
        } 
        if(0 == strcmp(azColName[i], "digest") && argv[i] != NULL) {
            memset(g_digest, 0, sizeof(g_digest));
            sprintf(g_digest, "%s", argv[i]);
        }
    }
    IF_VERBOSE printf("[getSecretCallback] gSecret: %s, gDigest: %s\n", g_secret, g_digest);
    return 0;
}


unsigned char *GZPKI_password_decrypt(unsigned char *secret, int secret_len, char *pwd) {
    unsigned char *p = NULL;

    GZPKI_CTX C;
    int len;
    
    GZPKI_init_ctx(&C);
    C.operation = GZPKI_DECRYPT;
    C.cipher_name = NULL;
    C.cipher_name = GZPKI_strdup("aes256");
    C.verbose = C.base64 = C.pbkdf2 = 1;
    C.printkey = 0;
    C.passphrase = GZPKI_strdup(pwd);
    char *master_secret = NULL;
                
    GZPKI_set_infile(&C, NULL, (char *)secret, secret_len, FORMAT_PEM);
    GZPKI_set_outfile(&C, NULL, FORMAT_MEM);

    if(CMS_RET_OK == GZPKI_do_ENC(&C)) {
        IF_VERBOSE fprintf(stderr, "GZPKI_do_ENC(GZPKI_DECRYPT): decrypt success.\n");
                
        len = GZPKI_get_mem_length(&C);
        IF_VERBOSE fprintf(stderr, "#MASTER SECRET = ["color_yellow_b"%d"color_reset"]\n", len);
        master_secret = malloc(len+1);
        snprintf(master_secret, len+1, "%s", GZPKI_get_mem(&C));
        IF_VERBOSE fprintf(stderr, "MASTER SECRET = ["color_yellow_b"%s"color_reset"]\n", (char *)master_secret);
        //p = GZPKI_strdup(master_secret);
        p = master_secret;
    }
    else {
        fprintf(stderr, "error:GZPKI_password_decrypt:fail to decrypt secret.\n");
        IF_VERBOSE fprintf(stderr, "secret: %s, #secret=%d, pwd=%s\n", secret, secret_len, pwd);
        //GZPKI_free_ctx(&C);
        //return NULL;
    }

    //if(C.cipher_name) free(C.cipher_name);
    //if(C.passphrase) free(C.passphrase);

    GZPKI_free_ctx(&C);

    return p;
}

unsigned char *GZPKI_keypass_get_master_secret(char *dbfile, char *master_pass) {

    int type = KEY_TYPE_MASTER;
    //char master_secret[512];
    ///memset(master_secret, 0, sizeof(master_secret));
    //char *p = NULL;
    unsigned char *master_secret = NULL;
    char *master_pass_hash = NULL;
    //IF_VERBOSE fprintf(stderr, DEBUG_TAG"GZPKI_keypass_generate_password: type=[%d], ANY:0, PKEY:1, SECRET:2, MASTER:3\n", type);
    
    GZPKI_keypass_get_secret(dbfile, "master", "V");
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"GZPKI_keypass_get_master_secret(): %s\n", g_secret);
    if(g_secret == NULL) {
        fprintf(stderr, "error:fail to get master secret\n");
        return NULL;
    }

#if 1
    master_secret  = GZPKI_password_decrypt(g_secret, strlen(g_secret), master_pass);
    //if(master_secret == NULL) {
    //    fprintf(stderr, "error:fail to encrypt master secret\n");
    //    return NULL;
    //}
#else
    //master_secret을 복호화한다. 
    {
        GZPKI_CTX C;
        int len;
        GZPKI_init_ctx(&C);
        C.operation = GZPKI_DECRYPT;
        C.cipher_name = GZPKI_strdup("aes256");
        C.verbose = C.base64 = C.pbkdf2 = 1;
        C.printkey = 0;
        C.passphrase = GZPKI_strdup(master_pass);
                
        GZPKI_set_infile(&C, NULL, (char *)g_secret, strlen(g_secret), FORMAT_PEM);
        GZPKI_set_outfile(&C, NULL, FORMAT_MEM);

        if(CMS_RET_OK == GZPKI_do_ENC(&C)) {
            fprintf(stderr, "GZPKI_do_ENC(GZPKI_DECRYPT): decrypt success.\n");
                
            len = GZPKI_get_mem_length(&C);
            IF_VERBOSE fprintf(stderr, "#MASTER SECRET = ["color_yellow_b"%d"color_reset"]\n", len);
            snprintf(master_secret, len+1, "%s", GZPKI_get_mem(&C));
            IF_VERBOSE fprintf(stderr, "MASTER SECRET = ["color_yellow_b"%s"color_reset"]\n", (char *)master_secret);
            p = GZPKI_strdup(master_secret);
        }
        else {
            fprintf(stderr, "error:GZPKI_do_ENC:failed.\n");
            
        }

        GZPKI_free_ctx(&C);
    }
#endif    

    return master_secret;


}

char *GZPKI_keypass_export(char *file, char *master_secret, char *keyid) 
{
    //char *master_secret = NULL;
    char secret[1024];


    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;

    //char *filename = keydb_file;
    char *original = NULL;

    //파일이 없으면 오류 return 
    if(!is_file_exists(file)) {
        fprintf(stderr, "no database file: %s\n", file);
        return 0;
    }

    rc = sqlite3_open(file, &db);
    if( rc ) {
    	fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(db));
      	return NULL;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"Open keypass database successfully.\n");
   	}

	char sql[1024];
    memset(sql, 0, 1024);
    sprintf(sql, "SELECT secret FROM keydb WHERE name='%s' and status='%s'", keyid, KEY_STATUS_VALID);
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"SQL(2): %s\n", sql);

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,"error:fail to open database: %s\n", file);
        return NULL;
    }
    rc = sqlite3_step(stmt);
    int rowCount = 0;
    int i = 0;

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
            
                if(0==strcmp(columnName, "secret")) {
                    memset(secret, 0, sizeof(secret));
                    sprintf(secret, "%s", valChar);
                    //secret = GZPKI_strdup(valChar);
                }
            }
            

        }
        rc = sqlite3_step(stmt);
    }

	//rc = sqlite3_exec(db, sql, getSecretCallback, 0, &zErrMsg);
    rc = sqlite3_finalize(stmt);

    rc = sqlite3_close(db);
    
    /*if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  	
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"keypass table export successfully\n");
   	}*/

    //secret =  GZPKI_password_decrypt(g_secret, strlen(g_secret), master_pass);
    original =  GZPKI_password_decrypt(secret, strlen(secret), master_secret);
    //if(master_secret) 
    //    free(master_secret);

  	//sqlite3_close(db);
	return original;
}

int GZPKI_keypass_revoke(char *keydb_file, char *keyid, int force_update) {
    return GZPKI_keypass_change_status(keydb_file, keyid, force_update, KEY_STATUS_VALID, KEY_STATUS_REVOKED);
}

int GZPKI_keypass_delete(char *keydb_file, char *keyid, int force_update) {
    return GZPKI_keypass_change_status(keydb_file, keyid, force_update, KEY_STATUS_REVOKED, KEY_STATUS_DELETED);
}

int GZPKI_keypass_truncate(char *keydb_file) {
    sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int ret = -1;

    char *filename = keydb_file;
    
    rc = sqlite3_open(filename, &db);
   	
    if( rc ) {
    	fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(db));
      	return ret;
   	} 
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"Open keypass database successfully.\n");
   	
	char sql[512];
    memset(sql, 0, 512);
    sprintf(sql, "DELETE FROM keydb WHERE status ='%s' AND type IS NOT %d", KEY_STATUS_DELETED, KEY_TYPE_MASTER);
       
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"SQL: %s\n", sql);

	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  	
        ret = -1;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"update database successfully\n");
   	}

   	sqlite3_close(db);
    ret = 0;
	return ret;
}

//--------------------------------------------------
// master password 인증 후 수행. 
//--------------------------------------------------
int GZPKI_keypass_change_status(char *keydb_file, char *keyid, int force_update, char *old_state, char *new_status) 
{
    sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int ret = -1;

    char *filename = keydb_file;
    char *secret = NULL;

    rc = sqlite3_open(filename, &db);
   	
    if( rc ) {
    	fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(db));
      	return ret;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"Open keypass database successfully.\n");
   	}

	char sql[512];
    memset(sql, 0, 512);
    if(force_update == 1 ) {
        //이름만 보고 업데이트 
        sprintf(sql, "UPDATE keydb SET status='%s' WHERE name='%s' AND type IS NOT %d", new_status, keyid, KEY_TYPE_MASTER);
    }
    else {
        //VALID인 넘만
        sprintf(sql, "UPDATE keydb SET status='%s' WHERE name='%s' AND status='%s' AND type IS NOT %d", new_status, keyid, old_state, KEY_TYPE_MASTER);
    }
        
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"SQL: %s\n", sql);

	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  	
        ret = -1;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"change status successfully\n");
   	}

   	sqlite3_close(db);
    ret = 0;
	return ret;
}



unsigned char *GZPKI_keypass_gen_random_pass(int nbytes, int type)
{
    int r, i, num = nbytes;
    char *p = NULL;

    unsigned char buf[4096];
    memset(buf, 0, sizeof(buf));

    while (num > 0) {
        int chunk;
        chunk = num;
        if (chunk > (int)sizeof(buf))
            chunk = sizeof(buf);

        r = RAND_bytes(buf, chunk);
        if (r <= 0) {
            fprintf(stderr, ERR_TAG"fail to random bytes(%d)\n", nbytes);
            return NULL;
        }
        
        for (i = 0; i < chunk; i++)
            //IF_VERBOSE {
            if(0) {
                if (fprintf(stdout, "%02x", buf[i]) != 2)
                    return NULL;
            }
        num -= chunk;
    }

    p =  malloc(SHA256_DIGEST_LENGTH*2+1);
    GZPKI_sha256_hash(buf, p);

    IF_VERBOSE fprintf(stderr, "RAND_SHA256_KEY: ["color_yellow_b"%s"color_reset"]\n", p);
	return p;
}




unsigned char *GZPKI_password_encrypt(unsigned char *secret, int secret_len, char *master_pass) 
{
    GZPKI_CTX C;

    char *ciphertext = NULL; //[2048];
    int len = -1;
    
    GZPKI_init_ctx(&C);
    C.operation = GZPKI_ENCRYPT;
    C.cipher_name = GZPKI_strdup("aes256");
    C.verbose = C.base64 = C.pbkdf2 = 1;
    C.printkey = 0;
    C.passphrase = GZPKI_strdup(master_pass);
                
    GZPKI_set_infile(&C, NULL, (char *)secret, secret_len, FORMAT_PEM);
    GZPKI_set_outfile(&C, NULL, FORMAT_MEM);

    if(CMS_RET_OK == GZPKI_do_ENC(&C)) {
        IF_VERBOSE fprintf(stderr, "success:password encryption completed.\n");
       
        len = GZPKI_get_mem_length(&C);
        
        ciphertext = malloc(len+1);
        snprintf(ciphertext, len+1, "%s", GZPKI_get_mem(&C));
        IF_VERBOSE fprintf(stderr, "CIPHER TEXT: "color_yellow_b"%s"color_reset"\n", ciphertext);
    }
    else {
        fprintf(stderr, "error:password encryption failed.\n");
    }

    //C.passphrase, C.cipher_name FREE는 free_ctx에서 수행
    GZPKI_free_ctx(&C);
    return ciphertext;
    
}

int GZPKI_keypass_rename(char *dbfile, char *name, char *status, char *new_name)
{
	sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int r;
    
    char sql[256];
    memset(sql, 0, 256);

    sprintf(sql, "UPDATE keydb SET name='%s', mdate=DATETIME('now') WHERE name='%s' AND status='%s';", new_name, name, status);
    
    IF_VERBOSE fprintf(stderr, INFO_TAG"SQL: %s\n", sql);

    rc = sqlite3_open(dbfile, &db);
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "error:sql: %s\n", zErrMsg);
    }
    else {
        fprintf(stdout, "Rename keypass entry "color_yellow_b"%s"color_reset" to "color_yellow_b"%s"color_reset"\n", name, new_name);
        IF_VERBOSE fprintf(stderr, "success: rename %s to %s\n", name, new_name);
    }

   	sqlite3_close(db);
	return 0;
}

unsigned char *GZPKI_keypass_generate_password(char *dbfile, char *id, char *master_pass, int nbytes, int type)
{
	sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int r, i;
    int num = nbytes;

    char *master_pass_hash = NULL;
    unsigned char *ciphertext = NULL;

    char *p = NULL;
    IF_VERBOSE fprintf(stdout, "begin: num=%d\n", num);
    
    unsigned char buf[512];
    char sql[512];

    char *master_secret = NULL;

    IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "MASTER SECRET GENERATE...");
    p = GZPKI_keypass_gen_random_pass(nbytes, type);

    //1 master 이면 master_pass로 암호화
    if(type == KEY_TYPE_MASTER) 
    {
        
        //master_pass의 hash를 생성
        //keypass의 update시 master_pass의 check가 필요할 수 있다(eg, 특정 keyid의 status변경)
        {
            IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "DIGEST(MASTER_SECRET) GENERATE...");
            IF_VERBOSE fprintf(stderr, DEBUG_TAG"master password: %s\n", master_pass);

            master_pass_hash = GZPKI_ripemd160_hash( (unsigned char *)master_pass, strlen(master_pass));
            if(master_pass_hash == NULL ) {
                fprintf(stderr, "error:fail to generate hash(master secret)\n");
                return NULL;
            }
        }

        IF_VERBOSE fprintf(stderr, color_red_b"%s\n"color_reset, "ENCRYPT MASTER PWD WITH PASSPHRASE");
        ciphertext = GZPKI_password_encrypt(p, strlen(p), master_pass);
        sprintf(sql, "INSERT INTO keydb (name, secret, status, type, cdate, mdate, digest ) "\
            "VALUES ('%s', '%s', '%s', %d, DATETIME(\'now\'), DATETIME(\'now\'),'%s' );"
            , id, ciphertext, KEY_STATUS_VALID , type, master_pass_hash );
    } 
    else  
    { // MASTER가 아닌 나머지 키 pass들 암호화해서 저장
    
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"GZPKI_keypass_generate_password: type=[%d], ANY:0, PKEY:1, SECRET:2, MASTER:3\n", type);

        GZPKI_keypass_get_secret(dbfile, "master", "V");
        //unsigned char *GZPKI_keypass_get_master_secret(char *dbfile, char *master_pass);
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"global E(master secret): %s\n", g_secret);
        if(g_secret == NULL) {
            fprintf(stderr, "error:fail to get master secret\n");
            exit(0);
        }

        IF_VERBOSE fprintf(stderr, DEBUG_TAG"master secret by pass :%s\n", master_pass);
        master_secret = GZPKI_password_decrypt(g_secret, strlen(g_secret), master_pass);
        
        IF_VERBOSE fprintf(stderr, DEBUG_TAG"master secret: %s by pass[%s]\n", master_secret, master_pass);

        //master_pass의 hash를 생성
        //keypass의 update시 master_pass의 check가 필요할 수 있다(eg, 특정 keyid의 status변경)
        {
            master_pass_hash = GZPKI_ripemd160_hash( (unsigned char *)p, strlen(p));
            if(master_pass_hash == NULL ) {
                fprintf(stderr, "error:fail to generate hash(secret)\n");
                return NULL;
            }
        }

        ciphertext = GZPKI_password_encrypt(p, strlen(p), master_secret);
        sprintf(sql,  "INSERT INTO keydb (name, secret, status, type, cdate, mdate, digest ) "\
            "VALUES ('%s', '%s', '%s', %d, DATETIME(\'now\'),  DATETIME(\'now\'),'%s' );"
            , id, ciphertext, KEY_STATUS_VALID , type, master_pass_hash );
    } 

    IF_VERBOSE fprintf(stderr, INFO_TAG"SQL: %s\n", sql);

    rc = sqlite3_open(dbfile, &db);
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error : %s\n", zErrMsg);
    }
    else {
        fprintf(stdout, "New keypass entry '%s' added.\n", id);
        IF_VERBOSE fprintf(stderr, "SQL:success: %s\n", zErrMsg);
    }
    
end:

    if(master_pass_hash) free(master_pass_hash);
    if(ciphertext) free(ciphertext);
    if(master_secret) free(master_secret);
        
   	sqlite3_close(db);
	return p;
}


char *GZPKI_keypass_get_secret_by_id(char *file, int real_id ) {
    int rc;
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int rowcount;
    int i=0;
    char *secret = NULL;

    char sql[128];
    memset(sql, 0, 128);

    sprintf(sql ,"SELECT secret FROM keydb WHERE id = %d;", real_id);

    rc = sqlite3_open(file, &db);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr,"error:fail to open database: %s\n", file);
        return NULL;
    }
    rc = sqlite3_step(stmt);
    
    int rowCount = 0;
    i = 0;
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
            
                if(0==strcmp(columnName, "secret")) {
                    secret = GZPKI_strdup(valChar);
                }
            }
            else 
                secret = NULL;

        }
        rc = sqlite3_step(stmt);
    }
    
    rc = sqlite3_finalize(stmt);

    rc = sqlite3_close(db);

    return secret;

}


int GZPKI_keypass_get_entry_count(char *file, char *name, char *status) {
    int rc;
    char query[128];
    memset(query, 0, 128);
    if(status == NULL) {
        sprintf(query, "SELECT count(*) FROM %s WHERE name = '%s';", KEYPASS_TABLE, name);
    }
    else {
        sprintf(query, "SELECT count(*) FROM %s WHERE name = '%s' AND status = '%s';", KEYPASS_TABLE, name, status);
    }

    IF_VERBOSE printf("get cnt SQL: %s\n", query);

    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int rowcount;

    rc = sqlite3_open(file, &db);
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr,"error:fail to open database: %s\n", file);
        return -1;
    }
    rc = sqlite3_step(stmt);
    
    
    int colCount = sqlite3_column_count(stmt);

    const char * columnName = sqlite3_column_name(stmt, 0);
    rowcount = sqlite3_column_int(stmt, 0);

    IF_VERBOSE fprintf(stderr, "get_entry_cnt: %s: %d\n",columnName, rowcount);

    rc = sqlite3_finalize(stmt);
    rc = sqlite3_close(db);

    return rowcount;
}

// RET: 
//  KEY_TYPE_MASTER : master secret 
//  ELSE            : secret
unsigned char *GZPKI_keypass_update_password(char *dbfile, int real_id, char *secret, char *old_pass, char *new_pass, int nbytes, int type, int newgen)
{
	
   	char *zErrMsg = 0;
   	int rc;
    int r, i;
    int num = nbytes;

    char *pass_hash = NULL;
    unsigned char *ciphertext = NULL;

    unsigned char *p = NULL;
    //IF_VERBOSE fprintf(stdout, "begin: num=%d\n", num);
    
    unsigned char buf[512];
    char sql[512];

    char *master_secret = NULL;

    IF_VERBOSE fprintf(stderr, "GZPKI_keypass_update_password:\n");
    IF_VERBOSE fprintf(stderr, "    ID      : %d\n", real_id);
    IF_VERBOSE fprintf(stderr, "    SECRET  : %s\n", secret);
    IF_VERBOSE fprintf(stderr, "    newgen  : %d\n", newgen);
    IF_VERBOSE fprintf(stderr, "    OLD PWD : %s\n", old_pass);
    IF_VERBOSE fprintf(stderr, "    NEW PWD : %s\n", new_pass);

    //SHA256_HASH(RAND)
    //IF MASTER NEWGEN == 1
    memset(buf, 0, sizeof(buf));
    if(newgen == 1 && type==KEY_TYPE_MASTER) {
        p = GZPKI_keypass_gen_random_pass(nbytes, type);
        sprintf(buf, "%s", p);
        IF_VERBOSE fprintf(stderr, "MASTER SECRET : %s\n", buf);
        pass_hash = GZPKI_ripemd160_hash( (unsigned char *)new_pass, strlen(new_pass));
        if(pass_hash == NULL ) {
            fprintf(stderr, "error:fail to generate hash(secret)\n");
            return NULL;
        }
    }
    else {
        //기존 secret을 암호화만 다시
        //p = GZPKI_strdup(secret);
        p = GZPKI_password_decrypt(secret, strlen(secret), old_pass);
        sprintf(buf, "%s", p);
        IF_VERBOSE fprintf(stderr, "MASTER SECRET : %s\n", buf);
        IF_VERBOSE fprintf(stderr, "    DEC(SECRET) : %s\n", buf);
        pass_hash = GZPKI_ripemd160_hash( (unsigned char *)secret, strlen(secret));
        if(pass_hash == NULL ) {
            fprintf(stderr, "error:fail to generate hash(secret)\n");
            return NULL;
        }
    }
    
    //ENCRYPT(SECRET, NEW_PASS)
    ciphertext = GZPKI_password_encrypt(p, strlen(p), new_pass);
    ciphertext[strlen(ciphertext)-1] = 0;
    if(type == KEY_TYPE_MASTER) {
        sprintf(sql,  "UPDATE keydb SET secret='%s', mdate=DATETIME(\'now\'), digest='%s' WHERE name='master';" , ciphertext, pass_hash  );        
    }
    else {
        sprintf(sql,  "UPDATE keydb SET secret='%s', mdate=DATETIME(\'now\'), digest='%s' WHERE id='%d';" , ciphertext, pass_hash , real_id );
    }

    if(ciphertext) free(ciphertext);
    if(pass_hash) free(pass_hash);

    IF_VERBOSE fprintf(stderr, INFO_TAG"KEYPASS_UPGRADE_SQL: %s\n", sql);

    sqlite3 *db;
    rc = sqlite3_open(dbfile, &db);

    rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "error:query: %s\n", zErrMsg);
        fprintf(stderr, "error:query:rc=%d\n", rc);
        if(zErrMsg != NULL) sqlite3_free(zErrMsg); 
    }
    else {
        if(KEY_TYPE_MASTER==type)
            fprintf(stdout, "Keypass master updated.\n");
        else
            fprintf(stdout, "Keypass entry '%d' updated.\n",real_id);

        IF_VERBOSE fprintf(stderr, "success:keypass updated.\n");
    }

end:

   	sqlite3_close(db);
        
    //master_secret = GZPKI_strdup(buf);
    master_secret = malloc(strlen(p));
    sprintf(master_secret, "%s", p);

    IF_VERBOSE fprintf(stderr, "    GZPKI_keypass_update_password:RET: %s\n", master_secret);
    
    return master_secret;
	
}


int DEST_ID[4096];
//MASTER: old pass/new pass

int GZPKI_keypass_update_with_new_master(char *file, unsigned char *old_pass, unsigned char *new_pass ) {
    int rc;
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int rowcount;
    int i=0;

    char sql[1024];
    memset(sql, 0, 1024);

    //init
    for(i=0; i<4096; i++) DEST_ID[i] = -1;

    //master를 제외한 모든 item을 업데이트한다. 
	//sprintf(sql ,"SELECT id, name, cdate, secret, digest FROM keydb WHERE name IS NOT 'master' AND status IS NOT '%s';", KEY_STATUS_DELETED);
    sprintf(sql ,"SELECT id, name, cdate, secret, digest FROM keydb WHERE name IS NOT 'master';");

    rc = sqlite3_open(file, &db);
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr,"error:fail to open database: %s\n", file);
        return -1;
    }
    rc = sqlite3_step(stmt);
    
    int rowCount = 0;
    i = 0;
    while (rc != SQLITE_DONE && rc != SQLITE_OK) {
        rowCount++; 
        
        int colCount = sqlite3_column_count(stmt);
        IF_VERBOSE printf("  colCount: %d\n", colCount);
        int real_id = 0;
        char *name = NULL;
        char *secret = NULL;
        char *digest = NULL;

        for (int colIndex = 0; colIndex < colCount; colIndex++) {
            
            int type = sqlite3_column_type(stmt, colIndex);
            
            const char * columnName = sqlite3_column_name(stmt, colIndex);
            if (type == SQLITE_INTEGER)
            {
                int valInt = sqlite3_column_int(stmt, colIndex);
                printf("columnName = %s, Integer val = %d\n", columnName, valInt);
                if(0==strcmp(columnName, "id")) {
                    real_id = valInt;
                }
            }
            else if (type == SQLITE_TEXT)
            {
                const unsigned char * valChar = NULL;
                valChar = sqlite3_column_text(stmt, colIndex);
                //printf("    columnName = %s,Text val = %s\n", columnName, valChar);
                if(0==strcmp(columnName, "secret")) {
                    secret = GZPKI_strdup(valChar);
                }
                else if(0==strcmp(columnName, "digest")) {
                    digest = GZPKI_strdup(valChar);
                }
                else if(0==strcmp(columnName, "name")) {
                    name = GZPKI_strdup(valChar);
                }
            }
            else if (type == SQLITE_NULL)
            {
                printf("columnName = %s,NULL\n", columnName);
            }

        }
        
        printf("Line:%d, rowCount:%d, ID=%d, NAME=%s, SECRET=%s, DIGEST=%s\n", rowCount, colCount, real_id, name, secret, digest);
        if(1) 
        {
            //printf("Line:%d, rowCount:%d, ID=%d, NAME=%s\n", rowCount, colCount, real_id, name);
            //printf("SECRET:\n%s\n", secret);
            //printf("DIGEST=%s\n", digest);
            //char *p = GZPKI_keypass_update_password(&db, real_id, new_secret, 1024, KEY_TYPE_S_ANY);
            //char *p = GZPKI_keypass_update_password(file, real_id, new_secret, 1024, KEY_TYPE_S_ANY);

            DEST_ID[i] = real_id;
            //printf("ID %d will be updated\n", DEST_ID[i]);
            i++;
            
           
        }


        rc = sqlite3_step(stmt);
    }
    
    rc = sqlite3_finalize(stmt);

    rc = sqlite3_close(db);

    

    for(i=0; i<4096; i++) {
        char *secret = NULL;
        if(DEST_ID[i] == -1) 
            break;
        
        printf("ID %d will be updated\n", DEST_ID[i]);
        //newgen -> 0
        //

        secret = GZPKI_keypass_get_secret_by_id(file, DEST_ID[i]);
        printf("ID %d, SECRET=%s\n", DEST_ID[i], secret);

        //unsigned char *GZPKI_keypass_update_password(
        //char *dbfile, int real_id, char *secret, char *old_pass, char *new_pass, int nbytes, int type, int newgen)

        GZPKI_keypass_update_password(file, DEST_ID[i], secret, old_pass, new_pass, DEFAULT_KEYPASS_SEED_LEN, KEY_TYPE_ANY, 0);

        if(secret)
            free(secret);
    }
    
    return rc;

}


int GZPKI_keypass_get_secret(char *dbfile, char *name, char *status)
{
	sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int ret = 0;

    char *filename = dbfile;

    memset(g_secret, 0, sizeof(g_secret));

    rc = sqlite3_open(filename, &db);
   	
    if( rc ) {
    	fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(db));
      	return -1;
   	} 
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"GZPKI_keypass_get_secret(%s): Open keypass database successfully.\n", dbfile);
   	
    char sql[1024];
    memset(sql, 0, 1024);

	sprintf(sql ,"SELECT secret, digest FROM keydb WHERE name=\'%s\' and status=\'%s\';", name, status);

    IF_VERBOSE fprintf(stderr, DEBUG_TAG"GZPKI_keypass_get_secret:SQL=[%s]\n", sql);

	rc = sqlite3_exec(db, sql, getSecretCallback, 0, &zErrMsg);
    
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  	
        ret = -2;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"keypass table select successfully\n");
   	}

   	sqlite3_close(db);
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"database closed\n");
	return ret;
}



#if 0
unsigned char *GZPKI_keypass_generate_master_secret(int len) 
{
    	
    int r, i;
    int num = nbytes;

    char *p = NULL;
    fprintf(stdout, "begin: GZPKI_keypass_generate_master_secret, len=%d\n", len);
    
    unsigned char buf[4096];

    while (num > 0) {
        int chunk;

        chunk = num;
        if (chunk > (int)sizeof(buf))
            chunk = sizeof(buf);

        r = RAND_bytes(buf, chunk);
        if (r <= 0) {
            fprintf(stderr, ERR_TAG"fail to random bytes(%d)\n", nbytes);
            goto end;
        }
        
        for (i = 0; i < chunk; i++)
            if (fprintf(stdout, "%02x", buf[i]) != 2)
                goto end;
        
        num -= chunk;
    }
    
    fprintf(stdout, "\nnum=%d\n", num);
    //IF_VERBOSE fprintf(stdout, color_yellow_b"SHA256:\n"color_reset);

    p =  malloc(SHA256_DIGEST_LENGTH*2+1);
    GZPKI_sha256_hash(buf, p);

    IF_VERBOSE fprintf(stderr, "MASTER_SECRET/SHA256(RAND) = ["color_yellow_b"%s"color_reset"]\n", p);
    
	return p;

}
#endif



/*
int GSPKI_sha256_hash(char *string) {
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, string, strlen(string));
    SHA256_Final(sha256_digest, &ctx);

    char sha256_string[SHA256_DIGEST_LENGTH*2+1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&sha256_string[i*2], "%02x", (unsigned int)sha256_digest[i]);

    IF_VERBOSE fprintf(stderr, DEBUG_TAG"sha256_ripemd160_hash:SHA256 digest: [%s]\n", sha256_string);

    unsigned char hash[RIPEMD160_DIGEST_LENGTH];
    
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160,  sha256_string , strlen(sha256_string));
    RIPEMD160_Final(hash, &ripemd160);
    
    
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        sprintf(&g_RH_DIGEST[i*2], "%02x", hash[i]);
    }
    
    g_RH_DIGEST[40] = 0;
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"sha256_ripemd160_hash:RIPEMD160 digest: ["color_green_b"%s"color_reset"]\n", (char *)g_RH_DIGEST);
    return 0;
}
*/




//int GZPKI_do_CMS()
int GZPKI_do_RAND(GZPKI_CTX *ctx) {
    
    return CMS_RET_OK;

}

//--------------------------------------------------------------------------------
// DATA 필드에 관련된 URL, 파일명, 또는 파일의 내용 자체 resourcein를 추가한다.
// int ret = GZPKI_keypass_add_data(keydb_file, keyid_args, keytype, res);
//--------------------------------------------------------------------------------
int GZPKI_keypass_add_data(char *keydb_file, char *keyid, int keytype, char *data, char *pkid, char *loginid) 
{
    sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int ret = -1;

    char *filename = keydb_file;
    char *secret = NULL;

    rc = sqlite3_open(filename, &db);
   	
    if( rc ) {
    	fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(db));
      	return ret;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"Open keypass database successfully.\n");
   	}

	char sql[512];
    memset(sql, 0, 512);
    //VALID  only 
    sprintf(sql, "UPDATE keydb SET mdate=DATETIME('now'), data='%s', pkid='%s', loginid='%s', type=%d WHERE name='%s' AND status='%s' AND type IS NOT %d"
        , data
        , pkid
        , loginid
        , keytype 
        , keyid
        , KEY_STATUS_VALID
        , KEY_TYPE_MASTER);
    
        
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"SQL: %s\n", sql);

	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  	
        ret = -1;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"change status successfully\n");
   	}

   	sqlite3_close(db);
    ret = 0;
	return ret;
}



int GZPKI_keypass_update(char *keydb_file) {
    sqlite3 *db;
   	char *zErrMsg = 0;
   	int rc;
    int num = 0;
    int ret = -1;

    char *filename = keydb_file;
    
    rc = sqlite3_open(filename, &db);
   	
    if( rc ) {
    	fprintf(stderr, "error: create/open database: %s\n", sqlite3_errmsg(db));
      	return ret;
   	} 
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"Open keypass database successfully.\n");
   	
	char sql[512];
    memset(sql, 0, 512);
    sprintf(sql, "DELETE FROM keydb WHERE name IS NULL");
       
    IF_VERBOSE fprintf(stderr, DEBUG_TAG"SQL: %s\n", sql);

	rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
    	fprintf(stderr, "error:sql:%s\n", zErrMsg);
        sqlite3_free(zErrMsg);  	
        ret = -1;
   	} else {
    	IF_VERBOSE fprintf(stderr, DEBUG_TAG"update database successfully\n");
   	}

   	sqlite3_close(db);
    ret = 0;
	return ret;
}


