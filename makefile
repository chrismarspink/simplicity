
ifeq (aarch64, $(platform))
	CC=aarch64-linux-gnu-gcc
	AR=aarch64-linux-gnu-ar 
	RANLIB=aarch64-linux-gnu-ranlib 
	LD=aarch64-linux-gnu-ld 
	MAKEDEPPROG=aarch64-linux-gnu-gcc 
	PROCESSOR=ARM
	TARGET_DIR = linux-aarch64
	
else
	ifeq (x86_64, $(platform))
		AR=ar
		CC=gcc
		TARGET_DIR = linux-x86_64
	else 
		##default, Linux ubuntu on VMWare
		AR=ar
		CC=gcc
		TARGET_DIR = linux-x86_64
	endif
endif


SRC_DIR=./src
OBJ_DIR=$(TARGET_DIR)/objs
OPENSSL_DIR=./$(TARGET_DIR)/openssl-1.1.1f
	
CFLAGS=-g -O3 -Wall # -Os

SQLITE_OBJ=./$(TARGET_DIR)/sqlite/sqlite3.o
SQLITE_INC=./$(TARGET_DIR)/sqlite
SQLITE_FLAGS = -lsqlite3  -D__WITH_SQLITE__ 
LDFLAGS=-I$(OPENSSL_DIR)/include -DMG_ENABLE_SSL -lpthread -ldl -lm #-lz

DIALOG_FLAGS = -ldialog -lncurses 

NEWT_FLAGS = -lnewt


## case of developement/default, let's build gzcmm-cli(gzcms-cli + sqlite + CA)
all: gzcms_lib gzcms-cli gzcmm_lib gzpki-cli #gzpki_lib  

GZCMS_TARGET = ecc common cms x509 verify enc req api
GZCMM_TARGET = ecc common cms x509 verify enc req api ca keypass 

GZCMS_OBJS = ./$(TARGET_DIR)/gzpki_ecc.o \
	./$(TARGET_DIR)/gzpki_common.o \
	./$(TARGET_DIR)/gzpki_cms.o \
	./$(TARGET_DIR)/gzpki_req.o \
	./$(TARGET_DIR)/gzpki_x509.o \
	./$(TARGET_DIR)/gzpki_verify.o \
	./$(TARGET_DIR)/gzpki_api.o \
	./$(TARGET_DIR)/gzpki_enc.o 


## lib for CA tool
GZCMM_OBJS = $(GZCMS_OBJS) ./$(TARGET_DIR)/gzpki_ca.o ./$(TARGET_DIR)/gzpki_keypass.o 
	
sqlite: $(SQLITE_OBJ)
	cd ./$(TARGET_DIR)/sqlite; make; pwd; cd ../..


gzpki_lib : $(GZCMM_TARGET)
	$(AR) cr ./$(TARGET_DIR)/libgzpki.a $(GZCMS_OBJS) $(OBJ_DIR)/*.o 

gzcmm_lib : $(GZCMM_TARGET) 
	$(AR) cr ./$(TARGET_DIR)/libgzcmm.a $(GZCMM_OBJS)   $(SQLITE_OBJ) $(OBJ_DIR)/*.o  


test1 : 
	$(CC) -o ./test1  $(SRC_DIR)/test.c -L./$(TARGET_DIR)/ -lgzcms  $(CFLAGS) $(LDFLAGS)  -D_NO_CA_ -D_NO_NEWT_

## lib only for client, no gzpki_ca.o, no_sql
gzcms_lib : $(GZCMS_TARGET) 
	$(AR) cr ./$(TARGET_DIR)/libgzcms.a $(GZCMS_OBJS)  $(OBJ_DIR)/*.o   

gzpki-cli : gzpki_lib
	$(CC) -g -O3 -Wall -o ./$(TARGET_DIR)/gzpki-cli  $(SRC_DIR)/gzcms-cli.c -L./$(TARGET_DIR) -lgzcmm -I$(OPENSSL_DIR)/include -lpthread -ldl -lm  \
	-D__WITH_SQLITE__  -I$(SQLITE_INC)
	cp ./$(TARGET_DIR)/gzpki-cli ./

gzcms-cli : gzcms_lib
	$(CC) -o ./$(TARGET_DIR)/gzcms-cli  $(SRC_DIR)/gzcms-cli.c -L./$(TARGET_DIR)/ -lgzcms  $(CFLAGS) $(LDFLAGS)  -D_NO_CA_ -D_NO_NEWT_
	cp ./$(TARGET_DIR)/gzcms-cli ./


api : $(SRC_DIR)/gzpki_api.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_api.o -c  $(SRC_DIR)/gzpki_api.c  $(LDFLAGS) 

ca: $(SRC_DIR)/gzpki_ca.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_ca.o -c  $(SRC_DIR)/gzpki_ca.c  $(LDFLAGS) -I$(SQLITE_INC) -D__WITH_SQLITE__


verify : $(SRC_DIR)/gzpki_verify.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_verify.o -c  $(SRC_DIR)/gzpki_verify.c -I$(OPENSSL_DIR)/include

keypass : $(SRC_DIR)/gzpki_keypass.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_keypass.o -c  $(SRC_DIR)/gzpki_keypass.c   $(LDFLAGS)

enc : $(SRC_DIR)/gzpki_enc.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_enc.o -c  $(SRC_DIR)/gzpki_enc.c   $(LDFLAGS)

common : $(SRC_DIR)/gzpki_common.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_common.o -c  $(SRC_DIR)/gzpki_common.c  $(LDFLAGS) -Wwrite-strings

cms : $(SRC_DIR)/gzpki_cms.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_cms.o -c  $(SRC_DIR)/gzpki_cms.c  $(LDFLAGS)

ecc: $(SRC_DIR)/gzpki_ecc.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_ecc.o -c  $(SRC_DIR)/gzpki_ecc.c  $(LDFLAGS) -I$(OPENSSL_DIR)/include

req: $(SRC_DIR)/gzpki_req.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_req.o -c  $(SRC_DIR)/gzpki_req.c  $(LDFLAGS)

x509: $(SRC_DIR)/gzpki_x509.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_x509.o -c  $(SRC_DIR)/gzpki_x509.c  $(LDFLAGS)

ocsp: $(SRC_DIR)/gzpki_ocsp.c
	$(CC)  -g -o ./$(TARGET_DIR)/gzpki_ocsp.o -c  $(SRC_DIR)/gzpki_ocsp.c    $(LDFLAGS)

clean:
	rm -f ./$(TARGET_DIR)/gzcms-cli \
	./$(TARGET_DIR)/gzpki-cli \
	./$(TARGET_DIR)/libgzcms.a \
	./$(TARGET_DIR)/libgzcmm.a \
	./$(TARGET_DIR)/libgzpki.a \
	$(GZCMM_OBJS)



