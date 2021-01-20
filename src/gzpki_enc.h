#ifndef _GZPKI_ENC_H_
#define _GZPKI_ENC_H_


#undef SIZE
#undef BSIZE
#define SIZE    (512)
#define BSIZE   (8*1024)



int GZPKI_do_ENC(GZPKI_CTX *ctx);


void encrypt(char *infile, char *outfile);
void decrypt(char *infile, char *outfile);

#endif