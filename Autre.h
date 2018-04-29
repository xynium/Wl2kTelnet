/*
 ============================================================================
 Name        : Autre.h
 Author      : Xynium  
 Version     :
 Copyright   : FM4PN JPLathuile
 Description : Annexe po wl2k
 ============================================================================
 */

#ifndef Autre
#define Autre



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/socket.h>
#include "md5.h"
#include "lzhuf_1.h"

typedef enum { false, true } bool;

#define MAXBUFFLON 512
#define MAXRECPROP 10

#define CHRNUL 0
#define CHRSOH 1
#define CHRSTX 2
#define CHREOT 4
	

 struct qzbuffer {
  unsigned char *data;
  unsigned long alen;
  unsigned long dlen;
  unsigned int i;
};


/* Salt for Winlink 2000 secure login */
static const unsigned char sl_salt[] = {
  77, 197, 101, 206, 190, 249,
  93, 200, 51, 243, 93, 237,
  71, 94, 239, 138, 68, 108,
  70, 185, 225, 137, 217, 16,
  51, 122, 193, 48, 194, 195,
  198, 175, 172, 169, 70, 84,
  61, 62, 104, 186, 114, 52,
  61, 168, 66, 129, 192, 208,
  187, 249, 232, 193, 41, 113,
  41, 45, 240, 16, 29, 228,
  208, 228, 61, 20 };

 char  slgnbuffer[270];  
 struct qzbuffer *ubuf;
 struct qzbuffer *cbuf;
 
  char sMycall[10];
  char  password[10];
  char  locator[10];
  char saPropName[MAXRECPROP][20];

 char * FindSujet(const char *FName);
void compute_secure_login_response(char *challenge, char *response, char *password);
char *strupper(char *s);
struct qzbuffer * buffer_readfile(const char *path);
struct qzbuffer * buffer_new(void);
int buffer_addchar(struct qzbuffer *b, int c);
void buffer_free(struct qzbuffer *b);
void buffer_rewind(struct qzbuffer *b);
int buffer_iterchar(struct qzbuffer *b);
int  putcompressed(char *titre,long int offst, struct qzbuffer *buf, int *fp);
int buffer_writefile(const char *path, struct qzbuffer *buf);
int FCLongParse(char *s);
int LitConfig(void);

#endif
