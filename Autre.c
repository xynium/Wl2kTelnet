/*
 ============================================================================
 Name        : Autre.c
 Author      : Xynium  
 Version     :
 Copyright   : FM4PN JPLathuile
 Description : Annexe po wl2k
 *                  from Paclink
 ============================================================================
 */
 #include "Autre.h"
 #include <gtk/gtk.h>
 
 // Retrouve le texte du sujet.
 // Le nom sous lequel est envoyé le fichier devient le sujet c bizzare
// la reponse est limité a 30char
  char * FindSujet(const char *FName)
 {
int iCpc;
	 int iOut;
	 FILE *fp;
     int c;
 

  if ((fp = fopen(FName, "rb")) == NULL) {
       return NULL;
  }
  iCpc=0;iOut=0;
  slgnbuffer[29]=0;
  while ((c = fgetc(fp)) != EOF) {
				 slgnbuffer[iCpc++] = c;
				 if ((c=='\n')||(c=='\r') || (iCpc>28)) {
						 if (iOut==1){
							  slgnbuffer[--iCpc]=0;
							   fclose(fp);
							   return slgnbuffer;
						 }
					     iCpc=0;
				 }
			   if (strncmp(slgnbuffer,"Subject: ",9)==0){
				   iCpc = 0; iOut=1;
				}
	} 
	fclose(fp);
	return NULL;
 }

void compute_secure_login_response(char *challenge, char *response, char *password)
{
  char *hash_input;
  unsigned char hash_sig[16];
  unsigned int m, n;
  int i, pr;
  char pr_str[20];

  m = strlen(challenge) + strlen(password);
  n = m + sizeof(sl_salt);
  hash_input = (char*)malloc(n);
  strcpy(hash_input, challenge);
  strcat(hash_input, password);
  strupper(hash_input);
  memcpy(hash_input+m, sl_salt, sizeof(sl_salt));
  md5_buffer(hash_input, n, hash_sig);
  free(hash_input);

  pr = hash_sig[3] & 0x3f;
  for (i=2; i>=0; i--)
    pr = (pr << 8) | hash_sig[i];

  sprintf(pr_str, "%08d", pr);
  n = strlen(pr_str);
  if (n > 8)
    strcpy(response, pr_str+(n-8));
  else
    strcpy(response, pr_str);
}

char *strupper(char *s)
{
  unsigned char *cp;

  if (s == NULL) {
    return NULL;
  }
  for (cp = (unsigned char *) s; *cp; cp++) {
    if (islower(*cp)) {
      *cp = toupper(*cp);
    }
  }
  return s;
}

struct qzbuffer * buffer_readfile(const char *path)
{
  FILE *fp;
  int c;
  struct qzbuffer *buf;

  if ((fp = fopen(path, "rb")) == NULL) {
    return NULL;
  }
  if ((buf = buffer_new()) == NULL) {
    fclose(fp);
    return NULL;
  }
  while ((c = fgetc(fp)) != EOF) {
    if (buffer_addchar(buf, c) == -1) {
      fclose(fp);
      buffer_free(buf);
      return NULL;
    }
  }
  if (fclose(fp) != 0) {
    buffer_free(buf);
    return NULL;
  }
  return buf;
}

struct qzbuffer * buffer_new(void)
{
  struct qzbuffer *b;

  if ((b = malloc(sizeof(struct qzbuffer))) == NULL) {
    return NULL;
  }
  b->alen = 1;
  b->dlen = 0;
  b->i = 0;
  if ((b->data = malloc(b->alen * sizeof(unsigned char))) == NULL) {
    return NULL;
  }
  return b;
}

int buffer_addchar(struct qzbuffer *b, int c)
{
  unsigned char *d;
  unsigned long newlen;

  if (b->dlen == b->alen) {
    newlen = b->alen * 2;
    if ((d = realloc(b->data, newlen * sizeof(unsigned char))) == NULL) {
      return -1;
    }
    b->data = d;
    b->alen = newlen;
  }
  b->data[b->dlen++] = (unsigned char) c;
  return 0;
}

void buffer_free(struct qzbuffer *b)
{

  if (b->data) {
    free(b->data);
  }
  free(b);
}

void buffer_rewind(struct qzbuffer *b)
{

  b->i = 0;
}

int buffer_iterchar(struct qzbuffer *b)
{

  if (b->i >= b->dlen) {
    return EOF;
  }
  return b->data[b->i++];
}


/*
 *   envoie le fichier compressé
 *   dans le cas ou la demande se fait a partir d'un offset offst est non nul
 * 
 */
 int  putcompressed(char *titre,long int offst, struct qzbuffer *buf, int *fp)
{
  int len;
  char title[81];
  unsigned char offset[7];
  int cksum = 0;
  unsigned char *cp;
  long rem;
  unsigned char msglen;
   
  sprintf(title,"%s",titre);
  snprintf((char *) offset, sizeof(offset), "%lu", offst);
  len = strlen((const char *) title) + strlen((const char *) offset) + 2;
  
  sprintf(slgnbuffer, "%c%c%s%c%s%c", CHRSOH, len, title, CHRNUL, offset, CHRNUL);
  if  (send (*fp, slgnbuffer,len+2,MSG_MORE)  == -1)  return -1;  // Send header 
 
  rem = (long)buf->dlen;
  cp = buf->data;
  if (rem < 6)  return -2;
  cp += offst;
  rem -= (long)offst;
  if (rem < 0)  return -3;

  while (rem > 0) {
					if (rem > 250)    msglen = 250;
					else  msglen = (unsigned char)rem;
					sprintf(slgnbuffer, "%c%c", CHRSTX, msglen) ;
				    if  (send (*fp, slgnbuffer, 2,MSG_MORE)  == -1)  return -4;
				  
					len=0;
					while (msglen--) {
								   cksum = (cksum +  *cp) % 256;
                                   slgnbuffer[len++]=*cp++;                        
								   rem--;
					}
		  	       if  (send (*fp, slgnbuffer, len,MSG_MORE)  == -1)  return -5;
  }
  cksum = -cksum & 0xff;   // Send checksum 
  sprintf(slgnbuffer, "%c%c", CHREOT, cksum) ;
  if  (send (*fp, slgnbuffer,2,0)  == -1)  return -6;
  return 0;
}

int buffer_writefile(const char *path, struct qzbuffer *buf)
{
  FILE *fp;
  int c;

  if ((fp = fopen(path, "wb")) == NULL) {
    return -1;
  }
  buffer_rewind(buf);
  while ((c = buffer_iterchar(buf)) != EOF) {
    if (fputc(c, fp) == EOF) {
      fclose(fp);
      return -1;
    }
  }
  if (fclose(fp) != 0) {
    return -1;
  }
  return 0;
}


// Parse la phrase FC po retrouver la longeur
//et met le nom dans s  
 int FCLongParse(char *s)
 {
	gchar ** gsaPart;
	int iR;
	
	gsaPart= g_strsplit (s," ",7);
	
	 iR= atoi(gsaPart[4]);
	 strcpy(s,gsaPart[2]);
	 
	 g_strfreev (gsaPart);
	 
	 return iR;
	 
 }
 
 
 //Retrouve les preferances
 int LitConfig(void)
 {
      int iq,ir,is,pos;
      char sTmpp[20];
      FILE *fp;
      char c;
      char buffer[MAXBUFFLON];
     
      sprintf(buffer,"%s/PNMail/PNMail.conf",getenv("HOME")) ;
	  if ((fp = fopen(buffer, "r")) == NULL) {
                  return -1;
      }
      
       do { // read all lines in file
				pos = 0;
				do{ // read one line
						  c = fgetc(fp);
						  if(c != EOF) buffer[pos++] = (char)c;
						  if(pos >= MAXBUFFLON - 1) { // ierreur lecture trop longue
                                             break;
						  }
				}while(c != EOF && c != '\n');
				buffer[--pos] = 0;// line is now in buffer
				iq=0;
				for (ir=0; ir <strlen(buffer);ir++)
				{
					switch (iq){
						 case 0: sTmpp[ir]=buffer[ir]; // charge la phrase
									 if (sTmpp[ir]==':') {
										    sTmpp[ir-1]=0;
										    if (strcmp(sTmpp,"CallAdress")==0)     iq=1;
										    if (strcmp(sTmpp,"PassWord")==0)     iq=2;
										    if (strcmp(sTmpp,"Locator")==0)     iq=3;
										    is=0;
									 }
						             break;
						 case 1: sMycall[is++]=buffer[ir]; // charge la phrase
									 if (buffer[ir]=='@') {
										    sMycall[--is]=0;
										    iq=0;
										}
										break;
						 case 2: password[is++]=buffer[ir]; // charge la phrase
									 if (buffer[ir+1]==0) {
										    password[is]=0;
										    iq=0;
										}
										break;
				   	     case 3: locator[is++]=buffer[ir]; // charge la phrase
									 if (buffer[ir+1]==0) {
										    locator[is]=0;
										    iq=0;
										}
										break;
					}
			}
      } while(c != EOF); 
  		
 

 fclose(fp);
 return 0;

}
