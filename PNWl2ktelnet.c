/*
____  ________.___._______  .___ ____ ___  _____   
\   \/  /\__  |   |\      \ |   |    |   \/     \  
 \     /  /   |   |/   |   \|   |    |   /  \ /  \ 
 /     \  \____   /    |    \   |    |  /    Y    \
/___/\  \ / ______\____|__  /___|______/\____|__  /
      \_/ \/              \/                    \/ 

 ============================================================================
 Name        : PNWl2ktelnet.c
 Author      : Xynium
 Version     :
 Copyright   : JPLathuile FM4PN
 Description : Winlink via Telnet
 ============================================================================
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <gtk/gtk.h>

#include "Autre.h"

//typedef enum { false, true } bool;

   GtkBuilder  *  p_builder   = NULL;
   char sSPort[20];
   char sStatus[50];
   static char buffer[MAXBUFFLON];
   static char bufferU[MAXBUFFLON];
   int iFlag,iStatFlag;
   GtkTextBuffer *tvBuffer;
   GtkTextTag *tagG,*tagR,*tagB,*tagJ;
    const gchar  *sStatcall;
   int iRecFlag;
   int  ipos,iposr,iLgn;
   int iState;
   bool bDebFlag;
   int sockfd; 
   int len;
   unsigned char title[181];
   unsigned char offset[7];
   int cksum = 0;
   int iGetStat;
   int iNQTC;
   int iRQTC;
   int inbrR;
   int iaMstR[MAXRECPROP];
   char saNam[MAXRECPROP][15];
  char sTitls[30];
   
  
static void btnDep_clicked_cb (GtkWidget * p_wid, gpointer p_data)
{
  //  GtkWidget   *pentry =NULL;
   GtkWidget   *pdialog =NULL;
   char adress[20];
   char  sport[6];
   // struct hostent *host;
   struct addrinfo hints, *res;
  
     //Pref
     strcpy(adress,  "server.winlink.org");
     sprintf(sport,"%d",8772);
         
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    hints.ai_socktype = SOCK_STREAM;
  
    // get the host info
   if  (getaddrinfo(adress,sport, &hints, &res)!= 0)     {
           pdialog = gtk_message_dialog_new (  NULL,  GTK_DIALOG_MODAL,  GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Erreur dans la recherche des info d'adresse.");
		    gtk_dialog_run (GTK_DIALOG (pdialog));
			gtk_widget_destroy (pdialog);
			return;
    }
  
        //ouverture socket
    if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) <0) {
		    pdialog = gtk_message_dialog_new (  NULL,  GTK_DIALOG_MODAL,  GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Impossible d'ouvrir le socket");
		    gtk_dialog_run (GTK_DIALOG (pdialog));
			gtk_widget_destroy (pdialog);
			return;
	 }
	    
	sprintf(sStatus,"Connection....");	
    GtkWidget*   pentry = (GtkWidget *) gtk_builder_get_object (  p_builder, "labStatus"  );
    gtk_label_set_text (GTK_LABEL (pentry),sStatus);
    
    
	if(connect(sockfd, res->ai_addr, res->ai_addrlen) == -1)
	{
		    pdialog = gtk_message_dialog_new (  NULL,  GTK_DIALOG_MODAL,  GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Impossible de se connecter");
		    gtk_dialog_run (GTK_DIALOG (pdialog));
			gtk_widget_destroy (pdialog);
			return;
	}
	
	sprintf(sStatus,"Connecté a %s and port %s...\n",adress , sport);	
    gtk_label_set_text (GTK_LABEL (pentry),sStatus);
    
    if(fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0) {   // met en non bloquant 
            pdialog = gtk_message_dialog_new (  NULL,  GTK_DIALOG_MODAL,  GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "Erreur changement de mode du socket");
		    gtk_dialog_run (GTK_DIALOG (pdialog));
			gtk_widget_destroy (pdialog);
			return;
    }  
    
	iFlag=1;
    iState=0;
    iStatFlag=0;
}


static gboolean timeout_callback (gpointer data){
	 ssize_t br;
      GtkTextIter iter,iter2;   
       long int lrep;
     GtkWidget   *pscroll =NULL;
     GtkAdjustment *verticalAdjust;
     gchar  *   utf8_text;
     GError *error = NULL;
     char sTmp[10];
 //    int cksum = 0;
     struct dirent *ent;
	 DIR *dir;
   	 int irt,ierr;
		 
    lrep=0;
         
	if (iFlag==0) return TRUE;  // on n'est pas encore initialisé
	do {
				
				br= recv(sockfd, buffer, MAXBUFFLON, 0);
				if (br==-1) {
							
								if (iLgn==1){
											  switch (iStatFlag) {    //    iLgn=0;	po attendre une reponse
														case 0:
															   sprintf(buffer, "%s\r" ,sMycall);   send (sockfd, buffer, strlen(buffer),0);   iStatFlag=1; iLgn=0;	
															   break;
														 case 1:
															   sprintf(buffer, "CMSTelnet\r" );   send (sockfd, buffer, strlen(buffer),0);   iStatFlag=2;iState=1; iLgn=0;	
															   break;
														 case 2:
															   sprintf(buffer, "[UnixLINK-0.5.1.0-B2FHM$]\r" );   send (sockfd, buffer, strlen(buffer),0);  iStatFlag=3;
															   break;
														case 3:	    
														       compute_secure_login_response(sSPort, sTmp,password); 
										   				       sprintf(buffer, ";PR: %s\r" ,sTmp);   send (sockfd, buffer, strlen(buffer),0);  iStatFlag=4;
															   break;
														case 4:	   
														       sprintf(buffer, ";Wl2k de %s (%s)\r" ,sMycall,locator);   send (sockfd, buffer, strlen(buffer),0);  iStatFlag=5; 
														       break;
													    case 5:      //  Gere  les proposals du mobile
														      iNQTC=0;
														//      printf("cmpt 2send");
														      sprintf (buffer,"%s/PNMail/OutBox", getenv("HOME"));
                                                              if ((dir = opendir (buffer)) != NULL) {     // cherche le nombre de message a Tx
                                                                          while ((ent = readdir (dir)) != NULL) {
																			       if ((ent->d_type==DT_REG)  && (ent->d_name[0]!='*'))   {
																					        iNQTC++;
																					       	if ((ubuf = malloc(sizeof(struct qzbuffer))) == NULL) {
																									   sprintf(buffer,"malloc() - %s",strerror(errno));  // Erreur
																									   gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                                                	           gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,strlen(buffer),tagR,NULL);	
																									   break;
																					 	    }
																					       sprintf (buffer,"%s/PNMail/OutBox/%s", getenv("HOME"),ent->d_name);
																					       strcpy (sTitls,   FindSujet(buffer));
																					       if ((ubuf = buffer_readfile(buffer)) == NULL) {     // lit le fichier
				                                                                                       sprintf(buffer,"%s - %s", ent->d_name, strerror(errno));   //Erreur
				                                                                                       gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                                                	           gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,strlen(buffer),tagR,NULL);	
					                                                                                    break;
				                                                                         	}
				                                                                    		if ((cbuf = version_1_Encode(ubuf)) == NULL) {   // Compresse le buffer
																								      sprintf(buffer,"Erreur dans la compression du fichier.");    //Erreur
																								      gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                                                	          gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,strlen(buffer),tagR,NULL);	
																							          break;
																							}
																							
                                                                                            strcpy(sSPort,ent->d_name);   //Renome le fichier avec une *
                                                                                            sSPort[0]='*';
                                                                                            sprintf (sStatus,"%s/PNMail/OutBox/%s",getenv("HOME"),sSPort);
                                                                                            rename(buffer,sStatus);
                                                                                            ent->d_name[strlen(ent->d_name)-4]=0;  // tronque extension					                                                                
																			                sprintf(buffer,"FC EM %s %ld %ld 0\r",ent->d_name,ubuf->dlen,  cbuf->dlen);
																			                send (sockfd, buffer, strlen(buffer),0); 
																			                gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                                                	gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,strlen(buffer),tagB,NULL);	
										                                                											                                                																				        
																			                cksum=0;
																		  		            for(int it=0;it<strlen(buffer);it++) { // check sum   doit y avoir \r a la fin
																					  	                     cksum += (unsigned char) buffer[it];
																						    }
																						    cksum = -cksum & 0xff;
																						    sprintf(buffer,"F> %X\r",cksum);
																						    send (sockfd, buffer, strlen(buffer),0); 
																						    
																						 //   strcpy(sSPort,ent->d_name); 	
																						    iState=2; 
																						    closedir (dir);
																						    break;
																			   }
																			}	   
																}	   
														        if(iNQTC==0){
																	sprintf(buffer, "FF\r" );   send (sockfd, buffer, strlen(buffer),0);   // pas de message a envoyer
														            iState=3;
													 	        }
														        iStatFlag=6; iLgn=0;	
															   break;
													     case 6:      
													          if (   iState==2) { // envoie le message 
																     sprintf(buffer,"Envoie %ld Octets.\r", cbuf->dlen);
																     gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                   	         gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,strlen(buffer),tagJ,NULL);	
										                   	     
										                   	         if  ((irt = putcompressed(sTitls,0,cbuf, &sockfd)) !=0){
																	                       sprintf(buffer,"Erreur d'ecriture %d", irt);    //Erreur
																						   gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   
										                                                   gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,strlen(buffer),tagR,NULL);
										                                                   iState=6; //fin en erreur	
																							       
																    }
																    sprintf(buffer,"Fin\r");
																    gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                   	        gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,strlen(buffer),tagJ,NULL);
										                   	        buffer[0]=0; iLgn=0;	
										                   	        iNQTC=0;
										                   	     //   iState = 2; //Attend FF
															  } 
															  else {   // repond au proposal de la stat
																        sprintf(buffer, "FS " );  
																        for (int it=0; it<iNQTC;it++) buffer[3+it]='Y';
																        buffer[3+iNQTC]='\r'; buffer[4+iNQTC]=0;
																        send (sockfd, buffer, strlen(buffer),0);  
																        iLgn=0;	
																        iGetStat=0; ipos=0;  // init po reception
																     //   iNQTC=0;
																        iRQTC=0;
																        if ((cbuf = buffer_new()) == NULL) iState=6;  // Termine il y une erreur le buffer ne peut etre alloue
  															            else iState=4;
															  }
													     	  break;
													     	  
													     case 7:   // envoie FQ termine
													                  sprintf(buffer, ",Wl2k de %s Out\r" ,sMycall);   send (sockfd, buffer, strlen(buffer),0);  
													                  gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
											                          gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,br,tagB,NULL);		
													                  sprintf(buffer, "FQ\r" );   send (sockfd, buffer, strlen(buffer),0);  
													                  close(sockfd);
																	  iFlag=0;  // c'est fini
																	  iLgn=0;	
																	  sprintf(buffer,"Deconnecte.\r");
														              gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                   	          gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,br,tagJ,NULL);
										                   	          sprintf(buffer, "FQ\r" ); 
															          break;
													     	//break;
													     	  
													     	  
																										
														  default :      
															   break;  
												}  
										     
										  	  gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
											  gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer,br,tagB,NULL);						
                				}
				}
				else {    //des char on été reçu
			 		lrep+=br;   // po statistiques reception
					sprintf(sStatus, "Iu %ld ",lrep);
				
				if (iState!=4) {	
								gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // recopie a l'ecran
								utf8_text = g_convert (buffer, br, "UTF-8", "ISO-8859-1",  NULL, NULL, &error);   // traduit en UTF
								strcpy(bufferU,utf8_text);
								gtk_text_buffer_insert_with_tags(tvBuffer,&iter,bufferU,br,tagG,NULL);  
								
								pscroll =  (GtkWidget *)gtk_builder_get_object (p_builder, "scrolledwindow1");
								verticalAdjust = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(pscroll));
								gtk_adjustment_set_value (verticalAdjust, gtk_adjustment_get_upper(verticalAdjust));
								gtk_scrolled_window_set_vadjustment (GTK_SCROLLED_WINDOW(pscroll),  verticalAdjust);
				}			
					switch (iState) {
											case 0: {  //dans le preambule pas connecté
														 for (int it=0; it <br ; it++){
																   if  (buffer[it]!='\n') slgnbuffer[iposr++]=buffer[it];
																   if (buffer[it]=='\r') { //fin de lgn
																		if ( --iposr>0)  slgnbuffer[iposr]=0;
																	    if ((strcmp(slgnbuffer,"Callsign :")==0)&&(iposr>1))   {  // Attend une commande
																					iLgn=1;iposr=0;
																		}	
																		 if ((strcmp(slgnbuffer,"Password :")==0)&&(iposr>1))   {  // Attend une commande
																					iLgn=1;iposr=0;
																		}			
																	}
														} 
														break;
										   }
										   case 1 :{   // negocie avec la stat 
											            for (int it=0; it <br ; it++){
																   if  (buffer[it]!='\n') slgnbuffer[iposr++]=buffer[it];
																   if (buffer[it]=='\r') { //fin de lgn
																		if ( --iposr>0)  slgnbuffer[iposr]=0;
																		iposr=0;
																	    if ((strncmp(slgnbuffer,";PQ:",4))==0) {// cherche si ligne PQ
																			     for(int jt=5; jt<strlen(slgnbuffer) ;jt++)  sSPort[iposr++]=slgnbuffer[jt];
																			     sSPort[iposr]=0;
																			     iposr=0;iLgn=1;
																		 }
																	}	
														} 
											            break;
										   }
										   case 3:
										   case 2 :{   // gere les reponse a mes proposals envoie de mes message
															 for (int it=0; it <br ; it++){
																	   if  (buffer[it]!='\n') slgnbuffer[iposr++]=buffer[it];
																	   if (buffer[it]=='\r') { //fin de lgn
																			if ( --iposr>0)  slgnbuffer[iposr]=0;
																			iposr=0;
																			if (strncmp(slgnbuffer,"FS ",3)==0) {     //proposal acceptage 
																				   if  ( slgnbuffer[3]!='Y') iStatFlag=5; 
																				   iLgn=1;   iState=2;
																			 }
																			 
																			 if (strcmp(slgnbuffer,"FF")==0) {     //ack retourne po d'autre message
																					  iStatFlag=5;  iLgn=1;    iState=2;
																			 }
																			 
																			if (strncmp(slgnbuffer,"FC",2)==0) {     //Retrouve dans la lgnProposal la longueur et met dans un tableau
																				    iaMstR[iNQTC]=FCLongParse(slgnbuffer);  // splite et retourne longeur
																				    strcpy(saNam[iNQTC],slgnbuffer);  // la fonction a modilfié pointer
																					iNQTC++;
																			}
																		
																			if (strncmp(slgnbuffer,"FQ",2)==0) {     //rien a recevoir on termine
																					close(sockfd);
																					iFlag=0;  // c'est fini
																				    sprintf(slgnbuffer,"Deconnecte.\r");
																			 	    if  (cbuf)  buffer_free(cbuf);
											                                        if  (ubuf)   buffer_free(ubuf);
														                		    gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                   	                        gtk_text_buffer_insert_with_tags(tvBuffer,&iter,slgnbuffer,strlen(slgnbuffer),tagJ,NULL);
																			 }
																			 if (strncmp(slgnbuffer,"F> ",3)==0) {     //il y a a recevoir    TODO Verifier le checksum
																				 //iNQTC--;  
																				  iState=3;
																			      iLgn=1;  // Lgn=1 po envoie des Y
																			 }
																		}	
															} 
											            break;
											             }
											    case 4 :{   // recoit le message
												 	     for (int it=0; it <br ; it++){
																   		switch (iGetStat){
																						case 0 : // charge le header
																								  if   (buffer[it]==CHRSOH)  iGetStat++;      //((it==0) &&  (buffer[it]==CHRSOH))  iGetStat++;
																								  else {it=MAXBUFFLON; iState=6;ierr=1;}  //sort erreur
																								  break;
																						  case 1 : // charge la longueur mais sert a rien
																								  len = buffer[it];
																								  iGetStat++;
																								  break;
																						  case 2 : // charge le titre
																									title[ipos++]=buffer[it];
																									if (buffer[it]==0) {
																										ipos=0;
																								  	    iGetStat++;	inbrR=0;
																								  	    sprintf(slgnbuffer,"Recoit : %s    0%%",title);
														                		                        gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                   	                                            gtk_text_buffer_insert_with_tags(tvBuffer,&iter,slgnbuffer,strlen(slgnbuffer),tagJ,NULL);
																								    }
																								    if (ipos>179) {it=MAXBUFFLON; iState=6;ierr=2;}  //secu depassement
																								    break;    
																							case 3 : // charge offset
																								   offset[ipos++]=buffer[it];
																								   if (buffer[it]==0){
																										ipos=0;
																										iGetStat++;
																										cksum=0;
																										if (strcmp((const char *) offset, "0") != 0)  	 {it=MAXBUFFLON; iState=6;ierr=3;}  // du code original n'exploite pas offset
																								  }
																								  if (ipos>6) {it=MAXBUFFLON; iState=6;ierr=4;}
																								  break;       
																							case 4 : // debut charge payload   verifie un CHRSTX
																								   if (buffer[it]==CHRSTX)  iGetStat=5; 
																								   if (buffer[it]==CHREOT)  iGetStat=7; 
																								   if (  iGetStat==4) {it=MAXBUFFLON; iState=6;ierr=5;}
																								  break;    
																							case 5 : // Charge la longueur
																							       len = buffer[it];
																								   if ( len <=0 )  len+=256;
																								   iGetStat=6;
																								//   printf("5  %d \r\n",len);  // debug
																								   break;
																							 case 6: // Charge la vrai payload len char     
																									len--;
																									if (buffer_addchar(cbuf, buffer[it]) == EOF)  {it=MAXBUFFLON; iState=6;ierr=6;}
																									cksum = (cksum + buffer[it]) % 256;
																									if (len ==0)   iGetStat=4;
																									// indic de progression
																									inbrR++;
																								    gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // recule de 3char
																								 	gtk_text_buffer_get_end_iter (tvBuffer,  &iter2); 
																								    gtk_text_iter_backward_chars (&iter2,3);
																								    gtk_text_buffer_delete (tvBuffer,&iter2,&iter);
	
																									sprintf(slgnbuffer,"%2d%%",(int)(100*inbrR/iaMstR[iRQTC]));
																									gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
																									gtk_text_buffer_insert_with_tags(tvBuffer,&iter,slgnbuffer,strlen(slgnbuffer),tagJ,NULL);	// fin indic progress
																									
                                                                                                    break;
																							 case 7 : //Verif check sum    
																								   cksum = (cksum +  buffer[it]) % 256;
																								   if (cksum != 0) { iState=6;ierr=7;}  //sort erreur
																							       if ((ubuf = version_1_Decode(cbuf)) == NULL) {
							                                                                                          printf( "version_1_Decode() - %s",strerror(errno));
																								    }
                                                                                                    sprintf(slgnbuffer,"%s/PNMail/InBox/%s.msg" ,getenv("HOME"), saNam[iRQTC++]);   // forme le nom du fichier  TODO extraire le MID
                                                                                                    printf("ckeck  %d  name  %s\r\n",cksum,slgnbuffer);  // debug
																									if (buffer_writefile(slgnbuffer, ubuf) != 0) {                               //stoque  en fichier le msg reçu
																												 	   printf( "buffer_writefile - %s",strerror(errno));
																									}
																								    sprintf(slgnbuffer,"Recu \r");
														                		                    gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                   	                                        gtk_text_buffer_insert_with_tags(tvBuffer,&iter,slgnbuffer,strlen(slgnbuffer),tagJ,NULL);
																								    if (iRQTC>=iNQTC) {  // tout recu on sort
																								                  iStatFlag=5;   
																								                  iLgn=1; 
																								    }
																								    iGetStat=0;  // po les autres messages
																								    break;
																				 }																					 
																		}
											            break; }   // fin case 4
											
											      case 6 : // fin chargement avec erreur     
											                                       sprintf(buffer, ",Wl2k de %s got an error %i Out\r" ,sMycall,ierr);   send (sockfd, buffer, strlen(buffer),0);  
													                               gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
											                                       gtk_text_buffer_insert_with_tags(tvBuffer,&iter,buffer, strlen(buffer),tagB,NULL);	
											                                       sprintf(slgnbuffer, "FQ\r" );   send (sockfd, slgnbuffer, strlen(slgnbuffer),0);  
											                                        printf("Erreur 6");
											                                        if  (cbuf)  buffer_free(cbuf);   // a Supprimer
											                                        if  (ubuf)   buffer_free(ubuf);
											                                        close(sockfd);
																					iFlag=0;  // c'est fini
																				    sprintf(slgnbuffer,"Erreur Deconnecte.\r");
														                		    gtk_text_buffer_get_end_iter (tvBuffer,  &iter );   // visu
										                   	                        gtk_text_buffer_insert_with_tags(tvBuffer,&iter,slgnbuffer,strlen(slgnbuffer),tagR,NULL);
																			
											            break;
											
				   }   // fin switch
				}  
    } while (br==MAXBUFFLON);
    GtkWidget*   pentry = (GtkWidget *) gtk_builder_get_object (  p_builder, "labStatus"  );
    gtk_label_set_text (GTK_LABEL (pentry),sStatus);

    return TRUE;
}

static void destroy( GtkWidget *widget,  gpointer   data )
{
  //  close(tty);
  	close(sockfd);
    gtk_main_quit ();
}
 
int main (int argc, char ** argv)
{
    GError      *  p_err       = NULL;
        
     iFlag=0;
   //Initialisation de GTK+ 
   gtk_init (& argc, & argv);
    
   // Creation d'un nouveau GtkBuilder 
   p_builder = gtk_builder_new ();
       
   if (p_builder != NULL)
   {
      //Chargement du XML dans p_builder 
      gtk_builder_add_from_file (p_builder, "PNWl2ktelnet.ui", & p_err);
 
      if (p_err == NULL)
      {
          // Recuparation d'un pointeur sur la fenetre. 
          GtkWidget * p_win = (GtkWidget *) gtk_builder_get_object (  p_builder, "appWin"  );
          g_signal_connect (p_win, "destroy",  G_CALLBACK (destroy), NULL);  // signal destroy
  
          //  Signal du bouton depart
          g_signal_connect (gtk_builder_get_object (p_builder, "btnDep"), "clicked", G_CALLBACK (btnDep_clicked_cb), NULL);
      
          GtkWidget * pentry = (GtkWidget *) gtk_builder_get_object (  p_builder, "tvLog"  );
     
          sprintf(sStatus, "                           ");
          pentry= (GtkWidget *)gtk_builder_get_object (p_builder, "labPortO");
          gtk_label_set_text (GTK_LABEL (pentry),sStatus);
          
          sprintf(sStatus, "Initialisé");
          pentry = (GtkWidget *) gtk_builder_get_object (  p_builder, "labStatus"  );
          gtk_label_set_text (GTK_LABEL (pentry),sStatus);
          
       
          tvBuffer = gtk_text_buffer_new (NULL);   // The text buffer 
          GtkWidget  *ptextview = (GtkWidget *) gtk_builder_get_object (  p_builder, "tvLog"  );
          tvBuffer= gtk_text_view_get_buffer( GTK_TEXT_VIEW(ptextview) );
          // les tag de couleurs
           tagG = gtk_text_buffer_create_tag (tvBuffer, "green_foreground",         "foreground", "green", NULL);  
           tagR = gtk_text_buffer_create_tag (tvBuffer, "red_foreground",         "foreground", "red", NULL);  
           tagB = gtk_text_buffer_create_tag (tvBuffer, "blue_foreground",         "foreground", "blue", NULL);  
           tagJ = gtk_text_buffer_create_tag (tvBuffer, "yellow_foreground",         "foreground", "orange", NULL);  
               
           if (LitConfig()!=0)     // recup des preferances
                    printf ("erreur lecture config");// erreur
               
          g_timeout_add (300,  timeout_callback,   NULL);
       
          gtk_widget_show_all (p_win);
          gtk_main ();
      }  
      else
      {
         // Affichage du message d'erreur de GTK+ 
         g_error ("%s", p_err->message);
         g_error_free (p_err);
      }
   }
  
   return EXIT_SUCCESS;
}
