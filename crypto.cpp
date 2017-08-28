#include "crypto.h"

#include <iostream>

Crypto::Crypto(QString fingerPrint)
{
    m_fingerPrint = fingerPrint;

   char *p;
   char buf[2048];
   size_t read_bytes;
   int tmp;
   //gpgme_ctx_t ceofcontext;
   gpgme_error_t err;
   gpgme_data_t data;

   gpgme_engine_info_t enginfo;

   /* The function `gpgme_check_version' must be called before any other
    * function in the library, because it initializes the thread support
    * subsystem in GPGME. (from the info page) */
   setlocale (LC_ALL, "");
   p = (char *) gpgme_check_version(NULL);
   printf("version=%s\n",p);
   /* set locale, because tests do also */
   gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

   /* check for OpenPGP support */
   err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
   if(err != GPG_ERR_NO_ERROR) printf("Got error");

   p = (char *) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);
   printf("Protocol name: %s\n",p);

   /* get engine information */
   err = gpgme_get_engine_info(&enginfo);
   if(err != GPG_ERR_NO_ERROR) printf("Got error");
   printf("file=%s, home=%s\n",enginfo->file_name,enginfo->home_dir);

   /* create our own context */
   err = gpgme_new(&m_ctx);
   if(err != GPG_ERR_NO_ERROR) printf("Got error");

   /* set protocol to use in our context */
   err = gpgme_set_protocol(m_ctx,GPGME_PROTOCOL_OpenPGP);
   if(err != GPG_ERR_NO_ERROR) printf("Got error");

   /* set engine info in our context; I changed it for ceof like this:

   err = gpgme_ctx_set_engine_info (ceofcontext, GPGME_PROTOCOL_OpenPGP,
               "/usr/bin/gpg","/home/user/nico/.ceof/gpg/");

      but I'll use standard values for this example: */

   err = gpgme_ctx_set_engine_info (m_ctx, GPGME_PROTOCOL_OpenPGP,
               enginfo->file_name,enginfo->home_dir);
   if(err != GPG_ERR_NO_ERROR) printf("Got error");

   /* do ascii armor data, so output is readable in console */
   gpgme_set_armor(m_ctx, 1);

   /* create buffer for data exchange with gpgme*/
   err = gpgme_data_new(&data);
   if(err != GPG_ERR_NO_ERROR) printf("Got error");

   /* set encoding for the buffer... */
   err = gpgme_data_set_encoding(data,GPGME_DATA_ENCODING_ARMOR);
   if(err != GPG_ERR_NO_ERROR) printf("Got error");

   /* verify encoding: not really needed */
   tmp = gpgme_data_get_encoding(data);
   if(tmp == GPGME_DATA_ENCODING_ARMOR) {
      printf("encode ok\n");
   } else {
      printf("encode broken\n");
   }

   /* with NULL it exports all public keys */
   err = gpgme_op_export(m_ctx,NULL,0,data);
   if(err != GPG_ERR_NO_ERROR) printf("Got error");

   read_bytes = gpgme_data_seek (data, 0, SEEK_END);
   printf("end is=%d\n",read_bytes);
   if(read_bytes == -1) {
      p = (char *) gpgme_strerror(errno);
      printf("data-seek-err: %s\n",p);
      printf("Got error");
   }
   read_bytes = gpgme_data_seek (data, 0, SEEK_SET);
   printf("start is=%d (should be 0)\n",read_bytes);

   /* write keys to stderr */
   /*while ((read_bytes = gpgme_data_read (data, buf, SIZE)) > 0) {
      write(2,buf,read_bytes);
   }*/
   /* append \n, so that there is really a line feed */
   //write(2,"\n",1);

   /* free data */
   gpgme_data_release(data);

   /* free context */
   gpgme_release(m_ctx);

}
