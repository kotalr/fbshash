/*
 *    Copyright (C) 2006 Richard Kotal
 *
 *    This library is free software; you can redistribute it and/or modify it 
 *    under the terms of the GNU Library General Public License as published 
 *    by the Free Software Foundation; either version 2 of the License, or 
 *    (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Library General Public License for more details.
 *
 *    You should have received a copy of the GNU Library General Public
 *    License along with this library; if not, write to the
 *    Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *    Boston, MA 02111-1307, USA.
 */  
  
#include "config.h"
#include "inc.utils.c"
#include "inc.uuencode.c"
#include "inc.hash.c"
#include "inc.hmac.c"




char * WIN32DLL_DEFINE
fb_shash_hash (ARG (char *, outtype), ARG (char *, algoname), ARG (char *, txt))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for hash 
ARGLIST (char *txt)		// text for hash 
{
  int bin = 0;
  char *out = NULL;

  OpenSSL_add_all_digests();
  if (outtype != NULL  && (strcasecmp (outtype, "bin") == 0  || strcasecmp (outtype, "raw") == 0))    bin = 1;
  if (bin == 0 && outtype != NULL && strcasecmp (outtype, "base64") == 0)    bin = 2;
  out = fb_shash_GenHash (bin, algoname, txt);
  if (out == NULL) out =  fb_shash_GetOutStr ("");
  EVP_cleanup();
  return out;
}


char * WIN32DLL_DEFINE
fb_shash_hash_blob (ARG (char *, outtype), ARG (char *, algoname), ARG (BLOBCALLBACK, txt))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for hash 
ARGLIST (BLOBCALLBACK txt)	// text for hash 
{
  int bin = 0;
  char *out = NULL;


  OpenSSL_add_all_digests();
  if (outtype != NULL && (strcasecmp (outtype, "bin") == 0 || strcasecmp (outtype, "raw") == 0)) bin = 1;
  if (bin == 0 && outtype != NULL && strcasecmp (outtype, "base64") == 0)  bin = 2;
  out = fb_shash_GenHashBlob (bin, algoname, txt);
  if (out == NULL) out =  fb_shash_GetOutStr ("");
  EVP_cleanup();
  return out;
}


char * WIN32DLL_DEFINE
fb_shash_hmac (ARG (char *, outtype), ARG (char *, algoname),  ARG (char *, txt), ARG (char *, password))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for hash 
ARGLIST (char *txt)		// text for hash 
ARGLIST (char *password)	// password for hmac generation
{
  int bin = 0;
  char *out = NULL;


  OpenSSL_add_all_digests();
  if (outtype != NULL && (strcasecmp (outtype, "bin") == 0 || strcasecmp (outtype, "raw") == 0)) bin = 1;
  if (bin == 0 && outtype != NULL && strcasecmp (outtype, "base64") == 0) bin = 2;
  out = fb_shash_GenHmac (bin, algoname, txt, password);
  if (out == NULL) out =  fb_shash_GetOutStr ("");
  EVP_cleanup();
  return out;
}

char * WIN32DLL_DEFINE
fb_shash_hmac_blob (ARG (char *, outtype), ARG (char *, algoname), ARG (BLOBCALLBACK, txt), ARG (char *, password))
ARGLIST (char *outtype)		// type of key output  : hexadecimal - hex, binary - bin, base64 (uuencode) - base64 
ARGLIST (char *algoname)	// name of algorithm for hash 
ARGLIST (char BLOBCALLBACK)	// text for hash 
ARGLIST (char *password)	// password for hmac generation
{
  int bin = 0;
  char *out = NULL;


  OpenSSL_add_all_digests();
  if (outtype != NULL && (strcasecmp (outtype, "bin") == 0 || strcasecmp (outtype, "raw") == 0))  bin = 1;
  if (bin == 0 && outtype != NULL && strcasecmp (outtype, "base64") == 0) bin = 2;
  out = fb_shash_GenHmacBlob (bin, algoname, txt, password);
  if (out == NULL)   out =  fb_shash_GetOutStr ("");
  EVP_cleanup();
  return out;
}
