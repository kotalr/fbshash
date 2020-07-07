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
  
#define _GNU_SOURCE
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include "ibase.h"
#include "ib_util.h"
#define args		args
#define ARG(type, arg)		type arg
#define ARGLIST(arg)
#define ERREXIT(status, rc)	{isc_print_status(status); return rc;}

#ifdef WIN32
# define WIN32DLL_DEFINE __declspec( dllexport)
#else
# define WIN32DLL_DEFINE
#endif

#define UCHAR(c) 		((unsigned char)(c))


/* CONSTANTS */
#define STR_HASH "hash"
#define STR_HMAC "hmac"
/* STATIC FUNCTIONS */
static char *fb_shash_GenHash (int bin, char *algoname, char *txt);
static char *fb_shash_GenHashBlob (int bin, char *algoname, BLOBCALLBACK txt);
static int fb_shash_HashCreate (char *name, EVP_MD_CTX *mdctx);
static char *fb_shash_EndHash (void *mdctx, char *type, int *len);
static char *fb_shash_DigestPrintFromHash (void *mdctx, int bin, char *type);

static char *fb_shash_GenHmac (int bin, char *algoname, char *txt,
			       char *password);
static char *fb_shash_GenHmacBlob (int bin, char *algoname, BLOBCALLBACK txt,
				   char *password);

static int fb_shash_HmacCreate (char *name, char *keyword, int key_size, HMAC_CTX *mdctx);


static const EVP_MD*fb_shash_GetHashId (char *name);
static char *fb_shash_GetOutStr (char *err);
static int Ns_HtuuEncode (unsigned char *input, unsigned int len,
			  char *output);
static int Ns_HtuuDecode (char *input, unsigned char *output, int outputlen);
static char *fb_shash_StrToUpper(char *string);
static unsigned char fb_shash_utils_val2char(unsigned char x);
static char * fb_shash_utils_asciify(char *in, long len);

