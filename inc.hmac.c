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

static int fb_shash_HmacCreate (char *name, char *keyword, int key_size, HMAC_CTX *mdctx)
{
  const EVP_MD *MD = NULL;
  int out = 0;

  MD = fb_shash_GetHashId (name);
  if (MD == NULL)  return out;

  HMAC_Init(mdctx,(void *)keyword ,key_size ,MD);
  out = 1;
  return out;
}



static char * fb_shash_GenHmac (int bin, char *algoname, char *txt, char *password)
{
  HMAC_CTX mdctx;
  char *out = NULL;
  int len = 0;
  int err = 0;


  if (txt == NULL)    return out;
  if (password == NULL)    return out;
  err = fb_shash_HmacCreate (algoname, password, strlen (password), &mdctx);
  if (err == 0) return out;
  len = strlen (txt);
  HMAC_Update(&mdctx, (void *)txt, len);
  out = fb_shash_DigestPrintFromHash ((void *)&mdctx, bin, STR_HMAC);


  return out;
}

static char *fb_shash_GenHmacBlob (int bin, char *algoname, BLOBCALLBACK txt, char *password)
{
  HMAC_CTX mdctx;
  char *out = NULL;
  char *buf = NULL;
  ISC_USHORT actual_length = 0;
  ISC_LONG max_length = 0;
  int err = 0;


  if (!txt->blob_handle)  return out;
  if (password == NULL)  return out;
  err = fb_shash_HmacCreate (algoname, password, strlen (password), &mdctx);
  if (err == 0) return out;

  max_length = txt->blob_max_segment + 1;
  buf = malloc (max_length);
  while ((*txt->blob_get_segment) (txt->blob_handle, buf, max_length,   &actual_length))
    HMAC_Update(&mdctx, (void *)buf,  actual_length);
  if (buf != NULL)   free (buf);
  out = fb_shash_DigestPrintFromHash ((void *)&mdctx, bin, STR_HMAC);


  return out;
}

