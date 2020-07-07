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

static char *fb_shash_EndHash (void *mdctx, char *type, int *len)
{
  char *buf = NULL;


  if (type == NULL || mdctx == NULL)  return buf;
  buf = (char *)malloc(EVP_MAX_MD_SIZE*sizeof(char *));
  if (strcmp (type, STR_HASH) == 0) {
    EVP_DigestFinal((EVP_MD_CTX *)mdctx, buf, len);
    EVP_MD_CTX_cleanup((EVP_MD_CTX *)mdctx);
  }
  else if (strcmp (type, STR_HMAC) == 0) {
    HMAC_Final((HMAC_CTX *)mdctx, buf, len);
    HMAC_cleanup((HMAC_CTX *)mdctx);
  }
  return buf;
}


static char *fb_shash_DigestPrintFromHash (void *mdctx, int bin, char *type)
{
  char *buf = NULL;
  int len = 0;
  char *out = NULL;


  if (type == NULL ||  mdctx == NULL)  return out;

  buf = fb_shash_EndHash (mdctx, type, &len);
  if (buf == NULL) return out;

  switch (bin)
    {
    case 2:
      {
	int size = (1 + (len * 2) );
	unsigned char b64[size];
	memset (b64,'\0', size);
	Ns_HtuuEncode (buf, len, b64);
	out = fb_shash_GetOutStr (b64);
	break;
      }
    case 1:
      {
	out = ib_util_malloc (len + 1);
	memset (out,'\0', len + 1);
	memcpy (out, buf, len);
	break;
      }
    default:
      {
	char *tmp = NULL;
	tmp = fb_shash_utils_asciify (buf, len);
	if (tmp != NULL)
	  {
	    out = fb_shash_GetOutStr (tmp);
	    free (tmp);
	  }
	break;
      }
    }
  if (buf != NULL) free (buf);

  return out;
}





static int fb_shash_HashCreate (char *name, EVP_MD_CTX *mdctx)
{
  const EVP_MD *MD = NULL;
  int out = 0;

  MD = fb_shash_GetHashId (name);
  if (MD == NULL)  return out;
  EVP_DigestInit(mdctx, MD);
  out = 1;
  return out;
}






static char *fb_shash_GenHash (int bin, char *algoname, char *txt)
{
  EVP_MD_CTX mdctx;
  char *out = NULL;
  int len = 0;
  int err = 0;


  if (txt == NULL) return out;
  err = fb_shash_HashCreate (algoname, &mdctx);
  if (err == 0) return out;
  len = strlen (txt);
  EVP_DigestUpdate(&mdctx, (void *)txt, len);
  out = fb_shash_DigestPrintFromHash ((void *)&mdctx, bin, STR_HASH);


  return out;
}

static char *fb_shash_GenHashBlob (int bin, char *algoname, BLOBCALLBACK txt)
{
  EVP_MD_CTX mdctx;
  char *out = NULL;
  ISC_USHORT actual_length = 0;
  ISC_LONG max_length = 0;
  char *buf = NULL;
  int err = 0;


  if (!txt->blob_handle)
    return out;
  err = fb_shash_HashCreate (algoname, &mdctx);
  if (err == 0) return out;
  max_length = txt->blob_max_segment + 1;
  buf = malloc (max_length);
  while ((*txt->blob_get_segment) (txt->blob_handle, buf, max_length,  &actual_length))
     EVP_DigestUpdate(&mdctx, (void *)buf, actual_length);
  if (buf != NULL) free (buf);
  out = fb_shash_DigestPrintFromHash ((void *)&mdctx, bin, STR_HASH);

  return out;
}


