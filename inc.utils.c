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

 
static const EVP_MD* fb_shash_GetHashId (char *name)
{
  const EVP_MD *MD = NULL;
  char *s = NULL;
  char *buf = NULL;
  int len = 0;

  if (name == NULL) return MD;
  len = strlen(name);
  buf = malloc(len+1);
  memset (buf, '\0' , len+1);
  memcpy(buf,name,len);
  s = fb_shash_StrToUpper(buf);
  MD = EVP_get_digestbyname(s);
  if (buf != NULL) free(buf);

 return MD;
}



static char *fb_shash_GetOutStr (char *err)
{
  int len = 0;
  char *out = NULL;

  if (err == NULL)    return out;
  len = strlen (err);
  out = (char *) ib_util_malloc (len + 1);
  memset (out, '\0' , len + 1);
  memcpy (out, err,len);
  return out;
}

static char *fb_shash_StrToUpper(char *string)
{
    char *s = NULL;

    s = string;
    while (*s != '\0') {
        if (islower(UCHAR(*s))) {
            *s = toupper(UCHAR(*s));
        }
        ++s;
    }
    return string;
}
/*
 *    Copyright (C) 1998 Nikos Mavroyanopoulos
 *    Copyright (C) 1999,2000 Sascha Schumman, Nikos Mavroyanopoulos
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


/*
   $Id: stdfns.c,v 1.2 2006/01/10 03:47:18 imipak Exp $ 
 */
/**
 * Some of these are wrappers. The idea is to eventually produce an extremely
 * lightweight set of robust, portable functions that are guaranteed to produce
 * a "safe" result, even with bogus inputs. We can't trust native C libraries
 * to validate inputs.
 */





static unsigned char fb_shash_utils_val2char(unsigned char x)
{
	unsigned char out;

	switch(x)
	{
		case 0x0 : { out = '0'; break; }
		case 0x1 : { out = '1'; break; }
		case 0x2 : { out = '2'; break; }
		case 0x3 : { out = '3'; break; }
		case 0x4 : { out = '4'; break; }
		case 0x5 : { out = '5'; break; }
		case 0x6 : { out = '6'; break; }
		case 0x7 : { out = '7'; break; }
		case 0x8 : { out = '8'; break; }
		case 0x9 : { out = '9'; break; }
		case 0xa : { out = 'a'; break; }
		case 0xb : { out = 'b'; break; }
		case 0xc : { out = 'c'; break; }
		case 0xd : { out = 'd'; break; }
		case 0xe : { out = 'e'; break; }
		case 0xf : { out = 'f'; break; }
	}
	return(out);
}



static char * fb_shash_utils_asciify(char *in, long len)
{
	char *ptrIn = in;
	char *buffer = malloc((2 * len) + 1);
	char *ptrOut = buffer;
	long loop;
	memset (buffer, '\0' , (2 * len) + 1);
	
	for (loop = 0; loop < len; loop++, ptrIn++)
	{
		*ptrOut++ = fb_shash_utils_val2char((*ptrIn & 0xf0) >> 4);
		*ptrOut++ = fb_shash_utils_val2char((*ptrIn & 0x0f));
	}
	return(buffer);
}





