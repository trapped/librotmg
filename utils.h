#ifndef rotmg_utils_h

#define rotmg_utils_h

#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

unsigned char* reverse_endian (long length, unsigned char* buffer);
unsigned char* ltoc           (long num);
long           ctol           (unsigned char* buffer);
unsigned char* stoc           (short num);
short          ctos           (unsigned char* buffer);
unsigned char* b64_enc		  (int length, unsigned char* data);

#endif