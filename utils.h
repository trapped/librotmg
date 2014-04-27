#ifndef rotmg_utils_h

#define rotmg_utils_h

#include <stdlib.h>

char*          reverse_endian (long length, char* buffer);
unsigned char* ltoc           (long num);
long           ctol           (unsigned char* buffer);
unsigned char* stoc           (short num);
short          ctos           (unsigned char* buffer);

#endif