#ifndef rc4_h

#define rc4_h

#include <stdlib.h>
#include <string.h>

char* rc4_crypt(long message_length, char* message, long key_length, char* key);

#endif