#ifndef rc4_h

#define rc4_h

#include <stdlib.h>
#include <string.h>
#include <openssl/rc4.h>

unsigned char* rc4_crypt(long message_length, unsigned char* message, long key_length, unsigned char* key);

#endif