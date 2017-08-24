#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <string.h>
#include "ntru_crypto.h"

static uint8_t 
	get_entropy(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{

    static uint8_t seed[81];

    srand(time(NULL)); 
    int i; 
    for (i = 0; i < sizeof(seed); i++) 
    { 
        seed[i] = rand() % 256; 
    }

    static size_t index;

    if (cmd == INIT) {
        /* Any initialization for a real entropy source goes here. */
        index = 0;
        return 1;
    }

    if (out == NULL)
        return 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        /* Here we return the number of bytes needed from the entropy
         * source to obtain 8 bits of entropy.  Maximum is 8.
         */
        *out = 1;                       /* this is a perfectly random source */
        return 1;
    }

    if (cmd == GET_BYTE_OF_ENTROPY) {
        if (index == sizeof(seed))
            return 0;                   /* used up all our entropy */

        *out = seed[index++];           /* deliver an entropy byte */
        return 1;
    }
    return 0;
}

static uint8_t const pers_str[] = {
    'S', 'S', 'L', ' ', 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n'
};

void DumpHex(const unsigned char* buf, int len)
{
    int i;
    for(i=0;i<len;i++)
    {
      if(i&0x1f) printf(":");
      printf("%02X",buf[i]);
      if((i&0x1f)==0x1f) printf("\n");
    }
    printf("\n");
}

