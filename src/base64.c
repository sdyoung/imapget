/* base64.c - Steven Young <sdyoung@miranda.org>
 * An implmentation of base64.
 *
 * This file is released into the public domain.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cf.h"
#include "utils.h"
#include "base64.h"

/* Our ASCII mapping table doesn't have the first 43 bytes. */
int decodeshift = 43;
/* A mapping of ASCII Base64 character -> integer value. */
static unsigned char dc[] = 
           { 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 
             255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 
             8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 
             23, 24, 25, 255, 255, 255, 255, 255, 255, 26, 27, 28, 29, 
             30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 
             45, 46, 47, 48, 49, 50, 51 };

/* Lookup the value of a character in the base64 decoding table. */
#define val(c) ((c > sizeof(dc) + decodeshift) || (c == '=') ? 0 : dc[c - decodeshift])

/* Determine if a character is a valid Base64 character. */
#define invalid(c) ((c < decodeshift || c >= (sizeof(dc) + decodeshift)) || \
                    (c != '=' && dc[c - decodeshift] == 255))

/* Decode a Base64-encoded buffer.  This is pretty forgiving of malformed
 * input. */
char *base64_decode(char *buf) {
    static char *retp = NULL;
    char *p = buf, *outp;
    int lshift = 2, rshift = 4;

    if(retp) 
        free(retp);

    /* XXX XXX: This code just looks to me like it probably has a buffer
     * overflow or some other horrible security exploit */
    retp = outp = gmmalloc((int)(strlen(buf)*.75) + 1);

    while(*p && strlen(p) > 1) {
        if(invalid(*p)) {
            p++;
            continue;
        }
        *(outp++) = val(*p) << lshift | val(*(p + 1)) >> rshift;
        if((lshift += 2) == 8)
            lshift = 2;
        if((rshift -= 2) == -2) {
            rshift = 4;
            p++;
        }
        p++;
    }

    *outp = '\0';
    return(retp);
}

/* The Base64 alphabet.  ec[value] = the base64 encoding of value. */
static unsigned char ec[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
                            "lmnopqrstuvwxyz0123456789+/";

/* Encode a buffer. */
char *base64_encode(char *buf, int buflen) {
    static char *retp = NULL;
    unsigned char *p = (unsigned char *)buf;
    char *outp;

    if(retp)
        free(retp);
    
    retp = outp = gmmalloc((int)(buflen*1.33 + 8));

    while(*p && buflen >= 3) {
        *(outp++) = ec[(*p >> 2)];
        *(outp++) = ec[(((*p << 4)&0x3F) | (*(p+1) >> 4))];
        *(outp++) = ec[(((*(p+1) << 2)&0x3F) | (*(p+2) >> 6))];
        *(outp++) = ec[(*(p+2)&0x3F)];
        p += 3;
        buflen -= 3;
    }
    if(buflen) {
        *(outp++) = ec[*p >> 2];
        if(buflen == 2) {
            *(outp++) = ec[((*p << 4)&0x3F) | (*(p+1) >> 4)];
            *(outp++) = ec[(*(p+1) << 2)&0x3C];
        } else {
            *(outp++) = ec[(*p << 4)&0x30];
            *(outp++) = '=';
        }
        *(outp++) = '=';
    } 
    *outp = '\0';
    return(retp);
}
