/* md5.h
 * Structures and prototypes for md5.
 *
 * This is released into the public domain.
 */
#ifndef _MD5_H
#define _MD5_H
typedef unsigned long uint32;

struct MD5Context {
    uint32 buf[4];
    uint32 bits[2];
    unsigned char in[64];
    unsigned char digest[16];
};

char *MD5_tohex(unsigned char *);
char *MD5_HMAC(unsigned char *, unsigned char *);
char *MD5_hash(unsigned char *, unsigned int);
unsigned char *MD5_digest(unsigned char *key, unsigned int keylen);
#endif /* !_MD5_H */
