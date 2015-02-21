/* auth.h
 * Prototypes for our various authentication functions. 
 *
 * See the LICENSE file included with this disribution.
 */
#ifndef _AUTH_H
#define _AUTH_H

#define DIGEST_MD5_RESPONSEBUFFER 8192

struct digest_md5_challenge {
    char *realm;
    char *nonce;
    char *qop;
    unsigned int maxbuf;
    char *charset;
    char *algorithm;
    char *cipher;
    char *auth;
    char *cnonce;
    char *digest_uri;
};

char *cram_md5_respond(struct server *, char *);
char *digest_md5_respond(struct server *, struct folder *, char *);
bool digest_md5_verify(struct server *, struct folder *, char *);

#endif /* !_AUTH_H */
