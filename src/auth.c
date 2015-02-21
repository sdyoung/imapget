/* auth.c
 * Implements cram-md5 and digest-md5.
 * 
 * See the LICENSE file included with this disribution.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cf.h"
#include "auth.h"
#include "base64.h"
#include "md5.h"
#include "utils.h"
#include "log.h"

/* Generate a CRAM-MD5 response to a given challenge. */
char *cram_md5_respond(struct server *sptr, char *challenge) {
    char *response_plain;
    char *response;
    char *decoded = base64_decode(challenge);
    int buflen;

    /* An MD5_HMAC'ed string is always 32 chars long. */
    /* username space hmac \0 */
    buflen = strlen(sptr->username) + 1 + 32 + 1;
    response_plain = gmmalloc(buflen);
    
    snprintf(response_plain, buflen, "%s %s", sptr->username, 
                                            MD5_HMAC((unsigned char *)sptr->pw,
                                                     (unsigned char *)decoded));
    response = base64_encode(response_plain, strlen(response_plain));

    free(response_plain);

    return(response);
}

/* Free a DIGEST-MD5 challenge object. */
static void digest_md5_freechallenge(struct digest_md5_challenge *c) {
    if(c->realm)
        free(c->realm);
    if(c->nonce)
        free(c->nonce);
    if(c->qop) 
        free(c->qop);
    if(c->charset)
        free(c->charset);
    if(c->algorithm)
        free(c->algorithm);
    if(c->cipher)
        free(c->cipher);
    if(c->auth)
        free(c->auth);
    if(c->cnonce)
        free(c->cnonce);
    if(c->digest_uri)
        free(c->digest_uri);
    free(c);
}

/* Generate a nonce for our DIGEST-MD5 respones.  This is done
 * by calling rand and then base64 encoding the result. */
#define CNONCE_ENTROPY 8
static char *digest_md5_getcnonce(void) {
    int entropy[CNONCE_ENTROPY];
    int i;
    static int gencount = 0;
    static char *entropystr;

    /* we use gencount so two connections happening in the same second 
     * will not use the same seed */
    srand(time(NULL) + (gencount++));

    for(i = 0; i < CNONCE_ENTROPY; i++) 
        entropy[i] = rand();
        
    entropystr = base64_encode((char *)entropy, sizeof(int) * CNONCE_ENTROPY);
    return(entropystr);
}

/* Figure out what the response value should be for a DIGEST-MD5
 * challenge. */
static char *digest_md5_getresponse(char *username, char *pw, char *realm,
                                   char *nonce, char *nc, char *cnonce,
                                   char *qop, char *uri, bool initial) {
    char *a1, *a2;
    char tmpstr[BUFSIZ];
    unsigned char *digest;

    /* HEX(H(a1hex:nonce:nc:cnonce:qop:a2hex))
     * A1 = H(username:realm:passwd):nonce-value:cnonce-value
     * A2 = "AUTHENTICATE:"uri
     * H(x) = md5 hash */
    
    snprintf(tmpstr, BUFSIZ, "%s:%s:%s", username, realm, pw);
    digest = MD5_digest((unsigned char *)tmpstr, strlen(tmpstr));
    memcpy(tmpstr, digest, 16);
    snprintf(tmpstr+16, BUFSIZ, ":%s:%s", nonce, cnonce);
    a1 = gmstrdup(MD5_hash((unsigned char *)tmpstr, 
                           16+1+strlen(nonce)+1+strlen(cnonce)));

    snprintf(tmpstr, BUFSIZ, "%s:%s", initial == true ? "AUTHENTICATE" : "",
                                        uri);
    a2 = MD5_hash((unsigned char *)tmpstr, strlen(tmpstr));

    snprintf(tmpstr, BUFSIZ, "%s:%s:%s:%s:%s:%s",
            a1, nonce, nc, cnonce, qop, a2);

    free(a1);

    return(MD5_hash((unsigned char *)tmpstr, strlen(tmpstr)));
}

/* Generate a DIGEST-MD5 response to a given challenge.  This doesn't
 * fully implement RFC 2831, because most servers don't either (and
 * might even get confused if we tried).  It also doesn't support
 * reauthentication.  Despite all this, it should work with most
 * servers. */
char *digest_md5_respond(struct server *sptr, struct folder *fptr, 
                            char *challenge) {
    struct digest_md5_challenge *challengevals;
    int tokenc, i;
    char *key, *val, *p, *decoded, **tokens, *response;
    char responsestr[DIGEST_MD5_RESPONSEBUFFER];

    decoded = base64_decode(challenge);
    tokens = gettokens_sep(decoded, &tokenc, sep_iscomma);

    challengevals = gmmalloc(sizeof(struct digest_md5_challenge));
    memset(challengevals, 0, sizeof(struct digest_md5_challenge));

    for(i = 0; i < tokenc; i++) {
        key = tokens[i];
        val = strchr(key, '=');
        if(!val && strlen(val) <= 1)
            continue;
        *val = '\0';
        val++;
        
        if(*val == '"') {
            /* remove quotes */
            val++;
            if((p = strrchr(val, '"'))) 
                *p = '\0';
        }
        /* There are several limitations implied by this code:
         * in servers with more than one realm, the first will
         * be used.  In other values that can appear more than
         * once, the last value will be used. */
        if(!strcasecmp(key, "realm") && !challengevals->realm)
            challengevals->realm = gmstrdup(val);
        else if(!strcasecmp(key, "nonce"))
            challengevals->nonce = gmstrdup(val);
        else if(!strcasecmp(key, "qop"))
            challengevals->qop = gmstrdup(val);
        else if(!strcasecmp(key, "maxbuf"))
            challengevals->maxbuf = strtoul(val, NULL, 10);
        else if(!strcasecmp(key, "charset"))
            challengevals->charset = gmstrdup(val);
        else if(!strcasecmp(key, "algorithm"))
            challengevals->algorithm = gmstrdup(val);
        else if(!strcasecmp(key, "cipher"))
            challengevals->cipher = gmstrdup(val);
        else if(!strcasecmp(key, "auth"))
            challengevals->auth = gmstrdup(val);
    }

    /* Do some verification of the challenge.  We make up defaults for
     * everything we can - the only value without which we cannot 
     * proceed is the nonce. */
    if(!challengevals->realm)
        challengevals->realm = sptr->hostname;
    if(!challengevals->algorithm) {
        challengevals->algorithm = "md5-sess";
    } else if(strcasecmp(challengevals->algorithm, "md5-sess")) {
        xlog(LOG_ERR, "server '%s' uses unknown authentication algorithm '%s'.",
                sptr->hostname, challengevals->algorithm);
        freetokens(tokens, tokenc);
    }
    if(!challengevals->nonce) {
        xlog(LOG_ERR, "server '%s' did not provide a usable DIGEST-MD5 challenge.",
                    sptr->hostname);
        freetokens(tokens, tokenc);
        return(NULL);
    }

    /* okay, let's generate a response.  Note the hardcoded nonce-count.
     * This is because we do not support reauthentication. */
    challengevals->digest_uri = gmmalloc(5 + strlen(sptr->hostname) + 1);
    snprintf(challengevals->digest_uri, 5 + strlen(sptr->hostname) + 1, 
                "imap/%s", sptr->hostname);
    challengevals->cnonce = gmstrdup(digest_md5_getcnonce());

    response = gmstrdup(digest_md5_getresponse(sptr->username, sptr->pw, 
                                      challengevals->realm, 
                                      challengevals->nonce,
                                      "00000001", 
                                      challengevals->cnonce, 
                                      "auth", 
                                      challengevals->digest_uri, true));

    snprintf(responsestr, DIGEST_MD5_RESPONSEBUFFER, 
        "username=\"%s\", nonce=\"%s\", cnonce=\"%s\", nc=00000001, qop=auth, "
        "digest-uri=\"%s\", realm=\"%s\", response=%s",
        sptr->username, challengevals->nonce, challengevals->cnonce, 
        challengevals->digest_uri, challengevals->realm, response);

    freetokens(tokens, tokenc);
    fptr->conn.auth_info = (void *)challengevals;
    return(base64_encode(responsestr, strlen(responsestr)));
}

/* Verify the server's second DIGEST-MD5 challenge. */
bool digest_md5_verify(struct server *sptr, struct folder *fptr, 
                       char *response) {
    char *decoded = base64_decode(response);
    struct digest_md5_challenge *challenge;
    char *shouldbe;

    challenge = (struct digest_md5_challenge *)fptr->conn.auth_info;
    shouldbe = digest_md5_getresponse(sptr->username, sptr->pw,
                                      challenge->realm, challenge->nonce,
                                      "00000001", challenge->cnonce, "auth", 
                                      challenge->digest_uri,
                                      false);
    digest_md5_freechallenge(challenge);
    fptr->conn.auth_info = NULL;

    if(strncasecmp(decoded, "rspauth=", 8)) 
        return(false);

    decoded += 8;
    if(strcasecmp(decoded, shouldbe)) 
        return(false);
    return(true);
}
