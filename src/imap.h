/* imap.h
 * Prototypes and definitions for IMAP-specific functions. 
 *
 * See the LICENSE file included with this distribution.
 */
#ifndef _IMAP_H
#define _IMAP_H

#define IMAP_DEFAULTPORT 143
#define IMAPS_DEFAULTPORT 993
#define IMAP_RETRY_DELAY 5
#define IMAP_INITIAL_FAILSLEEP 60
#define IMAP_IDLE_TIMEOUT (25 * 60) /* exit and re-enter IDLE ever 25mins */

#define IMAP_TAGLEN 7
#define IMAP_TAGMAX 999999
#define IMAP_TAGFMT "%06u"
#define IMAP_READBUFFER 16384

#ifdef _USE_OPENSSL
/* XXX */
#include <openssl/ssl.h>
#endif

#include <time.h>

enum connstate { IMAP_CONNWAIT, IMAP_CAPABILITY, IMAP_LOGIN, IMAP_SELECT, 
                 IMAP_SEARCH, IMAP_FETCH, IMAP_FETCH_INMSG, IMAP_FETCH_DONE,
                 IMAP_IDLE, IMAP_INIDLE, IMAP_EXITIDLE, IMAP_BYE, IMAP_DELETE,
                 IMAP_COPY, IMAP_CLOSE, IMAP_GETCRLF, IMAP_IN_GETCRLF,
                 IMAP_GETCRLF_DONE, IMAP_AUTH_DONE, IMAP_CRAM_MD5, 
                 IMAP_DIGEST_MD5, IMAP_PLAIN, 
                 IMAP_DIGEST_MD5_DONE, IMAP_STARTTLS, IMAP_INPOLL, IMAP_UNKNOWN, 
                 IMAP_ANYTHING };

bool establish_connections(void);

struct conn {
    enum connstate lastcommand;
    char *buf;
    size_t bufsz;
    int fd;
    char *actual_host;
    void *auth_info;
    unsigned int curtagidx;
    unsigned int highestmsg;
    unsigned int *fetchlist;
    unsigned int *fetchptr;
    unsigned int flistsz;
    unsigned int curfetchmsg;
    bool gotexists;
    bool fetch_inmsg; /* are we in the message body of a FETCH? */
    void *delivery_info;    /* delivery method specific info */
    unsigned int fetch_msgsize;
    bool fetch_deferred;
    char curtag[IMAP_TAGLEN];
    /* capabilities we have identified */
    struct {
        bool cram_md5, digest_md5, plain;
        bool idle;
        bool starttls, logindisabled;
    } caps;
    time_t lastresponsetm; /* last time we heard from the server */
    time_t sleepuntil; /* how long before trying this connection again */
#ifdef _USE_OPENSSL
    bool using_ssl; /* are we using SSL for this connection? */
    SSL *sslobj;
    bool want_write;
#endif
};

/* the R stands for 'Response' */
enum imap_msgtype { IMAPR_OK, IMAPR_NO, IMAPR_BAD, IMAPR_PREAUTH, 
                    IMAPR_CONTINUE, IMAPR_CAPABILITY, IMAPR_BYE,
                    IMAPR_EXISTS, IMAPR_EXPUNGE, IMAPR_ANYTHING, 
                    IMAPR_UNKNOWN };

struct imapmsg {
    char *tag;
    char **tokens;
    int tokenc;
    enum imap_msgtype type;
};

/* main entrypoint to the IMAP state machine */
bool check_connections(void);
void close_connections(void);
bool isany_deferred(void);
void pop_deferred(void);

#endif /* !_IMAP_H */
