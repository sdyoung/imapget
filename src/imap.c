/* imap.c
 * This file contains all the functions used to implement the actual IMAP 
 * protocol itself. It's a big state machine.
 *
 * See the LICENSE file included with this distribution.
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#ifdef _USE_OPENSSL
#include <openssl/ssl.h>
#endif /* _USE_OPENSSL */
#include "cf.h"
#include "imap.h"
#include "log.h"
#include "utils.h"
#include "tcp.h"
#include "deliver.h"
#include "auth.h"

/* This list is used to keep a queue of deferred connections 
 * to ensure we service them in a round-robin order and don't
 * starve any server connection through bad luck. */
struct deferred {
    struct server *sptr;
    struct folder *fptr;
    struct deferred *next;
} *deferrals = NULL, *lastdeferral = NULL;

/* prototypes for the various IMAP response handlers */
static void imap_gentag(struct folder *);
static void imap_manage_fetch(struct server *, struct folder *);
static void start_idle(struct server *, struct folder *);
static void start_exitidle(struct server *, struct folder *);
static void start_bye(struct server *, struct folder *);
static void start_capability(struct server *, struct folder *);
static void start_login(struct server *, struct folder *);
static void start_authentication(struct server *, struct folder *);
static void start_select(struct server *, struct folder *);
static void start_search(struct server *, struct folder *);
static void start_fetch(struct server *, struct folder *);
static void imap_bannerok(struct imapmsg *, struct server *, struct folder *);
static void imap_bannerbye(struct imapmsg *, struct server *, struct folder *);
static void imap_bannerpreauth(struct imapmsg *, struct server *, struct folder *);
static void imap_capability(struct imapmsg *, struct server *, struct folder *);
static void imap_capok(struct imapmsg *, struct server *, struct folder *);
static void imap_unexpected(struct imapmsg *, struct server *, struct folder *);
static void imap_loginok(struct imapmsg *, struct server *, struct folder *);
static void imap_loginbad(struct imapmsg *, struct server *, struct folder *);
static void imap_byeok(struct imapmsg *, struct server *, struct folder *);
static void imap_unexpectedbye(struct imapmsg *, struct server *, struct folder *);
static void imap_selectbad(struct imapmsg *, struct server *, struct folder *);
static void imap_selectok(struct imapmsg *, struct server *, struct folder *);
static void imap_select(struct imapmsg *, struct server *, struct folder *);
static void imap_searchbad(struct imapmsg *, struct server *, struct folder *);
static void imap_search(struct imapmsg *, struct server *, struct folder *);
static void imap_searchok(struct imapmsg *, struct server *, struct folder *);
static void imap_fetch(struct imapmsg *, struct server *, struct folder *);
static void imap_idleok(struct imapmsg *, struct server *, struct folder *);
static void imap_idlebad(struct imapmsg *, struct server *, struct folder *);
static void imap_idle(struct imapmsg *, struct server *, struct folder *);
static void auth_digest_md5(struct imapmsg *, struct server *, struct folder *);
static void auth_cram_md5(struct imapmsg *, struct server *, struct folder *);
static void imap_doneidle(struct imapmsg *, struct server *, struct folder *);
static void imap_freemsg(struct imapmsg *);
static void add_deferred(struct server *sptr, struct folder *fptr);
void pop_deferred(void);

/* Add a connection to the deferral list */
static void add_deferred(struct server *sptr, struct folder *fptr) {
    if(!deferrals) {
        deferrals = lastdeferral = gmmalloc(sizeof(struct deferred));
    } else {
        lastdeferral->next = gmmalloc(sizeof(struct deferred));
        lastdeferral = lastdeferral->next;
    }
    
    lastdeferral->fptr = fptr;
    lastdeferral->sptr = sptr;
    lastdeferral->next = NULL;
    lastdeferral->fptr->conn.fetch_deferred = true;
}

/* Check if anything is deferred */
bool isany_deferred(void) {
    if(deferrals) 
        return(true);
    return(false);
}

/* Un-defer the oldest entry from the deferrals queue. */
void pop_deferred(void) {
    struct deferred *dptr = deferrals; 
    static time_t max_defer = 0;

    if(!deferrals) {
        xlog_bug("bug: pop_deferred called when no connections were deferred");
        return;
    }

    deferrals->fptr->conn.fetch_deferred = false;
    deferrals = deferrals->next;
    if(!deferrals) 
        lastdeferral = NULL;

    if(time(NULL) - dptr->fptr->conn.lastresponsetm > max_defer) {
        max_defer = time(NULL) - dptr->fptr->conn.lastresponsetm;
    }

    start_fetch(dptr->sptr, dptr->fptr); 

    free(dptr);
}

/* Disable a server permanently. */
void disable_server(struct server *sptr) {
    sptr->disabled = true;
    xlog(LOG_ERR, "disabling server %s.", sptr->hostname);
}

/* Disable a folder permanently. */
void disable_folder(struct server *sptr, struct folder *fptr) {
    fptr->disabled = true;
    xlog(LOG_ERR, "disabling folder '%s' on server %s.", 
                    fptr->name, sptr->hostname);
}

/* Calculate how long we should sleep for on this failure.
 * We use a simple exponential backoff. */
unsigned int calc_failsleep(unsigned int oldvalue) {
    unsigned int newvalue;

    if(!oldvalue) 
        newvalue = IMAP_INITIAL_FAILSLEEP;
    else
        newvalue = oldvalue * 2;

    /* did the value overflow? */
    if(newvalue < oldvalue) 
            return(oldvalue);
    return(newvalue);
}

/* Try to establish connections to all of our servers where
 * the connection is curerntly closed. */
bool establish_connections(void) {
    struct server *sptr;
    struct folder *fptr;
    time_t now = time(NULL);
    bool anyenabled = false;
    bool anyfolders;

    /* iterate through all servers */
    for(sptr = config.servers; sptr; sptr = sptr->next) {
        if(sptr->disabled == true)
            continue;
        anyenabled = true;
        if(sptr->consec_failures >= config.maxfailures) {
            sptr->failsleep = calc_failsleep(sptr->failsleep);
            xlog(LOG_WARNING, "server %s has had too many failures; disabling for %u seconds.", 
                            sptr->hostname, sptr->failsleep);
            sptr->wakeup_time = now + sptr->failsleep;
            sptr->consec_failures = 0;
            continue;
        } else if(sptr->wakeup_time) {
            if(sptr->wakeup_time < now) 
                sptr->wakeup_time = 0;
            continue;
        } 

        anyfolders = false;

        /* iterate through all folders on server */
        for(fptr = sptr->folders; fptr; fptr = fptr->next) {
            if(fptr->disabled == true) 
                    continue;

            anyfolders = true;

            if(fptr->conn.fd == -1) {
                /* connection is closed, try and open */
                xlog(LOG_WARNING, "attempting to connect to %s:%d...",
                    sptr->hostname, sptr->port);
                if(tcp_connect(sptr, fptr) == false) {
                    /* tcp_connect reports errors to the user because of 
                     * gethostbyname being weird */
                    sptr->consec_failures++;
                    /* wait 5 seconds between retries */
                    sptr->wakeup_time = time(NULL) + IMAP_RETRY_DELAY;
                    break;
                } 

                sptr->failsleep = 0;
                fptr->conn.lastcommand = IMAP_CONNWAIT;
                xlog(LOG_WARNING, "connected to %s:%d.",
                    sptr->hostname, sptr->port);
                fptr->conn.lastresponsetm = time(NULL);
            }
        }

        if(anyfolders == false) {
            xlog(LOG_ERR, "server '%s' has no folders enabled, disabling.",
                            sptr->hostname);
            disable_server(sptr);
        }
    }
    return(anyenabled);
}

/* Generate a new tag for the next command.  We never pipeline so
 * tags aren't that important, but we do use them to make sure we
 * only process the server response issued for whatever the last
 * command we sent was. */
static void imap_gentag(struct folder *fptr) {
    fptr->conn.curtagidx++;
    if(fptr->conn.curtagidx > IMAP_TAGMAX)
        fptr->conn.curtagidx = 0;

    snprintf(fptr->conn.curtag, IMAP_TAGLEN, IMAP_TAGFMT, fptr->conn.curtagidx);
}

/* Handle data when the last command sent was FETCH.  fptr->conn.buf is
 * always NULL when we reach this point */
static void imap_manage_fetch(struct server *sptr, struct folder *fptr) {
    int bytesleft = deliver_getleft(fptr);
    char inbuf[IMAP_READBUFFER];
    int readbytes;
    
    if(!bytesleft) {
        xlog_bug("bug: tried to manage_fetch a finished message!");
        /* try and get the connection back in to a known state */
        start_search(sptr, fptr);
    }

    readbytes = tcp_read(fptr, inbuf, MIN(bytesleft, IMAP_READBUFFER));

    if(readbytes == -1) {
        if(errno != EAGAIN) {
            xlog(LOG_ERR, "disconnected from server %s: %s",
                    sptr->hostname, strerror(errno));
            conn_teardown(sptr, fptr);
            return;
        }
        xlog_bug("bug: imap_manage_fetch called on an inactive fd (%d)", fptr->conn.fd);
        return;
    }

    if(readbytes > 0) {
        deliver_adddata(sptr, fptr, inbuf, readbytes);
        if(readbytes == bytesleft)
            fptr->conn.lastcommand = IMAP_FETCH_DONE;
    }

    fptr->conn.lastresponsetm = time(NULL);
}

static void imap_manage_getcrlf(struct server *sptr, struct folder *fptr) {
    char inbuf[IMAP_READBUFFER];
    int bytesread;
    char *tmp = NULL;

    bytesread = tcp_read(fptr, inbuf, MIN(IMAP_READBUFFER, 
                                    fptr->conn.fetch_msgsize));
    if(bytesread == -1 && errno != EAGAIN) {
        xlog(LOG_ERR, "disconnected from server %s: %s",
            sptr->hostname, strerror(errno));
        conn_teardown(sptr, fptr);
        return;
    }

    if(bytesread > 0) {
        fptr->conn.buf = gmrealloc(fptr->conn.buf, fptr->conn.bufsz + bytesread);
        memcpy(fptr->conn.buf + fptr->conn.bufsz, inbuf, bytesread);
        fptr->conn.bufsz += bytesread;
        fptr->conn.buf[fptr->conn.bufsz] = '\0';
        fptr->conn.fetch_msgsize -= bytesread;
    }

    if(fptr->conn.bufsz >= fptr->conn.fetch_msgsize) {
        sptr->crlf = gmmalloc(fptr->conn.fetch_msgsize + 1);
        memcpy(sptr->crlf, fptr->conn.buf, fptr->conn.fetch_msgsize);
        sptr->crlf[fptr->conn.fetch_msgsize] = '\0';

        fptr->conn.bufsz -= fptr->conn.fetch_msgsize;

        if(fptr->conn.bufsz) {
            tmp = gmmalloc(fptr->conn.bufsz + 1);
            memcpy(tmp, fptr->conn.buf + fptr->conn.fetch_msgsize, 
                        fptr->conn.bufsz);
            tmp[fptr->conn.bufsz] = '\0';
            free(fptr->conn.buf);
            fptr->conn.buf = tmp;
        } else {
            fptr->conn.buf = NULL;
        }

        fptr->conn.lastcommand = IMAP_GETCRLF_DONE;
    }
}

static void imap_getcrlf_done(struct imapmsg *msg,
                                struct server *sptr, struct folder *fptr) {
    start_fetch(sptr, fptr);
}

static void start_idle(struct server *sptr, struct folder *fptr) {
    if(fptr->conn.flistsz > 0) {
        start_fetch(sptr, fptr);
    } else if(sptr->usepoll == true) {
        fptr->conn.lastcommand = IMAP_INPOLL;
    } else {
        imap_gentag(fptr);
        tcp_sockprintf(fptr, "%s IDLE\r\n", fptr->conn.curtag);
        fptr->conn.lastcommand = IMAP_IDLE;
    }
}

static void start_exitidle(struct server *sptr, struct folder *fptr) {
    tcp_sockprintf(fptr, "DONE\r\n");
    fptr->conn.lastcommand = IMAP_EXITIDLE;
    /* Reset the timeout counter */
    fptr->conn.lastresponsetm = time(NULL);
}

/* Start the process of saying goodbye to a server. */
static void start_bye(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s LOGOUT\r\n", fptr->conn.curtag);
    fptr->conn.lastcommand = IMAP_BYE;
}

static void start_close(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s CLOSE\r\n", fptr->conn.curtag);
    fptr->conn.lastcommand = IMAP_CLOSE;
}

/* Ask server for CAPABILITY. */
static void start_capability(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s CAPABILITY\r\n", fptr->conn.curtag);
    fptr->conn.lastcommand = IMAP_CAPABILITY;
}

static void start_login(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s LOGIN %s %s\r\n", fptr->conn.curtag,
                    sptr->username, sptr->pw);
    fptr->conn.lastcommand = IMAP_LOGIN;
}

static void start_digest_md5(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s AUTHENTICATE DIGEST-MD5\r\n",
                    fptr->conn.curtag);
    fptr->conn.lastcommand = IMAP_DIGEST_MD5;
}

static void start_cram_md5(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s AUTHENTICATE CRAM-MD5\r\n",
                    fptr->conn.curtag);
    fptr->conn.lastcommand = IMAP_CRAM_MD5;
}

/* Start authenticating, however we are supposed to. */
static void start_authentication(struct server *sptr, struct folder *fptr) {
    switch(sptr->authtype) {
        case autonegotiate: 
        case digest_md5:
            if(fptr->conn.caps.digest_md5 == true) {
                start_digest_md5(sptr, fptr);
                break;
            }
        case cram_md5:
            if(fptr->conn.caps.cram_md5 == true) {
                start_cram_md5(sptr, fptr);
                break;
            }
        case login:
#ifdef _USE_OPENSSL
            if(fptr->conn.using_ssl == true) {
                /* if we're using openssl then this is fine */
                start_login(sptr, fptr);
                return;
            } else  
#endif
            if(sptr->authtype != login) {
                xlog(LOG_ERR, "refusing to autonegotiate plaintext login with %s - force "
                              "this with authentication login keyword.", sptr->hostname);
                disable_server(sptr);
                start_bye(sptr, fptr);
            } else if(fptr->conn.caps.logindisabled == true) {
                xlog(LOG_ERR, "server %s does not support plaintext login.", sptr->hostname);
                disable_server(sptr);
                start_bye(sptr, fptr);
            } else {
                start_login(sptr, fptr);
            }
            break;
        /* preauth connections will never enter start_authentication */
        case preauth:
            xlog_bug("bug: start_authentication called on preauth server.");
            start_capability(sptr, fptr);
            break;
    }
}

static void start_select(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s SELECT %s\r\n", fptr->conn.curtag,
                        fptr->name);
    fptr->conn.lastcommand = IMAP_SELECT;
}

static void start_search(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s SEARCH UNSEEN\r\n", fptr->conn.curtag);
    fptr->conn.lastcommand = IMAP_SEARCH;
    fptr->conn.gotexists = false;
}

static void start_delete(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s STORE %d FLAGS.SILENT (\\Deleted)\r\n",
                    fptr->conn.curtag, fptr->conn.curfetchmsg);
    fptr->conn.lastcommand = IMAP_DELETE;
}

static void start_move(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    tcp_sockprintf(fptr, "%s COPY %d %s\r\n",
                        fptr->conn.curtag, fptr->conn.curfetchmsg,
                        fptr->movetarget);
    fptr->conn.lastcommand = IMAP_COPY;
}

/* Pop a message from the stack of messages to be FETCHed. */
static int fetch_pop(struct folder *fptr) {
    int i;

    if(!fptr->conn.fetchptr)
        return(0);

    if(fptr->conn.fetchptr == (fptr->conn.fetchlist + fptr->conn.flistsz)) {
        free(fptr->conn.fetchlist);
        fptr->conn.fetchptr = fptr->conn.fetchlist = NULL;
        fptr->conn.flistsz = 0;
        return(0);
    }

    i = *fptr->conn.fetchptr;
    fptr->conn.fetchptr++;

    return(i);
}

static void start_get_crlf(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);
    /* we get an imaginary header so we can get the line encoding */
    tcp_sockprintf(fptr, "%s FETCH %d (BODY[HEADER.FIELDS (X-imapget-Nonexistant)])\r\n",
                        fptr->conn.curtag, *fptr->conn.fetchlist);
    fptr->conn.lastcommand = IMAP_GETCRLF;
}

static void start_fetch(struct server *sptr, struct folder *fptr) {
    if(quit == true || reloadcf == true) {
        start_bye(sptr, fptr);
        return;
    }

    if(!sptr->crlf && fptr->conn.fetchlist) {
        /* We don't know what kind of CRLF mapping this server uses;
         * get it before we start fetching. */
        start_get_crlf(sptr, fptr);
        return;
    }

    if(deliver_newok_noinc() == true) {
        if((fptr->conn.curfetchmsg = fetch_pop(fptr))) {
            if(deliver_newok() == true) {
                imap_gentag(fptr);
                tcp_sockprintf(fptr, "%s FETCH %d RFC822\r\n",
                                    fptr->conn.curtag, fptr->conn.curfetchmsg);
                fptr->conn.lastcommand = IMAP_FETCH;
            } else {
                add_deferred(sptr, fptr);
            }
        } else {
               if(fptr->conn.gotexists == true)
                   start_search(sptr, fptr);
               else
                   start_idle(sptr, fptr);
        }
    } else {
        add_deferred(sptr, fptr);
    }
}

/* convert a {size}-type argument to an unsigned integer. */
unsigned int get_fetch_size(char *szstr) {
    char *endp;
    int retsz;

    endp = &szstr[strlen(szstr) - 1];

    if(strlen(szstr) < 2 || szstr[0] != '{' || 
            (*endp != '}')) {
        xlog(LOG_WARNING, "malformed message size in response to FETCH request: '%s'", 
                    szstr);
        return(0);
    }

    retsz = strtoul(szstr + 1, &endp, 10);
    return(retsz);
}

/* we reuse some structure parameters in struct folder for the crlf
 * fetch, since they are the same as those used in a regular fetch. */
static void imap_getcrlf(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    int newsz;

    /* we're looking for * num FETCH (BODY[HEADER.FIELDS (blah)] {size} */
    /* XXX yuck */
    if((msg->tokenc > 2 && strcasecmp(msg->tokens[2], "FETCH")) ||
                    (msg->tokenc > 1 && 
                     (atoi(msg->tokens[1]) != *fptr->conn.fetchlist)) ||
                    ((newsz = get_fetch_size(msg->tokens[msg->tokenc - 1]))
                                                 == 0)) 
        return;
    
    fptr->conn.fetch_msgsize = newsz;
    fptr->conn.lastcommand = IMAP_IN_GETCRLF;
}

/* Called when we receieved an OK-type response while waiting for
 * the server to say hello. */
static void imap_bannerok(struct imapmsg *msg, struct server *sptr, 
                    struct folder *fptr) {
    /* If we're configured for preauth, this is an error. */
    if(sptr->authtype == preauth) {
        xlog(LOG_WARNING, "was expecting server %s to preauthenticate, but it requires credentials.", sptr->hostname);
        disable_server(sptr);
        start_bye(sptr, fptr);
    } else {
        /* request CAPABILITY to find out what kinds of authentication
         * this server will support. */
        start_capability(sptr, fptr);
        sptr->consec_failures = 0;
    }
}

/* Called when the server told us to get lost when we tried to
 * connect.  This has nothing to do with TCP-level errors. */
static void imap_bannerbye(struct imapmsg *msg, struct server *sptr,
                    struct folder *fptr) {
    xlog(LOG_WARNING, "server said '%s' when we tried to connect.",
            sptr->hostname);
    disable_server(sptr);
    /* server was rude to us, let's be rude to the server! */
    conn_teardown(sptr,fptr);
}

/* Called when the server tells us we are preauthenticated. */
static void imap_bannerpreauth(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    /* If we're not configured for preauth, this is an error. */
    if(sptr->authtype != preauth) {
        xlog(LOG_WARNING, "server %s is preauthenticating, perhaps a preauth keyword is needed?",
                sptr->hostname);
        disable_server(sptr);
        start_bye(sptr, fptr);
    }
    
    sptr->consec_failures = 0;
    start_capability(sptr, fptr);
}

/* We got a response to our CAPABILITY string. */
static void imap_capability(struct imapmsg *msg, struct server *sptr,
                     struct folder *fptr) {
    int i;
    struct {
        char *capastring;
        bool *bptr;
    } *capptr, caps[] = 
            { { "AUTH=CRAM-MD5", &fptr->conn.caps.cram_md5 },
              { "AUTH=DIGEST-MD5", &fptr->conn.caps.digest_md5 },
              { "STARTTLS", &fptr->conn.caps.starttls },
              { "LOGINDISABLED", &fptr->conn.caps.logindisabled },
              { "IDLE", &fptr->conn.caps.idle },
              { NULL, NULL } };

    for(i = 2; i < msg->tokenc; i++) 
        for(capptr = caps; capptr->capastring; capptr++) 
            if(!strcasecmp(capptr->capastring, msg->tokens[i])) 
                *(capptr->bptr) = true;

    if(sptr->usepoll == false && fptr->conn.caps.idle == false) {
        xlog(LOG_WARNING, "server '%s' doesn't support IDLE - falling back to polling.  You can disable this warning with the use-poll keyword.", sptr->hostname);
        sptr->usepoll = true;
    }
}

#ifdef _USE_OPENSSL
static void start_tls(struct server *sptr, struct folder *fptr) {
    imap_gentag(fptr);

    tcp_sockprintf(fptr, "%s STARTTLS\r\n", fptr->conn.curtag);
    fptr->conn.lastcommand = IMAP_STARTTLS;
}

static void clear_caps(struct folder *fptr) {
    memset(&fptr->conn.caps, 0, sizeof(fptr->conn.caps));
}

static void imap_starttls_ok(struct imapmsg *msg, struct server *sptr,
                         struct folder *fptr) {
    if(do_ssl_connect(sptr, fptr) == false) {
        conn_teardown(sptr, fptr);
    }
    clear_caps(fptr);
    start_capability(sptr, fptr);
}

static void imap_starttls_bad(struct imapmsg *msg, struct server *sptr,
                          struct folder *fptr) {
    xlog(LOG_ERR, "server %s refused SSL negotation, but said it supports it.",
                sptr->hostname);
    disable_server(sptr);
    start_bye(sptr, fptr);
}
#endif /* _USE_OPENSSL */

static void imap_capok(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {

    /* okay, we have all the caps we care about.
     * if we were configured to authenticate, then do so now. 
     * use_imaps = just LOGIN, we're on 993
     * use_imaps == FALSE, try STARTTLS */

#ifdef _USE_OPENSSL 
    if(sptr->use_imaps == true) {
        start_authentication(sptr, fptr);
    } else if(fptr->conn.caps.starttls == true && 
                        fptr->conn.using_ssl == false) {
        start_tls(sptr, fptr);
    } else {
#endif
        if(sptr->authtype != preauth) 
            start_authentication(sptr, fptr);
        else
            start_select(sptr, fptr);
#ifdef _USE_OPENSSL
    }
#endif
}

/* We got something we don't know how to handle for the state
 * we're in. 
 * XXX: We always receive an unexpected ) after a FETCH request,
 * which works out by coincidence but needs to be fixed.
 */
static void imap_unexpected(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    /* do nothing */
}

/* We received an OK response to our login attempt. */
static void imap_loginok(struct imapmsg *msg, struct server *sptr,
                         struct folder *fptr) {
    start_select(sptr, fptr);
}

static void imap_loginbad(struct imapmsg *msg, struct server *sptr,
                          struct folder *fptr) {
    xlog(LOG_ERR, "invalid login/password for server %s.",
            sptr->hostname);
    disable_server(sptr);
    start_bye(sptr, fptr);
}

/* this function gets called no matter what the server says to our 
 * BYE request. */
static void imap_byeok(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    conn_teardown(sptr,fptr);
}

/* We got a BYE when we weren't expecting it. */
static void imap_unexpectedbye(struct imapmsg *msg, struct server *sptr,
                                struct folder *fptr) {
    xlog(LOG_WARNING, "server %s disconnected.",
            sptr->hostname);
    conn_teardown(sptr,fptr);
}

static void imap_selectbad(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    xlog(LOG_ERR, "unable to select mailbox '%s' on server %s",
            fptr->name, sptr->hostname);
    disable_folder(sptr, fptr);
    start_bye(sptr, fptr);
}
    
static void imap_selectok(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    /* start searching */
    start_search(sptr, fptr);
}

static void imap_select(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    if(msg->tokenc == 3) {
        if(!strcasecmp(msg->tokens[2], "EXISTS")) {
            fptr->conn.highestmsg = (unsigned int)strtoul(msg->tokens[1], 
                                        NULL, 10);
        }
    }
}

static void imap_searchbad(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    xlog(LOG_ERR, "unable to search for unseen messages in folder '%s' on server %s.",
            fptr->name, sptr->hostname);
    disable_folder(sptr, fptr);
    start_bye(sptr, fptr);
}

static void imap_search(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    int i;

    if(msg->tokenc > 1 && !strcasecmp(msg->tokens[1], "SEARCH")) {
        if(msg->tokenc == 2)
            return; /* no messages */
        fptr->conn.fetchlist = gmmalloc(sizeof(int) * (msg->tokenc - 2));
        fptr->conn.fetchptr = fptr->conn.fetchlist;
        for(i = 2; i < msg->tokenc; i++) 
            fptr->conn.fetchlist[i - 2] = (unsigned int)strtoul(msg->tokens[i], 
                                                            NULL, 10);
    }

    fptr->conn.flistsz = msg->tokenc - 2;
}

static void imap_searchok(struct imapmsg *msg, struct server *sptr,
                          struct folder *fptr) {
    if(fptr->conn.fetchlist) {
        start_fetch(sptr, fptr);
    } else {
        start_idle(sptr, fptr);
    }
}

static void imap_fetch(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    unsigned int msgsz;
    char *tmp;

    if(msg->tokenc < 5)
        return;
    if(strcasecmp(msg->tokens[2], "FETCH"))
        return;
    
    msgsz = get_fetch_size(msg->tokens[msg->tokenc - 1]);

    if(!msgsz) {
        xlog(LOG_WARNING, "malformed or 0 message size in response to FETCH request: '%s'",
                msg->tokens[4]);
        return;
    }

    /* don't check MSN because we only have one outstanding FETCH
     * at a time. */
    if(deliver_new(fptr, msgsz) == false) 
        return;

    if(fptr->conn.buf) {
        if(fptr->conn.bufsz <= msgsz) {
            deliver_adddata(sptr, fptr, fptr->conn.buf, fptr->conn.bufsz);
            free(fptr->conn.buf);
            fptr->conn.buf = NULL;
            fptr->conn.bufsz = 0;
            fptr->conn.lastcommand = IMAP_FETCH_INMSG;
        } else {
            deliver_adddata(sptr, fptr, fptr->conn.buf, msgsz);
            tmp = gmmalloc(fptr->conn.bufsz - msgsz);
            memcpy(tmp, fptr->conn.buf + msgsz, fptr->conn.bufsz - msgsz); 
            free(fptr->conn.buf);
            fptr->conn.buf = tmp;
            fptr->conn.bufsz -= msgsz;
            /* we're done getting this message. */
            fptr->conn.lastcommand = IMAP_FETCH_DONE;
        }
    }
}

static void imap_donefetch(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    switch(fptr->readaction) {
        case delete_read:
            start_delete(sptr, fptr);
            break;
        case move_read:
            start_move(sptr, fptr);
            break;
        case leave_read:
            start_fetch(sptr, fptr);
            break;
        default:
            xlog(LOG_ERR, "internal error: invalid readaction - disconnecting from %s", 
                    sptr->hostname);
            conn_teardown(sptr,fptr);
    }
}

static void imap_idleok(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    fptr->conn.lastcommand = IMAP_INIDLE;
}
                        
static void imap_idlebad(struct imapmsg *msg, struct server *sptr,
                         struct folder *fptr) {
    /* IDLE didn't work for some reason, try polling. */
    fptr->conn.lastcommand = IMAP_INPOLL;
    sptr->usepoll = true;
    xlog(LOG_ERR, "unable to idle, even though server said it was okay - falling back to polling.");
}

static void imap_idle(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    /* all IDLE EXISTS/EXPUNGE traffic should be handled by
     * imap_exists and imap_expunge. */
    if(msg->type == IMAPR_BAD || 
                    msg->type == IMAPR_NO) {
        xlog(LOG_ERR, "unexpected server error during IDLE!");
        start_bye(sptr, fptr);
        sptr->consec_failures++;
    }
}

static void imap_exists(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    fptr->conn.gotexists = true;
    if(fptr->conn.lastcommand == IMAP_INIDLE) 
        start_exitidle(sptr, fptr);
}

static void imap_expunge(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    if(fptr->conn.highestmsg)
        fptr->conn.highestmsg--;
    else
        xlog(LOG_WARNING, "server '%s' got rid of a nonexistant message!");
}

static void imap_doneidle(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    if(quit == false && reloadcf == false)
        start_search(sptr, fptr);
    else 
        start_close(sptr, fptr);
}

static void imap_deleteok(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    start_fetch(sptr, fptr);
}

static void imap_deletebad(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    xlog(LOG_WARNING, "unable to delete message from server %s",
            sptr->hostname);
    start_fetch(sptr, fptr);
}

static void imap_copyok(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    start_delete(sptr, fptr);
}

static void imap_copybad(struct imapmsg *msg, struct server *sptr,
                         struct folder *fptr) {
    xlog(LOG_WARNING, "unable to copy message on server %s, leaving in original folder",
            sptr->hostname);
    start_fetch(sptr, fptr);
}

static void imap_closedone(struct imapmsg *msg, struct server *sptr,
                        struct folder *fptr) {
    if(msg->type != IMAPR_OK) 
        xlog(LOG_WARNING, "error closing folder '%s' on server %s",
                fptr->name, sptr->hostname);

    start_bye(sptr, fptr);
}

static void auth_digest_md5(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    char *response;

    if(msg->tokenc < 2) {
        xlog(LOG_ERR, "missing challenge text from server '%s'",
                sptr->hostname);
        disable_server(sptr);
        start_bye(sptr, fptr);
        return;
    } 
    
    response = digest_md5_respond(sptr, fptr, msg->tokens[1]);
    tcp_sockprintf(fptr, "%s\r\n", response);
    fptr->conn.lastcommand = IMAP_DIGEST_MD5_DONE;
}

static void auth_digest_md5_done(struct imapmsg *msg, 
                                   struct server *sptr, struct folder *fptr) {
    if(msg->tokenc < 2) {
        xlog(LOG_ERR, "server '%s' sent invalid second DIGEST-MD5 challenge.",
                sptr->hostname);
        disable_server(sptr);
        start_bye(sptr, fptr);
    }

    if(digest_md5_verify(sptr, fptr, msg->tokens[1]) == false) {
        xlog(LOG_ERR, "server '%s' sent incorrent response during DIGEST-MD5 authentication.",
                sptr->hostname);
        disable_server(sptr);
        start_bye(sptr, fptr);
    } else {
        tcp_sockprintf(fptr, "\r\n");
        start_select(sptr, fptr);
    }
}

static void auth_cram_md5(struct imapmsg *msg, struct server *sptr,
                            struct folder *fptr) {
    char *response;

    if(msg->tokenc < 2) {
        xlog(LOG_ERR, "missing challenge text from server '%s'", 
                    sptr->hostname);
        disable_server(sptr);
        start_bye(sptr, fptr);
        return;
    }

    response = cram_md5_respond(sptr, msg->tokens[1]);
    tcp_sockprintf(fptr, "%s\r\n", response);
    fptr->conn.lastcommand = IMAP_AUTH_DONE;
}

static void auth_bad(struct imapmsg *msg, struct server *sptr,
                                struct folder *fptr) {
    xlog(LOG_ERR, "unable to authenticate with '%s'. ", sptr->hostname);
    disable_server(sptr);
    start_bye(sptr, fptr);
}

/* this is where the main statemachine happens, it switches
 * based on what the last command issued was and what the server
 * response is. */
static void manage_connection(struct imapmsg *msg, struct server *sptr, 
                                struct folder *fptr) {
    bool foundfn = false;
    /* this table evaluates from top to bottom and uses the 
     * first hit it finds.  IMAP_ANYTHING and IMAPR_ANYTHING are
     * wildcards - the order in which entries appear is very
     * important. */
    struct {
        enum connstate cmdstate; /* the conn state this entry is valid for */
        enum imap_msgtype type; /* what server response this entry is for */
        bool tagmatch; /* match tags to the last-sent command? */
        void (*fn)(struct imapmsg *, struct server *, struct folder *);
    } *srptr, serverresponses[] = 
                    { { IMAP_CONNWAIT, IMAPR_OK, false, imap_bannerok },
                      { IMAP_CONNWAIT, IMAPR_NO, false, imap_bannerbye },
                      { IMAP_CONNWAIT, IMAPR_BYE, false, imap_bannerbye },
                      { IMAP_CONNWAIT, IMAPR_BAD, false, imap_bannerbye },
                      { IMAP_CONNWAIT, IMAPR_PREAUTH, false, imap_bannerpreauth},
                      { IMAP_BYE, IMAPR_OK, true, imap_byeok },
                      { IMAP_BYE, IMAPR_BAD, true, imap_byeok },
                      { IMAP_BYE, IMAPR_BYE, true, imap_byeok },
                      { IMAP_ANYTHING, IMAPR_BYE, false, imap_unexpectedbye },
                      { IMAP_CAPABILITY, IMAPR_CAPABILITY, false, imap_capability },
                      { IMAP_CAPABILITY, IMAPR_OK, true, imap_capok },
                      { IMAP_LOGIN, IMAPR_OK, true, imap_loginok },
                      { IMAP_LOGIN, IMAPR_NO, true, imap_loginbad },
                      { IMAP_LOGIN, IMAPR_BAD, true, imap_loginbad },
                      { IMAP_SELECT, IMAPR_BAD, true, imap_selectbad },
                      { IMAP_SELECT, IMAPR_NO, true, imap_selectbad },
                      { IMAP_SELECT, IMAPR_OK, true, imap_selectok },
                      { IMAP_SELECT, IMAPR_ANYTHING, false, imap_select },
                      { IMAP_ANYTHING, IMAPR_EXISTS, false, imap_exists },
                      { IMAP_ANYTHING, IMAPR_EXPUNGE, false, imap_expunge },
                      { IMAP_SEARCH, IMAPR_OK, true, imap_searchok },
                      { IMAP_SEARCH, IMAPR_BAD, true, imap_searchbad },
                      { IMAP_SEARCH, IMAPR_NO, true, imap_searchbad },
                      { IMAP_SEARCH, IMAPR_ANYTHING, false, imap_search },
                      { IMAP_FETCH, IMAPR_OK, true, imap_donefetch },
                      { IMAP_FETCH, IMAPR_ANYTHING, false, imap_fetch },
                      { IMAP_FETCH_DONE, IMAPR_OK, true, imap_donefetch },
                      { IMAP_GETCRLF_DONE, IMAPR_OK, true, imap_getcrlf_done },
                      { IMAP_GETCRLF, IMAPR_ANYTHING, false, imap_getcrlf },
                      { IMAP_IDLE, IMAPR_CONTINUE, false, imap_idleok },
                      { IMAP_IDLE, IMAPR_BAD, true, imap_idlebad },
                      { IMAP_IDLE, IMAPR_NO, true, imap_idlebad },
                      { IMAP_INIDLE, IMAPR_ANYTHING, false, imap_idle },
                      { IMAP_EXITIDLE, IMAPR_OK, true, imap_doneidle },
                      { IMAP_EXITIDLE, IMAPR_ANYTHING, false, NULL },
                      { IMAP_DELETE, IMAPR_OK, true, imap_deleteok },
                      { IMAP_DELETE, IMAPR_BAD, true, imap_deletebad },
                      { IMAP_DELETE, IMAPR_NO, true, imap_deletebad },
                      { IMAP_COPY, IMAPR_OK, true, imap_copyok },
                      { IMAP_COPY, IMAPR_BAD, true, imap_copybad },
                      { IMAP_COPY, IMAPR_NO, true, imap_copybad },
                      { IMAP_CLOSE, IMAPR_ANYTHING, true, imap_closedone },
                      { IMAP_CRAM_MD5, IMAPR_CONTINUE, false, auth_cram_md5 },
                      { IMAP_CRAM_MD5, IMAPR_BAD, true, auth_bad },
                      { IMAP_CRAM_MD5, IMAPR_NO, true, auth_bad },
                      { IMAP_DIGEST_MD5, IMAPR_CONTINUE, false, auth_digest_md5 },
                      { IMAP_DIGEST_MD5, IMAPR_BAD, true, auth_bad },
                      { IMAP_DIGEST_MD5, IMAPR_NO, true, auth_bad },
                      { IMAP_DIGEST_MD5_DONE, IMAPR_CONTINUE, false, auth_digest_md5_done },
                      { IMAP_DIGEST_MD5_DONE, IMAPR_BAD, false, auth_bad },
                      { IMAP_DIGEST_MD5_DONE, IMAPR_NO, false, auth_bad },
                      { IMAP_AUTH_DONE, IMAPR_OK, true, imap_loginok },
                      { IMAP_AUTH_DONE, IMAPR_BAD, false, auth_bad },
                      { IMAP_AUTH_DONE, IMAPR_NO, false, auth_bad },
#ifdef _USE_OPENSSL
                      { IMAP_STARTTLS, IMAPR_OK, true, imap_starttls_ok },
                      { IMAP_STARTTLS, IMAPR_BAD, true, imap_starttls_bad },
                      { IMAP_STARTTLS, IMAPR_NO, true, imap_starttls_bad },
#endif /* _USE_OPENSSL */
                      { IMAP_ANYTHING, IMAPR_ANYTHING, false, imap_unexpected },
                      { IMAP_UNKNOWN, IMAPR_UNKNOWN, false, NULL } };

    for(srptr = serverresponses; srptr->cmdstate != IMAP_UNKNOWN; srptr++) {
        if((srptr->cmdstate == fptr->conn.lastcommand ||
            srptr->cmdstate == IMAP_ANYTHING) && 
           (msg->type == srptr->type || 
            srptr->type == IMAPR_ANYTHING)) {
            if((srptr->tagmatch == true && !strcmp(msg->tag, fptr->conn.curtag))
                    || srptr->tagmatch == false) {
                if(srptr->fn)
                    srptr->fn(msg, sptr, fptr);
                foundfn = true;
                break;
            }
        }
    }

    if(foundfn == false) 
        imap_unexpected(msg, sptr, fptr);
}

struct imapmsg *imap_parsemsg(char *str) {
    struct imapmsg *newmsg = gmmalloc(sizeof(struct imapmsg));
    struct msgtypes { 
        char *msg;
        enum imap_msgtype type;
        int pos;
    } *mptr, mtypes[] = 
            { { "OK", IMAPR_OK, 1 },
              { "NO", IMAPR_NO, 1 },
              { "BAD", IMAPR_BAD, 1 },
              { "PREAUTH", IMAPR_PREAUTH, 1 },
              { "CAPABILITY", IMAPR_CAPABILITY, 1 },
              { "BYE", IMAPR_BYE, 1 },
              { "EXISTS", IMAPR_EXISTS, 2 },
              { "EXPUNGE", IMAPR_EXPUNGE, 2 },
              { NULL, IMAPR_UNKNOWN, 2 } };
              

    newmsg->tokens = gettokens(str, &newmsg->tokenc);
    if(!newmsg->tokens) {
        free(newmsg);
        return(NULL);
    } else if(!newmsg->tokenc) {
        freetokens(newmsg->tokens, newmsg->tokenc);
        free(newmsg);
        return(NULL);
    }
    
    newmsg->type = IMAPR_UNKNOWN;

    /* we have at least one token */
    if(!strcmp(newmsg->tokens[0], "+")) {
        /* this is a continuation */
        newmsg->type = IMAPR_CONTINUE;
    } else {
        /* this is a regular response */
        newmsg->tag = newmsg->tokens[0];
    }
        
    for(mptr = mtypes; mptr->msg; mptr++) {
        if(newmsg->tokenc > mptr->pos &&
            !strcasecmp(mptr->msg, newmsg->tokens[mptr->pos])) {
            newmsg->type = mptr->type;
            break;
        }
    }

    return(newmsg);
}

/* Free a struct imapmsg instance. */
static void imap_freemsg(struct imapmsg *msg) {
    if(msg->tokens)
        freetokens(msg->tokens, msg->tokenc);
    free(msg);
}


/* See if we've been waiting too long for a response from the server. */
bool conn_istimedout(struct server *sptr, struct folder *fptr) {
    time_t curtm = time(NULL);

    if((fptr->conn.lastcommand != IMAP_INPOLL &&
                fptr->conn.lastcommand != IMAP_INIDLE) && 
            (fptr->conn.fetch_deferred == false) &&
            (curtm > (fptr->conn.lastresponsetm + sptr->timeout)))
        return(true);
    return(false);
}

/* sleep on all folder file descriptors until there is activity on one of them.
 * this function is also responsible for finding out if a connection has been 
 * dropped, and if so setting it's state and fd appropriately. */
bool check_connections(void) {
    struct server *sptr;
    struct folder *fptr;
    fd_set readfds, writefds;
    struct timeval timeout;
    int max = 0, numactive;
    char *inbuf;
    struct imapmsg *msg;
    bool datapending = false;

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    /* Add all connections to the read set. */
    for(sptr = config.servers; sptr; sptr = sptr->next) {
        for(fptr = sptr->folders; fptr; fptr = fptr->next) {
            if(fptr->conn.fd == -1)
                continue;
            if(max < fptr->conn.fd)
                max = fptr->conn.fd;

#ifdef _USE_OPENSSL
            if(fptr->conn.want_write == true) {
                FD_SET(fptr->conn.fd, &writefds);
            } else
#endif 
            if(fptr->conn.fetch_deferred == false) 
                FD_SET(fptr->conn.fd, &readfds);
    
            if(fptr->conn.buf)
                datapending = true;
        }
    }

    /* we only select for 1 second so we can collect zombies.
     * the timeout is managed by checking how long it's been since
     * we sent our command to the server. */
    timeout.tv_usec = 0;
    if(datapending == false) 
        timeout.tv_sec = 1;
    else 
        timeout.tv_sec = 0;

    /* Go to sleep. */
    numactive = select(max + 1, &readfds, &writefds, NULL, &timeout);

    /* was there an error? */
    if(numactive == -1) {
        if(errno == EINTR)
            return(true);

        xlog(LOG_ERR, "unable to select(): %s", strerror(errno));
        return(false);
    }

    /* iterate over all folders */
    for(sptr = config.servers; sptr; sptr = sptr->next) {
        for(fptr = sptr->folders; fptr; fptr = fptr->next) {
            if(fptr->conn.fd == -1)
                continue;
#ifdef _USE_OPENSSL
            if(FD_ISSET(fptr->conn.fd, &writefds) || 
                    FD_ISSET(fptr->conn.fd, &readfds) || fptr->conn.bufsz || 
                    (fptr->conn.sslobj && 
                     (SSL_pending(fptr->conn.sslobj) > 0))) {
#else
            if(FD_ISSET(fptr->conn.fd, &readfds) || fptr->conn.bufsz) {
#endif /* !_USE_OPENSSL */
                if(fptr->conn.lastcommand != IMAP_INIDLE)
                    fptr->conn.lastresponsetm = time(NULL);
                if(fptr->conn.lastcommand == IMAP_FETCH_INMSG) {
                    imap_manage_fetch(sptr, fptr);
                } else if (fptr->conn.lastcommand == IMAP_IN_GETCRLF) {
                    imap_manage_getcrlf(sptr, fptr);
                } else {
                    inbuf = tcp_readline(sptr, fptr);
                    if(inbuf) {
                        /* we've read in a whole line over the TCP connection;
                         * process it. */
                        msg = imap_parsemsg(inbuf);
                        if(msg) {
                            manage_connection(msg, sptr, fptr);
                            imap_freemsg(msg);
                        }
                        free(inbuf);
                    }
                } 
            } else if(fptr->conn.lastcommand == IMAP_INPOLL &&
                      (time(NULL) - fptr->conn.lastresponsetm) >
                        sptr->pollinterval) {
                start_search(sptr, fptr);
            } else if(fptr->conn.lastcommand == IMAP_INIDLE &&
                      (time(NULL) - fptr->conn.lastresponsetm) > 
                        config.keepalive) {
                start_exitidle(sptr, fptr);
            } else if(fptr->conn.lastcommand != IMAP_INIDLE) {
                if(conn_istimedout(sptr, fptr) == true) {
                    xlog(LOG_WARNING, "connection to server %s timed out.",
                            sptr->hostname);
                    sptr->consec_failures++;
                    conn_teardown(sptr,fptr);
                }
            } 
        }
    }
    return(true);
}

/* Try and gracefully close all connections. */
void close_connections(void) {
    struct server *sptr;
    struct folder *fptr;
    time_t end;
    bool servsleft = true;
    bool announced = false;
    
    while(isany_deferred()) 
        pop_deferred();

    end = time(NULL) + config.dfltimeout;

    while(servsleft == true) {
        servsleft = false;
        for(sptr = config.servers; sptr; sptr = sptr->next) {
            for(fptr = sptr->folders; fptr; fptr = fptr->next) {
                if(fptr->conn.fd != -1) {
                    if(announced == false) {
                        /* first, try and close all connections. */
                        xlog(LOG_WARNING, "waiting %d seconds for all connections to close.",
                                        config.dfltimeout);
                        announced = true;
                    }
                    servsleft = true;
                    if(time(NULL) > end) {
                        xlog(LOG_WARNING, "unable to close connection to %s - forcing disconnect.",
                                sptr->hostname);
                        conn_teardown(sptr, fptr);
                    } else if(fptr->conn.lastcommand == IMAP_INIDLE) {
                        start_exitidle(sptr, fptr);
                    } else if(fptr->conn.lastcommand != IMAP_CLOSE &&
                              fptr->conn.lastcommand != IMAP_BYE &&
                              fptr->conn.lastcommand != IMAP_FETCH_INMSG &&
                              fptr->conn.lastcommand != IMAP_FETCH_DONE &&
                              fptr->conn.lastcommand != IMAP_FETCH) {
                        start_close(sptr, fptr);
                    } 
                }
            }
        }
        check_connections();
    }

    /* next, finish any deliveries in progress. */
    for(sptr = config.servers; sptr; sptr = sptr->next) {
        for(fptr = sptr->folders; fptr; fptr = fptr->next) {
            if(deliver_inprogress(fptr))
                deliver_finishall(fptr);
        }
    }
}

void imap_undefer(void) {
    if(isany_deferred()) 
        pop_deferred();
}
