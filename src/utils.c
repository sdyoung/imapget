/* utils.c 
 * Various utility functions used throughout imapget.
 *
 * See the LICENSE file included with this disribution.
 */
#include <stdio.h>
#include <sysexits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/utsname.h>
#include "cf.h"
#include "log.h"
#include "utils.h"

#ifndef DEBUG /* these wrappers conflict with dmalloc */
/* the x* series are lazy wrappers for libc calls whose failure probably 
 * indicate we're not going to be able to recover gracefully anyway. */
char *xstrdup(char *s) {
    char *r = strdup(s);

    if(!s) {
        xlog(LOG_ERR, "unable to duplicate string: %s", strerror(errno));
        exit(EX_TEMPFAIL);
    }

    return(r);
}

void *xmalloc(size_t sz) {
    void *p = malloc(sz);

    if(!p) {
        xlog(LOG_ERR, "unable to allocate %lu bytes: %s", sz, strerror(errno));
        exit(EX_TEMPFAIL);
    }

    return(p);
}

void *xrealloc(void *p, size_t sz) {
    void *r = realloc(p, sz);

    if(!r) {
        xlog(LOG_ERR, "unable to resize to %lu bytes", sz);
        exit(EX_TEMPFAIL);
    }

    return(r);
}
#endif

/* These are wrappers for isspace etc so we can use pointers to functions
 * with them.  This is necessary because isspace and friends are often
 * macros. */
int sep_isspace (char c) {
    return(isspace(c));
}

int sep_iscomma (char c) {
    return(c == ',' ? 1 : 0);
}

/* This whole gettokens/freetokens thing needs to be replaced with something
 * less bad, I just had get_next_token laying around.  It needs to be
 * replaced with something that knows about escaping and is better with
 * quoting. */
/* gets the next token in a string.  has a slightly complicated set of 
 * return values:
 * return value = true, *retptr = NULL: the string has ended.
 * return value = false: syntax error (missing quote)
 * return value = true, *retptr != NULL: *retptr has the next token.
 * you must call get_next_token(NULL, retptr) when you are done to release
 * retptr (or you can just free it yourself). *retptr should be null when
 * you first call get_next_token.
 *
 * This is gross, but it actually makes breaking out a string really easy. */
bool get_next_token(char *buf, char **retptr, int (*sepfn)(char c)) {
    static char *oldptr = NULL, *oldpos = NULL;
    char *endp;
    bool quoted = false;

    if(retptr && *retptr) {
        free(*retptr);
        *retptr = NULL;
    }

    if(!buf || (oldpos && !(*oldpos))) {
        oldpos = oldptr = NULL;
        return(true);
    }

    if(oldptr != buf)
        oldptr = oldpos = buf;

    /* find the beginning of the next token */
    while(sepfn(*oldpos))
        oldpos++;

    if(!strlen(oldpos)) {
        oldpos = oldptr = NULL;
        return(true);
    }

    if(*oldpos == '"') {
           endp = strchr(oldpos + 1, '"');
        /* missing endquotes are a syntax error */
        if(!endp)
            return(false);
        quoted = true;
    } else {
        endp = strchr(oldpos, ' ');
    }

    if(!endp)
        endp = oldpos + strlen(oldpos);

    if(quoted == true) {
        *retptr = malloc(endp - oldpos);
        memcpy(*retptr, oldpos + 1, endp - oldpos - 1);
        *(*retptr + (endp - oldpos) - 1) = '\0';
    } else {
        *retptr = malloc(endp - oldpos + 1);
        memcpy(*retptr, oldpos, endp - oldpos);
        *(*retptr + (endp - oldpos)) = '\0';
    }

    if(*endp)
        oldpos = endp + 1;
    else
        oldpos = endp;

    return(true);
}

/* Free a set of tokens previously split with gettokens. */
void freetokens(char **tokens, int tokenc) {
    int i;

    for(i = 0; i < tokenc; i++)
        free(tokens[i]);
    free(tokens);
}

/* split up a string into a set of tokens */
char **gettokens_sep(char *str, int *tokenc, int (*sepfn)(char)) {
    char *curtok = NULL;
    char **tokens = NULL;
    bool stat;

    *tokenc = 0;
    
    if(!strlen(str))
        return(NULL);

    while((stat = get_next_token(str, &curtok, sepfn)) == true 
                                                && curtok) {
        (*tokenc)++;
        tokens = gmrealloc(tokens, sizeof(char *) * *tokenc);
        tokens[*tokenc - 1] = gmstrdup(curtok);
    }

    if(stat == false) {
        freetokens(tokens, *tokenc);
        tokens = NULL;
        *tokenc = 0;
    }

    return(tokens);
}

char **gettokens(char *str, int *tokenc) {
    return(gettokens_sep(str, tokenc, sep_isspace));
}

/* Detach from the current session and close std* */
bool godaemon(void) {
    int pid = fork();

    if(pid < 0) {
        xlog(LOG_ERR, "unable to fork: %s", strerror(errno));
        return(false);
    }

    if(pid > 0)
        exit(EX_OK);
    
    setsid();

    close(0);
    close(1);
    close(2);

    return(true);
}

/* Convert a string using the server's given \n mapping (typically \r\n)
 * using the newline separator crlf.
 *
 * N.B. like everything to do with crlf, this is hideous. */
int crlf_convert(bool *incrlf, char *crlf, char **crlfpos, char *buf, 
            unsigned int bufsz) {
    unsigned int convertedsz = bufsz;
    char *dst = buf, *src = buf;
    char *p;
    unsigned int szdelta = strlen(crlf) - 1;

    if(*crlfpos == NULL)
        *crlfpos = crlf;

    while(src < (buf + bufsz)) {
        if(*incrlf == false) {
            /* keep copying until we come across a CRLF or the
             * end of the buffer. */
            if(*src == *crlf) {
                /* this might be the beginning of a CRLF
                 * sequence. */
                *incrlf = true;
                *crlfpos = crlf;
                src++;
                (*crlfpos)++;
            } else {
                /* this is just a regular character */
                *dst = *src;
                dst++;
                src++;
            }
        } else {
            /* We are in the middle of what may be a CRLF
             * sequence. */
            if(**crlfpos && *src && (*src == **crlfpos)) {
                /* This character matches, advance pointers. */
                src++;
                (*crlfpos)++;
            } else {
                /* This character doesn't match.  is it 
                 * because we reached the end of the CRLF
                 * sequence? */
                if(!(**crlfpos)) {
                    /* Yes.  So we're actually at the
                     * end of the CRLF sequence. */
                    *dst = '\n';
                    dst++;
                    *crlfpos = crlf;
                    *incrlf = false;
                    convertedsz -= szdelta;
                } else {
                    /* No.  This was not really a 
                     * CRLF sequence. */
                    *incrlf = false;
                    /* Output however much of the string
                     * was eaten while we thought it was a crlf
                     * sequence. */
                    for(p = crlf; p < *crlfpos; p++) 
                        *(dst++) = *p;
                    *crlfpos = crlf;
                }
            }
        }
    }

    if(*incrlf == true) {
        if(**crlfpos == '\0') {
            *dst = '\n';
            convertedsz -= szdelta;
            *incrlf = false;
        }
    }

    return(convertedsz);
}

/* Write a From line to the mbox.  We just make something
 * up that looks like From imapget@hostname  timestamp */
char *mbox_genhdr(void) {
    time_t curtm = time(NULL);
    static char outbuf[BUFSIZ];
    struct utsname hostinfo;

    uname(&hostinfo);

    snprintf(outbuf, BUFSIZ, "From imapget@%s  %s", 
                hostinfo.nodename, ctime(&curtm));

    return(outbuf);
}
