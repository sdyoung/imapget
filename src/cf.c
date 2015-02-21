/* cf.c
 * This file contains all the code used for parsing and managing configuration
 * information. 
 *
 * See the LICENSE file included with this distribution.
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include "cf.h"
#include "log.h"
#include "utils.h"
#include "folder.h"
#include "deliver.h"
#include "secrets.h"

/* This configuration is zeroed at startup and sanity checked afterwards. 
 * The enums present have their default values set to equal zero. */
struct config config = {
    1,
    false,
    true,
    NULL,
    NULL,
#ifdef _USE_OPENSSL
    NULL,
#endif /* _USE_OPENSSL */
    30,
    pipeto,
    "procmail",
    NULL,
    NULL,
    5,
    autonegotiate,
    leave_read,
    NULL,
    600,
    10,
    300,
#ifdef _USE_OPENSSL
    NULL
#endif /* _USE_OPENSSL */
};

/* prototypes for the various keyword handlers */
static bool cf_setuint(char **, int, void *);
#ifdef _USE_OPENSSL
static bool cf_setsecrets(char **, int, void *);
#endif /* _USE_OPENSSL */
static bool cf_setdeliverymech(char **, int, void *);
static bool cf_setuint(char **, int, void *);
static bool cf_setbool(char **, int, void *);
static bool cf_setlogfile(char **, int, void *);
static bool cf_setdfl_moveread(char **, int, void *);
static bool cf_setdfl_delread(char **, int, void *);
static bool cf_setdfl_leaveread(char **, int, void *);
static bool cf_startserver(char **, int, void *);
static bool cf_endserver(char **, int, void *);
static bool cf_addfolder(char **, int, void *);
static bool cf_setsrv_moveread(char **, int, void *);
static bool cf_setsrv_delread(char **, int, void *);
static bool cf_setsrv_leaveread(char **, int, void *);
static bool cf_setstr(char **, int, void *);
static bool cf_setauth(char **, int, void *);
static bool cf_setdfl_auth(char **, int, void *);
#ifndef _USE_OPENSSL
static bool cf_ssl_notsupported(char **, int, void *);
#endif

/* store the path to the config we're reading */
static char *cfpath = NULL;
/* cfhandlers are sets of keyword/function to pointer pairs.  a given
 * function is called when a certain keyword is encountered.  by 
 * swapping around the active cfhandler we can enter and exit different
 * scopes where different commandsets are available. */
struct cfhandler {
    char *keyword;
    int numargs;
    /* tokens, tokencount, linenum, arg */
    bool (*kfn)(char **, int, void *);
    void *arg;
};

/* we declare this in advance and zero it out and clone it as
 * servers are added.. that's so we can pass static addresses as
 * parameters to various keyword handlers in the arg field of the
 * serverkeywords[] handler set */

static struct server newserver;

/* cfhandler block for global keywords */
static struct cfhandler gblkeywords[] = 
    { { "authentication", 2, cf_setdfl_auth, NULL },
      { "keepalive", 2, cf_setuint, &config.keepalive },
      { "timeout", 2, cf_setuint, &config.dfltimeout },
#ifdef _USE_OPENSSL
      { "encrypted-secrets", 2, cf_setsecrets, NULL },
#else
      { "encrypted-secrets", 2, cf_ssl_notsupported, NULL },
#endif
      { "deliver-mechanism", 3, cf_setdeliverymech, NULL },
      { "deliver-maxconcurrency", 2, cf_setuint, &config.maxdeliveries },
      { "log-syslog", 1, cf_setbool, &config.logsyslog },
      { "log-file", 2, cf_setlogfile, NULL },
      { "move-read", 3, cf_setdfl_moveread, NULL },
      { "delete-read", 2, cf_setdfl_delread, NULL },
      { "leave-read", 2, cf_setdfl_leaveread, NULL },
      { "verbose", 2, cf_setuint, &config.verbose, },
      { "runforeground", 1, cf_setbool, &config.nobg },
      { "server", 2, cf_startserver, NULL },
#ifdef _USE_OPENSSL
      { "imaps-server", 2, cf_startserver, NULL },
#else
      { "imaps-server", 2, cf_ssl_notsupported, NULL },
#endif
      { "timeout", 2, cf_setuint, &config.dfltimeout },
      { "maximum-consecutive-failures", 2, cf_setuint, &config.maxfailures },
      { "pollinterval", 2, cf_setuint, &config.pollinterval },
      { NULL, 0, NULL, NULL } };

/* cfhandler block for server keywords */
static struct cfhandler serverkeywords[] = 
    { { "endserver", 1, cf_endserver, NULL },
      { "username", 2, cf_setstr, &newserver.username },
      { "password", 2, cf_setstr, &newserver.pw },
      { "checkfolder", 2, cf_addfolder, NULL },
      { "authentication", 2, cf_setauth, NULL },
      { "move-read", 3, cf_setsrv_moveread, NULL },
      { "delete-read", 2, cf_setsrv_delread, NULL },
      { "leave-read", 2, cf_setsrv_leaveread, NULL },
      { "timeout", 2, cf_setuint, &newserver.timeout },
      { "use-poll", 1, cf_setbool, &newserver.usepoll },
      { "pollinterval", 2, cf_setuint, &newserver.pollinterval },
      { NULL, 0, NULL } }; 
/* we start out in the global keyword handler context */
static struct cfhandler *curhandler = gblkeywords;

/* global config handlers */
/* set an unsigned int passed in arg to the value of the second argument */
static bool cf_setuint(char **tokens, int lc, void *arg) {
    unsigned int *p = (unsigned int *)arg;

    *p = (unsigned int) strtoul(tokens[1], NULL, 10);

    /* make sure the number is valid.  error checking from strtoul seems
     * iffy */
    if((*p == ULONG_MAX && errno == ERANGE) ||
       (*p == 0 && errno == EINVAL)) {
        xlog(LOG_ERR, "%s:%d: invalid number specified in argument", cfpath, 
                lc);
        return(false);
    }

    return(true);
}

/* set a boolean variable passed in arg to true */
static bool cf_setbool(char **tokens, int lc, void *arg) {
    bool *p = (bool *)arg;

    *p = true;
    return(true);
}

#ifndef _USE_OPENSSL
static bool cf_ssl_notsupported(char **tokens, int lc, void *arg) {
    xlog(LOG_ERR, "%s:%d: keyword %s not supported because imapget was not compiled with SSL support.", cfpath, lc, tokens[0]);
    return(false);
}
#endif

#ifdef _USE_OPENSSL
static bool cf_setsecrets(char **tokens, int lc, void *arg) {
    config.encrypted_secrets = gmstrdup(tokens[1]);
    /* we ignore the return value, because this is allowed
     * to fail */
    readsecrets();
    return(true);
}
#endif

static char **new_deliverargs(char *str) {
    char **ret;
    int retc;

    ret = gettokens(str, &retc);
    ret = gmrealloc(ret, sizeof(char *) * (retc + 1));
    ret[retc] = NULL;
    return(ret);
}

/* set our delivery mechanism. */
static bool cf_setdeliverymech(char **tokens, int lc, void *arg) {
    if(!strcasecmp(tokens[1], "pipeto")) {
        config.deliverytype = pipeto;
        config.deliverargs = new_deliverargs(tokens[2]);
        config.delivertarget = gmstrdup(config.deliverargs[0]);
    } else if(!strcasecmp(tokens[1], "mbox")) {
        config.deliverytype = mbox;
        config.delivertarget = gmstrdup(tokens[2]);
    } else if(!strcasecmp(tokens[1], "maildir")) { 
        config.deliverytype = maildir;
        config.delivertarget = gmstrdup(tokens[2]);
    } else {
        xlog(LOG_ERR, "%s:%d: expected either pipeto, mbox or maildir as argument to "
                      "'delivery-mechanism'", cfpath, lc);
        return(false);
    }

    return(true);
}

static bool cf_setlogfile(char **tokens, int lc, void *arg) {
    config.logpath = gmstrdup(tokens[1]);

    return(true);
}

static bool cf_setdfl_moveread(char **tokens, int lc, void *arg) {
    /* in the global section, the second argument must be * */
    if(strcasecmp(tokens[1], "*")) {
        xlog(LOG_ERR, "%s:%d: only * is allowed as the source folder argument in the global "
                      "configuration section for 'move-read' on line %d", cfpath, lc);
        return(false);
    }

    config.dflreadaction = move_read;
    config.dflmovetarget = gmstrdup(tokens[2]);
    return(true);
}

static bool cf_setdfl_readaction(char **tokens, int lc, enum readaction set) {
    if(strcasecmp(tokens[1], "*")) {
        xlog(LOG_ERR, "%s:%d: only * is allowed as the source folder argument in the global "
                      "configuration section for '%s'", 
                      cfpath, lc, tokens[0]);
        return(false);
    }

    config.dflreadaction = set;
    return(true);
}

static bool cf_setdfl_delread(char **tokens, int lc, void *arg) {
    return(cf_setdfl_readaction(tokens, lc, delete_read));
}

static bool cf_setdfl_leaveread(char **tokens, int lc, void *arg) {
    return(cf_setdfl_readaction(tokens, lc, leave_read));
}

/* this function moves us into server context.  This function is a lot more 
 * tolerant of errors than the rest because if there is an error on the 
 * 'server' line, we still want to end up in the right context so the user 
 * doesn't get a ton of incorrect error messages because of one typo. */
static bool cf_startserver(char **tokens, int lc, void *arg) {
    int newport;
    bool isok = true;
    char *p;

    memset(&newserver, 0, sizeof(newserver));

#ifdef _USE_OPENSSL
    if(!strcasecmp(tokens[0], "imaps-server")) {
        newserver.port = IMAPS_DEFAULTPORT;
        newserver.use_imaps = true;
    } else {
        newserver.port = IMAP_DEFAULTPORT;
    }
#else
    newserver.port = IMAP_DEFAULTPORT;
#endif /* _USE_OPENSSL */

    if((p = strchr(tokens[1], ':'))) {
        /* there is a port specified here, maybe */
        if(strlen(p) == 1) {
            xlog(LOG_ERR, "%s:%d: expected port after : in hostname", 
                cfpath, lc);
            /* we don't error return so we're in the right context
             * at least when we finish so the user doesn't
             * get a deluge of incorrect error messages */
            isok = false;
        } else { 
            /* strlen(p) is > 1 */
            newport = strtoul(p + 1, NULL, 10);
            if((newport == ULONG_MAX && errno == ERANGE) ||
               (newport == 0 && errno == EINVAL)) {
                xlog(LOG_ERR, "%s:%d: invalid number specified as server port", 
                    cfpath, lc);
                isok = false;
            } else 
                newserver.port = newport;
        }
        *p = '\0';
    } 

    if(!strlen(tokens[1])) {
        xlog(LOG_ERR, "%s:%d: missing server hostname", cfpath, lc);
        isok = false;
    }

    newserver.hostname = gmstrdup(tokens[1]);
    /* set the server defaults from the global set */
    newserver.timeout = config.dfltimeout;
    newserver.authtype = config.dflauth;
    newserver.pollinterval = config.pollinterval;
    newserver.dflreadaction = config.dflreadaction;
    if(config.dflmovetarget)
        newserver.dflmovetarget = gmstrdup(config.dflmovetarget);

    /* flip into server context */
    curhandler = serverkeywords;
    return(isok);
}

/* free all the folders of a server */
static void freefolders(struct folder *f) {
    struct folder *fp;

    do {
        fp = f->next;

        free(f->name);
        if(f->movetarget)
            free(f->movetarget);

        free(f);
    } while(fp);
}
        
/* free a server that has not itself been malloced */
static void free_static_server(struct server *s) {
    free(s->hostname);
    free(s->dflmovetarget);
    freefolders(s->folders);
}

/* exit server context */
static bool cf_endserver(char **tokens, int lc, void *arg) {
    struct server *newp = gmmalloc(sizeof(struct server));
    bool isok = true;
#ifdef _USE_OPENSSL
    char *tmp;
#endif /* _USE_OPENSSL */

    /* no folders defined - not a fatal error, we just ignore it */
    if(!newserver.folders) {
        xlog(LOG_WARNING, "%s:%d: server '%s' has no folders defined, ignoring...",
                cfpath, lc, newserver.hostname);
        isok = false;
    } 
#ifdef _USE_OPENSSL
    if(!newserver.username && (newserver.authtype != preauth)) {
#else
    if((!newserver.pw || !newserver.username) && 
            (newserver.authtype != preauth)) {
#endif
        xlog(LOG_WARNING, "%s:%d: server '%s' is missing authentication credentials, ignoring...",
                cfpath, lc, newserver.hostname);
        isok = false;
    }

    if(isok == false) {
        free_static_server(&newserver);
        curhandler = gblkeywords;
        return(true);
    }

    /* clone the newserver object.  note the new server object
     * gets newserver's folders pointer. */
    memcpy(newp, &newserver, sizeof(struct server));
    memset(&newserver, 0, sizeof(struct server));

#ifdef _USE_OPENSSL
    if(!newp->pw) {
        tmp = find_secret(newp->hostname, newp->username,
                newp->port);
        if(!tmp) {
            newp->next = config.nopassword_servers;
            config.nopassword_servers = newp;
        } else {
            newp->pw = gmstrdup(tmp);
        }
    }
    if(newp->pw) {    
#endif /* _USE_OPENSSL */
        /* add new server to linked list */
        newp->next = config.servers;
        config.servers = newp;
#ifdef _USE_OPENSSL
    }
#endif /* _USE_OPENSSL */
    /* back to global context */
    curhandler = gblkeywords;
    return(true);
}

static bool cf_setstr(char **tokens, int lc, void *arg) {
    char **p = (char **)arg;

    *p = gmstrdup(tokens[1]);

    return(true);
}

static bool cf_addfolder(char **tokens, int lc, void *arg) {
    struct folder *newf = gmmalloc(sizeof(struct folder));

    memset(newf, 0, sizeof(struct folder));

    newf->name = gmstrdup(tokens[1]);
    newf->conn.fd = -1;
    newf->readaction = newserver.dflreadaction;
    if(newserver.dflmovetarget)
        newf->movetarget = gmstrdup(newserver.dflmovetarget);
    
    newf->next = newserver.folders;
    newserver.folders = newf;

    return(true);
}

/* Set authentication type. */
static bool cf_setauth_ptr(char **tokens, int lc, enum authtype *arg) {
    if(!strcasecmp(tokens[1], "cram-md5")) {
        *arg = cram_md5;
    } else if(!strcasecmp(tokens[1], "digest-md5")) {
        *arg = digest_md5;
    } else if(!strcasecmp(tokens[1], "preuath")) {
        *arg = preauth;
    } else if(!strcasecmp(tokens[1], "login")) {
        *arg = login;
    } else {
        xlog(LOG_ERR, "%s:%d: invalid/unsupported authentication type '%s' specified.", 
            cfpath, lc, tokens[1]);
        return(false);
    }

    return(true);
}

static bool cf_setdfl_auth(char **tokens, int lc, void *arg) {
    return(cf_setauth_ptr(tokens, lc, &config.dflauth));
}

static bool cf_setauth(char **tokens, int lc, void *arg) {
    return(cf_setauth_ptr(tokens, lc, &newserver.authtype));
}

/* XXX I need code factored out of me. */
static bool cf_setsrv_readaction(char **tokens, int lc, enum readaction action, char *movetarget) {
    struct folder *f;

    /* wildcard? */
    if(!strcmp(tokens[1], "*")) {
        /* yes, operate on server and not on specific folder. */
        newserver.dflreadaction = action;

        if(newserver.dflmovetarget) 
            free(newserver.dflmovetarget);

        if(movetarget) 
            newserver.dflmovetarget = gmstrdup(movetarget);
        else
            newserver.dflmovetarget = NULL;

        /* set all non-explicitly-set folders to the new default */
        for(f = newserver.folders; f; f = f->next) {
            if(f->readaction_override == false) {
                f->readaction = action;
                if(f->movetarget)
                    free(f->movetarget);
                if(movetarget)
                    f->movetarget = gmstrdup(movetarget);
                else
                    f->movetarget = NULL;
            }
        }
    } else {
        if(!(f = findfolder(newserver.folders, tokens[1]))) {
            xlog(LOG_ERR, "%s:%d: tried to set read-action property for undefined folder '%s'",
                cfpath, lc, tokens[1]);
            return(false);
        }

        f->readaction = action;
        if(f->movetarget)
            free(f->movetarget);

        if(movetarget) 
            f->movetarget = gmstrdup(movetarget);
        else
            f->movetarget = NULL;

        f->readaction_override = true;
    }
    return(true);
}

static bool cf_setsrv_moveread(char **tokens, int lc, void *arg) {
    return(cf_setsrv_readaction(tokens, lc, move_read, tokens[2]));
}
        
static bool cf_setsrv_delread(char **tokens, int lc, void *arg) {
    return(cf_setsrv_readaction(tokens, lc, delete_read, NULL));
}

static bool cf_setsrv_leaveread(char **tokens, int lc, void *arg) {
    return(cf_setsrv_readaction(tokens, lc, leave_read, NULL));
}

/* remove comments from a line */
static void killcomments(char *s) {
    char *p;

    if(s && (p = strchr(s, '#')))
        *p = '\0';
}

/* XXX fill me in */
static bool cf_sanity_check(void) {
#ifdef _USE_OPENSSL
    if(!config.servers && !config.nopassword_servers) {
#else
    if(!config.servers) {
#endif
        xlog(LOG_ERR, "no servers configured!");
        return(false);
    }
    return(true);
}

/* read in a given configuration. */
bool readconfig(char *cfp) {
    FILE *cf;
    char inbuf[BUFSIZ], **tokens;
    int lc = 0, tokenc;
    bool validkey; /* is the current keyword okay? */
    bool validfile = true; /* does the file not contain syntax errors? */
    struct cfhandler *cfhptr;

    cfpath = cfp;

    if(!(cf = fopen(cfpath, "r"))) {
        xlog(LOG_ERR, "unable to read config file '%s': %s", cfpath,
            strerror(errno));
        return(false);
    }

    while(fgets(inbuf, BUFSIZ, cf)) {
        lc++;

        stripnl(inbuf);
        killcomments(inbuf); /* replace the first # with \0 */
        tokens = gettokens(inbuf, &tokenc);
        /* empty line? */
        if(!tokenc)
            continue;
        if(!strlen(tokens[0])) {
            freetokens(tokens, tokenc);
            continue;
        }
        /* find the appropriate handler function for this keyword */
        validkey = false;
        for(cfhptr = curhandler; cfhptr->keyword; cfhptr++) {
            if(!strcasecmp(cfhptr->keyword, tokens[0])) {
                if(tokenc < cfhptr->numargs) {
                    xlog(LOG_ERR, "%s:%d: insufficient arguments to keyword '%s'",
                            cfpath, lc, cfhptr->keyword);
                    validfile = false;
                    break;
                } else if(tokenc > cfhptr->numargs) {
                    xlog(LOG_ERR, "%s:%d: extra argument(s) to keyword '%s'",
                            cfpath, lc, cfhptr->keyword);
                    validfile = false;
                    break;
                }
                validkey = true;
                if(cfhptr->kfn(tokens, lc, cfhptr->arg) == false) 
                    validfile = false;
                break;
            }
        }

        /* was the right handler found? */
        if(validkey == false) {
            /* no */
            validfile = false;
            xlog(LOG_ERR, "%s:%d: unknown or invalid keyword '%s'", 
                cfpath, lc, tokens[0]);
            /* XXX should we look in other cfhandler blocks to see if they 
             * are specifying a keyword in the wrong scope? it would lead to better
             * error reporting. */
        }

        freetokens(tokens, tokenc);
    }

    fclose(cf);

    deliver_setfns();

    if(validfile == true)
        return(cf_sanity_check());
    else
        return(false);
}

void freecf(void) {
    struct server *sptr, *nextsptr;
    struct folder *fptr, *nextfptr;

    if(config.logpath)
        free(config.logpath);
    
    for(sptr = config.servers; sptr;) {
        for(fptr = sptr->folders; fptr;) {
            nextfptr = fptr->next;
            if(fptr->name)
                free(fptr->name);
            if(fptr->movetarget)
                free(fptr->movetarget);
            free(fptr);
            fptr = nextfptr;
        }

        nextsptr = sptr->next;
        if(sptr->hostname)
            free(sptr->hostname);
        if(sptr->username) {
            memset(sptr->username, 0, strlen(sptr->username));
            free(sptr->username);
        }
        if(sptr->pw) {
            memset(sptr->pw, 0, strlen(sptr->pw));
            free(sptr->pw);
        }
        if(sptr->dflmovetarget)
            free(sptr->dflmovetarget);
        if(sptr->crlf)
            free(sptr->crlf);

        free(sptr);
        sptr = nextsptr;
    }

    if(config.delivertarget)
        free(config.delivertarget);
    if(config.dflmovetarget)
        free(config.dflmovetarget);
    memset(&config, 0, sizeof(struct config));
}
