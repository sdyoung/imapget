/* cf.h
 * This file contains structures used for storing the client's configuration -
 * servers, folders, default actions, etc.  Everything that is in the config
 * file is stored in structures found here. 
 *
 * See the LICENSE file included with this disribution.
 */
#ifndef _CF_H
#define _CF_H

/* cf.h depends on these two include files */
#include "types.h"
#include "imap.h"

/* an instance of a folder on a server.  we open a separate connection for each
 * folder, hence why the fd is in here. */
struct folder {
    char *name;
    struct conn conn;
    enum readaction readaction;
    char *movetarget; /* if readaction = move_folder */
    bool readaction_override;
    bool disabled;
    struct folder *next; 
};

/* an instance of a server in the global configuration */
struct server {
    char *hostname;
    int port;
    bool use_imaps;
    char *username, *pw;
    struct folder *folders;
    unsigned int timeout;
    unsigned int pollinterval;
    bool usepoll;
    enum authtype authtype;
    enum readaction dflreadaction;
    char *dflmovetarget; /* if dflreadaction = move_folder */
    struct server *next;
    unsigned int consec_failures;
    unsigned int wakeup_time; /* when to try again if too many consec.
                               * failures have occurred. */
    char *crlf;                  /* this contains whatever the server
                                 is using for CRLF in messages. */
    bool disabled;              /* has server been disabled permenantly? */
    unsigned int failsleep;      /* current failure sleep value */
};

/* the root node of the global configuration */
struct config {
    unsigned short verbose; /* verbosity level */
    bool nobg; /* don't background */
    bool logsyslog; /* use syslog? if false log to file. */
    char *logpath; /* if not using syslog */
    struct server *servers;
#ifdef _USE_OPENSSL
    struct server *nopassword_servers;
#endif /* _USE_OPENSSL */
    unsigned int dfltimeout; /* default timeout */
    enum deliverytype deliverytype; /* how to deliver mail */
    char *delivertarget; /* program to pipe to, or file to write to if mbox */
    char **deliverargs;
    struct deliverfns *deliverfns;
    unsigned int maxdeliveries; /* max. concurrent deliveries */
    enum authtype dflauth; /* default auth type */
    enum readaction dflreadaction;
    char *dflmovetarget; /* if dflreadaction = move_folder */
    unsigned int keepalive; /* how long to wait between keepalives */
    unsigned int maxfailures; /* max. consecutive failures */
    unsigned int pollinterval; /* default polling interval */
#ifdef _USE_OPENSSL
    char *encrypted_secrets;
#endif /* _USE_OPENSSL */
};

extern struct config config;
extern bool quit, reloadcf;

bool readconfig(char *);
void freecf(void);

#endif /* !_CF_H */
