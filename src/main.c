/* main.c 
 * This is the main entrypoint to imapget.
 *
 * See the LICENSE file included with this disribution. 
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sysexits.h>
#include <stdlib.h>
#include "types.h"
#include "cf.h"
#include "utils.h"
#include "log.h"
#include "imap.h"
#include "deliver.h"
#include "secrets.h"

bool quit = false, reloadcf = false, child_exited = false;

void sighandle(int sig) {
    switch(sig) {
        case SIGINT:
        case SIGTERM:
            quit = true;
            break;
        case SIGHUP:
            reloadcf = true;
            break;
        case SIGCHLD:
            child_exited = true;
            break;
    }
}

bool setsignals(void) {
    struct sigaction sa;

    sa.sa_handler = sighandle;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGHUP);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGCHLD);
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;

    if(sigaction(SIGTERM, &sa, NULL) == -1 || 
        sigaction(SIGHUP, &sa, NULL) == -1 ||
        sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGCHLD, &sa, NULL) == -1) {
        xlog(LOG_ERR, "unable to set signal handlers!");
        return(false);
    }

    return(true);
}

int main(int argc, char **argv) {
    extern char *optarg;
    char optch;
    bool showusage = false;
#ifdef _USE_OPENSSL
    bool update_secrets = false;
#endif /* _USE_OPENSSL */
    char *cfpath = NULL;

    memset(&config, 0, sizeof(config));
    
#ifndef _USE_OPENSSL
#define ARGSTR "vc:hf"
#else
#define ARGSTR "vc:hfu"
#endif

    while((optch = getopt(argc, argv, ARGSTR)) != -1) {
        switch(optch) {
            case 'v':
                config.verbose++;
                break;
            case 'c':
                cfpath = gmstrdup(optarg);
                break;
            case 'f':
                config.nobg = true;
                break;
#ifdef _USE_OPENSSL
            case 'u':
                update_secrets = true;
                break;
#endif /* _USE_OPENSSL */
            case 'h':
            default:
                showusage = true;
                break;
        }
    }

    if(!cfpath || showusage == true) {
#ifndef _USE_OPENSSL
        fprintf(stderr, "usage: imapget [-vfh] -c configfile\n");
#else
        fprintf(stderr, "usage: imapget [-vfuh] -c configfile\n");
#endif /* !_USE_OPENSSL */
        exit(EX_USAGE);
    }

    if(readconfig(cfpath) == false) {
        xlog(LOG_ERR, "unable to read configuration, exiting.");
        exit(EX_NOINPUT);
    }

#ifdef _USE_OPENSSL
    if(update_secrets == true && config.nopassword_servers) {
        if(update_stored_secrets() == false) 
            exit(EX_TEMPFAIL);
    } else if(config.nopassword_servers) {
        xlog(LOG_WARNING, "there are servers without secrets defined: use -u to correct.");
    }

#endif /* _USE_OPENSSL */
    if(!config.servers) {
        xlog(LOG_ERR, "no servers available; aborting.");
        exit(EX_TEMPFAIL);
    }

    if(logstart() == false) 
        exit(EX_TEMPFAIL);

    xlog(LOG_ERR, "imapget starting up.");

    if(setsignals() == false)
        exit(EX_TEMPFAIL);

    if(config.nobg == false) 
        if(godaemon() == false)
            exit(EX_TEMPFAIL);

    while(quit == false) {
        if(reloadcf == true) {
            xlog(LOG_WARNING, "reloading config at user request.");
            close_connections();
            closelog();
            freecf();
            if(readconfig(cfpath) == false) {
                xlog(LOG_ERR, "unable to read configuration, exiting.");
                exit(EX_NOINPUT);
            }
#ifdef _USE_OPENSSL
            if(config.nopassword_servers) 
                if(update_stored_secrets() == false) 
                    exit(EX_TEMPFAIL);
#endif /* _USE_OPENSSL */
            if(logstart() == false) 
                exit(EX_TEMPFAIL);
            reloadcf = false;
        }
        
        /* re-establish any connections that have been closed. */
        if(establish_connections() == false) {
            xlog(LOG_ERR, "all servers have been disabled - exiting.");
            quit = true;
        }

        /* see if the server has said anything interesting. */
        if(check_connections() == false)
            quit = true;

        /* Periodically let the delivery mechanism clean up after 
         * itself. */
        deliver_cleanup();

        if(child_exited == true) {
            deliver_childexit();
            child_exited = false;
        }
    }

    xlog(LOG_ERR, "imapget shutting down.");

    close_connections();
    deliver_shutdown();

    freecf();

#ifdef _USE_OPENSSL
    free_secrets();
#endif /* _USE_OPENSSL */

    closelog();

    xlog(LOG_ERR, "imapget done.");
    exit(EX_OK);
}

