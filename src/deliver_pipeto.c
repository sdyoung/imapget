/* deliver_pipeto.c
 * Functions used for delivering mail to external binaries.  This is 
 * refreshingly simple.
 * 
 * See the LICENSE file included with this distribution.
 */
#include <stdio.h>
#include <sysexits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "cf.h"
#include "deliver.h"
#include "deliver_pipeto.h"
#include "log.h"
#include "utils.h"
#include "imap.h"

static int curdeliveries = 0;
static int *pids;

bool pipeto_new(struct folder *, unsigned int);
bool pipeto_add(struct server *, struct folder *, char *, unsigned int);
unsigned int pipeto_getleft(struct folder *);
bool pipeto_inprogress(struct folder *);
void pipeto_finish(struct folder *);
void pipeto_childexit(void);
bool pipeto_newok(void);
bool pipeto_newok_noinc(void);
void pipeto_shutdown(void);

struct deliverfns pipeto_deliverfns = 
    { pipeto_new,
      pipeto_add,
      pipeto_getleft,
      pipeto_inprogress,
      pipeto_finish,
      NULL,
      pipeto_shutdown,
      pipeto_newok,
      pipeto_newok_noinc,
      pipeto_childexit };

static void add_pid(int pid) {
    int i;

    if(!pids) {
        pids = gmmalloc(sizeof(int) * config.maxdeliveries);
        memset(pids, 0, sizeof(int) * config.maxdeliveries);
    }

    for(i = 0; i < config.maxdeliveries; i++) {
        if(!pids[i]) {
            pids[i] = pid;
            return;
        }
    }

    xlog_bug("bug: adding a new delivery when max has been reached?");
}

static void remove_pid(int i) {
    if(!pids[i]) {
        xlog_bug("bug: removing nonexistant delivery job?");
        return;
    }

    pids[i] = 0;
}

static void pipeto_stop(struct folder *fptr) {
    struct pipeto_deliverinfo *p = 
        (struct pipeto_deliverinfo *)fptr->conn.delivery_info;

    close(p->pipes[1]);
    free(p);
    fptr->conn.delivery_info = NULL;
}

static bool pipeto_writehdr(struct pipeto_deliverinfo *dinfo) {
    char *hdrstr = mbox_genhdr();
    int len = strlen(hdrstr);

    if(write(dinfo->pipes[1], hdrstr, len) < len) {
        xlog(LOG_ERR, "unable to write header to delivery process: %s",
                strerror(errno));
        return(false);
    }

    return(true);
}

bool pipeto_newok_noinc(void) {
    if((curdeliveries < config.maxdeliveries) || !config.maxdeliveries) 
            return(true);
    return(false);
}

bool pipeto_newok(void) {
    if(pipeto_newok_noinc() == true) {
        curdeliveries++;
        return(true);
    } 
    return(false);
}

bool pipeto_new(struct folder *fptr, unsigned int msgsz) {
    int pid;
    int nullfd;
    struct pipeto_deliverinfo *newd = 
                        gmmalloc(sizeof(struct pipeto_deliverinfo));

    if(fptr->conn.delivery_info) {
        xlog_bug("bug: new delivery started while old delivery in progress");
        pipeto_stop(fptr);
    }

    newd->szleft = msgsz;
    newd->incrlf = false;
    newd->crlfpos = NULL;

    if(pipe(newd->pipes) == -1) {
        xlog(LOG_ERR, "unable to create pipes for delivery: %s",
                strerror(errno));
        free(newd);
        return(false);
    }

    pid = fork();
    if(pid == -1) {
        xlog(LOG_ERR, "unable to fork for delivery: %s",
                        strerror(errno));
        return(false);
    }

    fptr->conn.delivery_info = (void *)newd;
    /* if we're the parent.  Write out the mbox header and return. */
    if(pid) {
        add_pid(pid);

        close(newd->pipes[0]);
        if(pipeto_writehdr(newd) == false) {
            pipeto_stop(fptr);
            return(false);
        }
        return(true);
    }

    /* we're the child. */
    close(newd->pipes[1]);

    if((nullfd = open("/dev/null", O_WRONLY)) == -1) {
        xlog(LOG_ERR, "unable to open /dev/null: %s",
                strerror(errno));
        exit(EX_TEMPFAIL);
    }

    if(dup2(newd->pipes[0], 0) == -1 || dup2(nullfd, 1) == -1 ||
       dup2(nullfd, 2) == -1) {
        xlog(LOG_ERR, "unable to set file descriptors for delivery: %s",
                strerror(errno));
        exit(EX_TEMPFAIL);
    }

    /* otherwise, the children are ready and the pipes have been created.
     * the pipes are blocking, since we assume a local process will always
     * outpace the network. */

    execvp(config.delivertarget, config.deliverargs);

    xlog(LOG_ERR, "unable to exec '%s': %s", config.delivertarget,
            strerror(errno));
    exit(EX_TEMPFAIL);
}

bool pipeto_add(struct server *sptr, struct folder *fptr, char *buf,
                    unsigned int bufsz) {
    int byteswr;
    struct pipeto_deliverinfo *dinfo = 
            (struct pipeto_deliverinfo *) fptr->conn.delivery_info;
    unsigned int convertedsz;

    if(!dinfo) {
        xlog_bug("bug: pipeto_add called when no delivery was in progress!");
        return(false);
    }

    convertedsz = crlf_convert(&dinfo->incrlf, sptr->crlf, &dinfo->crlfpos,
                                buf, bufsz);

    byteswr = write(dinfo->pipes[1], buf, convertedsz);

    if(byteswr < convertedsz) {
        xlog(LOG_ERR, "unable to write entire buffer to delivery process: %s",
                strerror(errno));
        pipeto_stop(fptr);
        return(false);
    }
    dinfo->szleft -= bufsz;
    
    if(!dinfo->szleft) 
        pipeto_stop(fptr);    

    return(true);
}

unsigned int pipeto_getleft(struct folder *fptr) {
    struct pipeto_deliverinfo *dinfo = 
            (struct pipeto_deliverinfo *) fptr->conn.delivery_info;

    if(!dinfo) {
        xlog(LOG_DEBUG, "pipeto_getleft called on nonexistant delivery?");
        return(0);
    }

    return(dinfo->szleft);
}

bool pipeto_inprogress(struct folder *fptr) {
    if(fptr->conn.delivery_info)
        return(true);
    return(false);
}

void pipeto_finish(struct folder *fptr) {
    /* nothing to do here */
}

/* Just collect any zombies.. */
void pipeto_childexit(void) {
    int status, i;

    if(!pids)
        return;

    for(i = 0; i < config.maxdeliveries; i++) {
        if(pids[i]) {
            if(waitpid(pids[i], &status, WNOHANG)) {
                remove_pid(i);
                curdeliveries--;
                if(isany_deferred())
                    pop_deferred();
            }
        }
    }
}

void pipeto_shutdown(void) {
    int pid, i, childcount = 0;

    if(!pids)
        return;

    for(i = 0; i < config.maxdeliveries; i++) 
        if(pids[i])
            childcount++;

    while(childcount) {
        if((pid = waitpid(-1, NULL, 0)) < 0) {
               xlog_bug("bug: unable to wait for all delivery processes to exit (%s)", 
                   strerror(errno));
               return;
        }

        childcount--;
    }
}
