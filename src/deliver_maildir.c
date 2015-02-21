/* deliver_maildir.c
 * Deliver to a maildir folder.
 *
 * See the LICENSE file included with this distribution.
 */
#include <stdio.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "cf.h"
#include "deliver.h"
#include "deliver_maildir.h"
#include "log.h"
#include "utils.h"

bool maildir_new(struct folder *, unsigned int);
bool maildir_add(struct server *, struct folder *, char *, unsigned int);
unsigned int maildir_getleft(struct folder *);
bool maildir_inprogress(struct folder *);
void maildir_finish(struct folder *);
void maildir_cleanup(void);
bool maildir_newok(void);

struct deliverfns maildir_deliverfns = 
    { maildir_new,
      maildir_add,
      maildir_getleft,
      maildir_inprogress,
      maildir_finish,
      maildir_cleanup,
      NULL,
      maildir_newok,
      NULL,
      NULL };

static unsigned int delno = 0;

static int maildir_createtmp(struct maildir_deliverinfo *dinfo) {
    char newfile[BUFSIZ];
    char newpath[BUFSIZ];
    struct utsname hostinfo;
    int fd;

    uname(&hostinfo);

    snprintf(newfile, BUFSIZ, "%lu.P%d-Q%d.%s",
                time(NULL), getpid(), delno++, hostinfo.nodename);

    snprintf(newpath, BUFSIZ, "%s/tmp/%s",
                config.delivertarget, newfile);
    
    fd = open(newpath, O_WRONLY | O_CREAT, MAILDIR_CREATEPERM);
    if(fd == -1) {
        xlog(LOG_ERR, "unable to create new file in maildir: %s",
                strerror(errno));
        return(-1);
    }

    /* Indicate where this file is now. */
    dinfo->oldpathname = gmstrdup(newpath);
    /* Indicate where this file will be moved when it is done delivery. */
    snprintf(newpath, BUFSIZ, "%s/new/%s:2,", 
                config.delivertarget, newfile);
    dinfo->newpathname = gmstrdup(newpath);
    return(fd);
}

static void maildir_stop(struct folder *fptr) {
    struct maildir_deliverinfo *dinfo = 
            (struct maildir_deliverinfo *)fptr->conn.delivery_info;

    if(!dinfo)
        return;

    close(dinfo->fd);

    if(rename(dinfo->oldpathname, dinfo->newpathname) == -1) {
        xlog(LOG_ERR, "unable to rename file to new/ in maildir: %s",
                strerror(errno));
    }

    free(dinfo->newpathname);
    free(dinfo->oldpathname);
    free(dinfo);

    fptr->conn.delivery_info = NULL;
}

bool maildir_new(struct folder *fptr, unsigned int msgsz) {
    struct maildir_deliverinfo *newd = gmmalloc(sizeof(struct maildir_deliverinfo));

    if(fptr->conn.delivery_info) {
        xlog_bug("bug: new delivery started while previous delivery in progress");
        maildir_stop(fptr);
    }

    newd->fd = maildir_createtmp(newd);
    if(newd->fd == -1) {
        xlog(LOG_ERR, "unable to open maildir for delivery: %s",
                strerror(errno));
        free(newd);
        return(false);
    }
    newd->szleft = msgsz;
    newd->incrlf = false;
    newd->crlfpos = NULL;

    fptr->conn.delivery_info = (void *)newd;

    return(true);
}

bool maildir_add(struct server *sptr, struct folder *fptr, char *buf, 
                    unsigned int bufsz) {
    int byteswr;
    struct maildir_deliverinfo *dinfo = 
            (struct maildir_deliverinfo *)fptr->conn.delivery_info;
    unsigned int convertedsz;

    if(!dinfo) {
        xlog(LOG_ERR, "maildir_add called when no delivery was in progress");
        return(false);
    }

    convertedsz = crlf_convert(&dinfo->incrlf, sptr->crlf, &dinfo->crlfpos,
                                buf, bufsz);
    
    byteswr = write(dinfo->fd, buf, convertedsz);
    if(byteswr < convertedsz) {
        xlog(LOG_ERR, "unable to write entire message to file: %s",
                strerror(errno));
        maildir_stop(fptr);
        return(false);
    }

    dinfo->szleft -= bufsz;
    if(!dinfo->szleft) 
        maildir_stop(fptr);

    return(true);
}

unsigned int maildir_getleft(struct folder *fptr) {
    struct maildir_deliverinfo *dinfo = 
            (struct maildir_deliverinfo *)fptr->conn.delivery_info;

    if(!dinfo)
        return(0);
    return(dinfo->szleft);
}

bool maildir_inprogress(struct folder *fptr) {
    if(fptr->conn.delivery_info)
        return(true);
    return(false);
}

bool maildir_newok(void) {
    /* it's always OK for maildir delivery */
    return(true);
}
void maildir_finish(struct folder *fptr) {
    /* nothing to do here */
}

void maildir_cleanup(void) {
    /* nothing to do here */
}
