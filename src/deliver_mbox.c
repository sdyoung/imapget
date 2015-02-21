/* deliver_mbox.c 
 * Functions for delivering to a local mbox.  Although mbox access
 * is seralized per-connection (we only ever FETCH one message at at 
 * time for a given connection), we have to lock against ourselves to
 * serialize over all connections.  As a result, in mbox_new, we try
 * to get the lock, and if so we start writing the message out immediately.
 * Otherwise, we store the message in memory and deliver it when the lock
 * becomes available.
 *
 * Basically the strategy is: If there is a new message to be delivered,
 * wait until we get the first chunk of data and then try and lock the
 * mailbox.  If we get the lock, deliver all queued messages for this
 * folder and leave it locked until we have received
 * all data for this message, and then unlock it.  If we don't get the
 * lock, add the data to the queue of data to be delievered when the
 * lock becomes available.  Additionally, mbox_cleanup periodically checks
 * to see if the lock is available, and if so, flushes all queued messages.
 * 
 * See the LICENSE file included with this disribution.
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include "cf.h"
#include "deliver.h"
#include "deliver_mbox.h"
#include "log.h"
#include "utils.h"

#ifdef DEBUG
#endif

bool mbox_new(struct folder *, unsigned int);
bool mbox_add(struct server *, struct folder *, char *, unsigned int);
unsigned int mbox_getleft(struct folder *);
bool mbox_inprogress(struct folder *);
void mbox_finish(struct folder *);
void mbox_cleanup(void);
bool mbox_newok(void);

struct deliverfns mbox_deliverfns = 
    { mbox_new,
      mbox_add,
      mbox_getleft,
      mbox_inprogress,
      mbox_finish,
      mbox_cleanup,
      NULL,
      mbox_newok,
      NULL,
      NULL };

/* Write the message separator to a locked mbox. */
void mbox_write_sep(int fd) {
    char *sep = "\n\n";

    if(write(fd, sep, strlen(sep)) != strlen(sep)) 
        xlog(LOG_ERR, "unable to write message separator to mbox");

    return;
}

/* Write a message header (From ...) to a locked mbox. */
bool mbox_writehdr(struct mbox_deliverhdr *hdr) {
    char *hdrstr = mbox_genhdr();
    int len = strlen(hdrstr);
    
    if(write(hdr->mbox_fd, hdrstr, len) < len) {
        xlog(LOG_ERR, "unable to write mbox header: %s",
                strerror(errno));
        return(false);
    }

    return(true);
}

/* Try to lock the mbox for writing. 
 * XXX should use more than just flock */
void mbox_lock(struct mbox_deliverhdr *hdr) {
    if(hdr->mbox_fd != -1) {
        xlog_bug("bug: locking already-locked mbox");
        return;
    }

    hdr->mbox_fd = open(config.delivertarget, O_WRONLY | O_APPEND | O_CREAT, 
                            MBOX_CREATEPERM);
    if(hdr->mbox_fd == -1) {
        xlog(LOG_ERR, "unable to open mbox: %s",
                strerror(errno));
        return;
    }

    if(flock(hdr->mbox_fd, LOCK_EX | LOCK_NB) == -1) {
        /* unable to acquire lock */
        xlog(LOG_DEBUG, "lock: tried and failed to lock mbox");
        close(hdr->mbox_fd);
        hdr->mbox_fd = -1;
        if(errno == EWOULDBLOCK) {
            return;
        }
        xlog(LOG_ERR, "error acquiring lock on mbox: %s",
                strerror(errno));
        return;
    }

    /* we now have the file locked. */
    xlog(LOG_DEBUG, "lock: mbox locked");
    return;
}

/* XXX */
bool mbox_newok(void) {
    return(true);
}

/* Unlock a locked mbox. */
void mbox_unlock(struct mbox_deliverhdr *hdr) {
    if(hdr->mbox_fd == -1) {
        xlog_bug("bug: unlocking an already unlocked mbox");
        return;
    }

    if(flock(hdr->mbox_fd, LOCK_UN) == -1) {
        /* unable to release lock?! */
        xlog(LOG_ERR, "unable to release lock on mbox: %s",
                strerror(errno));
        return;
    }

    close(hdr->mbox_fd);
    hdr->mbox_fd = -1;
    xlog(LOG_DEBUG, "lock: unlocked mbox");
}

/* Flush a given queued message to the mbox. */
static void mbox_flush(struct mbox_deliverhdr *hdr, 
                        struct mbox_deliverinfo *dinfo) {
    int byteswr;

    if(!dinfo->msgbody)
        return;
    if(dinfo->sz == dinfo->szleft) 
        if(mbox_writehdr(hdr) == false)
            return;

    byteswr = write(hdr->mbox_fd, dinfo->msgbody, dinfo->convsz);
    if(byteswr < (dinfo->sz - dinfo->szleft)) 
        xlog(LOG_ERR, "error flushing mbox: %s",
                strerror(errno));
    
    free(dinfo->msgbody);
    dinfo->msgbody = NULL;
    mbox_write_sep(hdr->mbox_fd);
}

/* flush out all the old messages queued up for delivery.
 * this should always be called with the lock held */
static void mbox_flushold(struct mbox_deliverhdr *hdr) {
    struct mbox_deliverinfo *dinfo, *dptr, *dptrnext;

    dinfo = hdr->deliveries;
    if(!dinfo || !dinfo->next)
        return;
    
    for(dptr = dinfo->next; dptr;) {
        mbox_flush(hdr, dinfo);
        dptrnext = dptr->next;
        free(dptr);
        dptr = dptrnext;
    }

    dinfo->next = NULL;
}

/* flush all messages to an mbox. */
static void mbox_flushall(struct mbox_deliverhdr *hdr) {
    struct mbox_deliverinfo *dinfo, *dptr, *dptrnext;

    dinfo = hdr->deliveries;
    if(!dinfo)
        return;
    
    for(dptr = dinfo; dptr;) {
        mbox_flush(hdr, dptr);
        dptrnext = dptr->next;
        free(dptr);
        dptr = dptrnext;
    }

    hdr->deliveries = NULL;
}

/* A new message is to be delivered. */
bool mbox_new(struct folder *fptr, unsigned int sz) {
    struct mbox_deliverinfo *newd = gmmalloc(sizeof(struct mbox_deliverinfo));
    struct mbox_deliverhdr *newh;

    newd->sz = newd->szleft = sz;
    newd->msgbody = NULL;
    newd->crlfpos = NULL;
    /* mbox starts out as closed and unlocked */

    /* if there are no deliveries already queued, create a header */
    if(!fptr->conn.delivery_info) {
        newh = fptr->conn.delivery_info = 
                gmmalloc(sizeof(struct mbox_deliverhdr));
        newh->mbox_fd = -1;
        newh->deliveries = NULL;
    } else 
        newh = (struct mbox_deliverhdr *)fptr->conn.delivery_info;

    /* prepend this delivery to the folder's queue */
    newd->next = newh->deliveries;
    newh->deliveries = (void *)newd;

    return(true);
}

/* Add some data to the message in progress. */
bool mbox_add(struct server *sptr, struct folder *fptr, char *buf, 
                unsigned int bufsz) {
    struct mbox_deliverinfo *dinfo;
    struct mbox_deliverhdr *hdr;
    int byteswr;
    int convertedsz;

    hdr = (struct mbox_deliverhdr *)fptr->conn.delivery_info;
    if(!hdr) {
        xlog_bug("bug: mbox_add called on folder with no mbox header");
        return(false);
    } else if(!hdr->deliveries) {
        xlog_bug("bug: mbox_add called on folder with mbox header but no deliveries");
        return(false);
    }

    dinfo = hdr->deliveries;
    
    convertedsz = crlf_convert(&dinfo->incrlf, sptr->crlf, 
                    &dinfo->crlfpos, buf, bufsz); 

    /* if we already have the lock for this mbox, that means
     * we are all caught up and can just write this message directly. */
    if(hdr->mbox_fd != -1) {
        byteswr = write(hdr->mbox_fd, buf, convertedsz);
        if(byteswr < convertedsz) {
            xlog(LOG_ERR, "unable to write to mbox: %s", 
                    strerror(errno));

            return(false);
        }

        dinfo->szleft -= byteswr;
        /* don't need to keep dinfo->convsz up to date when
         * we aren't queueing */
        if(!dinfo->szleft) {
            mbox_write_sep(hdr->mbox_fd);
            /* we're done writing this message, release the lock */
            mbox_unlock(hdr);
            /* since this is the last message, we can also free
             * the delivery header and delivery entry. */
            if(dinfo->next) {
                xlog(LOG_ERR, "dinfo->next exists when it should have been flushed");
            } else {
                free(dinfo);
                free(hdr);
                fptr->conn.delivery_info = NULL;
            }
        }
    } else {
        /* we don't have the lock.  try and acquire it. */
        mbox_lock(hdr);
        if(hdr->mbox_fd != -1) {
            /* we got the lock.  first, try and write out all the old
             * messages queued up for delivery, if there are any */
            if(dinfo->next) 
                mbox_flushold(hdr);

            /* since we will only ever not have the lock for the message
             * if none of the message data has been written, we
             * add the From header here */
            if(mbox_writehdr(hdr) == false) {
                mbox_unlock(hdr);
                return(false);
            }

            /* now write out the queued up data for this delivery, if any */
            if(dinfo->msgbody) {
                byteswr = write(hdr->mbox_fd, dinfo->msgbody, dinfo->convsz);
                if(byteswr < dinfo->convsz) {
                    xlog(LOG_ERR, "unable to write to mbox: %s",
                            strerror(errno));
                    mbox_unlock(hdr);
                    return(false);
                }
                /* buffer is cleared, we can free it */
                free(dinfo->msgbody);
                dinfo->msgbody = NULL;
            }    

            /* now write what just came in .. */
            byteswr = write(hdr->mbox_fd, buf, convertedsz);
            if(byteswr < convertedsz) {
                xlog(LOG_ERR, "unable to write to mbox: %s",
                        strerror(errno));
                mbox_unlock(hdr);
                return(false);
            }

            dinfo->szleft -= bufsz;
            /* since we're just writing directly and will never have
             * to queue again because we have the lock, we don't need
             * to bother about keeping dinfo->convsz up to date. */
            if(!dinfo->szleft) {
                mbox_write_sep(hdr->mbox_fd);
                /* we're done with this message, the queue is empty */
                mbox_unlock(hdr); /* release the message queue */
                if(dinfo->msgbody)
                    free(dinfo->msgbody);
                free(dinfo);
                /* release the mbox header */
                free(hdr);
                fptr->conn.delivery_info = NULL;
            }

            return(true);
        } else {
            /* we did not get the lock; queue this data up. */
            dinfo->msgbody = gmrealloc(dinfo->msgbody, dinfo->convsz + convertedsz);
            memcpy(dinfo->msgbody + dinfo->convsz, buf, convertedsz);
            if(bufsz > dinfo->szleft) {
                xlog(LOG_WARNING, "received %d more bytes for message than server reported!",
                        bufsz - dinfo->szleft);
                dinfo->szleft = 0;
            } else {
                dinfo->szleft -= bufsz;
            }
        }
    }
    return(true);
}

/* get the amount of data left for the current message */
unsigned int mbox_getleft(struct folder *fptr) {
    struct mbox_deliverhdr *hdr;

    hdr = (struct mbox_deliverhdr *)fptr->conn.delivery_info;

    if(!hdr) {
        xlog_bug("bug: asked about size left of nonexistant delivery chain");
        return(0);
    }

    return(hdr->deliveries->szleft);
}

/* check if a delivery is in progress */
bool mbox_inprogress(struct folder *fptr) {
    if(fptr->conn.delivery_info)
        return(true);
    return(false);
}

/* finish all deliveries for a given folder.  this is only called
 * when we are exiting or restarting. */
void mbox_finish(struct folder *fptr) {
    struct mbox_deliverhdr *hdr = fptr->conn.delivery_info;
    struct mbox_deliverinfo *dinfo;

    if(!hdr)
        return;

    dinfo = hdr->deliveries;
    if(!dinfo) {
        xlog_bug("bug: mbox header exists but no delivery chain is present");
        return;
    }

    mbox_lock(hdr);
    if(hdr->mbox_fd == -1) {
        xlog(LOG_DEBUG, "unable to acquire lock in mbox_finish");
        return;
    }
    mbox_flushall(hdr);
    mbox_unlock(hdr);
}

/* iterate through all the folders and do whatever cleanup needs to happen. 
 * In this case, it's see if there are any queued up messages that can
 * be delivered. */
void mbox_cleanup(void) {
    struct server *sptr;
    struct folder *fptr;
    struct mbox_deliverhdr *hdr;

    for(sptr = config.servers; sptr; sptr = sptr->next) {
        for(fptr = sptr->folders; fptr; fptr = fptr->next) {
            if(fptr->conn.delivery_info) {
                hdr = (struct mbox_deliverhdr *)fptr->conn.delivery_info;
                /* if mbox_fd is != 1, we've come across a folder that
                 * has the mailbox locked, and so we know all attempts
                 * we make to lock the mbox this iteration will fail,
                 * so we give up right away. */
                if(hdr->mbox_fd != -1)
                    return;
                mbox_lock(hdr);
                if(hdr->mbox_fd == -1) {
                    xlog(LOG_DEBUG, "unable to acquire mbox lock in mbox_cleanup");
                    return;
                }
                if(hdr->deliveries && hdr->deliveries->szleft)
                    mbox_flushall(hdr);
                mbox_unlock(hdr);
                free(hdr);
                fptr->conn.delivery_info = NULL;
            }
        }
    }
}
