/* deliver.c
 * This file basically just contains some wrappers that switch between
 * the different delivery types the user may have selected.
 *
 * See the LICENSE file included with this disribution.
 */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "cf.h"
#include "deliver.h"
#include "log.h"
#include "deliver_mbox.h"
#include "deliver_maildir.h"
#include "deliver_pipeto.h"

#ifdef DEBUG
#endif

void deliver_setfns(void) {
    switch(config.deliverytype) {
        case mbox:
            config.deliverfns = &mbox_deliverfns;
            break;
        case pipeto:
            config.deliverfns = &pipeto_deliverfns;
            break; 
        case maildir:
            config.deliverfns = &maildir_deliverfns;
            break;
        default:
            xlog(LOG_ERR, "unimplemented delivery type selected.");
            break;
    }
}

bool deliver_new(struct folder *fptr, unsigned int sz) {
    return(config.deliverfns->newfn(fptr, sz));
}

bool deliver_adddata(struct server *sptr, struct folder *fptr, char *buf, 
                        unsigned int sz) {
    return(config.deliverfns->addfn(sptr, fptr, buf, sz));
}

unsigned int deliver_getleft(struct folder *fptr) {
    return(config.deliverfns->getleftfn(fptr));
}

bool deliver_inprogress(struct folder *fptr) {
    return(config.deliverfns->inprogressfn(fptr));
}

void deliver_finishall(struct folder *fptr) {
    return(config.deliverfns->finishfn(fptr));
}

bool deliver_newok(void) {
    return(config.deliverfns->newokfn());
}

bool deliver_newok_noinc(void) {
    if(config.deliverfns->newok_noincfn)
        return(config.deliverfns->newok_noincfn());
    return(true);
}

void deliver_cleanup(void) {
    if(config.deliverfns->cleanupfn) 
        config.deliverfns->cleanupfn();
}

void deliver_childexit(void) {
    if(config.deliverfns->childexit) 
        config.deliverfns->childexit();
}

void deliver_shutdown(void) {
    if(config.deliverfns->shutdownfn)
        config.deliverfns->shutdownfn();
}
