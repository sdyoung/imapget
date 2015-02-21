/* delivery_mbox.h
 * Prototypes for delivering to local mbox-format files.
 *
 * See the LICENSE file included with this disribution. 
 */
#ifndef _DELIVERY_MBOX
#define _DELIVERY_MBOX

#define MBOX_CREATEPERM 0600

struct mbox_deliverinfo {
    char *msgbody;
    unsigned int sz, szleft, convsz;
    struct mbox_deliverinfo *next;
    bool incrlf;
    char *crlfpos;
};

struct mbox_deliverhdr {
    int mbox_fd;
    struct mbox_deliverinfo *deliveries;
};

extern struct deliverfns mbox_deliverfns;
#endif /* !_DELIVERY_MBOX */
