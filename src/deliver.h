/* delivery.h
 * structs and prototypes for initiating local mail delivery. 
 *
 * See the LICENSE file included with this distribution.
 */
#ifndef _DELIVERY_H
#define _DELIVERY_H

struct deliveries {
    char *msgbody;
    int msgsz;
    int outfd;
    struct deliveries *prev, *next;
};

struct deliverfns {
    bool (*newfn)(struct folder *, unsigned int);
    bool (*addfn)(struct server *, struct folder *, char *, unsigned int);
    unsigned int (*getleftfn)(struct folder *);
    bool (*inprogressfn)(struct folder *);
    void (*finishfn)(struct folder *);
    void (*cleanupfn)(void);
    void (*shutdownfn)(void);
    bool (*newokfn)(void);
    bool (*newok_noincfn)(void);
    void (*childexit)(void);
};

bool deliver_new(struct folder *, unsigned int);
bool deliver_adddata(struct server *, struct folder *, char *buf, unsigned int);
unsigned int deliver_getleft(struct folder *);
bool deliver_inprogress(struct folder *);
void deliver_finishall(struct folder *);
void deliver_cleanup(void);
void deliver_setfns(void);
bool deliver_newok(void);
bool deliver_newok_noinc(void);
void deliver_childexit(void);
void deliver_shutdown(void);

#endif /* !_DELIVERY_H */
