/* deliver_maildir.h
 * Structures and prototypes for deliverying to a maildir.
 *
 * See the LICENSE file included with this disribution.
 */
#ifndef _DELIVER_MAILDIR_H
#define _MAILDIR_DELIVER_H

#define MAILDIR_CREATEPERM 0600

struct maildir_deliverinfo {
    int fd;
    unsigned int szleft;
    bool incrlf;
    char *crlfpos;
    char *oldpathname, *newpathname;
};

extern struct deliverfns maildir_deliverfns;

#endif /* !_MAILDIR_DELIVER_H */
