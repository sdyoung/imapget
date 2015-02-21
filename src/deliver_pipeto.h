/* deliver_pipeto.h
 * Structures and prototypes for delivering messages via external program
 * (eg, procmail)
 *
 * See the LICENSE file included with this distribution.
 */
#ifndef _DELIVER_PIPETO_H
#define _DELIVER_PIPETO_H

struct pipeto_deliverinfo {
    int pipes[2];
    unsigned int szleft;
    bool incrlf;
    char *crlfpos;
};

extern struct deliverfns pipeto_deliverfns;

#endif /* !_DELIVER_PIPETO_H */
