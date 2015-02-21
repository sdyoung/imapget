/* tcp.h
 * Prototypes and definitions for tcp.c.
 *
 * See the LICENSE file included with this disribution.
 */
#ifndef _TCP_H
#define _TCP_H

#define TCP_READBUFFER 8192

bool tcp_connect(struct server *, struct folder *);
void conn_teardown(struct server *, struct folder *);
char *tcp_readline(struct server *, struct folder *);
int tcp_sockprintf(struct folder *, char *, ...);
int tcp_write(struct folder *, void *, unsigned int);
int tcp_read(struct folder *, char *, unsigned int);
#ifdef _USE_OPENSSL
bool do_ssl_connect(struct server *sptr, struct folder *fptr);
#endif /* _USE_OPENSSL */

#endif /* !_TCP_H */
