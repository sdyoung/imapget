/* tcp.c
 * This file has all the lower-level cude used to manage TCP socket
 * connections with servers.
 *
 * See the LICENSE file included with this disribution.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef _USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif 
#include "cf.h"
#include "log.h"
#include "utils.h"
#include "tcp.h"

#ifdef _USE_OPENSSL
static SSL_CTX *sslcontext;
#endif /* _USE_OPENSSL */

/* Force a connection closed. */
void tcp_close(struct folder *fptr) {
#ifdef _USE_OPENSSL
    SSL_shutdown(fptr->conn.sslobj);
#endif
    close(fptr->conn.fd);
    fptr->conn.fd = -1;
}

/* Connect to a server. */
bool tcp_connect(struct server *sptr, struct folder *fptr) {
    int sockfd;
    struct hostent *shst;
    struct sockaddr_in saddr;
    char *lookup_err;
    long fdflags;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        xlog(LOG_ERR, "unable to create socket: %s",
            strerror(errno));
        return(false);
    }
    
    shst = gethostbyname(sptr->hostname);
    /* if an error occured, tell the user what happened */
    if(!shst) {
        switch(h_errno) {
            case HOST_NOT_FOUND:
                lookup_err = "Host not found";
                break;
            case NO_ADDRESS:
                lookup_err = "No address/data";
                break;
            case TRY_AGAIN:
                lookup_err = "Try again later";
                break;
            default:
                lookup_err = "Unknown error";
                break;
        }

        xlog(LOG_ERR, "unable to lookup host %s: %s",
            sptr->hostname, lookup_err);
        close(sockfd);
        return(false);
    }
    
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    memcpy(&saddr.sin_addr.s_addr, shst->h_addr,
        shst->h_length);
    
    saddr.sin_port = htons(sptr->port);

    /* establish a connection */
    if(connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        xlog(LOG_ERR, "unable to connect to host: %s",
            strerror(errno));
        close(sockfd);
        return(false);
    }

    fptr->conn.fd = sockfd;

#ifdef _USE_OPENSSL
    /* If we're using SSL, do the SSL handshake before we set the 
     * socket non-blocking.  This just makes everything easier. */
    if(sptr->use_imaps) {
        if(do_ssl_connect(sptr, fptr) == false) {
            close(sockfd);
            fptr->conn.fd = -1;
            return(false);
        }
    }
#endif /* _USE_OPENSSL */

    /* set socket nonblocking */
    fdflags = fcntl(sockfd, F_GETFL);
    if(fdflags == -1) {
        xlog(LOG_ERR, "unable to get socket flags for network connection: %s",
            strerror(errno));
        fptr->conn.fd = -1;
        tcp_close(fptr);
        return(false);
    }

    if(fcntl(sockfd, F_SETFL, fdflags | O_NONBLOCK) == -1) {
        xlog(LOG_ERR, "unable to set socket flags for network connection: %s",
            strerror(errno));
        fptr->conn.fd = -1;
        tcp_close(fptr);
        return(false);
    }

    if((shst = gethostbyaddr(&saddr.sin_addr, sizeof(struct in_addr), AF_INET)) 
                                    == NULL) {
        xlog(LOG_WARNING, "warning: unable to reverse-lookup %s: %s", 
                sptr->hostname, strerror(errno));
        fptr->conn.actual_host = gmstrdup(sptr->hostname);
    }

    fptr->conn.actual_host = gmstrdup(shst->h_name);

    return(true);
}

/* Forcibly close a connection.  Used when either the servers says
 * goodbye or something really bad happens. */
void conn_teardown(struct server *sptr, struct folder *fptr) {
    close(fptr->conn.fd);
    fptr->conn.fd = -1;
    if(fptr->conn.buf) {
        free(fptr->conn.buf);
        fptr->conn.buf = NULL;
    }

    fptr->conn.bufsz = 0;

    if(fptr->conn.actual_host)
        free(fptr->conn.actual_host);

    if(fptr->conn.fetchlist) {
        free(fptr->conn.fetchlist);
        fptr->conn.fetchlist = fptr->conn.fetchptr = NULL;
        fptr->conn.flistsz = 0;
    }

    /* the only time conn_teardown happens is when we are either
     * exiting, or there has been an error talking with the server.
     * in the former case it doesn't matter if we increment this
     * counter, in the latter is it the right thing to do. */
    sptr->consec_failures++;
}

/* Extract a line from the readline buffer. */
static char *tcp_readline_extract(struct conn *cptr) {
    char *p, *tmp, *retp;

    if(cptr->buf) {
        if((p = strstr(cptr->buf, "\r\n"))) {
            *p = '\0';
            retp = gmstrdup(cptr->buf);
            /* if we're at the end, tmp will point to
             * "" */
            if(*(p + 2) == '\0') {
                free(cptr->buf);
                cptr->buf = 0;
                cptr->bufsz = 0;
            } else {
                tmp = gmstrdup(p + 2);
                free(cptr->buf);
                cptr->buf = tmp;
                cptr->bufsz = strlen(tmp) + 1;
            }
            return(retp);
        }
    }

    return(NULL);
}

/* read a line in from a network socket in small increments (due to the
 * nonblocking nature our sockets). */
char *tcp_readline(struct server *sptr, struct folder *fptr) {
    int readsz;
    char inbuf[TCP_READBUFFER];
    struct conn *conn = &fptr->conn;
    char *tmp;

    /* always grab what's waiting on the socket and append it 
     * to our current buffer if necessary */
    readsz = tcp_read(fptr, inbuf, TCP_READBUFFER);
    if(readsz == -1) {
        if(errno != EAGAIN) {
            if((tmp = tcp_readline_extract(conn))) {
                return(tmp);
            } else {
                xlog(LOG_WARNING, "lost connection to %s: %s",
                        sptr->hostname, strerror(errno));
                conn_teardown(sptr, fptr);
                return(NULL);
            }
        }
    }

    if(readsz > 0) {
        /* Add new data to the connection buffer. */
        conn->buf = gmrealloc(conn->buf, conn->bufsz + readsz + 1);
        if(conn->bufsz) 
            memcpy(conn->buf + conn->bufsz - 1, inbuf, readsz);
        else
            memcpy(conn->buf, inbuf, readsz);

        conn->bufsz += readsz;
        conn->buf[conn->bufsz] = '\0';
    }

    /* then, see if there is existing data in the buffer to be 
     * processed. */
    tmp = tcp_readline_extract(conn);

#ifdef DEBUG
    if(tmp)
        xlog(LOG_DEBUG, "S(%d:%d): %s", conn->fd, conn->lastcommand, tmp);
#endif
    return(tmp);
}

/* print a line to a socket.  behaves like printf, but for sockets. */
int tcp_sockprintf(struct folder *fptr, char *fmt, ...) {
#ifdef _USE_OPENSSL
    int err;
#endif
    va_list ap;
    char outbuf[BUFSIZ], *p = outbuf;
    int bytes, byteswr;

    va_start(ap, fmt);
    bytes = vsnprintf(outbuf, BUFSIZ, fmt, ap);
    va_end(ap);

    /* We don't check to see if the connection was closed or if there's
     * any other kind of networking error here because tcp_readline
     * will catch it for us. */
    bytes = strlen(outbuf);

    /* This kind of sucks, but we emulate blocking writes.  Retries
     * are almost never necessary, however, so this loop will almost
     * never be executed more than once. */
    do { 
#ifdef _USE_OPENSSL
        if(fptr->conn.using_ssl == false) {
#endif
            byteswr = write(fptr->conn.fd, p, bytes);
#ifdef _USE_OPENSSL
        } else {
            byteswr = SSL_write(fptr->conn.sslobj, p, bytes);
            err = SSL_get_error(fptr->conn.sslobj, byteswr);
        }
#endif
        if(byteswr > 0) {
            bytes -= byteswr;
            p += byteswr;
        }
    } while(bytes > 0 && byteswr != -1);
#ifdef _USE_OPENSSL
    if(err == SSL_ERROR_WANT_WRITE)
        fptr->conn.want_write = true;
#endif
#ifdef DEBUG
    xlog(LOG_DEBUG, "C(%d:%d): %s", fptr->conn.fd, fptr->conn.lastcommand, 
                                    outbuf);
    if(byteswr < 0) 
            xlog(LOG_DEBUG, "(%d/%d)", byteswr, err);
#endif
    fptr->conn.lastresponsetm = time(NULL);
    return(bytes > BUFSIZ ? BUFSIZ : bytes);
}

#ifdef _USE_OPENSSL
char *get_ssl_error(void) {
    return(ERR_error_string(ERR_get_error(), NULL));
}

bool do_init_openssl(void) {
    SSL_library_init();
    SSL_load_error_strings();

    sslcontext = SSL_CTX_new(TLSv1_client_method());
    if(!sslcontext) {
        xlog(LOG_ERR, "unable to create SSL context: %s",
                get_ssl_error());
        return(false);
    }
    SSL_CTX_set_mode(sslcontext, SSL_MODE_AUTO_RETRY);
    return(true);
}

bool do_ssl_connect(struct server *sptr, struct folder *fptr) {
    int flags;
    int ret, err;

    if(!sslcontext)
        if(do_init_openssl() == false)
            return(false);

    if(!(fptr->conn.sslobj = SSL_new(sslcontext))) {
        xlog(LOG_ERR, "unable to create SSL object: %s",
                get_ssl_error());
        return(false);
    }

    /* If this connection is nonblocking, set it blocking momentarily
     * so we can SSL_connect without having to handle the very common
     * case that it cannot finish in one call without blocking. */
    flags = fcntl(fptr->conn.fd, F_GETFL);
    if(fcntl(fptr->conn.fd, F_SETFL, flags^O_NONBLOCK) == -1) {
        xlog(LOG_ERR, "unable to set file descriptor mode: %s",
                strerror(errno));
        return(false);
    }

    if(SSL_set_fd(fptr->conn.sslobj, fptr->conn.fd) == 0) {
        xlog(LOG_ERR, "unable to associate fd with SSL object: %s",
                get_ssl_error());
        return(false);
    }

    /* put this as a new connection state; get rid of the
     * busy loop. XXX */
    do {
        ret = SSL_connect(fptr->conn.sslobj);
        if(ret != 1)
            err = ERR_get_error();
    } while (ret != 1 && (err == SSL_ERROR_WANT_READ ||
                          err == SSL_ERROR_WANT_WRITE));
                         
    if(err == -1) {
        xlog(LOG_ERR, "unable to establish SSL connection: %s",
                get_ssl_error());
        return(false);
    }

    /* set the connection back to it's original mode */
    if(fcntl(fptr->conn.fd, F_SETFL, flags) == -1) {
        xlog(LOG_ERR, "unable to reset file descriptor mode: %s",
                strerror(errno));
        return(false);
    }
    fptr->conn.using_ssl = true;
    return(true);
}
#endif /* _USE_OPENSSL */

int tcp_read(struct folder *fptr, char *buf, unsigned int bufsz) {
#ifdef _USE_OPENSSL
    int ret, err;
    int bytesr, totalbytes = 0;

    if(fptr->conn.using_ssl == false) {
#endif /* _USE_OPENSSL */
        return(read(fptr->conn.fd, buf, bufsz));
#ifdef _USE_OPENSSL
    } else {
        do { 
            bytesr = SSL_read(fptr->conn.sslobj, buf + totalbytes, bufsz - totalbytes);
            if(bytesr <= 0) 
                err = SSL_get_error(fptr->conn.sslobj, ret);
            else 
                totalbytes += bytesr;
        } while(bytesr > 0 && (bufsz - totalbytes));

        if(bytesr <= 0 && err == SSL_ERROR_WANT_WRITE) {
            fptr->conn.want_write = true;
        } else if(bytesr == 0 && err == SSL_ERROR_SYSCALL && !totalbytes) {
            /* we convert OpenSSL-reported errors into errno
             * here so the rest of the code doesn't need to know
             * about OpenSSL. */
            errno = ECONNABORTED;
            return(-1);
        }

        return(totalbytes);
    }
#endif /* _USE_OPENSSL */
}
