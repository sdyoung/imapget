#ifdef _USE_OPENSSL
#include <stdio.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/blowfish.h>
#include <openssl/evp.h>
#ifndef _USE_GETPASS
#include <termios.h>
#endif
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include "types.h"
#include "utils.h"
#include "base64.h"
#include "md5.h"
#include "cf.h"
#include "log.h"

struct secrets {
    char *hostname;
    int port;
    char *username;
    char *pw;
    struct secrets *next;
} *secrets = NULL;

static unsigned char *md5passphrase = NULL;

void free_secrets(void) {
    struct secrets *secptr, *nextsecptr;

    for(secptr = secrets; secptr; secptr = nextsecptr) {
        nextsecptr = secptr->next;

        memset(secptr->hostname, 0, strlen(secptr->hostname));
        memset(secptr->username, 0, strlen(secptr->username));
        memset(secptr->pw, 0, strlen(secptr->pw));
        free(secptr->hostname);
        free(secptr->username);
        free(secptr->pw);
    }

    if(md5passphrase) {
            memset(md5passphrase, 0, 16);
            md5passphrase = NULL;
    }
}

char *find_secret(char *host, char *user, int port) {
    struct secrets *secp;

    for(secp = secrets; secp; secp = secp->next) {
        if(secp->port == port &&
                !strcmp(secp->hostname, host) &&
                !strcmp(secp->username, user)) 
            return(secp->pw);
    }
    return(NULL);
}

/* Just add a secret to the linked list of secrets.. */
void add_secret(char *host, char *user, int port, char *pw) {
    struct secrets *newsecret = gmmalloc(sizeof(struct secrets));

    newsecret->hostname = gmstrdup(host);
    newsecret->port = port;
    newsecret->username = gmstrdup(user);
    newsecret->pw = gmstrdup(pw);
    newsecret->next = secrets;
    secrets = newsecret;
}

/* XXX termios */
unsigned char *readphrase(char *prompt, ...) {
    char promptbuf[BUFSIZ];
    va_list ap;
#ifdef _USE_GETPASS
    char *retp, *staticp;
#else
    struct termios tm;
    char inbuf[BUFSIZ];
    unsigned char *retp;
    short reset_echo = 0;
#endif
    
    va_start(ap, prompt);
    vsnprintf(promptbuf, BUFSIZ, prompt, ap);
    va_end(ap);

#ifdef _USE_GETPASS
    staticp = getpass(prompt);
    retp = gmstrdup(staticp);
    memset(staticp, 0, strlen(staticp));
    return(retp);
#else
    printf("%s", promptbuf);
    fflush(stdout);
    
    if(tcgetattr(0, &tm) == -1) {
        xlog(LOG_ERR, "unable to get terminal attributes: %s", strerror(errno));
        return(NULL);
    }

    if(tm.c_lflag & ECHO) {
        tm.c_lflag = tm.c_lflag ^ ECHO;

        if(tcsetattr(0, TCSANOW, &tm) == -1) {
            xlog(LOG_ERR, "unable to set terminal attributes: %s", strerror(errno));
            return(NULL);
        }
        reset_echo = 1;
    }

    fgets(inbuf, BUFSIZ, stdin);

    if(reset_echo) {
        tm.c_lflag = tm.c_lflag | ECHO;

        if(tcsetattr(0, TCSANOW, &tm) == -1) {
            xlog(LOG_ERR, "unable to reset terminal attributes (try stty sane): %s", strerror(errno));
            /* non-fatal (but very annoying) */
        }
    }

    stripnl(inbuf);
    retp = (unsigned char *)gmstrdup(inbuf);
    memset(inbuf, 0, strlen(inbuf));

    printf("\n");
    return(retp);
#endif /* !_USE_GETPASS */
}

bool encryptsecrets(unsigned char *str, int strsz) {
    /* XXX YUCK!! */
    unsigned char *outbuf = gmmalloc(strsz * 2);
    unsigned char iv[8];
    int olen, tlen, secret_fd;
    EVP_CIPHER_CTX ctx;

    if(!md5passphrase) {
        xlog_bug("bug: encryptsecrets called without md5passphrase set!");
        return(false);
    }

    secret_fd = open(config.encrypted_secrets, O_TRUNC | O_CREAT | O_WRONLY,
             0600);
    if(secret_fd == -1) {
        xlog(LOG_ERR, "unable to open secrets file '%s' for writing: %s",
                config.encrypted_secrets, strerror(errno));
        return(false);
    }

    memset(iv, 0, 8);

    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_bf_cbc(), NULL, md5passphrase, iv);
    if(!EVP_EncryptUpdate(&ctx, outbuf, &olen, str, strsz)) {
        xlog(LOG_ERR, "encryption error!");
        close(secret_fd);
        return(false);
    }
    if(!EVP_EncryptFinal_ex(&ctx, outbuf + olen, &tlen)) {
        xlog(LOG_ERR, "encryption finalization error!");
        close(secret_fd);
        return(false);
    }

    tlen += olen;

    if(write(secret_fd, outbuf, tlen) != tlen) {
        xlog(LOG_ERR, "unable to write secrets file: %s",
                strerror(errno));
        close(secret_fd);
        return(false);
    }

    close(secret_fd);
    return(true);
}

int decryptsecrets(char *path, char **buf) {
    int secret_fd;
    EVP_CIPHER_CTX ctx;
    unsigned char iv[8], *passphrase;
    char *retbuf = NULL;
    int retbufsz = 0, readn, olen;
    unsigned char outbuf[BUFSIZ], inbuf[BUFSIZ];

    secret_fd = open(path, O_RDONLY);
    if(secret_fd == -1) {
        xlog(LOG_WARNING, "unable to open secrets file '%s': %s",
                config.encrypted_secrets, strerror(errno));
        return(-1);
    }

    memset(iv, 0, 8);

    if(!md5passphrase) {
        passphrase = readphrase("Enter passphrase for '%s': ", 
            config.encrypted_secrets);
        md5passphrase = MD5_digest(passphrase, strlen((char *)passphrase));
        md5passphrase[16] = '\0';
        memset(passphrase, 0, strlen((char *)passphrase));
    }

    /* XXX handle 0-byte file? */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_bf_cbc(), NULL, md5passphrase, iv);
    do {
        readn = read(secret_fd, inbuf, BUFSIZ);
        if(readn > 0) {
            if(!EVP_DecryptUpdate(&ctx, outbuf, &olen, 
                        inbuf, readn)) {
                xlog(LOG_ERR, "decryption error reading '%s'!",
                        path);
                return(-1);
            }
        } else {
            if(!EVP_DecryptFinal_ex(&ctx, outbuf, &olen)) {
                xlog(LOG_ERR, "decryption error reading '%s':",
                        path);
                return(-1);
            }
        }

        retbuf = gmrealloc(retbuf, retbufsz + olen + 1);
        memcpy(retbuf + retbufsz, outbuf, olen);
        retbufsz += olen;
    } while(readn > 0);

    close(secret_fd);

    memset(outbuf, 0, BUFSIZ);
    memset(inbuf, 0, BUFSIZ);

    *buf = retbuf;
    return(retbufsz);
}

static int create_secret(char *buf, int sz, char *host, char *user,
                         int port, char *pw) {
    /* XXX error checking? */
    int *bufi = (int *)buf;
    char *bufc;

    *(bufi++) = strlen(host);
    bufc = (char *)bufi;
    strcpy(bufc, host);
    bufc += strlen(host);
    bufi = (int *)bufc;
    *(bufi++) = strlen(user);
    bufc = (char *)bufi;
    strcpy(bufc, user);
    bufc += strlen(user);
    bufi = (int *)bufc;
    *(bufi++) = port;
    *(bufi++) = strlen(pw);
    bufc = (char *)bufi;
    strcpy(bufc, pw);
    bufc += strlen(pw);

    return(bufc - buf);
}

bool update_stored_secrets() {
    struct server *sptr, *oldsptr;
    char *passphrase = NULL, *verify = NULL;
    char *enc = NULL;
    int cmp, encsz = 0, secsz;
    char tmpbuf[BUFSIZ];

    if(!md5passphrase) {
        do {
            printf("It looks like we're creating a new secrets file.\n");
            if(passphrase)
                free(passphrase);
            if(verify)
                free(verify);
            passphrase = (char *)readphrase("Enter a new passphrase: ", "");
            verify = (char *)readphrase("Enter it again: ", "");
            cmp = strcmp(passphrase, verify);
            if(cmp) 
                printf("Passphrases do not match.  Try again.\n");
        } while(cmp);
        md5passphrase = MD5_digest((unsigned char *)verify, strlen(verify));
        md5passphrase[16] = '\0';

        memset(passphrase, 0, strlen(passphrase));
        memset(verify, 0, strlen(verify));
        free(passphrase);
        free(verify);
        passphrase = verify = NULL;
    } else {
        encsz = decryptsecrets(config.encrypted_secrets, &enc);
        if(!enc) {
            xlog(LOG_ERR, "unable to open old secrets file!");
            return(false);
        }
    }

    for(sptr = config.nopassword_servers; sptr; sptr = sptr->next) {
        printf("Server %s@%s:%d does not have a secret defined.\n",
                sptr->username, sptr->hostname, sptr->port);

        do { 
            if(passphrase)
                free(passphrase);
            if(verify)
                free(verify);
            passphrase = (char *)readphrase("Enter secret: ", "");
            verify = (char *)readphrase("Verify: ", "");
            
            cmp = strcmp(passphrase, verify);
            if(cmp) 
                printf("Secrets do not match.  Please try again.\n");
        } while(cmp);

        secsz = create_secret(tmpbuf, BUFSIZ, sptr->hostname, 
                              sptr->username, sptr->port, verify);

        enc = gmrealloc(enc, encsz + secsz + 1);
        memcpy(enc + encsz, tmpbuf, secsz);
        encsz += secsz;
        enc[encsz] = '\0';

        sptr->pw = gmstrdup(passphrase);
        memset(passphrase, 0, strlen(passphrase));
        memset(verify, 0, strlen(verify));

        free(passphrase);
        free(verify);
        passphrase = verify = NULL;
        oldsptr = sptr;
    }

    /* All servers should have pws defined by now. */
    encryptsecrets((unsigned char *)enc, encsz);

    oldsptr->next = config.servers;
    config.servers = oldsptr;

    memset(enc, 0, encsz);
    free(enc);
    
    return(true);
}

bool readsecrets() {
    int secretslen, curlen;
    char *host, *user, *pw;
    int port;
    char *secptr;
    char *bufc;
    int *bufi;

    secretslen = decryptsecrets(config.encrypted_secrets, &secptr);
    if(secretslen < 0)
        return(false);

    bufc = secptr;
    bufi = (int *)bufc;

    while((bufc - secptr) < secretslen) {
        curlen = *(bufi++);
        bufc = (char *)bufi;
        host = gmmalloc(curlen + 1);
        memcpy(host, bufc, curlen);
        host[curlen] = '\0';
        bufc += curlen;
        bufi = (int *)bufc;
        curlen = *(bufi++);
        bufc = (char *)bufi;
        user = gmmalloc(curlen + 1);
        memcpy(user, bufc, curlen);
        user[curlen] = '\0';
        bufc += curlen;
        bufi = (int *)bufc;
        port = *(bufi++);
        curlen = *(bufi++);
        bufc = (char *)bufi;
        pw = gmmalloc(curlen + 1);
        memcpy(pw, bufc, curlen);
        pw[curlen] = '\0';
        bufc += curlen;
        bufi = (int *)bufc;
        /* secret_fields[0] = host, [1] = user, [2] = port, [3] = pw */
        add_secret(host, user, port, pw);
        memset(user, 0, strlen(user));
        memset(pw, 0, strlen(pw));
        free(host);
        free(user);
        free(pw);
    }
    return(true);
}    
#endif /* _USE_OPENSSL */
