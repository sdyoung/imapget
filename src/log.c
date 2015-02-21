/* log.c 
 * Functions used for error logging. 
 * XXX loglevels are kind of messed up right now, need a properly defined
 * mapping between verbose levels and log levels. 
 *
 * See the LICENSE file included with this disribution.
 */
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include "cf.h"
#include "log.h"
#include "utils.h"

static FILE *logf;
static bool initialized = false;

bool logstart(void) {
    if(config.logsyslog == true) {
        openlog("imapget", LOG_PID, LOG_MAIL);
    } else {
        logf = fopen(config.logpath, "a");
        if(!logf) {
            xlog(LOG_ERR, "unable to open logpath '%s': %s",
                config.logpath, strerror(errno));
            return(false);
        }
    }

    initialized = true;
    return(true);
}

void logend(void) {
    if(initialized == false)
        return;
    if(config.logsyslog == true)
        closelog();
    else
        fclose(logf);
}

char *getlogdate(void) {
    char *tp;
    time_t tm = time(NULL);

    tp = ctime(&tm);
    stripnl(tp);
    return(tp);
}

void xlog(int prio, char *fmt, ...) {
    va_list ap;
    FILE *targetf;

    /* unless verbose is set, we only log errors */
    if((config.verbose < LOGLEVEL_DEBUG && prio == LOG_DEBUG) ||
       (config.verbose < LOGLEVEL_NORMAL && prio == LOG_WARNING))
        return;

    va_start(ap, fmt);
    if(initialized == false)
        targetf = stderr;
    else
        targetf = logf;

    if(config.logsyslog == true) {
        vsyslog(prio, fmt, ap);
    } else {
        fprintf(targetf, "%s [%d]: imapget: ", getlogdate(), getpid());
        vfprintf(targetf, fmt, ap);
        fprintf(targetf, "\n");
        fflush(targetf);
    }
    va_end(ap);
}

#ifdef DEBUG
void debug_trap() {
    int x = 0;

    x++;
}

void xlog_bug(char *fmt, ...) {
    va_list ap;
    FILE *targetf;

    va_start(ap, fmt);
    if(initialized == false)
        targetf = stderr;
    else
        targetf = logf;

    if(config.logsyslog == true) {
        vsyslog(LOG_ERR, fmt, ap);
    } else {
        fprintf(targetf, "%s [%d]: imapget: ", getlogdate(), getpid());
        vfprintf(targetf, fmt, ap);
        fprintf(targetf, "\n");
        fflush(targetf);
    }
    va_end(ap);

    debug_trap();
}
#endif
