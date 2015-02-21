/* log.h
 * Prototypes and #defines for logging functions.
 *
 * See the LICENSE file included with this distribution.
 */
#ifndef _LOG_H
#define _LOG_H

#include <syslog.h>

#define LOGLEVEL_QUIET 1
#define LOGLEVEL_NORMAL 2
#define LOGLEVEL_DEBUG 3

#ifndef DEBUG
#define xlog_bug xlog
#endif

bool logstart(void);
void logend(void);
void xlog(int, char *, ...);
#ifdef DEBUG
void xlog_bug(char *, ...);
#endif

#endif /* !_LOG_H */
