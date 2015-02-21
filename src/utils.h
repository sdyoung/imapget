/* utils.h
 * Prototypes and macros for generic utility functions (mostly for strings)
 *
 * See the LICENSE file included with this distribution.
 */
#ifndef _UTILS_H
#define _UTILS_H

#define stripnl(x) x[strlen(x) - 1] = '\0';
#define MIN(x,y) x < y ? x : y
#define MAX(x,y) x < y ? y : x

#ifndef DEBUG
char *xstrdup(char *);
void *xmalloc(size_t);
void *xrealloc(void *, size_t);
#define gmstrdup xstrdup
#define gmmalloc xmalloc
#define gmrealloc xrealloc
#else
#define gmstrdup strdup
#define gmmalloc malloc
#define gmrealloc realloc
#endif
void freetokens(char **, int);
char **duptokens(char **);
char **gettokens(char *, int *);
bool godaemon(void);
int crlf_convert(bool *, char *, char **, char *, unsigned int);
char *mbox_genhdr(void);

int sep_isspace(char c);
int sep_iscomma(char c);
char **gettokens_sep(char *, int *, int (*)(char));
#endif
