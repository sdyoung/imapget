#ifdef _USE_OPENSSL
#ifndef _SECRETS_H
#define _SECRETS_H

void readsecrets(void);
char *find_secret(char *, char *, int);
void free_secrets(void);
bool update_stored_secrets(void);

#endif /* !_SECRETS_H */
#endif /* _USE_OPENSSL */
