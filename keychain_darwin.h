#ifndef KEYCHAIN_DARWIN_H
#define KEYCHAIN_DARWIN_H

int kc_set(const char *service, const char *account, const char *secret);
int kc_get(const char *service, const char *account, char **out);
int kc_exists(const char *service, const char *account);
int kc_delete(const char *service, const char *account);
int kc_biometric_auth(const char *reason);
void kc_free(char *p);

#endif
