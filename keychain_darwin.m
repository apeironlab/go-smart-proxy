#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

#include <stdlib.h>
#include <string.h>

#include "keychain_darwin.h"

static NSMutableDictionary *kc_query(NSString *service, NSString *account) {
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: service,
        (__bridge id)kSecAttrAccount: account,
    } mutableCopy];
}

int kc_set(const char *service, const char *account, const char *secret) {
    NSString *svc = [NSString stringWithUTF8String:service];
    NSString *acc = [NSString stringWithUTF8String:account];
    NSData *data = [NSData dataWithBytes:secret length:strlen(secret)];

    SecItemDelete((__bridge CFDictionaryRef)kc_query(svc, acc));

    NSMutableDictionary *item = kc_query(svc, acc);
    item[(__bridge id)kSecValueData] = data;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    return (int)status;
}

int kc_get(const char *service, const char *account, char **out) {
    *out = NULL;
    NSMutableDictionary *q = kc_query([NSString stringWithUTF8String:service],
                                      [NSString stringWithUTF8String:account]);
    q[(__bridge id)kSecReturnData] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (status != errSecSuccess || result == NULL) {
        return (int)status;
    }
    NSData *data = (__bridge_transfer NSData *)result;
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (s == nil) {
        return (int)errSecDecode;
    }
    *out = strdup([s UTF8String]);
    return 0;
}

int kc_exists(const char *service, const char *account) {
    NSMutableDictionary *q = kc_query([NSString stringWithUTF8String:service],
                                      [NSString stringWithUTF8String:account]);
    q[(__bridge id)kSecReturnAttributes] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)q, NULL);
    return (int)status;
}

int kc_delete(const char *service, const char *account) {
    return (int)SecItemDelete((__bridge CFDictionaryRef)kc_query(
        [NSString stringWithUTF8String:service],
        [NSString stringWithUTF8String:account]));
}

// kc_biometric_auth returns 0 on success, 1 when biometrics are unavailable,
// 2 when the user cancelled or authentication failed.
int kc_biometric_auth(const char *reason) {
    LAContext *ctx = [[LAContext alloc] init];
    NSError *err = nil;
    LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    if (![ctx canEvaluatePolicy:policy error:&err]) {
        return 1;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block int result = 2;
    [ctx evaluatePolicy:policy
        localizedReason:[NSString stringWithUTF8String:reason]
                  reply:^(BOOL success, NSError *error) {
                    if (success) {
                        result = 0;
                    } else if (error != nil && error.code == LAErrorBiometryNotAvailable) {
                        result = 1;
                    } else {
                        result = 2;
                    }
                    dispatch_semaphore_signal(sem);
                  }];
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC));
    if (dispatch_semaphore_wait(sem, timeout) != 0) {
        return 1;
    }
    return result;
}

void kc_free(char *p) {
    free(p);
}
