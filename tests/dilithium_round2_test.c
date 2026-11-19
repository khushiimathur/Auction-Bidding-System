#include <stdio.h>
#include <string.h>

#include "api.h"

static int report(const char *name, int passed) {
    printf("%s: %s\n", passed ? "PASS" : "FAIL", name);
    return passed ? 0 : 1;
}

int main(void) {
    static const unsigned char message[] = "Round 2 attached-message API check";
    const unsigned long long message_len = (unsigned long long)(sizeof(message) - 1);
    unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
    unsigned char secret_key[CRYPTO_SECRETKEYBYTES];
    unsigned char signed_message[CRYPTO_BYTES + sizeof(message) - 1];
    unsigned char modified[CRYPTO_BYTES + sizeof(message) - 1];
    unsigned char recovered[sizeof(signed_message)];
    unsigned long long signed_message_len = 0;
    unsigned long long recovered_len = 0;
    int failures = 0;

    failures += report("public key size is 1760 bytes", CRYPTO_PUBLICKEYBYTES == 1760U);
    failures += report("secret key size is 3856 bytes", CRYPTO_SECRETKEYBYTES == 3856U);
    failures += report("signature size is 3366 bytes", CRYPTO_BYTES == 3366U);

    if (crypto_sign_keypair(public_key, secret_key) != 0) {
        failures += report("key-pair generation", 0);
        return 1;
    }
    failures += report("key-pair generation", 1);

    if (crypto_sign(signed_message, &signed_message_len, message, message_len,
                    secret_key) != 0) {
        failures += report("attached signing", 0);
        return 1;
    }
    failures += report("attached signing", 1);
    failures += report("attached message length", 
                       signed_message_len == CRYPTO_BYTES + message_len);

    recovered_len = 0;
    failures += report("valid signature verification and message recovery",
                       crypto_sign_open(recovered, &recovered_len, signed_message,
                                        signed_message_len, public_key) == 0 &&
                           recovered_len == message_len &&
                           memcmp(recovered, message, message_len) == 0);

    memcpy(modified, signed_message, (size_t)signed_message_len);
    modified[CRYPTO_BYTES] ^= 1U;
    recovered_len = 0;
    failures += report("modified message rejected",
                       crypto_sign_open(recovered, &recovered_len, modified,
                                        signed_message_len, public_key) != 0);

    memcpy(modified, signed_message, (size_t)signed_message_len);
    modified[0] ^= 1U;
    recovered_len = 0;
    failures += report("modified signature rejected",
                       crypto_sign_open(recovered, &recovered_len, modified,
                                        signed_message_len, public_key) != 0);

    return failures == 0 ? 0 : 1;
}
