#include <stdio.h>
#include <string.h>

#include "api.h"

static int report(const char *name, int passed) {
    printf("%s: %s\n", passed ? "PASS" : "FAIL", name);
    return passed ? 0 : 1;
}

int main(void) {
    static const uint8_t message[] = "Round 3 detached-signature API check";
    const size_t message_len = sizeof(message) - 1;
    uint8_t public_key[pqcrystals_dilithium5_PUBLICKEYBYTES];
    uint8_t secret_key[pqcrystals_dilithium5_SECRETKEYBYTES];
    uint8_t signature[pqcrystals_dilithium5_BYTES];
    uint8_t modified_signature[pqcrystals_dilithium5_BYTES];
    size_t signature_len = 0;
    int failures = 0;

    failures += report("public key size is 2592 bytes",
                       pqcrystals_dilithium5_PUBLICKEYBYTES == 2592);
    failures += report("secret key size is 4864 bytes",
                       pqcrystals_dilithium5_SECRETKEYBYTES == 4864);
    failures += report("signature size is 4595 bytes",
                       pqcrystals_dilithium5_BYTES == 4595);

    if (pqcrystals_dilithium5_ref_keypair(public_key, secret_key) != 0) {
        failures += report("key-pair generation", 0);
        return 1;
    }
    failures += report("key-pair generation", 1);

    if (pqcrystals_dilithium5_ref_signature(signature, &signature_len, message,
                                            message_len, secret_key) != 0) {
        failures += report("detached signing", 0);
        return 1;
    }
    failures += report("detached signing", 1);
    failures += report("detached signature length",
                       signature_len == pqcrystals_dilithium5_BYTES);

    failures += report("valid detached signature verification",
                       pqcrystals_dilithium5_ref_verify(signature, signature_len,
                                                        message, message_len,
                                                        public_key) == 0);

    {
        uint8_t modified_message[sizeof(message)];
        memcpy(modified_message, message, sizeof(message));
        modified_message[0] ^= 1U;
        failures += report("modified message rejected",
                           pqcrystals_dilithium5_ref_verify(
                               signature, signature_len, modified_message,
                               message_len, public_key) != 0);
    }

    memcpy(modified_signature, signature, signature_len);
    modified_signature[0] ^= 1U;
    failures += report("modified signature rejected",
                       pqcrystals_dilithium5_ref_verify(
                           modified_signature, signature_len, message,
                           message_len, public_key) != 0);

    return failures == 0 ? 0 : 1;
}
