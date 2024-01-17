// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _SECURITY_H_
#define _SECURITY_H_

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <stddef.h>
#include <stdint.h>

enum SecurityMode
{
    SECURITY_MODE_NONE, /* No authentification or enryption */
    SECURITY_MODE_AO,   /* Authentification only */
    SECURITY_MODE_AE,   /* Authentification and encryption */
};

enum SecurityAlgorithm
{
    SECURITY_ALGORITHM_AES256_GCM,
    SECURITY_ALGORITHM_AES128_GCM,
    SECURITY_ALGORITHM_CHACHA20_POLY1305,
};

static inline const char *SecurityModeToString(enum SecurityMode mode)
{
    switch (mode)
    {
    case SECURITY_MODE_NONE:
        return "None";
    case SECURITY_MODE_AO:
        return "Authentication";
    case SECURITY_MODE_AE:
        return "Authentication and Encryption";
    default:
        return "Unknown";
    }
}

static inline const char *SecurityAlgorithmToString(enum SecurityAlgorithm algorithm)
{
    switch (algorithm)
    {
    case SECURITY_ALGORITHM_AES256_GCM:
        return "AES-256-GCM";
    case SECURITY_ALGORITHM_AES128_GCM:
        return "AES-128-GCM";
    case SECURITY_ALGORITHM_CHACHA20_POLY1305:
        return "CHACHA20-POLY1305";
    default:
        return "Unknown";
    }
}

#define SECURITY_IV_LEN 12
#define SECURITY_IV_PREFIX_LEN 6
#define SECURITY_IV_COUNTER_LEN 6

struct SecurityIv
{
    unsigned char IvPrefix[SECURITY_IV_PREFIX_LEN];
    uint64_t Counter;
} __attribute__((packed));

struct SecurityContext
{
    enum SecurityAlgorithm Algorithm;
    EVP_CIPHER_CTX *Ctx;
    EVP_CIPHER *Cipher;
};

struct SecurityContext *SecurityInit(enum SecurityAlgorithm algorithm, const unsigned char *key);
void SecurityExit(struct SecurityContext *context);

int SecurityEncrypt(struct SecurityContext *context, const unsigned char *plaintext, size_t plaintextLength,
                    const unsigned char *associatedData, size_t associatedDataLength, const unsigned char *iv,
                    unsigned char *ciphertext, unsigned char *tag);

int SecurityDecrypt(struct SecurityContext *context, const unsigned char *ciphertext, size_t ciphertextLength,
                    const unsigned char *associatedData, size_t associatedDataLength, unsigned char *tag,
                    const unsigned char *iv, unsigned char *plaintext);

#endif /* _SECURITY_H_ */
