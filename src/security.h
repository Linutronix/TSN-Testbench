/* SPDX-License-Identifier: BSD-2-Clause */
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

enum security_mode {
	SECURITY_MODE_NONE, /* No authentification or enryption */
	SECURITY_MODE_AO,   /* Authentification only */
	SECURITY_MODE_AE,   /* Authentification and encryption */
};

enum security_algorithm {
	SECURITY_ALGORITHM_AES256_GCM,
	SECURITY_ALGORITHM_AES128_GCM,
	SECURITY_ALGORITHM_CHACHA20_POLY1305,
};

static inline const char *security_mode_to_string(enum security_mode mode)
{
	switch (mode) {
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

static inline const char *security_algorithm_to_string(enum security_algorithm algorithm)
{
	switch (algorithm) {
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

struct security_iv {
	unsigned char iv_prefix[SECURITY_IV_PREFIX_LEN];
	uint64_t counter;
} __attribute__((packed));

struct security_context {
	enum security_algorithm algorithm;
	EVP_CIPHER_CTX *ctx;
	EVP_CIPHER *cipher;
};

struct security_context *security_init(enum security_algorithm algorithm, const unsigned char *key);
void security_exit(struct security_context *context);

int security_encrypt(struct security_context *context, const unsigned char *plaintext,
		     size_t plaintext_length, const unsigned char *associated_data,
		     size_t associated_data_length, const unsigned char *iv,
		     unsigned char *ciphertext, unsigned char *tag);

int security_decrypt(struct security_context *context, const unsigned char *ciphertext,
		     size_t ciphertext_length, const unsigned char *associated_data,
		     size_t associated_data_length, unsigned char *tag, const unsigned char *iv,
		     unsigned char *plaintext);

#endif /* _SECURITY_H_ */
