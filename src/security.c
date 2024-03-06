// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>

#include "security.h"

/*
 * Code inspired by https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
 * and https://github.com/openssl/openssl/discussions/22161
 *
 * Notes for the algorithms used: The IV size is 12 bytes. The tag len is always 16 bytes. And Input
 * equals Output length. Furthermore, PROFINET supports Authentification Only. In that case
 * plaintext respectively ciphertext is NULL.
 */

struct SecurityContext *SecurityInit(enum SecurityAlgorithm algorithm, const unsigned char *key)
{
	struct SecurityContext *context;

	context = calloc(1, sizeof(*context));
	if (!context)
		return NULL;

	context->Algorithm = algorithm;

	context->Cipher = EVP_CIPHER_fetch(NULL, SecurityAlgorithmToString(algorithm), NULL);
	if (!context->Cipher)
		goto err_cipher;

	context->Ctx = EVP_CIPHER_CTX_new();
	if (!context->Ctx)
		goto err_ctx;

	/* Set key and cipher */
	if (1 != EVP_EncryptInit_ex2(context->Ctx, context->Cipher, key, NULL, NULL))
		goto err_ctx;

	return context;

err_ctx:
	EVP_CIPHER_free(context->Cipher);
err_cipher:
	free(context);

	return NULL;
}

void SecurityExit(struct SecurityContext *context)
{
	if (!context)
		return;

	EVP_CIPHER_free(context->Cipher);
	EVP_CIPHER_CTX_free(context->Ctx);
	free(context);
}

int SecurityEncrypt(struct SecurityContext *context, const unsigned char *plaintext,
		    size_t plaintextLength, const unsigned char *associatedData,
		    size_t associatedDataLength, const unsigned char *iv, unsigned char *ciphertext,
		    unsigned char *tag)
{
	int ret = -EINVAL, len;

	/* Set IV */
	if (1 != EVP_EncryptInit_ex2(context->Ctx, NULL, NULL, iv, NULL))
		goto out;

	/* Provide associatedData data. */
	if (1 != EVP_EncryptUpdate(context->Ctx, NULL, &len, associatedData, associatedDataLength))
		goto out;

	/* Provide the message to be encrypted, and obtain the encrypted output. */
	if (plaintext) {
		if (1 !=
		    EVP_EncryptUpdate(context->Ctx, ciphertext, &len, plaintext, plaintextLength))
			goto out;
	}

	if (1 != EVP_EncryptFinal_ex(context->Ctx, plaintext ? ciphertext + len : NULL, &len))
		goto out;

	if (1 != EVP_CIPHER_CTX_ctrl(context->Ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		goto out;

	ret = 0;

out:
	return ret;
}

int SecurityDecrypt(struct SecurityContext *context, const unsigned char *ciphertext,
		    size_t ciphertextLength, const unsigned char *associatedData,
		    size_t associatedDataLength, unsigned char *tag, const unsigned char *iv,
		    unsigned char *plaintext)
{
	int ret = -EINVAL, len;

	/* Set IV */
	if (1 != EVP_DecryptInit_ex2(context->Ctx, NULL, NULL, iv, NULL))
		goto out;

	/* Provide associatedData data. */
	if (!EVP_DecryptUpdate(context->Ctx, NULL, &len, associatedData, associatedDataLength))
		goto out;

	/* Provide the message to be decrypted, and obtain the plaintext output. */
	if (ciphertext) {
		if (!EVP_DecryptUpdate(context->Ctx, plaintext, &len, ciphertext, ciphertextLength))
			goto out;
	}

	if (!EVP_CIPHER_CTX_ctrl(context->Ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		goto out;

	ret = EVP_DecryptFinal_ex(context->Ctx, ciphertext ? plaintext + len : NULL, &len);

	ret = ret > 0 ? 0 : -EPERM;

out:
	return ret;
}
