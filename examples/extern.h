/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _EXTERN_H_
#define _EXTERN_H_

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

/* util.c */
EC_KEY *read_ec_pubkey(const char *);
RSA *read_rsa_pubkey(const  char *);
EVP_PKEY *read_eddsa_pubkey(const char *);
int read_blob(const char *, unsigned char **, size_t *);
int write_blob(const char *, const unsigned char *, size_t);
int write_ec_pubkey(const char *, const void *, size_t);
int write_rsa_pubkey(const char *, const void *, size_t);
int write_eddsa_pubkey(const char *, const void *, size_t);

#endif /* _EXTERN_H_ */
