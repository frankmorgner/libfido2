/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _FIDO_H
#define _FIDO_H

#include <openssl/ec.h>
#include <openssl/evp.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef void *fido_dev_io_open_t(const char *);
typedef void  fido_dev_io_close_t(void *);
typedef int   fido_dev_io_read_t(void *, unsigned char *, size_t, int);
typedef int   fido_dev_io_write_t(void *, const unsigned char *, size_t);

typedef struct fido_dev_io {
	fido_dev_io_open_t  *open;
	fido_dev_io_close_t *close;
	fido_dev_io_read_t  *read;
	fido_dev_io_write_t *write;
} fido_dev_io_t;

typedef enum {
	FIDO_OPT_OMIT = 0, /* use authenticator's default */
	FIDO_OPT_FALSE,    /* explicitly set option to false */
	FIDO_OPT_TRUE,     /* explicitly set option to true */
} fido_opt_t;

#ifdef _FIDO_INTERNAL
#include <cbor.h>
#include <limits.h>

#include "blob.h"
#include "../openbsd-compat/openbsd-compat.h"
#include "iso7816.h"
#include "types.h"
#include "extern.h"
#endif

#include "fido/err.h"
#include "fido/param.h"

#ifndef _FIDO_INTERNAL
typedef struct fido_assert fido_assert_t;
typedef struct fido_cbor_info fido_cbor_info_t;
typedef struct fido_cred fido_cred_t;
typedef struct fido_dev fido_dev_t;
typedef struct fido_dev_info fido_dev_info_t;
typedef struct es256_pk es256_pk_t;
typedef struct es256_sk es256_sk_t;
typedef struct rs256_pk rs256_pk_t;
typedef struct eddsa_pk eddsa_pk_t;
#endif

fido_assert_t *fido_assert_new(void);
fido_cred_t *fido_cred_new(void);
fido_dev_t *fido_dev_new(void);
fido_dev_info_t *fido_dev_info_new(size_t);
fido_cbor_info_t *fido_cbor_info_new(void);

void fido_assert_free(fido_assert_t **);
void fido_cbor_info_free(fido_cbor_info_t **);
void fido_cred_free(fido_cred_t **);
void fido_dev_force_fido2(fido_dev_t *);
void fido_dev_force_u2f(fido_dev_t *);
void fido_dev_free(fido_dev_t **);
void fido_dev_info_free(fido_dev_info_t **, size_t);

/* fido_init() flags. */
#define FIDO_DEBUG	0x01

void fido_init(int);

const unsigned char *fido_assert_authdata_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_clientdata_hash_ptr(const fido_assert_t *);
const unsigned char *fido_assert_hmac_secret_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_id_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_sig_ptr(const fido_assert_t *, size_t);
const unsigned char *fido_assert_user_id_ptr(const fido_assert_t *, size_t);

char **fido_cbor_info_extensions_ptr(const fido_cbor_info_t *);
char **fido_cbor_info_options_name_ptr(const fido_cbor_info_t *);
char **fido_cbor_info_versions_ptr(const fido_cbor_info_t *);
const bool *fido_cbor_info_options_value_ptr(const fido_cbor_info_t *);
const char *fido_assert_rp_id(const fido_assert_t *);
const char *fido_assert_user_display_name(const fido_assert_t *, size_t);
const char *fido_assert_user_icon(const fido_assert_t *, size_t);
const char *fido_assert_user_name(const fido_assert_t *, size_t);
const char *fido_cred_display_name(const fido_cred_t *);
const char *fido_cred_fmt(const fido_cred_t *);
const char *fido_cred_rp_id(const fido_cred_t *);
const char *fido_cred_rp_name(const fido_cred_t *);
const char *fido_cred_user_name(const fido_cred_t *);
const char *fido_dev_info_manufacturer_string(const fido_dev_info_t *);
const char *fido_dev_info_path(const fido_dev_info_t *);
const char *fido_dev_info_product_string(const fido_dev_info_t *);
const fido_dev_info_t *fido_dev_info_ptr(const fido_dev_info_t *, size_t);
const uint8_t *fido_cbor_info_protocols_ptr(const fido_cbor_info_t *);
const unsigned char *fido_cbor_info_aaguid_ptr(const fido_cbor_info_t *);
const unsigned char *fido_cred_authdata_ptr(const fido_cred_t *);
const unsigned char *fido_cred_clientdata_hash_ptr(const fido_cred_t *);
const unsigned char *fido_cred_id_ptr(const fido_cred_t *);
const unsigned char *fido_cred_user_id_ptr(const fido_cred_t *);
const unsigned char *fido_cred_pubkey_ptr(const fido_cred_t *);
const unsigned char *fido_cred_sig_ptr(const fido_cred_t *);
const unsigned char *fido_cred_x5c_ptr(const fido_cred_t *);

int fido_assert_allow_cred(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_set_authdata(fido_assert_t *, size_t, const unsigned char *,
    size_t);
int fido_assert_set_clientdata_hash(fido_assert_t *, const unsigned char *,
    size_t);
int fido_assert_set_count(fido_assert_t *, size_t);
int fido_assert_set_extensions(fido_assert_t *, int);
int fido_assert_set_hmac_salt(fido_assert_t *, const unsigned char *, size_t);
int fido_assert_set_options(fido_assert_t *, bool, bool) __attribute__((__deprecated__));
int fido_assert_set_rp(fido_assert_t *, const char *);
int fido_assert_set_up(fido_assert_t *, fido_opt_t);
int fido_assert_set_uv(fido_assert_t *, fido_opt_t);
int fido_assert_set_sig(fido_assert_t *, size_t, const unsigned char *, size_t);
int fido_assert_verify(const fido_assert_t *, size_t, int, const void *);
int fido_cred_exclude(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_authdata(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_clientdata_hash(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_extensions(fido_cred_t *, int);
int fido_cred_set_fmt(fido_cred_t *, const char *);
int fido_cred_set_options(fido_cred_t *, bool, bool) __attribute__((__deprecated__));
int fido_cred_set_rk(fido_cred_t *, fido_opt_t);
int fido_cred_set_rp(fido_cred_t *, const char *, const char *);
int fido_cred_set_sig(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_set_type(fido_cred_t *, int);
int fido_cred_set_uv(fido_cred_t *, fido_opt_t);
int fido_cred_type(const fido_cred_t *);
int fido_cred_set_user(fido_cred_t *, const unsigned char *, size_t,
    const char *, const char *, const char *);
int fido_cred_set_x509(fido_cred_t *, const unsigned char *, size_t);
int fido_cred_verify(const fido_cred_t *);
int fido_dev_close(fido_dev_t *);
int fido_dev_get_assert(fido_dev_t *, fido_assert_t *, const char *);
int fido_dev_get_cbor_info(fido_dev_t *, fido_cbor_info_t *);
int fido_dev_get_retry_count(fido_dev_t *, int *);
int fido_dev_info_manifest(fido_dev_info_t *, size_t, size_t *);
int fido_dev_make_cred(fido_dev_t *, fido_cred_t *, const char *);
int fido_dev_open(fido_dev_t *, const char *);
int fido_dev_reset(fido_dev_t *);
int fido_dev_set_io_functions(fido_dev_t *, const fido_dev_io_t *);
int fido_dev_set_pin(fido_dev_t *, const char *, const char *);

size_t fido_assert_authdata_len(const fido_assert_t *, size_t);
size_t fido_assert_clientdata_hash_len(const fido_assert_t *);
size_t fido_assert_count(const fido_assert_t *);
size_t fido_assert_hmac_secret_len(const fido_assert_t *, size_t);
size_t fido_assert_id_len(const fido_assert_t *, size_t);
size_t fido_assert_sig_len(const fido_assert_t *, size_t);
size_t fido_assert_user_id_len(const fido_assert_t *, size_t);
size_t fido_cbor_info_aaguid_len(const fido_cbor_info_t *);
size_t fido_cbor_info_extensions_len(const fido_cbor_info_t *);
size_t fido_cbor_info_options_len(const fido_cbor_info_t *);
size_t fido_cbor_info_protocols_len(const fido_cbor_info_t *);
size_t fido_cbor_info_versions_len(const fido_cbor_info_t *);
size_t fido_cred_authdata_len(const fido_cred_t *);
size_t fido_cred_clientdata_hash_len(const fido_cred_t *);
size_t fido_cred_id_len(const fido_cred_t *);
size_t fido_cred_user_id_len(const fido_cred_t *);
size_t fido_cred_pubkey_len(const fido_cred_t *);
size_t fido_cred_sig_len(const fido_cred_t *);
size_t fido_cred_x5c_len(const fido_cred_t *);

uint8_t  fido_assert_flags(const fido_assert_t *, size_t);
uint8_t  fido_cred_flags(const fido_cred_t *);
uint8_t  fido_dev_protocol(const fido_dev_t *);
uint8_t  fido_dev_major(const fido_dev_t *);
uint8_t  fido_dev_minor(const fido_dev_t *);
uint8_t  fido_dev_build(const fido_dev_t *);
uint8_t  fido_dev_flags(const fido_dev_t *);
int16_t  fido_dev_info_vendor(const fido_dev_info_t *);
int16_t  fido_dev_info_product(const fido_dev_info_t *);
uint64_t fido_cbor_info_maxmsgsiz(const fido_cbor_info_t *);

bool fido_dev_is_fido2(const fido_dev_t *);

#endif /* !_FIDO_H */
