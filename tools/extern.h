/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _EXTERN_H_
#define _EXTERN_H_

struct blob {
	unsigned char *ptr;
	size_t len;
};

EC_KEY *read_ec_pubkey(const char *);
fido_dev_t *open_dev(const char *);
FILE *open_read(const char *);
FILE *open_write(const char *);
int assert_get(int, char **);
int assert_verify(int, char **);
int base64_decode(char *, void **, size_t *);
int base64_encode(const void *, size_t, char **);
int base64_read(FILE *, struct blob *);
int cred_make(int, char **);
int cred_verify(int, char **);
int credman_delete_rk(fido_dev_t *, const char *, char *);
int credman_get_metadata(fido_dev_t *, const char *);
int credman_list_rk(char *, const char *);
int credman_list_rp(char *);
int credman_print_rk(fido_dev_t *, const char *, char *, char *);
int pin_change(char *);
int pin_set(char *);
int string_read(FILE *, char **);
int token_delete_rk(int, char **, char *);
int token_info(int, char **, char *);
int token_list(int, char **, char *);
int token_reset(char *);
int write_ec_pubkey(FILE *, const void *, size_t);
int write_rsa_pubkey(FILE *, const void *, size_t);
RSA *read_rsa_pubkey(const char *);
EVP_PKEY *read_eddsa_pubkey(const char *);
int write_eddsa_pubkey(FILE *, const void *, size_t);
void print_cred(FILE *, int, const fido_cred_t *);
void read_pin(const char *, char *, size_t);
void usage(void);
void xxd(const void *, size_t);

#define TOKEN_OPT	"CDILPRSVcdi:k:r"

#endif /* _EXTERN_H_ */
