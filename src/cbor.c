/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <string.h>
#include "fido.h"

static int
check_key_type(cbor_item_t *item)
{
	if (item->type == CBOR_TYPE_UINT || item->type == CBOR_TYPE_NEGINT ||
	    item->type == CBOR_TYPE_STRING)
		return (0);

	log_debug("%s: invalid type: %d", __func__, item->type);

	return (-1);
}

/*
 * Validate CTAP2 canonical CBOR encoding rules for maps.
 */
static int
ctap_check_cbor(cbor_item_t *prev, cbor_item_t *curr)
{
	size_t	curr_len;
	size_t	prev_len;

	if (check_key_type(prev) < 0 || check_key_type(curr) < 0)
		return (-1);

	if (prev->type != curr->type) {
		if (prev->type < curr->type)
			return (0);
		log_debug("%s: unsorted types", __func__);
		return (-1);
	}

	if (curr->type == CBOR_TYPE_UINT || curr->type == CBOR_TYPE_NEGINT) {
		if (cbor_int_get_width(curr) > cbor_int_get_width(prev) ||
		    cbor_get_int(curr) > cbor_get_int(prev))
			return (0);
	} else {
		curr_len = cbor_string_length(curr);
		prev_len = cbor_string_length(prev);

		if (curr_len > prev_len || (curr_len == prev_len &&
		    memcmp(cbor_string_handle(prev), cbor_string_handle(curr),
		    curr_len) < 0))
			return (0);
	}

	log_debug("%s: invalid cbor", __func__);

	return (-1);
}

int
cbor_map_iter(const cbor_item_t *item, void *arg, int(*f)(const cbor_item_t *,
    const cbor_item_t *, void *))
{
	struct cbor_pair	*v;
	size_t			 n;

	if ((v = cbor_map_handle(item)) == NULL) {
		log_debug("%s: cbor_map_handle", __func__);
		return (-1);
	}

	n = cbor_map_size(item);

	for (size_t i = 0; i < n; i++) {
		if (v[i].key == NULL || v[i].value == NULL) {
			log_debug("%s: key=%p, value=%p for i=%zu", __func__,
			    (void *)v[i].key, (void *)v[i].value, i);
			return (-1);
		}
		if (i && ctap_check_cbor(v[i - 1].key, v[i].key) < 0) {
			log_debug("%s: ctap_check_cbor", __func__);
			return (-1);
		}
		if (f(v[i].key, v[i].value, arg) < 0) {
			log_debug("%s: iterator < 0 on i=%zu", __func__, i);
			return (-1);
		}
	}

	return (0);
}

int
cbor_array_iter(const cbor_item_t *item, void *arg, int(*f)(const cbor_item_t *,
    void *))
{
	cbor_item_t	**v;
	size_t		  n;

	if ((v = cbor_array_handle(item)) == NULL) {
		log_debug("%s: cbor_array_handle", __func__);
		return (-1);
	}

	n = cbor_array_size(item);

	for (size_t i = 0; i < n; i++)
		if (v[i] == NULL || f(v[i], arg) < 0) {
			log_debug("%s: iterator < 0 on i=%zu,%p", __func__, i,
			    (void *)v[i]);
			return (-1);
		}

	return (0);
}

int
parse_cbor_reply(const unsigned char *blob, size_t blob_len, void *arg,
    int(*parser)(const cbor_item_t *, const cbor_item_t *, void *))
{
	cbor_item_t		*item = NULL;
	struct cbor_load_result	 cbor;
	int			 r;

	if (blob_len < 1) {
		log_debug("%s: blob_len=%zu", __func__, blob_len);
		r = FIDO_ERR_RX;
		goto fail;
	}

	if (blob[0] != FIDO_OK) {
		log_debug("%s: blob[0]=0x%02x", __func__, blob[0]);
		r = blob[0];
		goto fail;
	}

	if ((item = cbor_load(blob + 1, blob_len - 1, &cbor)) == NULL) {
		log_debug("%s: cbor_load", __func__);
		r = FIDO_ERR_RX_NOT_CBOR;
		goto fail;
	}

	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false) {
		log_debug("%s: cbor type", __func__);
		r = FIDO_ERR_RX_INVALID_CBOR;
		goto fail;
	}

	if (cbor_map_iter(item, arg, parser) < 0) {
		log_debug("%s: cbor_map_iter", __func__);
		r = FIDO_ERR_RX_INVALID_CBOR;
		goto fail;
	}

	r = FIDO_OK;
fail:
	if (item != NULL)
		cbor_decref(&item);

	return (r);
}

int
cbor_bytestring_copy(const cbor_item_t *item, unsigned char **buf, size_t *len)
{
	if (*buf != NULL || *len != 0) {
		log_debug("%s: dup", __func__);
		return (-1);
	}

	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	*len = cbor_bytestring_length(item);
	if ((*buf = malloc(*len)) == NULL) {
		*len = 0;
		return (-1);
	}

	memcpy(*buf, cbor_bytestring_handle(item), *len);

	return (0);
}

int
cbor_string_copy(const cbor_item_t *item, char **str)
{
	size_t len;

	if (*str != NULL) {
		log_debug("%s: dup", __func__);
		return (-1);
	}

	if (cbor_isa_string(item) == false ||
	    cbor_string_is_definite(item) == false) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	if ((len = cbor_string_length(item)) == SIZE_MAX ||
	    (*str = malloc(len + 1)) == NULL)
		return (-1);

	memcpy(*str, cbor_string_handle(item), len);
	(*str)[len] = '\0';

	return (0);
}

int
cbor_add_bytestring(cbor_item_t *item, const char *key,
    const unsigned char *value, size_t value_len)
{
	struct cbor_pair pair;
	int ok = -1;

	memset(&pair, 0, sizeof(pair));

	if ((pair.key = cbor_build_string(key)) == NULL ||
	    (pair.value = cbor_build_bytestring(value, value_len)) == NULL) {
		log_debug("%s: cbor_build", __func__);
		goto fail;
	}

	if (!cbor_map_add(item, pair)) {
		log_debug("%s: cbor_map_add", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pair.key)
		cbor_decref(&pair.key);
	if (pair.value)
		cbor_decref(&pair.value);

	return (ok);
}

int
cbor_add_string(cbor_item_t *item, const char *key, const char *value)
{
	struct cbor_pair pair;
	int ok = -1;

	memset(&pair, 0, sizeof(pair));

	if ((pair.key = cbor_build_string(key)) == NULL ||
	    (pair.value = cbor_build_string(value)) == NULL) {
		log_debug("%s: cbor_build", __func__);
		goto fail;
	}

	if (!cbor_map_add(item, pair)) {
		log_debug("%s: cbor_map_add", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pair.key)
		cbor_decref(&pair.key);
	if (pair.value)
		cbor_decref(&pair.value);

	return (ok);
}

int
cbor_add_bool(cbor_item_t *item, const char *key, fido_opt_t value)
{
	struct cbor_pair pair;
	int ok = -1;

	memset(&pair, 0, sizeof(pair));

	if ((pair.key = cbor_build_string(key)) == NULL ||
	    (pair.value = cbor_build_bool(value == FIDO_OPT_TRUE)) == NULL) {
		log_debug("%s: cbor_build", __func__);
		goto fail;
	}

	if (!cbor_map_add(item, pair)) {
		log_debug("%s: cbor_map_add", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pair.key)
		cbor_decref(&pair.key);
	if (pair.value)
		cbor_decref(&pair.value);

	return (ok);
}

static int
cbor_add_arg(cbor_item_t *item, uint8_t n, cbor_item_t *arg)
{
	struct cbor_pair pair;
	int ok = -1;

	memset(&pair, 0, sizeof(pair));

	if (arg == NULL)
		return (0); /* empty argument */

	if ((pair.key = cbor_build_uint8(n)) == NULL) {
		log_debug("%s: cbor_build", __func__);
		goto fail;
	}

	pair.value = arg;

	if (!cbor_map_add(item, pair)) {
		log_debug("%s: cbor_map_add", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pair.key)
		cbor_decref(&pair.key);

	return (ok);
}

cbor_item_t *
cbor_flatten_vector(cbor_item_t *argv[], size_t argc)
{
	cbor_item_t	*map;
	uint8_t		 i;

	if (argc > UINT8_MAX - 1)
		return (NULL);

	if ((map = cbor_new_definite_map(argc)) == NULL)
		return (NULL);

	for (i = 0; i < argc; i++)
		if (cbor_add_arg(map, i + 1, argv[i]) < 0)
			break;

	if (i != argc) {
		cbor_decref(&map);
		map = NULL;
	}

	return (map);
}

int
cbor_build_frame(uint8_t cmd, cbor_item_t *argv[], size_t argc, fido_blob_t *f)
{
	cbor_item_t	*flat = NULL;
	unsigned char	*cbor = NULL;
	size_t		 cbor_len;
	size_t		 cbor_alloc_len;
	int		 ok = -1;

	if ((flat = cbor_flatten_vector(argv, argc)) == NULL)
		goto fail;

	cbor_len = cbor_serialize_alloc(flat, &cbor, &cbor_alloc_len);
	if (cbor_len == 0 || cbor_len == SIZE_MAX) {
		log_debug("%s: cbor_len=%zu", __func__, cbor_len);
		goto fail;
	}

	if ((f->ptr = malloc(cbor_len + 1)) == NULL)
		goto fail;

	f->len = cbor_len + 1;
	f->ptr[0] = cmd;
	memcpy(f->ptr + 1, cbor, f->len - 1);

	ok = 0;
fail:
	if (flat != NULL)
		cbor_decref(&flat);

	free(cbor);

	return (ok);
}

cbor_item_t *
encode_rp_entity(const fido_rp_t *rp)
{
	cbor_item_t *item = NULL;

	if ((item = cbor_new_definite_map(2)) == NULL)
		return (NULL);

	if ((rp->id && cbor_add_string(item, "id", rp->id) < 0) ||
	    (rp->name && cbor_add_string(item, "name", rp->name) < 0)) {
		cbor_decref(&item);
		return (NULL);
	}

	return (item);
}

cbor_item_t *
encode_user_entity(const fido_user_t *user)
{
	cbor_item_t		*item = NULL;
	const fido_blob_t	*id = &user->id;
	const char		*display = user->display_name;

	if ((item = cbor_new_definite_map(4)) == NULL)
		return (NULL);

	if ((id->ptr && cbor_add_bytestring(item, "id", id->ptr, id->len) < 0) ||
	    (user->icon && cbor_add_string(item, "icon", user->icon) < 0) ||
	    (user->name && cbor_add_string(item, "name", user->name) < 0) ||
	    (display && cbor_add_string(item, "displayName", display) < 0)) {
		cbor_decref(&item);
		return (NULL);
	}

	return (item);
}

cbor_item_t *
encode_pubkey_param(int cose_alg)
{
	cbor_item_t		*item = NULL;
	cbor_item_t		*body = NULL;
	struct cbor_pair	 alg;
	int			 ok = -1;

	memset(&alg, 0, sizeof(alg));

	if ((item = cbor_new_definite_array(1)) == NULL ||
	    (body = cbor_new_definite_map(2)) == NULL ||
	    cose_alg > -1 || cose_alg < INT16_MIN)
		goto fail;

	alg.key = cbor_build_string("alg");

	if (-cose_alg - 1 > UINT8_MAX)
		alg.value = cbor_build_negint16((uint16_t)(-cose_alg - 1));
	else
		alg.value = cbor_build_negint8((uint8_t)(-cose_alg - 1));

	if (alg.key == NULL || alg.value == NULL) {
		log_debug("%s: cbor_build", __func__);
		goto fail;
	}

	if (cbor_map_add(body, alg) == false ||
	    cbor_add_string(body, "type", "public-key") < 0 ||
	    cbor_array_push(item, body) == false)
		goto fail;

	ok  = 0;
fail:
	if (ok < 0) {
		if (item != NULL) {
			cbor_decref(&item);
			item = NULL;
		}
	}

	if (body != NULL)
		cbor_decref(&body);
	if (alg.key != NULL)
		cbor_decref(&alg.key);
	if (alg.value != NULL)
		cbor_decref(&alg.value);

	return (item);
}

cbor_item_t *
encode_pubkey(const fido_blob_t *pubkey)
{
	cbor_item_t *cbor_key = NULL;

	if ((cbor_key = cbor_new_definite_map(2)) == NULL ||
	    cbor_add_bytestring(cbor_key, "id", pubkey->ptr, pubkey->len) < 0 ||
	    cbor_add_string(cbor_key, "type", "public-key") < 0) {
		if (cbor_key)
			cbor_decref(&cbor_key);
		return (NULL);
	}

	return (cbor_key);
}

cbor_item_t *
encode_pubkey_list(const fido_blob_array_t *list)
{
	cbor_item_t	*array = NULL;
	cbor_item_t	*key = NULL;

	if ((array = cbor_new_definite_array(list->len)) == NULL)
		goto fail;

	for (size_t i = 0; i < list->len; i++) {
		if ((key = encode_pubkey(&list->ptr[i])) == NULL ||
		    cbor_array_push(array, key) == false)
			goto fail;
		cbor_decref(&key);
	}

	return (array);
fail:
	if (key != NULL)
		cbor_decref(&key);
	if (array != NULL)
		cbor_decref(&array);

	return (NULL);
}

cbor_item_t *
encode_extensions(int ext)
{
	cbor_item_t *item = NULL;

	if (ext == 0 || ext != FIDO_EXT_HMAC_SECRET)
		return (NULL);

	if ((item = cbor_new_definite_map(1)) == NULL)
		return (NULL);

	if (cbor_add_bool(item, "hmac-secret", FIDO_OPT_TRUE) < 0) {
		cbor_decref(&item);
		return (NULL);
	}

	return (item);
}

cbor_item_t *
encode_options(fido_opt_t rk, fido_opt_t uv)
{
	cbor_item_t *item = NULL;

	if ((item = cbor_new_definite_map(2)) == NULL)
		return (NULL);

	if ((rk != FIDO_OPT_OMIT && cbor_add_bool(item, "rk", rk) < 0) ||
	    (uv != FIDO_OPT_OMIT && cbor_add_bool(item, "uv", uv) < 0)) {
		cbor_decref(&item);
		return (NULL);
	}

	return (item);
}

cbor_item_t *
encode_assert_options(fido_opt_t up, fido_opt_t uv)
{
	cbor_item_t *item = NULL;

	if ((item = cbor_new_definite_map(2)) == NULL)
		return (NULL);

	if ((up != FIDO_OPT_OMIT && cbor_add_bool(item, "up", up) < 0) ||
	    (uv != FIDO_OPT_OMIT && cbor_add_bool(item, "uv", uv) < 0)) {
		cbor_decref(&item);
		return (NULL);
	}

	return (item);
}

cbor_item_t *
encode_pin_auth(const fido_blob_t *hmac_key, const fido_blob_t *data)
{
	const EVP_MD	*md = NULL;
	unsigned char	 dgst[SHA256_DIGEST_LENGTH];
	unsigned int	 dgst_len;

	if ((md = EVP_sha256()) == NULL || HMAC(md, hmac_key->ptr,
	    (int)hmac_key->len, data->ptr, (int)data->len, dgst,
	    &dgst_len) == NULL || dgst_len != SHA256_DIGEST_LENGTH)
		return (NULL);

	return (cbor_build_bytestring(dgst, 16));
}

cbor_item_t *
encode_pin_opt(void)
{
	return (cbor_build_uint8(1));
}

cbor_item_t *
encode_pin_enc(const fido_blob_t *key, const fido_blob_t *pin)
{
	fido_blob_t	 pe;
	cbor_item_t	*item = NULL;

	if (aes256_cbc_enc(key, pin, &pe) < 0)
		return (NULL);

	item = cbor_build_bytestring(pe.ptr, pe.len);
	free(pe.ptr);

	return (item);
}

static int
sha256(const unsigned char *data, size_t data_len, fido_blob_t *digest)
{
	if ((digest->ptr = calloc(1, SHA256_DIGEST_LENGTH)) == NULL)
		return (-1);

	digest->len = SHA256_DIGEST_LENGTH;

	if (SHA256(data, data_len, digest->ptr) != digest->ptr) {
		free(digest->ptr);
		digest->ptr = NULL;
		digest->len = 0;
		return (-1);
	}

	return (0);
}

cbor_item_t *
encode_change_pin_auth(const fido_blob_t *key, const fido_blob_t *new_pin,
    const fido_blob_t *pin)
{
	unsigned char	 dgst[SHA256_DIGEST_LENGTH];
	unsigned int	 dgst_len;
	cbor_item_t	*item = NULL;
	const EVP_MD	*md = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX	 ctx;
#else
	HMAC_CTX	*ctx = NULL;
#endif
	fido_blob_t	*npe = NULL; /* new pin, encrypted */
	fido_blob_t	*ph = NULL;  /* pin hash */
	fido_blob_t	*phe = NULL; /* pin hash, encrypted */
	int		 ok = -1;

	if ((npe = fido_blob_new()) == NULL ||
	    (ph = fido_blob_new()) == NULL ||
	    (phe = fido_blob_new()) == NULL)
		goto fail;

	if (aes256_cbc_enc(key, new_pin, npe) < 0) {
		log_debug("%s: aes256_cbc_enc 1", __func__);
		goto fail;
	}

	if (sha256(pin->ptr, pin->len, ph) < 0 || ph->len < 16) {
		log_debug("%s: sha256", __func__);
		goto fail;
	}

	ph->len = 16; /* first 16 bytes */

	if (aes256_cbc_enc(key, ph, phe) < 0) {
		log_debug("%s: aes256_cbc_enc 2", __func__);
		goto fail;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX_init(&ctx);

	if ((md = EVP_sha256()) == NULL ||
	    HMAC_Init_ex(&ctx, key->ptr, (int)key->len, md, NULL) == 0 ||
	    HMAC_Update(&ctx, npe->ptr, (int)npe->len) == 0 ||
	    HMAC_Update(&ctx, phe->ptr, (int)phe->len) == 0 ||
	    HMAC_Final(&ctx, dgst, &dgst_len) == 0 || dgst_len != 32) {
		log_debug("%s: HMAC", __func__);
		goto fail;
	}
#else
	if ((ctx = HMAC_CTX_new()) == NULL ||
	    (md = EVP_sha256())  == NULL ||
	    HMAC_Init_ex(ctx, key->ptr, (int)key->len, md, NULL) == 0 ||
	    HMAC_Update(ctx, npe->ptr, (int)npe->len) == 0 ||
	    HMAC_Update(ctx, phe->ptr, (int)phe->len) == 0 ||
	    HMAC_Final(ctx, dgst, &dgst_len) == 0 || dgst_len != 32) {
		log_debug("%s: HMAC", __func__);
		goto fail;
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

	if ((item = cbor_build_bytestring(dgst, 16)) == NULL) {
		log_debug("%s: cbor_build_bytestring", __func__);
		goto fail;
	}

	ok = 0;
fail:
	fido_blob_free(&npe);
	fido_blob_free(&ph);
	fido_blob_free(&phe);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (ctx != NULL)
		HMAC_CTX_free(ctx);
#endif

	if (ok < 0) {
		if (item != NULL) {
			cbor_decref(&item);
			item = NULL;
		}
	}

	return (item);
}

cbor_item_t *
encode_set_pin_auth(const fido_blob_t *key, const fido_blob_t *pin)
{
	const EVP_MD	*md = NULL;
	unsigned char	 dgst[SHA256_DIGEST_LENGTH];
	unsigned int	 dgst_len;
	cbor_item_t	*item = NULL;
	fido_blob_t	*pe = NULL;

	if ((pe = fido_blob_new()) == NULL)
		goto fail;

	if (aes256_cbc_enc(key, pin, pe) < 0) {
		log_debug("%s: aes256_cbc_enc", __func__);
		goto fail;
	}

	if ((md = EVP_sha256()) == NULL || key->len != 32 || HMAC(md, key->ptr,
	    (int)key->len, pe->ptr, (int)pe->len, dgst, &dgst_len) == NULL ||
	    dgst_len != SHA256_DIGEST_LENGTH) {
		log_debug("%s: HMAC", __func__);
		goto fail;
	}

	item = cbor_build_bytestring(dgst, 16);
fail:
	fido_blob_free(&pe);

	return (item);
}

cbor_item_t *
encode_pin_hash_enc(const fido_blob_t *shared, const fido_blob_t *pin)
{
	cbor_item_t	*item = NULL;
	fido_blob_t	*ph = NULL;
	fido_blob_t	*phe = NULL;

	if ((ph = fido_blob_new()) == NULL || (phe = fido_blob_new()) == NULL)
		goto fail;

	if (sha256(pin->ptr, pin->len, ph) < 0 || ph->len < 16) {
		log_debug("%s: SHA256", __func__);
		goto fail;
	}

	ph->len = 16; /* first 16 bytes */

	if (aes256_cbc_enc(shared, ph, phe) < 0) {
		log_debug("%s: aes256_cbc_enc", __func__);
		goto fail;
	}

	item = cbor_build_bytestring(phe->ptr, phe->len);
fail:
	fido_blob_free(&ph);
	fido_blob_free(&phe);

	return (item);
}

cbor_item_t *
encode_hmac_secret_param(const fido_blob_t *ecdh, const es256_pk_t *pk,
    const fido_blob_t *hmac_salt)
{
	cbor_item_t		*item = NULL;
	cbor_item_t		*param = NULL;
	cbor_item_t		*argv[3];
	struct cbor_pair	 pair;

	memset(argv, 0, sizeof(argv));
	memset(&pair, 0, sizeof(pair));

	if (ecdh == NULL || pk == NULL || hmac_salt->ptr == NULL) {
		log_debug("%s: ecdh=%p, pk=%p, hmac_salt->ptr=%p", __func__,
		    (const void *)ecdh, (const void *)pk,
		    (const void *)hmac_salt->ptr);
		goto fail;
	}

	if (hmac_salt->len != 32 && hmac_salt->len != 64) {
		log_debug("%s: hmac_salt->len=%zu", __func__, hmac_salt->len);
		goto fail;
	}

	/* XXX not pin, but salt */
	if ((argv[0] = es256_pk_encode(pk)) == NULL ||
	    (argv[1] = encode_pin_enc(ecdh, hmac_salt)) == NULL ||
	    (argv[2] = encode_set_pin_auth(ecdh, hmac_salt)) == NULL) {
		log_debug("%s: cbor encode", __func__);
		goto fail;
	}

	if ((param = cbor_flatten_vector(argv, 3)) == NULL) {
		log_debug("%s: cbor_flatten_vector", __func__);
		goto fail;
	}

	if ((item = cbor_new_definite_map(1)) == NULL) {
		log_debug("%s: cbor_new_definite_map", __func__);
		goto fail;
	}

	if ((pair.key = cbor_build_string("hmac-secret")) == NULL) {
		log_debug("%s: cbor_build", __func__);
		goto fail;
	}

	pair.value = param;

	if (!cbor_map_add(item, pair)) {
		log_debug("%s: cbor_map_add", __func__);
		cbor_decref(&item);
		item = NULL;
		goto fail;
	}

fail:
	for (size_t i = 0; i < 3; i++)
		if (argv[i] != NULL)
			cbor_decref(&argv[i]);

	if (param != NULL)
		cbor_decref(&param);
	if (pair.key != NULL)
		cbor_decref(&pair.key);

	return (item);
}

int
decode_fmt(const cbor_item_t *item, char **fmt)
{
	char	*type = NULL;

	if (cbor_string_copy(item, &type) < 0) {
		log_debug("%s: cbor_string_copy", __func__);
		return (-1);
	}

	if (strcmp(type, "packed") && strcmp(type, "fido-u2f")) {
		log_debug("%s: type=%s", __func__, type);
		free(type);
		return (-1);
	}

	*fmt = type;

	return (0);
}

struct cose_key {
	int kty;
	int alg;
	int crv;
};

static int
find_cose_alg(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	struct cose_key *cose_key = arg;

	if (cbor_isa_uint(key) == true &&
	    cbor_int_get_width(key) == CBOR_INT_8) {
		switch (cbor_get_uint8(key)) {
		case 1:
			if (cbor_isa_uint(val) == false ||
			    cbor_get_int(val) > INT_MAX || cose_key->kty != 0) {
				log_debug("%s: kty", __func__);
				return (-1);
			}

			cose_key->kty = (int)cbor_get_int(val);

			break;
		case 3:
			if (cbor_isa_negint(val) == false ||
			    cbor_get_int(val) > INT_MAX || cose_key->alg != 0) {
				log_debug("%s: alg", __func__);
				return (-1);
			}

			cose_key->alg = -(int)cbor_get_int(val) - 1;

			break;
		}
	} else if (cbor_isa_negint(key) == true &&
	    cbor_int_get_width(key) == CBOR_INT_8) {
		if (cbor_get_uint8(key) == 0) {
			/* get crv if not rsa, otherwise ignore */
			if (cbor_isa_uint(val) == true &&
			    cbor_get_int(val) <= INT_MAX &&
			    cose_key->crv == 0)
				cose_key->crv = (int)cbor_get_int(val);
		}
	}

	return (0);
}

static int
get_cose_alg(const cbor_item_t *item, int *cose_alg)
{
	struct cose_key cose_key;

	memset(&cose_key, 0, sizeof(cose_key));

	*cose_alg = 0;

	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, &cose_key, find_cose_alg) < 0) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	switch (cose_key.alg) {
	case COSE_ES256:
		if (cose_key.kty != COSE_KTY_EC2 ||
		    cose_key.crv != COSE_P256) {
			log_debug("%s: invalid kty/crv", __func__);
			return (-1);
		}

		break;
	case COSE_EDDSA:
		if (cose_key.kty != COSE_KTY_OKP ||
		    cose_key.crv != COSE_ED25519) {
			log_debug("%s: invalid kty/crv", __func__);
			return (-1);
		}

		break;
	case COSE_RS256:
		if (cose_key.kty != COSE_KTY_RSA) {
			log_debug("%s: invalid kty/crv", __func__);
			return (-1);
		}

		break;
	default:
		log_debug("%s: unknown alg %d", __func__, cose_key.alg);

		return (-1);
	}

	*cose_alg = cose_key.alg;

	return (0);
}

int
decode_pubkey(const cbor_item_t *item, int *type, void *key)
{
	if (get_cose_alg(item, type) < 0) {
		log_debug("%s: get_cose_alg", __func__);
		return (-1);
	}

	switch (*type) {
	case COSE_ES256:
		if (es256_pk_decode(item, key) < 0) {
			log_debug("%s: es256_pk_decode", __func__);
			return (-1);
		}
		break;
	case COSE_RS256:
		if (rs256_pk_decode(item, key) < 0) {
			log_debug("%s: rs256_pk_decode", __func__);
			return (-1);
		}
		break;
	case COSE_EDDSA:
		if (eddsa_pk_decode(item, key) < 0) {
			log_debug("%s: eddsa_pk_decode", __func__);
			return (-1);
		}
		break;
	default:
		log_debug("%s: invalid cose_alg %d", __func__, *type);
		return (-1);
	}

	return (0);
}

static int
decode_attcred(const unsigned char **buf, size_t *len, int cose_alg,
    fido_attcred_t *attcred)
{
	cbor_item_t		*item = NULL;
	struct cbor_load_result	 cbor;
	uint16_t		 id_len;
	int			 ok = -1;

	log_debug("%s: buf=%p, len=%zu", __func__, (const void *)*buf, *len);

	if (buf_read(buf, len, &attcred->aaguid, sizeof(attcred->aaguid)) < 0) {
		log_debug("%s: buf_read aaguid", __func__);
		return (-1);
	}

	if (buf_read(buf, len, &id_len, sizeof(id_len)) < 0) {
		log_debug("%s: buf_read id_len", __func__);
		return (-1);
	}

	attcred->id.len = (size_t)be16toh(id_len);
	if ((attcred->id.ptr = malloc(attcred->id.len)) == NULL)
		return (-1);

	log_debug("%s: attcred->id.len=%zu", __func__, attcred->id.len);

	if (buf_read(buf, len, attcred->id.ptr, attcred->id.len) < 0) {
		log_debug("%s: buf_read id", __func__);
		return (-1);
	}

	if ((item = cbor_load(*buf, *len, &cbor)) == NULL) {
		log_debug("%s: cbor_load", __func__);
		log_xxd(*buf, *len);
		goto fail;
	}

	if (decode_pubkey(item, &attcred->type, &attcred->pubkey) < 0) {
		log_debug("%s: decode_pubkey", __func__);
		goto fail;
	}

	if (attcred->type != cose_alg) {
		log_debug("%s: cose_alg mismatch (%d != %d)", __func__,
		    attcred->type, cose_alg);
		goto fail;
	}

	*buf += cbor.read;
	*len -= cbor.read;

	ok = 0;
fail:
	if (item != NULL)
		cbor_decref(&item);

	return (ok);
}

static int
decode_extension(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	int	*authdata_ext = arg;
	char	*type = NULL;
	int	 ok = -1;

	if (cbor_string_copy(key, &type) < 0 || strcmp(type, "hmac-secret")) {
		log_debug("%s: cbor type", __func__);
		ok = 0; /* ignore */
		goto out;
	}

	if (cbor_isa_float_ctrl(val) == false ||
	    cbor_float_get_width(val) != CBOR_FLOAT_0 ||
	    cbor_is_bool(val) == false || *authdata_ext != 0) {
		log_debug("%s: cbor type", __func__);
		goto out;
	}

	if (cbor_ctrl_value(val) == CBOR_CTRL_TRUE)
		*authdata_ext |= FIDO_EXT_HMAC_SECRET;

	ok = 0;
out:
	free(type);

	return (ok);
}

static int
decode_extensions(const unsigned char **buf, size_t *len, int *authdata_ext)
{
	cbor_item_t		*item = NULL;
	struct cbor_load_result	 cbor;
	int			 ok = -1;

	log_debug("%s: buf=%p, len=%zu", __func__, (const void *)*buf, *len);

	*authdata_ext = 0;

	if ((item = cbor_load(*buf, *len, &cbor)) == NULL) {
		log_debug("%s: cbor_load", __func__);
		log_xxd(*buf, *len);
		goto fail;
	}

	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_size(item) != 1 ||
	    cbor_map_iter(item, authdata_ext, decode_extension) < 0) {
		log_debug("%s: cbor type", __func__);
		goto fail;
	}

	*buf += cbor.read;
	*len -= cbor.read;

	ok = 0;
fail:
	if (item != NULL)
		cbor_decref(&item);

	return (ok);
}

static int
decode_hmac_secret_aux(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_blob_t	*out = arg;
	char		*type = NULL;
	int		 ok = -1;

	if (cbor_string_copy(key, &type) < 0 || strcmp(type, "hmac-secret")) {
		log_debug("%s: cbor type", __func__);
		ok = 0; /* ignore */
		goto out;
	}

	ok = cbor_bytestring_copy(val, &out->ptr, &out->len);
out:
	free(type);

	return (ok);
}

static int
decode_hmac_secret(const unsigned char **buf, size_t *len, fido_blob_t *out)
{
	cbor_item_t		*item = NULL;
	struct cbor_load_result	 cbor;
	int			 ok = -1;

	log_debug("%s: buf=%p, len=%zu", __func__, (const void *)*buf, *len);

	if ((item = cbor_load(*buf, *len, &cbor)) == NULL) {
		log_debug("%s: cbor_load", __func__);
		log_xxd(*buf, *len);
		goto fail;
	}

	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_size(item) != 1 ||
	    cbor_map_iter(item, out, decode_hmac_secret_aux) < 0) {
		log_debug("%s: cbor type", __func__);
		goto fail;
	}

	*buf += cbor.read;
	*len -= cbor.read;

	ok = 0;
fail:
	if (item != NULL)
		cbor_decref(&item);

	return (ok);
}

int
decode_cred_authdata(const cbor_item_t *item, int cose_alg,
    fido_blob_t *authdata_cbor, fido_authdata_t *authdata,
    fido_attcred_t *attcred, int *authdata_ext)
{
	const unsigned char	*buf = NULL;
	size_t			 len;
	size_t			 alloc_len;

	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	if (authdata_cbor->ptr != NULL ||
	    (authdata_cbor->len = cbor_serialize_alloc(item,
	    &authdata_cbor->ptr, &alloc_len)) == 0) {
		log_debug("%s: cbor_serialize_alloc", __func__);
		return (-1);
	}

	buf = cbor_bytestring_handle(item);
	len = cbor_bytestring_length(item);

	log_debug("%s: buf=%p, len=%zu", __func__, (const void *)buf, len);

	if (buf_read(&buf, &len, authdata, sizeof(*authdata)) < 0) {
		log_debug("%s: buf_read", __func__);
		return (-1);
	}

	authdata->sigcount = be32toh(authdata->sigcount);

	if (attcred != NULL) {
		if ((authdata->flags & CTAP_AUTHDATA_ATT_CRED) == 0 ||
		    decode_attcred(&buf, &len, cose_alg, attcred) < 0)
			return (-1);
	}

	if (authdata_ext != NULL) {
		if ((authdata->flags & CTAP_AUTHDATA_EXT_DATA) != 0 && 
		    decode_extensions(&buf, &len, authdata_ext) < 0)
			return (-1);
	}

	/* XXX we should probably ensure that len == 0 at this point */

	return (FIDO_OK);
}

int
decode_assert_authdata(const cbor_item_t *item, fido_blob_t *authdata_cbor,
    fido_authdata_t *authdata, int *authdata_ext, fido_blob_t *hmac_secret_enc)
{
	const unsigned char	*buf = NULL;
	size_t			 len;
	size_t			 alloc_len;

	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	if (authdata_cbor->ptr != NULL ||
	    (authdata_cbor->len = cbor_serialize_alloc(item,
	    &authdata_cbor->ptr, &alloc_len)) == 0) {
		log_debug("%s: cbor_serialize_alloc", __func__);
		return (-1);
	}

	buf = cbor_bytestring_handle(item);
	len = cbor_bytestring_length(item);

	log_debug("%s: buf=%p, len=%zu", __func__, (const void *)buf, len);

	if (buf_read(&buf, &len, authdata, sizeof(*authdata)) < 0) {
		log_debug("%s: buf_read", __func__);
		return (-1);
	}

	authdata->sigcount = be32toh(authdata->sigcount);

	*authdata_ext = 0;
	if ((authdata->flags & CTAP_AUTHDATA_EXT_DATA) != 0) {
		/* XXX semantic leap: extensions -> hmac_secret */
		if (decode_hmac_secret(&buf, &len, hmac_secret_enc) < 0) {
			log_debug("%s: decode_hmac_secret", __func__);
			return (-1);
		}
		*authdata_ext = FIDO_EXT_HMAC_SECRET;
	}

	/* XXX we should probably ensure that len == 0 at this point */

	return (FIDO_OK);
}

static int
decode_x5c(const cbor_item_t *item, void *arg)
{
	fido_blob_t *x5c = arg;

	if (x5c->len)
		return (0); /* ignore */

	return (cbor_bytestring_copy(item, &x5c->ptr, &x5c->len));
}

static int
decode_attstmt_entry(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_attstmt_t	*attstmt = arg;
	char		*name = NULL;
	int		 ok = -1;

	if (cbor_string_copy(key, &name) < 0) {
		log_debug("%s: cbor type", __func__);
		ok = 0; /* ignore */
		goto out;
	}

	if (!strcmp(name, "alg")) {
		if (cbor_isa_negint(val) == false ||
		    cbor_int_get_width(val) != CBOR_INT_8 ||
		    cbor_get_uint8(val) != -COSE_ES256 - 1) {
			log_debug("%s: alg", __func__);
			goto out;
		}
	} else if (!strcmp(name, "sig")) {
		if (cbor_bytestring_copy(val, &attstmt->sig.ptr,
		    &attstmt->sig.len) < 0) {
			log_debug("%s: sig", __func__);
			goto out;
		}
	} else if (!strcmp(name, "x5c")) {
		if (cbor_isa_array(val) == false ||
		    cbor_array_is_definite(val) == false ||
		    cbor_array_iter(val, &attstmt->x5c, decode_x5c) < 0) {
			log_debug("%s: x5c", __func__);
			goto out;
		}
	}

	ok = 0;
out:
	free(name);

	return (ok);
}

int
decode_attstmt(const cbor_item_t *item, fido_attstmt_t *attstmt)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, attstmt, decode_attstmt_entry) < 0) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}

int
decode_uint64(const cbor_item_t *item, uint64_t *n)
{
	if (cbor_isa_uint(item) == false) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	*n = cbor_get_int(item);

	return (0);
}

static int
decode_cred_id_entry(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_blob_t	*id = arg;
	char		*name = NULL;
	int		 ok = -1;

	if (cbor_string_copy(key, &name) < 0) {
		log_debug("%s: cbor type", __func__);
		ok = 0; /* ignore */
		goto out;
	}

	if (!strcmp(name, "id"))
		if (cbor_bytestring_copy(val, &id->ptr, &id->len) < 0) {
			log_debug("%s: cbor_bytestring_copy", __func__);
			goto out;
		}

	ok = 0;
out:
	free(name);

	return (ok);
}

int
decode_cred_id(const cbor_item_t *item, fido_blob_t *id)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, id, decode_cred_id_entry) < 0) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}

static int
decode_user_entry(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_user_t	*user = arg;
	char		*name = NULL;
	int		 ok = -1;

	if (cbor_string_copy(key, &name) < 0) {
		log_debug("%s: cbor type", __func__);
		ok = 0; /* ignore */
		goto out;
	}

	if (!strcmp(name, "icon")) {
		if (cbor_string_copy(val, &user->icon) < 0) {
			log_debug("%s: icon", __func__);
			goto out;
		}
	} else if (!strcmp(name, "name")) {
		if (cbor_string_copy(val, &user->name) < 0) {
			log_debug("%s: name", __func__);
			goto out;
		}
	} else if (!strcmp(name, "displayName")) {
		if (cbor_string_copy(val, &user->display_name) < 0) {
			log_debug("%s: display_name", __func__);
			goto out;
		}
	} else if (!strcmp(name, "id")) {
		if (cbor_bytestring_copy(val, &user->id.ptr, &user->id.len) < 0) {
			log_debug("%s: id", __func__);
			goto out;
		}
	}

	ok = 0;
out:
	free(name);

	return (ok);
}

int
decode_user(const cbor_item_t *item, fido_user_t *user)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, user, decode_user_entry) < 0) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}

static int
decode_rp_entity_entry(const cbor_item_t *key, const cbor_item_t *val,
    void *arg)
{
	fido_rp_t	*rp = arg;
	char		*name = NULL;
	int		 ok = -1;

	if (cbor_string_copy(key, &name) < 0) {
		log_debug("%s: cbor type", __func__);
		ok = 0; /* ignore */
		goto out;
	}

	if (!strcmp(name, "id")) {
		if (cbor_string_copy(val, &rp->id) < 0) {
			log_debug("%s: id", __func__);
			goto out;
		}
	} else if (!strcmp(name, "name")) {
		if (cbor_string_copy(val, &rp->name) < 0) {
			log_debug("%s: name", __func__);
			goto out;
		}
	}

	ok = 0;
out:
	free(name);

	return (ok);
}

int
decode_rp_entity(const cbor_item_t *item, fido_rp_t *rp)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, rp, decode_rp_entity_entry) < 0) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}
