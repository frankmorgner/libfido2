/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <string.h>
#include "fido.h"
#include "fido/es256.h"

static int
parse_makecred_reply(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_cred_t *cred = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 1: /* fmt */
		return (decode_fmt(val, &cred->fmt));
	case 2: /* authdata */
		return (decode_cred_authdata(val, cred->type,
		    &cred->authdata_cbor, &cred->authdata, &cred->attcred,
		    &cred->authdata_ext));
	case 3: /* attestation statement */
		return (decode_attstmt(val, &cred->attstmt));
	default: /* ignore */
		log_debug("%s: cbor type", __func__);
		return (0);
	}
}

static int
fido_dev_make_cred_tx(fido_dev_t *dev, fido_cred_t *cred, const char *pin)
{
	fido_blob_t	 f;
	fido_blob_t	*ecdh = NULL;
	es256_pk_t	*pk = NULL;
	cbor_item_t	*argv[9];
	int		 r;

	memset(&f, 0, sizeof(f));
	memset(argv, 0, sizeof(argv));

	if (cred->cdh.ptr == NULL || cred->type == 0) {
		log_debug("%s: cdh=%p, type=%d", __func__,
		    (void *)cred->cdh.ptr, cred->type);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((argv[0] = fido_blob_encode(&cred->cdh)) == NULL ||
	    (argv[1] = encode_rp_entity(&cred->rp)) == NULL ||
	    (argv[2] = encode_user_entity(&cred->user)) == NULL ||
	    (argv[3] = encode_pubkey_param(cred->type)) == NULL) {
		log_debug("%s: cbor encode", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	/* excluded credentials */
	if (cred->excl.len)
		if ((argv[4] = encode_pubkey_list(&cred->excl)) == NULL) {
			log_debug("%s: encode_pubkey_list", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* extensions */
	if (cred->ext)
		if ((argv[5] = encode_extensions(cred->ext)) == NULL) {
			log_debug("%s: encode_extensions", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* options */
	if (cred->rk != FIDO_OPT_OMIT || cred->uv != FIDO_OPT_OMIT)
		if ((argv[6] = encode_options(cred->rk, cred->uv)) == NULL) {
			log_debug("%s: encode_options", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* pin authentication */
	if (pin) {
		if ((r = fido_do_ecdh(dev, &pk, &ecdh)) != FIDO_OK) {
			log_debug("%s: fido_do_ecdh", __func__);
			goto fail;
		}
		if ((r = add_cbor_pin_params(dev, &cred->cdh, pk, ecdh, pin,
		    &argv[7], &argv[8])) != FIDO_OK) {
			log_debug("%s: add_cbor_pin_params", __func__);
			goto fail;
		}
	}

	/* framing and transmission */
	if (cbor_build_frame(CTAP_CBOR_MAKECRED, argv, 9, &f) < 0 ||
	    tx(dev, CTAP_FRAME_INIT | CTAP_CMD_CBOR, f.ptr, f.len) < 0) {
		log_debug("%s: tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	es256_pk_free(&pk);
	fido_blob_free(&ecdh);

	for (size_t i = 0; i < 9; i++)
		if (argv[i])
			cbor_decref(&argv[i]);

	free(f.ptr);

	return (r);
}

static int
fido_dev_make_cred_rx(fido_dev_t *dev, fido_cred_t *cred, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	fido_cred_reset_rx(cred);

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	if ((r = parse_cbor_reply(reply, (size_t)reply_len, cred,
	    parse_makecred_reply)) != FIDO_OK) {
		log_debug("%s: parse_makecred_reply", __func__);
		return (r);
	}

	if (cred->fmt == NULL || fido_blob_is_empty(&cred->authdata_cbor) ||
	    fido_blob_is_empty(&cred->attcred.id) ||
	    fido_blob_is_empty(&cred->attstmt.x5c) ||
	    fido_blob_is_empty(&cred->attstmt.sig)) {
		fido_cred_reset_rx(cred);
		return (FIDO_ERR_INVALID_CBOR);
	}

	return (FIDO_OK);
}

static int
fido_dev_make_cred_wait(fido_dev_t *dev, fido_cred_t *cred, const char *pin, int ms)
{
	int  r;

	if ((r = fido_dev_make_cred_tx(dev, cred, pin)) != FIDO_OK ||
	    (r = fido_dev_make_cred_rx(dev, cred, ms)) != FIDO_OK)
		return (r);

	return (FIDO_OK);
}

int
fido_dev_make_cred(fido_dev_t *dev, fido_cred_t *cred, const char *pin)
{
	if (fido_dev_is_fido2(dev) == false) {
		if (pin != NULL || cred->rk == FIDO_OPT_TRUE || cred->ext != 0)
			return (FIDO_ERR_UNSUPPORTED_OPTION);
		return (u2f_register(dev, cred, -1));
	}

	return (fido_dev_make_cred_wait(dev, cred, pin, -1));
}

static int
check_extensions(int authdata_ext, int ext)
{
	if (authdata_ext != ext) {
		log_debug("%s: authdata_ext=0x%x != ext=0x%x", __func__,
		    authdata_ext, ext);
		return (-1);
	}

	return (0);
}

int
check_rp_id(const char *id, const unsigned char *obtained_hash)
{
	unsigned char expected_hash[SHA256_DIGEST_LENGTH];

	explicit_bzero(expected_hash, sizeof(expected_hash));

	if (SHA256((const unsigned char *)id, strlen(id),
	    expected_hash) != expected_hash) {
		log_debug("%s: sha256", __func__);
		return (-1);
	}

	return (timingsafe_bcmp(expected_hash, obtained_hash,
	    SHA256_DIGEST_LENGTH));
}

static int
get_signed_hash_packed(fido_blob_t *dgst, const fido_blob_t *clientdata,
    const fido_blob_t *authdata_cbor)
{
	cbor_item_t		*item = NULL;
	unsigned char		*authdata_ptr = NULL;
	size_t			 authdata_len;
	struct cbor_load_result	 cbor;
	SHA256_CTX		 ctx;
	int			 ok = -1;

	if ((item = cbor_load(authdata_cbor->ptr, authdata_cbor->len,
	    &cbor)) == NULL) {
		log_debug("%s: cbor_load", __func__);
		goto fail;
	}

	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false) {
		log_debug("%s: cbor type", __func__);
		goto fail;
	}

	authdata_ptr = cbor_bytestring_handle(item);
	authdata_len = cbor_bytestring_length(item);

	if (dgst->len != SHA256_DIGEST_LENGTH || SHA256_Init(&ctx) == 0 ||
	    SHA256_Update(&ctx, authdata_ptr, authdata_len) == 0 ||
	    SHA256_Update(&ctx, clientdata->ptr, clientdata->len) == 0 ||
	    SHA256_Final(dgst->ptr, &ctx) == 0) {
		log_debug("%s: sha256", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (item != NULL)
		cbor_decref(&item);

	return (ok);
}

static int
get_signed_hash_u2f(fido_blob_t *dgst, const unsigned char *rp_id,
    size_t rp_id_len, const fido_blob_t *clientdata, const fido_blob_t *id,
    const es256_pk_t *pk)
{
	const uint8_t		zero = 0;
	const uint8_t		four = 4; /* uncompressed point */
	SHA256_CTX		ctx;

	if (dgst->len != SHA256_DIGEST_LENGTH || SHA256_Init(&ctx) == 0 ||
	    SHA256_Update(&ctx, &zero, sizeof(zero)) == 0 ||
	    SHA256_Update(&ctx, rp_id, rp_id_len) == 0 ||
	    SHA256_Update(&ctx, clientdata->ptr, clientdata->len) == 0 ||
	    SHA256_Update(&ctx, id->ptr, id->len) == 0 ||
	    SHA256_Update(&ctx, &four, sizeof(four)) == 0 ||
	    SHA256_Update(&ctx, pk->x, sizeof(pk->x)) == 0 ||
	    SHA256_Update(&ctx, pk->y, sizeof(pk->y)) == 0 ||
	    SHA256_Final(dgst->ptr, &ctx) == 0) {
		log_debug("%s: sha256", __func__);
		return (-1);
	}

	return (0);
}

static int
verify_sig(const fido_blob_t *dgst, const fido_blob_t *x5c,
    const fido_blob_t *sig)
{
	BIO		*rawcert = NULL;
	X509		*cert = NULL;
	EVP_PKEY	*pkey = NULL;
	EC_KEY		*ec;
	int		 ok = -1;

	/* openssl needs ints */
	if (dgst->len > INT_MAX || x5c->len > INT_MAX || sig->len > INT_MAX) {
		log_debug("%s: dgst->len=%zu, x5c->len=%zu, sig->len=%zu",
		    __func__, dgst->len, x5c->len, sig->len);
		return (-1);
	}

	/* fetch key from x509 */
	if ((rawcert = BIO_new_mem_buf(x5c->ptr, (int)x5c->len)) == NULL ||
	    (cert = d2i_X509_bio(rawcert, NULL)) == NULL ||
	    (pkey = X509_get_pubkey(cert)) == NULL ||
	    (ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL) {
		log_debug("%s: x509 key", __func__);
		goto fail;
	}

	if (ECDSA_verify(0, dgst->ptr, (int)dgst->len, sig->ptr,
	    (int)sig->len, ec) != 1) {
		log_debug("%s: ECDSA_verify", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (rawcert != NULL)
		BIO_free(rawcert);
	if (cert != NULL)
		X509_free(cert);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return (ok);
}

int
fido_cred_verify(const fido_cred_t *cred)
{
	unsigned char	buf[SHA256_DIGEST_LENGTH];
	fido_blob_t	dgst;
	int		r;

	dgst.ptr = buf;
	dgst.len = sizeof(buf);

	/* do we have everything we need? */
	if (cred->cdh.ptr == NULL || cred->authdata_cbor.ptr == NULL ||
	    cred->attstmt.x5c.ptr == NULL || cred->attstmt.sig.ptr == NULL ||
	    cred->fmt == NULL || cred->attcred.id.ptr == NULL ||
	    cred->rp.id == NULL) {
		log_debug("%s: cdh=%p, authdata=%p, x5c=%p, sig=%p, fmt=%p "
		    "id=%p, rp.id=%s", __func__, (void *)cred->cdh.ptr,
		    (void *)cred->authdata_cbor.ptr,
		    (void *)cred->attstmt.x5c.ptr,
		    (void *)cred->attstmt.sig.ptr, (void *)cred->fmt,
		    (void *)cred->attcred.id.ptr, cred->rp.id);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if (check_rp_id(cred->rp.id, cred->authdata.rp_id_hash) != 0) {
		log_debug("%s: check_rp_id", __func__);
		r = FIDO_ERR_INVALID_PARAM;
		goto out;
	}

	if (check_flags(cred->authdata.flags, FIDO_OPT_TRUE, cred->uv) < 0) {
		log_debug("%s: check_flags", __func__);
		r = FIDO_ERR_INVALID_PARAM;
		goto out;
	}

	if (check_extensions(cred->authdata_ext, cred->ext) < 0) {
		log_debug("%s: check_extensions", __func__);
		r = FIDO_ERR_INVALID_PARAM;
		goto out;
	}

	if (!strcmp(cred->fmt, "packed")) {
		if (get_signed_hash_packed(&dgst, &cred->cdh,
		    &cred->authdata_cbor) < 0) {
			log_debug("%s: get_signed_hash_packed", __func__);
			r = FIDO_ERR_INTERNAL;
			goto out;
		}
	} else {
		if (get_signed_hash_u2f(&dgst, cred->authdata.rp_id_hash,
		    sizeof(cred->authdata.rp_id_hash), &cred->cdh,
		    &cred->attcred.id, &cred->attcred.pubkey.es256) < 0) {
			log_debug("%s: get_signed_hash_u2f", __func__);
			r = FIDO_ERR_INTERNAL;
			goto out;
		}
	}

	if (verify_sig(&dgst, &cred->attstmt.x5c, &cred->attstmt.sig) < 0) {
		log_debug("%s: verify_sig", __func__);
		r = FIDO_ERR_INVALID_SIG;
		goto out;
	}

	r = FIDO_OK;
out:
	explicit_bzero(buf, sizeof(buf));

	return (r);
}

fido_cred_t *
fido_cred_new(void)
{
	return (calloc(1, sizeof(fido_cred_t)));
}

static void
fido_cred_clean_authdata(fido_cred_t *cred)
{
	free(cred->authdata_cbor.ptr);
	free(cred->attcred.id.ptr);

	memset(&cred->authdata_ext, 0, sizeof(cred->authdata_ext));
	memset(&cred->authdata_cbor, 0, sizeof(cred->authdata_cbor));
	memset(&cred->authdata, 0, sizeof(cred->authdata));
	memset(&cred->attcred, 0, sizeof(cred->attcred));
}

void
fido_cred_reset_tx(fido_cred_t *cred)
{
	free(cred->cdh.ptr);
	free(cred->rp.id);
	free(cred->rp.name);
	free(cred->user.id.ptr);
	free(cred->user.icon);
	free(cred->user.name);
	free(cred->user.display_name);
	free_blob_array(&cred->excl);

	memset(&cred->cdh, 0, sizeof(cred->cdh));
	memset(&cred->rp, 0, sizeof(cred->rp));
	memset(&cred->user, 0, sizeof(cred->user));
	memset(&cred->excl, 0, sizeof(cred->excl));

	cred->type = 0;
	cred->ext = 0;
	cred->rk = FIDO_OPT_OMIT;
	cred->uv = FIDO_OPT_OMIT;
}

static void
fido_cred_clean_x509(fido_cred_t *cred)
{
	free(cred->attstmt.x5c.ptr);
	cred->attstmt.x5c.ptr = NULL;
	cred->attstmt.x5c.len = 0;
}

static void
fido_cred_clean_sig(fido_cred_t *cred)
{
	free(cred->attstmt.sig.ptr);
	cred->attstmt.sig.ptr = NULL;
	cred->attstmt.sig.len = 0;
}

void
fido_cred_reset_rx(fido_cred_t *cred)
{
	free(cred->fmt);
	cred->fmt = NULL;

	fido_cred_clean_authdata(cred);
	fido_cred_clean_x509(cred);
	fido_cred_clean_sig(cred);
}

void
fido_cred_free(fido_cred_t **cred_p)
{
	fido_cred_t *cred;

	if (cred_p == NULL || (cred = *cred_p) == NULL)
		return;

	fido_cred_reset_tx(cred);
	fido_cred_reset_rx(cred);

	free(cred);

	*cred_p = NULL;
}

int
fido_cred_set_authdata(fido_cred_t *cred, const unsigned char *ptr, size_t len)
{
	cbor_item_t		*item = NULL;
	struct cbor_load_result	 cbor;
	int			 r;

	fido_cred_clean_authdata(cred);

	if (ptr == NULL || len == 0) {
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((item = cbor_load(ptr, len, &cbor)) == NULL) {
		log_debug("%s: cbor_load", __func__);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if (decode_cred_authdata(item, cred->type, &cred->authdata_cbor,
	    &cred->authdata, &cred->attcred, &cred->authdata_ext) < 0) {
		log_debug("%s: decode_cred_authdata", __func__);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	r = FIDO_OK;
fail:
	if (item != NULL)
		cbor_decref(&item);

	if (r != FIDO_OK)
		fido_cred_clean_authdata(cred);

	return (r);

}

int
fido_cred_set_x509(fido_cred_t *cred, const unsigned char *ptr, size_t len)
{
	unsigned char *x509;

	fido_cred_clean_x509(cred);

	if (ptr == NULL || len == 0)
		return (FIDO_ERR_INVALID_ARGUMENT);
	if ((x509 = malloc(len)) == NULL)
		return (FIDO_ERR_INTERNAL);

	memcpy(x509, ptr, len);
	cred->attstmt.x5c.ptr = x509;
	cred->attstmt.x5c.len = len;

	return (FIDO_OK);
}

int
fido_cred_set_sig(fido_cred_t *cred, const unsigned char *ptr, size_t len)
{
	unsigned char *sig;

	fido_cred_clean_sig(cred);

	if (ptr == NULL || len == 0)
		return (FIDO_ERR_INVALID_ARGUMENT);
	if ((sig = malloc(len)) == NULL)
		return (FIDO_ERR_INTERNAL);

	memcpy(sig, ptr, len);
	cred->attstmt.sig.ptr = sig;
	cred->attstmt.sig.len = len;

	return (FIDO_OK);
}

int
fido_cred_exclude(fido_cred_t *cred, const unsigned char *id_ptr, size_t id_len)
{
	fido_blob_t id_blob;
	fido_blob_t *list_ptr;

	memset(&id_blob, 0, sizeof(id_blob));

	if (fido_blob_set(&id_blob, id_ptr, id_len) < 0)
		return (FIDO_ERR_INTERNAL);

	if (cred->excl.len == SIZE_MAX) {
		free(id_blob.ptr);
		return (FIDO_ERR_INVALID_ARGUMENT);
	}

	if ((list_ptr = recallocarray(cred->excl.ptr, cred->excl.len,
	    cred->excl.len + 1, sizeof(fido_blob_t))) == NULL) {
		free(id_blob.ptr);
		return (FIDO_ERR_INTERNAL);
	}

	list_ptr[cred->excl.len++] = id_blob;
	cred->excl.ptr = list_ptr;

	return (FIDO_OK);
}

int
fido_cred_set_clientdata_hash(fido_cred_t *cred, const unsigned char *hash,
    size_t hash_len)
{
	if (fido_blob_set(&cred->cdh, hash, hash_len) < 0)
		return (FIDO_ERR_INTERNAL);

	return (FIDO_OK);
}

int
fido_cred_set_rp(fido_cred_t *cred, const char *id, const char *name)
{
	fido_rp_t *rp = &cred->rp;

	if (rp->id != NULL) {
		free(rp->id);
		rp->id = NULL;
	}
	if (rp->name != NULL) {
		free(rp->name);
		rp->name = NULL;
	}

	if (id != NULL && (rp->id = strdup(id)) == NULL)
		goto fail;
	if (name != NULL && (rp->name = strdup(name)) == NULL)
		goto fail;

	return (FIDO_OK);
fail:
	free(rp->id);
	free(rp->name);
	rp->id = NULL;
	rp->name = NULL;

	return (FIDO_ERR_INTERNAL);
}

int
fido_cred_set_user(fido_cred_t *cred, const unsigned char *user_id,
    size_t user_id_len, const char *name, const char *display_name,
    const char *icon)
{
	fido_user_t *up = &cred->user;

	if (up->id.ptr != NULL) {
		free(up->id.ptr);
		up->id.ptr = NULL;
		up->id.len = 0;
	}
	if (up->name != NULL) {
		free(up->name);
		up->name = NULL;
	}
	if (up->display_name != NULL) {
		free(up->display_name);
		up->display_name = NULL;
	}
	if (up->icon != NULL) {
		free(up->icon);
		up->icon = NULL;
	}

	if (user_id != NULL) {
		if ((up->id.ptr = malloc(user_id_len)) == NULL)
			goto fail;
		memcpy(up->id.ptr, user_id, user_id_len);
		up->id.len = user_id_len;
	}
	if (name != NULL && (up->name = strdup(name)) == NULL)
		goto fail;
	if (display_name != NULL &&
	    (up->display_name = strdup(display_name)) == NULL)
		goto fail;
	if (icon != NULL && (up->icon = strdup(icon)) == NULL)
		goto fail;

	return (FIDO_OK);
fail:
	free(up->id.ptr);
	free(up->name);
	free(up->display_name);
	free(up->icon);

	up->id.ptr = NULL;
	up->id.len = 0;
	up->name = NULL;
	up->display_name = NULL;
	up->icon = NULL;

	return (FIDO_ERR_INTERNAL);
}

int
fido_cred_set_extensions(fido_cred_t *cred, int ext)
{
	if (ext != 0 && ext != FIDO_EXT_HMAC_SECRET)
		return (FIDO_ERR_INVALID_ARGUMENT);

	cred->ext = ext;

	return (FIDO_OK);
}

int
fido_cred_set_options(fido_cred_t *cred, bool rk, bool uv)
{
	cred->rk = rk ? FIDO_OPT_TRUE : FIDO_OPT_FALSE;
	cred->uv = uv ? FIDO_OPT_TRUE : FIDO_OPT_FALSE;

	return (FIDO_OK);
}

int
fido_cred_set_rk(fido_cred_t *cred, fido_opt_t rk)
{
	cred->rk = rk;

	return (FIDO_OK);
}

int
fido_cred_set_uv(fido_cred_t *cred, fido_opt_t uv)
{
	cred->uv = uv;

	return (FIDO_OK);
}

int
fido_cred_set_fmt(fido_cred_t *cred, const char *fmt)
{
	free(cred->fmt);
	cred->fmt = NULL;

	if (fmt == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	if (strcmp(fmt, "packed") && strcmp(fmt, "fido-u2f"))
		return (FIDO_ERR_INVALID_ARGUMENT);

	if ((cred->fmt = strdup(fmt)) == NULL)
		return (FIDO_ERR_INTERNAL);

	return (FIDO_OK);
}

int
fido_cred_set_type(fido_cred_t *cred, int cose_alg)
{
	if ((cose_alg != COSE_ES256 && cose_alg != COSE_RS256 &&
	    cose_alg != COSE_EDDSA) || cred->type != 0)
		return (FIDO_ERR_INVALID_ARGUMENT);

	cred->type = cose_alg;

	return (FIDO_OK);
}

int
fido_cred_type(const fido_cred_t *cred)
{
	return (cred->type);
}

uint8_t
fido_cred_flags(const fido_cred_t *cred)
{
	return (cred->authdata.flags);
}

const unsigned char *
fido_cred_clientdata_hash_ptr(const fido_cred_t *cred)
{
	return (cred->cdh.ptr);
}

size_t
fido_cred_clientdata_hash_len(const fido_cred_t *cred)
{
	return (cred->cdh.len);
}

const unsigned char *
fido_cred_x5c_ptr(const fido_cred_t *cred)
{
	return (cred->attstmt.x5c.ptr);
}

size_t
fido_cred_x5c_len(const fido_cred_t *cred)
{
	return (cred->attstmt.x5c.len);
}

const unsigned char *
fido_cred_sig_ptr(const fido_cred_t *cred)
{
	return (cred->attstmt.sig.ptr);
}

size_t
fido_cred_sig_len(const fido_cred_t *cred)
{
	return (cred->attstmt.sig.len);
}

const unsigned char *
fido_cred_authdata_ptr(const fido_cred_t *cred)
{
	return (cred->authdata_cbor.ptr);
}

size_t
fido_cred_authdata_len(const fido_cred_t *cred)
{
	return (cred->authdata_cbor.len);
}

const unsigned char *
fido_cred_pubkey_ptr(const fido_cred_t *cred)
{
	const void *ptr;

	switch (cred->attcred.type) {
	case COSE_ES256:
		ptr = &cred->attcred.pubkey.es256;
		break;
	case COSE_RS256:
		ptr = &cred->attcred.pubkey.rs256;
		break;
	case COSE_EDDSA:
		ptr = &cred->attcred.pubkey.eddsa;
		break;
	default:
		ptr = NULL;
		break;
	}

	return (ptr);
}

size_t
fido_cred_pubkey_len(const fido_cred_t *cred)
{
	size_t len;

	switch (cred->attcred.type) {
	case COSE_ES256:
		len = sizeof(cred->attcred.pubkey.es256);
		break;
	case COSE_RS256:
		len = sizeof(cred->attcred.pubkey.rs256);
		break;
	case COSE_EDDSA:
		len = sizeof(cred->attcred.pubkey.eddsa);
		break;
	default:
		len = 0;
		break;
	}

	return (len);
}

const unsigned char *
fido_cred_id_ptr(const fido_cred_t *cred)
{
	return (cred->attcred.id.ptr);
}

size_t
fido_cred_id_len(const fido_cred_t *cred)
{
	return (cred->attcred.id.len);
}

const char *
fido_cred_fmt(const fido_cred_t *cred)
{
	return (cred->fmt);
}

const char *
fido_cred_rp_id(const fido_cred_t *cred)
{
	return (cred->rp.id);
}

const char *
fido_cred_rp_name(const fido_cred_t *cred)
{
	return (cred->rp.name);
}

const char *
fido_cred_user_name(const fido_cred_t *cred)
{
	return (cred->user.name);
}

const char *
fido_cred_display_name(const fido_cred_t *cred)
{
	return (cred->user.display_name);
}

const unsigned char *
fido_cred_user_id_ptr(const fido_cred_t *cred)
{
	return (cred->user.id.ptr);
}

size_t
fido_cred_user_id_len(const fido_cred_t *cred)
{
	return (cred->user.id.len);
}
