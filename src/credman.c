/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/sha.h>

#include <string.h>

#include "fido.h"
#include "fido/credman.h"
#include "fido/es256.h"

#define CMD_CRED_METADATA	0x01
#define CMD_RP_BEGIN		0x02
#define CMD_RP_NEXT		0x03
#define CMD_RK_BEGIN		0x04
#define CMD_RK_NEXT		0x05
#define CMD_DELETE_CRED		0x06

static int
credman_grow_array(void **ptr, size_t *n_alloc, size_t *n_rx, size_t n,
    size_t size)
{
	void *new_ptr;

#ifdef FIDO_FUZZ
	if (n > UINT8_MAX) {
		log_debug("%s: n > UINT8_MAX", __func__);
		return (-1);
	}
#endif

	if (n < *n_alloc)
		return (0);

	/* sanity check */
	if (*n_rx > 0 || *n_rx > *n_alloc || n < *n_alloc) {
		log_debug("%s: n=%zu, n_rx=%zu, n_alloc=%zu", __func__, n,
		    *n_rx, *n_alloc);
		return (-1);
	}

	if ((new_ptr = recallocarray(*ptr, *n_alloc, n, size)) == NULL)
		return (-1);

	*ptr = new_ptr;
	*n_alloc = n;

	return (0);
}

static int
credman_prepare_hmac(uint8_t cmd, const fido_blob_t *body, cbor_item_t **param,
    fido_blob_t *hmac_data)
{
	cbor_item_t *param_cbor[2];
	size_t n;
	int ok = -1;

	memset(&param_cbor, 0, sizeof(param_cbor));

	if (body == NULL)
		return (fido_blob_set(hmac_data, &cmd, sizeof(cmd)));

	switch (cmd) {
	case CMD_RK_BEGIN:
		n = 1;
		param_cbor[n - 1] = fido_blob_encode(body);
		break;
	case CMD_DELETE_CRED:
		n = 2;
		param_cbor[n - 1] = encode_pubkey(body);
		break;
	default:
		log_debug("%s: unknown cmd=0x%02x", __func__, cmd);
		return (-1);
	}

	if (param_cbor[n - 1] == NULL) {
		log_debug("%s: cbor encode", __func__);
		return (-1);
	}
	if ((*param = cbor_flatten_vector(param_cbor, n)) == NULL) {
		log_debug("%s: cbor_flatten_vector", __func__);
		goto fail;
	}
	if (cbor_build_frame(cmd, param_cbor, n, hmac_data) < 0) {
		log_debug("%s: cbor_build_frame", __func__);
		goto fail;
	}

	ok = 0;
fail:
	for (size_t i = 0; i < 2; i++)
		if (param_cbor[i])
			cbor_decref(&param_cbor[i]);

	return (ok);
}

static int
credman_tx(fido_dev_t *dev, uint8_t cmd, const fido_blob_t *param,
    const char *pin)
{
	fido_blob_t	 f;
	fido_blob_t	*ecdh = NULL;
	fido_blob_t	 hmac;
	es256_pk_t	*pk = NULL;
	cbor_item_t	*argv[4];
	int		 r = FIDO_ERR_INTERNAL;

	memset(&f, 0, sizeof(f));
	memset(&hmac, 0, sizeof(hmac));
	memset(&argv, 0, sizeof(argv));

	/* subCommand */
	if ((argv[0] = cbor_build_uint8(cmd)) == NULL) {
		log_debug("%s: cbor encode", __func__);
		goto fail;
	}

	/* pinProtocol, pinAuth */
	if (pin != NULL) {
		if (credman_prepare_hmac(cmd, param, &argv[1], &hmac) < 0) {
			log_debug("%s: credman_prepare_hmac", __func__);
			goto fail;
		}
		if ((r = fido_do_ecdh(dev, &pk, &ecdh)) != FIDO_OK) {
			log_debug("%s: fido_do_ecdh", __func__);
			goto fail;
		}
		if ((r = add_cbor_pin_params(dev, &hmac, pk, ecdh, pin,
		    &argv[3], &argv[2])) != FIDO_OK) {
			log_debug("%s: add_cbor_pin_params", __func__);
			goto fail;
		}
	}

	/* framing and transmission */
	if (cbor_build_frame(CTAP_CBOR_CRED_MGMT_PRE, argv, 4, &f) < 0 ||
	    tx(dev, CTAP_FRAME_INIT | CTAP_CMD_CBOR, f.ptr, f.len) < 0) {
		log_debug("%s: tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	es256_pk_free(&pk);
	fido_blob_free(&ecdh);

	for (size_t i = 0; i < 4; i++)
		if (argv[i])
			cbor_decref(&argv[i]);

	free(f.ptr);
	free(hmac.ptr);

	return (r);
}

static int
credman_parse_metadata(const cbor_item_t *key, const cbor_item_t *val,
    void *arg)
{
	fido_credman_metadata_t *metadata = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 1:
		return (decode_uint64(val, &metadata->rk_existing));
	case 2:
		return (decode_uint64(val, &metadata->rk_remaining));
	default:
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}
}

static int
credman_rx_metadata(fido_dev_t *dev, fido_credman_metadata_t *metadata, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[512];
	int		reply_len;
	int		r;

	memset(metadata, 0, sizeof(*metadata));

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	if ((r = parse_cbor_reply(reply, (size_t)reply_len, metadata,
	    credman_parse_metadata)) != FIDO_OK) {
		log_debug("%s: credman_parse_metadata", __func__);
		return (r);
	}

	return (FIDO_OK);
}

static int
credman_get_metadata_wait(fido_dev_t *dev, fido_credman_metadata_t *metadata,
    const char *pin, int ms)
{
	int r;

	if ((r = credman_tx(dev, CMD_CRED_METADATA, NULL, pin)) != FIDO_OK ||
	    (r = credman_rx_metadata(dev, metadata, ms)) != FIDO_OK)
		return (r);

	return (FIDO_OK);
}

int
fido_credman_get_dev_metadata(fido_dev_t *dev, fido_credman_metadata_t *metadata,
    const char *pin)
{
	if (fido_dev_is_fido2(dev) == false)
		return (FIDO_ERR_INVALID_COMMAND);
	if (pin == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	return (credman_get_metadata_wait(dev, metadata, pin, -1));
}

static int
credman_parse_rk(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_cred_t *cred = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 6: /* user entity */
		return (decode_user(val, &cred->user));
	case 7:
		return (decode_cred_id(val, &cred->attcred.id));
	case 8:
		if (decode_pubkey(val, &cred->attcred.type,
		    &cred->attcred.pubkey) < 0)
			return (-1);
		cred->type = cred->attcred.type; /* XXX */
		return (0);
	default:
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}
}

static void
credman_reset_rk(fido_credman_rk_t *rk)
{
	for (size_t i = 0; i < rk->n_alloc; i++) {
		fido_cred_reset_tx(&rk->ptr[i]);
		fido_cred_reset_rx(&rk->ptr[i]);
	}

	free(rk->ptr);
	rk->ptr = NULL;
	memset(rk, 0, sizeof(*rk));
}

static int
credman_parse_rk_count(const cbor_item_t *key, const cbor_item_t *val,
    void *arg)
{
	fido_credman_rk_t *rk = arg;
	uint64_t n;

	/* totalCredentials */
	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8 ||
	    cbor_get_uint8(key) != 9) {
		log_debug("%s: cbor_type", __func__);
		return (0); /* ignore */
	}

	if (decode_uint64(val, &n) < 0 || n > SIZE_MAX) {
		log_debug("%s: decode_uint64", __func__);
		return (-1);
	}

	if (credman_grow_array((void **)&rk->ptr, &rk->n_alloc, &rk->n_rx,
	    (size_t)n, sizeof(*rk->ptr)) < 0) {
		log_debug("%s: credman_grow_array", __func__);
		return (-1);
	}

	return (0);
}

static int
credman_rx_rk(fido_dev_t *dev, fido_credman_rk_t *rk, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	credman_reset_rk(rk);

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* adjust as needed */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, rk,
	    credman_parse_rk_count)) != FIDO_OK) {
		log_debug("%s: credman_parse_rk_count", __func__);
		return (r);
	}

	if (rk->n_alloc == 0) {
		log_debug("%s: n_alloc=0", __func__);
		return (FIDO_OK);
	}

	/* parse the first rk */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, &rk->ptr[0],
	    credman_parse_rk)) != FIDO_OK) {
		log_debug("%s: credman_parse_rk", __func__);
		return (r);
	}

	rk->n_rx++;

	return (FIDO_OK);
}

static int
credman_rx_next_rk(fido_dev_t *dev, fido_credman_rk_t *rk, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* sanity check */
	if (rk->n_rx >= rk->n_alloc) {
		log_debug("%s: n_rx=%zu, n_alloc=%zu", __func__, rk->n_rx,
		    rk->n_alloc);
		return (FIDO_ERR_INTERNAL);
	}

	if ((r = parse_cbor_reply(reply, (size_t)reply_len, &rk->ptr[rk->n_rx],
	    credman_parse_rk)) != FIDO_OK) {
		log_debug("%s: credman_parse_rk", __func__);
		return (r);
	}

	return (FIDO_OK);
}

static int
credman_get_rk_wait(fido_dev_t *dev, const char *rp_id, fido_credman_rk_t *rk,
    const char *pin, int ms)
{
	fido_blob_t	rp_dgst;
	uint8_t		dgst[SHA256_DIGEST_LENGTH];
	int		r;

	if (SHA256((const unsigned char *)rp_id, strlen(rp_id), dgst) != dgst) {
		log_debug("%s: sha256", __func__);
		return (FIDO_ERR_INTERNAL);
	}

	rp_dgst.ptr = dgst;
	rp_dgst.len = sizeof(dgst);

	if ((r = credman_tx(dev, CMD_RK_BEGIN, &rp_dgst, pin)) != FIDO_OK ||
	    (r = credman_rx_rk(dev, rk, ms)) != FIDO_OK)
		return (r);

	while (rk->n_rx < rk->n_alloc) {
		if ((r = credman_tx(dev, CMD_RK_NEXT, NULL, NULL)) != FIDO_OK ||
		    (r = credman_rx_next_rk(dev, rk, ms)) != FIDO_OK)
			return (r);
		rk->n_rx++;
	}

	return (FIDO_OK);
}

int
fido_credman_get_dev_rk(fido_dev_t *dev, const char *rp_id,
    fido_credman_rk_t *rk, const char *pin)
{
	if (fido_dev_is_fido2(dev) == false)
		return (FIDO_ERR_INVALID_COMMAND);
	if (pin == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	return (credman_get_rk_wait(dev, rp_id, rk, pin, -1));
}

static int
credman_rx_del_rk(fido_dev_t *dev, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0 ||
	    reply_len < 0 || (size_t)reply_len < 1) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	return (reply[0]);
}

static int
credman_del_rk_wait(fido_dev_t *dev, const unsigned char *cred_id,
    size_t cred_id_len, const char *pin, int ms)
{
	fido_blob_t cred;
	int r;

	memset(&cred, 0, sizeof(cred));

	if (fido_blob_set(&cred, cred_id, cred_id_len) < 0) {
		log_debug("%s: fido_blob_set", __func__);
		return (FIDO_ERR_INTERNAL);
	}

	if ((r = credman_tx(dev, CMD_DELETE_CRED, &cred, pin)) != FIDO_OK ||
	    (r = credman_rx_del_rk(dev, ms)) != FIDO_OK)
		goto fail;

	r = FIDO_OK;
fail:
	free(cred.ptr);

	return (r);
}

int
fido_credman_del_dev_rk(fido_dev_t *dev, const unsigned char *cred_id,
    size_t cred_id_len, const char *pin)
{
	if (fido_dev_is_fido2(dev) == false)
		return (FIDO_ERR_INVALID_COMMAND);
	if (pin == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	return (credman_del_rk_wait(dev, cred_id, cred_id_len, pin, -1));
}

static int
credman_parse_rp(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	struct fido_credman_single_rp *rp = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 3:
		return (decode_rp_entity(val, &rp->rp_entity));
	case 4:
		return (fido_blob_decode(val, &rp->rp_id_hash));
	default:
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}
}

static void
credman_reset_rp(fido_credman_rp_t *rp)
{
	for (size_t i = 0; i < rp->n_alloc; i++) {
		free(rp->ptr[i].rp_entity.id);
		free(rp->ptr[i].rp_entity.name);
		rp->ptr[i].rp_entity.id = NULL;
		rp->ptr[i].rp_entity.name = NULL;
		free(rp->ptr[i].rp_id_hash.ptr);
		memset(&rp->ptr[i].rp_id_hash, 0,
		    sizeof(rp->ptr[i].rp_id_hash));
	}

	free(rp->ptr);
	rp->ptr = NULL;
	memset(rp, 0, sizeof(*rp));
}

static int
credman_parse_rp_count(const cbor_item_t *key, const cbor_item_t *val,
    void *arg)
{
	fido_credman_rp_t *rp = arg;
	uint64_t n;

	/* totalRPs */
	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8 ||
	    cbor_get_uint8(key) != 5) {
		log_debug("%s: cbor_type", __func__);
		return (0); /* ignore */
	}

	if (decode_uint64(val, &n) < 0 || n > SIZE_MAX) {
		log_debug("%s: decode_uint64", __func__);
		return (-1);
	}

	if (credman_grow_array((void **)&rp->ptr, &rp->n_alloc, &rp->n_rx,
	    (size_t)n, sizeof(*rp->ptr)) < 0) {
		log_debug("%s: credman_grow_array", __func__);
		return (-1);
	}

	return (0);
}

static int
credman_rx_rp(fido_dev_t *dev, fido_credman_rp_t *rp, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	credman_reset_rp(rp);

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* adjust as needed */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, rp,
	    credman_parse_rp_count)) != FIDO_OK) {
		log_debug("%s: credman_parse_rp_count", __func__);
		return (r);
	}

	if (rp->n_alloc == 0) {
		log_debug("%s: n_alloc=0", __func__);
		return (FIDO_OK);
	}

	/* parse the first rp */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, &rp->ptr[0],
	    credman_parse_rp)) != FIDO_OK) {
		log_debug("%s: credman_parse_rp", __func__);
		return (r);
	}

	rp->n_rx++;

	return (FIDO_OK);
}

static int
credman_rx_next_rp(fido_dev_t *dev, fido_credman_rp_t *rp, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* sanity check */
	if (rp->n_rx >= rp->n_alloc) {
		log_debug("%s: n_rx=%zu, n_alloc=%zu", __func__, rp->n_rx,
		    rp->n_alloc);
		return (FIDO_ERR_INTERNAL);
	}

	if ((r = parse_cbor_reply(reply, (size_t)reply_len, &rp->ptr[rp->n_rx],
	    credman_parse_rp)) != FIDO_OK) {
		log_debug("%s: credman_parse_rp", __func__);
		return (r);
	}

	return (FIDO_OK);
}

static int
credman_get_rp_wait(fido_dev_t *dev, fido_credman_rp_t *rp, const char *pin,
    int ms)
{
	int r;

	if ((r = credman_tx(dev, CMD_RP_BEGIN, NULL, pin)) != FIDO_OK ||
	    (r = credman_rx_rp(dev, rp, ms)) != FIDO_OK)
		return (r);

	while (rp->n_rx < rp->n_alloc) {
		if ((r = credman_tx(dev, CMD_RP_NEXT, NULL, NULL)) != FIDO_OK ||
		    (r = credman_rx_next_rp(dev, rp, ms)) != FIDO_OK)
			return (r);
		rp->n_rx++;
	}

	return (FIDO_OK);
}

int
fido_credman_get_dev_rp(fido_dev_t *dev, fido_credman_rp_t *rp, const char *pin)
{
	if (fido_dev_is_fido2(dev) == false)
		return (FIDO_ERR_INVALID_COMMAND);
	if (pin == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	return (credman_get_rp_wait(dev, rp, pin, -1));
}

fido_credman_rk_t *
fido_credman_rk_new(void)
{
	return (calloc(1, sizeof(fido_credman_rk_t)));
}

void
fido_credman_rk_free(fido_credman_rk_t **rk_p)
{
	fido_credman_rk_t *rk;

	if (rk_p == NULL || (rk = *rk_p) == NULL)
		return;

	credman_reset_rk(rk);
	free(rk);
	*rk_p = NULL;
}

size_t
fido_credman_rk_count(const fido_credman_rk_t *rk)
{
	return (rk->n_rx);
}

const fido_cred_t *
fido_credman_rk(const fido_credman_rk_t *rk, size_t idx)
{
	if (idx >= rk->n_alloc)
		return (NULL);

	return (&rk->ptr[idx]);
}

fido_credman_metadata_t *
fido_credman_metadata_new(void)
{
	return (calloc(1, sizeof(fido_credman_metadata_t)));
}

void
fido_credman_metadata_free(fido_credman_metadata_t **metadata_p)
{
	fido_credman_metadata_t *metadata;

	if (metadata_p == NULL || (metadata = *metadata_p) == NULL)
		return;

	free(metadata);
	*metadata_p = NULL;
}

uint64_t
fido_credman_rk_existing(const fido_credman_metadata_t *metadata)
{
	return (metadata->rk_existing);
}

uint64_t
fido_credman_rk_remaining(const fido_credman_metadata_t *metadata)
{
	return (metadata->rk_remaining);
}

fido_credman_rp_t *
fido_credman_rp_new(void)
{
	return (calloc(1, sizeof(fido_credman_rp_t)));
}

void
fido_credman_rp_free(fido_credman_rp_t **rp_p)
{
	fido_credman_rp_t *rp;

	if (rp_p == NULL || (rp = *rp_p) == NULL)
		return;

	credman_reset_rp(rp);
	free(rp);
	*rp_p = NULL;
}

size_t
fido_credman_rp_count(const fido_credman_rp_t *rp)
{
	return (rp->n_rx);
}

const char *
fido_credman_rp_id(const fido_credman_rp_t *rp, size_t idx)
{
	if (idx >= rp->n_alloc)
		return (NULL);

	return (rp->ptr[idx].rp_entity.id);
}

const char *
fido_credman_rp_name(const fido_credman_rp_t *rp, size_t idx)
{
	if (idx >= rp->n_alloc)
		return (NULL);

	return (rp->ptr[idx].rp_entity.name);
}

size_t
fido_credman_rp_id_hash_len(const fido_credman_rp_t *rp, size_t idx)
{
	if (idx >= rp->n_alloc)
		return (0);

	return (rp->ptr[idx].rp_id_hash.len);
}

const unsigned char *
fido_credman_rp_id_hash_ptr(const fido_credman_rp_t *rp, size_t idx)
{
	if (idx >= rp->n_alloc)
		return (NULL);

	return (rp->ptr[idx].rp_id_hash.ptr);
}
