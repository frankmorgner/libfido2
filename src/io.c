/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fido.h"
#include "packed.h"

PACKED_TYPE(frame_t,
struct frame {
	uint32_t cid; /* channel id */
	union {
		uint8_t type;
		struct {
			uint8_t cmd;
			uint8_t bcnth;
			uint8_t bcntl;
			uint8_t data[CTAP_RPT_SIZE - 7];
		} init;
		struct {
			uint8_t seq;
			uint8_t data[CTAP_RPT_SIZE - 5];
		} cont;
	} body;
})

#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

#if 0
static size_t
tx_preamble(fido_dev_t *d,  uint8_t cmd, const void *buf, size_t count)
{
	struct frame	*fp;
	unsigned char	pkt[sizeof(*fp) + 1];
	int		n;

	if (d->io.write == NULL || (cmd & 0x80) == 0)
		return (0);

	memset(&pkt, 0, sizeof(pkt));
	fp = (struct frame *)(pkt + 1);
	fp->cid = d->cid;
	fp->body.init.cmd = 0x80 | cmd;
	fp->body.init.bcnth = (count >> 8) & 0xff;
	fp->body.init.bcntl = count & 0xff;
	count = MIN(count, sizeof(fp->body.init.data));
	memcpy(&fp->body.init.data, buf, count);

	n = d->io.write(d->io_handle, pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (0);

	return (count);
}

static size_t
tx_frame(fido_dev_t *d, int seq, const void *buf, size_t count)
{
	struct frame	*fp;
	unsigned char	 pkt[sizeof(*fp) + 1];
	int		 n;

	if (d->io.write == NULL || seq < 0 || seq > UINT8_MAX)
		return (0);

	memset(&pkt, 0, sizeof(pkt));
	fp = (struct frame *)(pkt + 1);
	fp->cid = d->cid;
	fp->body.cont.seq = (uint8_t)seq;
	count = MIN(count, sizeof(fp->body.cont.data));
	memcpy(&fp->body.cont.data, buf, count);

	n = d->io.write(d->io_handle, pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (0);

	return (count);
}
#endif

int
tx(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count)
{
	log_debug("%s: d=%p, cmd=0x%02x, buf=%p, count=%zu", __func__,
	    (void *)d, cmd, buf, count);
	log_xxd(buf, count);

	if (d->io_handle == NULL || count > UINT16_MAX) {
		log_debug("%s: invalid argument (%p, %zu)", __func__,
		    d->io_handle, count);
		return (-1);
	}

#if 0
	if ((sent = tx_preamble(d, cmd, buf, count)) == 0) {
		log_debug("%s: tx_preamble", __func__);
		return (-1);
	}

	while (sent < count) {
		if (seq & 0x80) {
			log_debug("%s: seq & 0x80", __func__);
			return (-1);
		}
		const uint8_t *p = (const uint8_t *)buf + sent;
		size_t n = tx_frame(d, seq++, p, count - sent);
		if (n == 0) {
			log_debug("%s: tx_frame", __func__);
			return (-1);
		}
		sent += n;
	}

	return (0);
#endif
	unsigned char apdu[0xFFFF+6];
	apdu[0] = 0x80;
	apdu[1] = 0x10;
	apdu[2] = 0x00;
	apdu[3] = 0x00;
	apdu[4] = 0x00;
	apdu[5] = (unsigned char) (count>>8);
	apdu[6] = (unsigned char) count;
	memcpy(apdu+7, buf, count);
	apdu[7+count] = 0x00;
	apdu[8+count] = 0x00;

	int n = d->io.write(d->io_handle, apdu, 9+count);
	if (n < 0 || (size_t)n != 9+count)
		return -1;

	return 0;
}

#if 0
static int
rx_frame(fido_dev_t *d, struct frame *fp, int ms)
{
	int n;

	if (d->io.read == NULL)
		return (-1);

	n = d->io.read(d->io_handle, (unsigned char *)fp, sizeof(*fp), ms);
	if (n < 0 || (size_t)n != sizeof(*fp))
		return (-1);

	return (0);
}

static int
rx_preamble(fido_dev_t *d, struct frame *fp, int ms)
{
	do {
		if (rx_frame(d, fp, ms) < 0)
			return (-1);
#ifdef FIDO_FUZZ
		fp->cid = d->cid;
#endif
	} while (fp->cid == d->cid &&
	    fp->body.init.cmd == (CTAP_FRAME_INIT | CTAP_KEEPALIVE));

	return (0);
}
#endif

int
rx(fido_dev_t *d, uint8_t cmd, void *buf, size_t count, int ms)
{
	if (d->io_handle == NULL || (cmd & 0x80) == 0) {
		log_debug("%s: invalid argument (%p, 0x%02x)", __func__,
		    d->io_handle, cmd);
		return (-1);
	}

#if 0
	if (rx_preamble(d, &f, ms) < 0) {
		log_debug("%s: rx_preamble", __func__);
		return (-1);
	}

	log_debug("%s: initiation frame at %p, len %zu", __func__, (void *)&f,
	    sizeof(f));
	log_xxd(&f, sizeof(f));

#ifdef FIDO_FUZZ
	f.cid = d->cid;
	f.body.init.cmd = cmd;
#endif

	if (f.cid != d->cid || f.body.init.cmd != cmd) {
		log_debug("%s: cid (0x%x, 0x%x), cmd (0x%02x, 0x%02x)",
		    __func__, f.cid, d->cid, f.body.init.cmd, cmd);
		return (-1);
	}

	flen = (f.body.init.bcnth << 8) | f.body.init.bcntl;
	if (count < (size_t)flen) {
		log_debug("%s: count < flen (%zu, %zu)", __func__, count,
		    (size_t)flen);
		return (-1);
	}
	if (flen < sizeof(f.body.init.data)) {
		memcpy(buf, f.body.init.data, flen);
		return (flen);
	}

	memcpy(buf, f.body.init.data, sizeof(f.body.init.data));
	r = sizeof(f.body.init.data);
	seq = 0;

	while ((size_t)r < flen) {
		if (rx_frame(d, &f, ms) < 0) {
			log_debug("%s: rx_frame", __func__);
			return (-1);
		}

		log_debug("%s: continuation frame at %p, len %zu", __func__,
		    (void *)&f, sizeof(f));
		log_xxd(&f, sizeof(f));

#ifdef FIDO_FUZZ
		f.cid = d->cid;
		f.body.cont.seq = seq;
#endif

		if (f.cid != d->cid || f.body.cont.seq != seq++) {
			log_debug("%s: cid (0x%x, 0x%x), seq (%d, %d)",
			    __func__, f.cid, d->cid, f.body.cont.seq, seq);
			return (-1);
		}

		uint8_t *p = (uint8_t *)buf + r;

		if ((size_t)(flen - r) > sizeof(f.body.cont.data)) {
			memcpy(p, f.body.cont.data, sizeof(f.body.cont.data));
			r += sizeof(f.body.cont.data);
		} else {
			memcpy(p, f.body.cont.data, flen - r);
			r += (flen - r); /* break */
		}
	}
#endif

	unsigned char rapdu[0xFFFF];

	int n = d->io.read(d->io_handle, rapdu, sizeof rapdu, ms);
	if (n < 2)
		return (-1);

	if (count < (size_t)n-2) {
		log_debug("%s: count < flen (%zu, %zu)", __func__, count,
		    (size_t)n);
		return (-1);
	}
	memcpy(buf, rapdu, n-2);

	log_debug("%s: payload at %p, len %zu", __func__, buf, (size_t)n-2);
	log_xxd(buf, n-2);

	return (n-2);
}
