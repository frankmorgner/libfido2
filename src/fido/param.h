/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _FIDO_PARAM_H
#define _FIDO_PARAM_H

/* Authentication data flags. */
#define CTAP_AUTHDATA_USER_PRESENT	0x01
#define CTAP_AUTHDATA_USER_VERIFIED	0x04
#define CTAP_AUTHDATA_ATT_CRED		0x40
#define CTAP_AUTHDATA_EXT_DATA		0x80

/* CTAPHID command opcodes. */
#define CTAP_CMD_PING			0x01
#define CTAP_CMD_MSG			0x03
#define CTAP_CMD_LOCK			0x04
#define CTAP_CMD_INIT			0x06
#define CTAP_CMD_WINK			0x08
#define CTAP_CMD_CBOR			0x10
#define CTAP_KEEPALIVE			0x3b
#define CTAP_FRAME_INIT			0x80

/* CTAPHID CBOR command opcodes. */
#define CTAP_CBOR_MAKECRED		0x01
#define CTAP_CBOR_ASSERT		0x02
#define CTAP_CBOR_GETINFO		0x04
#define CTAP_CBOR_CLIENT_PIN		0x06
#define CTAP_CBOR_RESET			0x07
#define CTAP_CBOR_NEXT_ASSERT		0x08
#define CTAP_CBOR_CRED_MGMT_PRE		0x41

/* U2F command opcodes. */
#define U2F_CMD_REGISTER		0x01
#define U2F_CMD_AUTH			0x02

/* U2F command flags. */
#define U2F_AUTH_SIGN			0x03
#define U2F_AUTH_CHECK			0x07

/* ISO7816-4 status words. */
#define SW_CONDITIONS_NOT_SATISFIED	0x6985
#define SW_WRONG_DATA			0x6a80
#define SW_NO_ERROR			0x9000

/* HID Broadcast channel ID. */
#define CTAP_CID_BROADCAST		0xffffffff

/* Expected size of a HID report in bytes. */
#define CTAP_RPT_SIZE			64

/* Randomness device on UNIX-like platforms. */
#ifndef FIDO_RANDOM_DEV
#define FIDO_RANDOM_DEV			"/dev/urandom"
#endif

/* CTAP capability bits. */
#define FIDO_CAP_WINK	0x01 /* if set, device supports CTAP_CMD_WINK */
#define FIDO_CAP_CBOR	0x04 /* if set, device supports CTAP_CMD_CBOR */
#define FIDO_CAP_NMSG	0x08 /* if set, device doesn't support CTAP_CMD_MSG */

/* Supported COSE algorithms. */
#define	COSE_ES256	-7
#define	COSE_EDDSA	-8
#define	COSE_RS256	-257

/* Supported COSE types. */
#define COSE_KTY_OKP	1
#define COSE_KTY_EC2	2
#define COSE_KTY_RSA	3

/* Supported curves. */
#define COSE_P256	1
#define COSE_ED25519	6

/* Supported extensions. */
#define FIDO_EXT_HMAC_SECRET	0x01

#endif /* !_FIDO_PARAM_H */
