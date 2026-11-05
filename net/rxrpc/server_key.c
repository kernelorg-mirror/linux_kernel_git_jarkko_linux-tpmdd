// SPDX-License-Identifier: GPL-2.0-or-later
/* RxRPC key management
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * RxRPC keys should have a description of describing their purpose:
 *	"afs@CAMBRIDGE.REDHAT.COM>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define RXRPC_KEY_PROVIDER

#include <crypto/des.h>
#include <crypto/krb5.h>
#include <linux/fips.h>

#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/key-type.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include <keys/rxrpc-type.h>
#include <keys/user-type.h>
#include "ar-internal.h"

static int rxrpc_vet_description_s(const char *);
static int rxrpc_preparse_s(struct key_preparsed_payload *);
static void rxrpc_free_preparse_s(struct key_preparsed_payload *);
static void rxrpc_destroy_s(struct key *);
static void rxrpc_describe_s(const struct key *, struct seq_file *);

/*
 * rxrpc server keys take "<serviceId>:<securityIndex>[:<sec-specific>]" as the
 * description and the key material as the payload.
 */
struct key_type key_type_rxrpc_s = {
	.name		= "rxrpc_s",
	.flags		= KEY_TYPE_NET_DOMAIN,
	.vet_description = rxrpc_vet_description_s,
	.preparse	= rxrpc_preparse_s,
	.free_preparse	= rxrpc_free_preparse_s,
	.instantiate	= generic_key_instantiate,
	.destroy	= rxrpc_destroy_s,
	.describe	= rxrpc_describe_s,
};
EXPORT_SYMBOL(key_type_rxrpc_s);

/*
 * Vet the description for an RxRPC server key.
 */
static int rxrpc_vet_description_s(const char *desc)
{
	unsigned long service, sec_class;
	char *p;

	service = simple_strtoul(desc, &p, 10);
	if (*p != ':' || service > 65535)
		return -EINVAL;
	sec_class = simple_strtoul(p + 1, &p, 10);
	if ((*p && *p != ':') || sec_class < 1 || sec_class > 255)
		return -EINVAL;
	return 0;
}

#ifdef CONFIG_RXKAD
/*
 * Parse the information from a server key
 *
 * The data should be the 8-byte secret key.
 */
static int rxkad_preparse_server_key(struct key_preparsed_payload *prep)
{
	struct des_ctx *des_key;
	int err;

	if (fips_enabled)
		return -ENOPKG;

	if (prep->datalen != 8)
		return -EINVAL;

	memcpy(&prep->payload.data[2], prep->data, 8);

	des_key = kmalloc_obj(*des_key);
	if (!des_key) {
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	err = des_expand_key(des_key, prep->data, 8);
	if (err) {
		kfree_sensitive(des_key);
		_leave(" = %d", err);
		return err;
	}

	prep->payload.data[0] = des_key;
	_leave(" = 0");
	return 0;
}

static void rxkad_free_preparse_server_key(struct key_preparsed_payload *prep)
{
	kfree_sensitive(prep->payload.data[0]);
}

static void rxkad_destroy_server_key(struct key *key)
{
	kfree_sensitive(key->payload.data[0]);
	key->payload.data[0] = NULL;
}
#endif

#ifdef CONFIG_RXGK
/*
 * Parse the information from a server key
 */
static int rxgk_preparse_server_key(struct key_preparsed_payload *prep)
{
	const struct krb5_enctype *krb5;
	struct krb5_buffer *server_key = (void *)&prep->payload.data[2];
	unsigned int service, sec_class, kvno, enctype;
	int n = 0;

	_enter("%zu", prep->datalen);

	if (sscanf(prep->orig_description, "%u:%u:%u:%u%n",
		   &service, &sec_class, &kvno, &enctype, &n) != 4)
		return -EINVAL;

	if (prep->orig_description[n])
		return -EINVAL;

	krb5 = crypto_krb5_find_enctype(enctype);
	if (!krb5)
		return -ENOPKG;

	prep->payload.data[0] = (struct krb5_enctype *)krb5;

	if (prep->datalen != krb5->key_len)
		return -EKEYREJECTED;

	server_key->len = prep->datalen;
	server_key->data = kmemdup(prep->data, prep->datalen, GFP_KERNEL);
	if (!server_key->data)
		return -ENOMEM;

	_leave(" = 0");
	return 0;
}

static void rxgk_free_server_key(union key_payload *payload)
{
	struct krb5_buffer *server_key = (void *)&payload->data[2];

	kfree_sensitive(server_key->data);
}

static void rxgk_free_preparse_server_key(struct key_preparsed_payload *prep)
{
	rxgk_free_server_key(&prep->payload);
}

static void rxgk_destroy_server_key(struct key *key)
{
	rxgk_free_server_key(&key->payload);
}

static void rxgk_describe_server_key(const struct key *key, struct seq_file *m)
{
	const struct krb5_enctype *krb5 = key->payload.data[0];

	if (krb5)
		seq_printf(m, ": %s", krb5->name);
}
#endif

/*
 * Preparse a server secret key.
 */
static int rxrpc_preparse_s(struct key_preparsed_payload *prep)
{
	unsigned int service, sec_class;
	int n;

	_enter("%zu", prep->datalen);

	if (!prep->orig_description)
		return -EINVAL;

	if (sscanf(prep->orig_description, "%u:%u%n", &service, &sec_class, &n) != 2)
		return -EINVAL;

	prep->payload.data[1] = (void *)(uintptr_t)sec_class;

	switch (sec_class) {
#ifdef CONFIG_RXKAD
	case RXRPC_SECURITY_RXKAD:
		return rxkad_preparse_server_key(prep);
#endif
#ifdef CONFIG_RXGK
	case RXRPC_SECURITY_YFS_RXGK:
		return rxgk_preparse_server_key(prep);
#endif
	default:
		return -ENOPKG;
	}
}

static void rxrpc_free_preparse_s(struct key_preparsed_payload *prep)
{
	switch ((uintptr_t)prep->payload.data[1]) {
#ifdef CONFIG_RXKAD
	case RXRPC_SECURITY_RXKAD:
		rxkad_free_preparse_server_key(prep);
		break;
#endif
#ifdef CONFIG_RXGK
	case RXRPC_SECURITY_YFS_RXGK:
		rxgk_free_preparse_server_key(prep);
		break;
#endif
	default:
		break;
	}
}

static void rxrpc_destroy_s(struct key *key)
{
	switch ((uintptr_t)key->payload.data[1]) {
#ifdef CONFIG_RXKAD
	case RXRPC_SECURITY_RXKAD:
		rxkad_destroy_server_key(key);
		break;
#endif
#ifdef CONFIG_RXGK
	case RXRPC_SECURITY_YFS_RXGK:
		rxgk_destroy_server_key(key);
		break;
#endif
	default:
		break;
	}
}

static void rxrpc_describe_s(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);

	switch ((uintptr_t)key->payload.data[1]) {
#ifdef CONFIG_RXGK
	case RXRPC_SECURITY_YFS_RXGK:
		rxgk_describe_server_key(key, m);
		break;
#endif
	default:
		break;
	}
}
