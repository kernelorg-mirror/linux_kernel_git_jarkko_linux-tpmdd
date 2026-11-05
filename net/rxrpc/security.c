// SPDX-License-Identifier: GPL-2.0-or-later
/* RxRPC security handling
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/crypto.h>
#include <linux/key-type.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include <keys/rxrpc-type.h>
#include "ar-internal.h"

static const struct rxrpc_security *rxrpc_security_types[] = {
	[RXRPC_SECURITY_NONE]	= &rxrpc_no_security,
#ifdef CONFIG_RXKAD
	[RXRPC_SECURITY_RXKAD]	= &rxkad,
#endif
#ifdef CONFIG_RXGK
	[RXRPC_SECURITY_YFS_RXGK] = &rxgk_yfs,
#endif
};

int __init rxrpc_init_security(void)
{
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(rxrpc_security_types); i++) {
		if (rxrpc_security_types[i]) {
			ret = rxrpc_security_types[i]->init();
			if (ret < 0)
				goto failed;
		}
	}

	return 0;

failed:
	for (i--; i >= 0; i--)
		if (rxrpc_security_types[i])
			rxrpc_security_types[i]->exit();
	return ret;
}

void rxrpc_exit_security(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rxrpc_security_types); i++)
		if (rxrpc_security_types[i])
			rxrpc_security_types[i]->exit();
}

/*
 * look up an rxrpc security module
 */
const struct rxrpc_security *rxrpc_security_lookup(u8 security_index)
{
	if (security_index >= ARRAY_SIZE(rxrpc_security_types))
		return NULL;
	return rxrpc_security_types[security_index];
}

/*
 * Initialise the security on a client call.
 */
int rxrpc_init_client_call_security(struct rxrpc_call *call)
{
	const struct rxrpc_security *sec = &rxrpc_no_security;
	struct rxrpc_key_token *token;
	struct key *key = call->key;
	int ret;

	if (!key)
		goto found;

	ret = key_validate(key);
	if (ret < 0)
		return ret;

	for (token = key->payload.data[0]; token; token = token->next) {
		sec = rxrpc_security_lookup(token->security_index);
		if (sec)
			goto found;
	}
	return -EKEYREJECTED;

found:
	call->security = sec;
	call->security_ix = sec->security_index;
	return 0;
}

/*
 * initialise the security on a client connection
 */
int rxrpc_init_client_conn_security(struct rxrpc_connection *conn)
{
	struct rxrpc_key_token *token;
	struct key *key = conn->key;
	int ret = 0;

	_enter("{%d},{%x}", conn->debug_id, key_serial(key));

	for (token = key->payload.data[0]; token; token = token->next) {
		if (token->security_index == conn->security->security_index)
			goto found;
	}
	return -EKEYREJECTED;

found:
	mutex_lock(&conn->security_lock);
	if (conn->state == RXRPC_CONN_CLIENT_UNSECURED) {
		ret = conn->security->init_connection_security(conn, token);
		if (ret == 0) {
			spin_lock_irq(&conn->state_lock);
			if (conn->state == RXRPC_CONN_CLIENT_UNSECURED)
				conn->state = RXRPC_CONN_CLIENT;
			spin_unlock_irq(&conn->state_lock);
		}
	}
	mutex_unlock(&conn->security_lock);
	return ret;
}

/*
 * Set the ops a server connection.
 */
const struct rxrpc_security *rxrpc_get_incoming_security(struct rxrpc_sock *rx,
							 struct sk_buff *skb)
{
	const struct rxrpc_security *sec;
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);

	_enter("");

	sec = rxrpc_security_lookup(sp->hdr.securityIndex);
	if (!sec) {
		rxrpc_direct_conn_abort(skb, rxrpc_abort_unsupported_security,
					RX_INVALID_OPERATION, -EKEYREJECTED);
		return NULL;
	}

	if (sp->hdr.securityIndex != RXRPC_SECURITY_NONE &&
	    !rx->securities) {
		rxrpc_direct_conn_abort(skb, rxrpc_abort_no_service_key,
					sec->no_key_abort, -EKEYREJECTED);
		return NULL;
	}

	return sec;
}

/*
 * Find the security key for a server connection.
 */
struct key *rxrpc_look_up_server_security(struct rxrpc_connection *conn,
					  struct sk_buff *skb,
					  u32 kvno, u32 enctype)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxrpc_sock *rx;
	struct key *key = ERR_PTR(-EKEYREJECTED);
	key_ref_t kref = NULL;
	char kdesc[5 + 1 + 3 + 1 + 12 + 1 + 12 + 1];
	int ret;

	_enter("");

	if (enctype)
		sprintf(kdesc, "%u:%u:%u:%u",
			sp->hdr.serviceId, sp->hdr.securityIndex, kvno, enctype);
	else if (kvno)
		sprintf(kdesc, "%u:%u:%u",
			sp->hdr.serviceId, sp->hdr.securityIndex, kvno);
	else
		sprintf(kdesc, "%u:%u",
			sp->hdr.serviceId, sp->hdr.securityIndex);

	read_lock(&conn->local->services_lock);

	rx = conn->local->service;
	if (!rx)
		goto out;

	/* look through the service's keyring */
	kref = keyring_search(make_key_ref(rx->securities, 1UL),
			      &key_type_rxrpc_s, kdesc, true);
	if (IS_ERR(kref)) {
		key = ERR_CAST(kref);
		goto out;
	}

	key = key_ref_to_ptr(kref);

	ret = key_validate(key);
	if (ret < 0) {
		key_put(key);
		key = ERR_PTR(ret);
		goto out;
	}

out:
	read_unlock(&conn->local->services_lock);
	return key;
}

/*
 * grab the security key for a socket
 */
int rxrpc_request_key(struct rxrpc_sock *rx, sockptr_t optval, int optlen)
{
	struct key *key;
	char *description;

	_enter("");

	if (optlen <= 0 || optlen > PAGE_SIZE - 1 || rx->key)
		return -EINVAL;

	description = memdup_sockptr_nul(optval, optlen);
	if (IS_ERR(description))
		return PTR_ERR(description);

	key = request_key_net(&key_type_rxrpc, description, sock_net(&rx->sk), NULL);
	if (IS_ERR(key)) {
		kfree(description);
		_leave(" = %ld", PTR_ERR(key));
		return PTR_ERR(key);
	}

	rx->key = key;
	kfree(description);
	_leave(" = 0 [key %x]", key->serial);
	return 0;
}

/*
 * generate a server data key
 */
int rxrpc_get_server_data_key(struct rxrpc_connection *conn,
			      const void *session_key,
			      time64_t expiry,
			      u32 kvno)
{
	const struct cred *cred = current_cred();
	struct {
		u32 kver;
		struct rxrpc_key_data_v1 v1;
	} data;
	struct key *key;
	int ret;

	_enter("");

	key = key_alloc(&key_type_rxrpc, "x",
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred, 0,
			KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(key)) {
		_leave(" = -ENOMEM [alloc %ld]", PTR_ERR(key));
		return -ENOMEM;
	}

	_debug("key %d", key_serial(key));

	data.kver = 1;
	data.v1.security_index = RXRPC_SECURITY_RXKAD;
	data.v1.ticket_length = 0;
	data.v1.expiry = rxrpc_time64_to_u32(expiry);
	data.v1.kvno = 0;

	memcpy(&data.v1.session_key, session_key, sizeof(data.v1.session_key));

	ret = key_instantiate_and_link(key, &data, sizeof(data), NULL, NULL);
	if (ret < 0)
		goto error;

	conn->key = key;
	_leave(" = 0 [%d]", key_serial(key));
	return 0;

error:
	key_revoke(key);
	key_put(key);
	_leave(" = -ENOMEM [ins %d]", ret);
	return -ENOMEM;
}
EXPORT_SYMBOL(rxrpc_get_server_data_key);

/*
 * grab the security keyring for a server socket
 */
int rxrpc_server_keyring(struct rxrpc_sock *rx, sockptr_t optval, int optlen)
{
	struct key *key;
	char *description;

	_enter("");

	if (rx->securities)
		return -EINVAL;

	if (optlen <= 0 || optlen > PAGE_SIZE - 1)
		return -EINVAL;

	description = memdup_sockptr_nul(optval, optlen);
	if (IS_ERR(description))
		return PTR_ERR(description);

	key = request_key(&key_type_keyring, description, NULL);
	if (IS_ERR(key)) {
		kfree(description);
		_leave(" = %ld", PTR_ERR(key));
		return PTR_ERR(key);
	}

	rx->securities = key;
	kfree(description);
	_leave(" = 0 [key %x]", key->serial);
	return 0;
}

/**
 * rxrpc_sock_set_security_keyring - Set the security keyring for a kernel service
 * @sk: The socket to set the keyring on
 * @keyring: The keyring to set
 *
 * Set the server security keyring on an rxrpc socket.  This is used to provide
 * the encryption keys for a kernel service.
 *
 * Return: %0 if successful and a negative error code otherwise.
 */
int rxrpc_sock_set_security_keyring(struct sock *sk, struct key *keyring)
{
	struct rxrpc_sock *rx = rxrpc_sk(sk);
	int ret = 0;

	lock_sock(sk);
	if (rx->securities)
		ret = -EINVAL;
	else if (rx->sk.sk_state != RXRPC_UNBOUND)
		ret = -EISCONN;
	else
		rx->securities = key_get(keyring);
	release_sock(sk);
	return ret;
}
EXPORT_SYMBOL(rxrpc_sock_set_security_keyring);

/**
 * rxrpc_sock_set_manage_response - Set the manage-response flag for a kernel service
 * @sk: The socket to set the keyring on
 * @set: True to set, false to clear the flag
 *
 * Set the flag on an rxrpc socket to say that the caller wants to manage the
 * RESPONSE packet and the user-defined data it may contain.  Setting this
 * means that recvmsg() will return messages with RXRPC_CHALLENGED in the
 * control message buffer containing information about the challenge.
 *
 * The user should respond to the challenge by passing RXRPC_RESPOND or
 * RXRPC_RESPOND_ABORT control messages with sendmsg() to the same call.
 * Supplementary control messages, such as RXRPC_RESP_RXGK_APPDATA, may be
 * included to indicate the parts the user wants to supply.
 *
 * The server will be passed the response data with a RXRPC_RESPONDED control
 * message when it gets the first data from each call.
 *
 * Note that this is only honoured by security classes that need auxiliary data
 * (e.g. RxGK).  Those that don't offer the facility (e.g. RxKAD) respond
 * without consulting userspace.
 *
 * Return: The previous setting.
 */
int rxrpc_sock_set_manage_response(struct sock *sk, bool set)
{
	struct rxrpc_sock *rx = rxrpc_sk(sk);
	int ret;

	lock_sock(sk);
	ret = !!test_bit(RXRPC_SOCK_MANAGE_RESPONSE, &rx->flags);
	if (set)
		set_bit(RXRPC_SOCK_MANAGE_RESPONSE, &rx->flags);
	else
		clear_bit(RXRPC_SOCK_MANAGE_RESPONSE, &rx->flags);
	release_sock(sk);
	return ret;
}
EXPORT_SYMBOL(rxrpc_sock_set_manage_response);
