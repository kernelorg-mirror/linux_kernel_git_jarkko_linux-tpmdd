// SPDX-License-Identifier: LGPL-2.1-or-later
/* Upcall routine, designed to work as a key type and working through
 * /sbin/request-key to contact userspace when handling DNS queries.
 *
 * See Documentation/networking/dns_resolver.rst
 *
 *   Copyright (c) 2007 Igor Mammedov
 *   Author(s): Igor Mammedov (niallain@gmail.com)
 *              Steve French (sfrench@us.ibm.com)
 *              Wang Lei (wang840925@gmail.com)
 *		David Howells (dhowells@redhat.com)
 *
 *   The upcall wrapper used to make an arbitrary DNS query.
 *
 *   This function requires the appropriate userspace tool dns.upcall to be
 *   installed and something like the following lines should be added to the
 *   /etc/request-key.conf file:
 *
 *	create dns_resolver * * /sbin/dns.upcall %k
 *
 *   For example to use this module to query AFSDB RR:
 *
 *	create dns_resolver afsdb:* * /sbin/dns.afsdb %k
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/keyctl.h>
#include <linux/dns_resolver.h>
#include <linux/err.h>
#include <net/net_namespace.h>

#include <keys/dns_resolver-type.h>
#include <keys/user-type.h>

#include "internal.h"

static const struct cred *dns_resolver_cache;

/**
 * dns_query - Query the DNS
 * @net: The network namespace to operate in.
 * @type: Query type (or NULL for straight host->IP lookup)
 * @name: Name to look up
 * @namelen: Length of name
 * @options: Request options (or NULL if no options)
 * @_result: Where to place the returned data (or NULL)
 * @_expiry: Where to store the result expiry time (or NULL)
 * @invalidate: Always invalidate the key after use
 *
 * The data will be returned in the pointer at *result, if provided, and the
 * caller is responsible for freeing it.
 *
 * The description should be of the form "[<query_type>:]<domain_name>", and
 * the options need to be appropriate for the query type requested.  If no
 * query_type is given, then the query is a straight hostname to IP address
 * lookup.
 *
 * The DNS resolution lookup is performed by upcalling to userspace by way of
 * requesting a key of type dns_resolver.
 *
 * Returns the size of the result on success, -ve error code otherwise.
 */
int dns_query(struct net *net,
	      const char *type, const char *name, size_t namelen,
	      const char *options, char **_result, time64_t *_expiry,
	      bool invalidate)
{
	struct user_key_payload *upayload;
	struct key *rkey;
	int ret, len;
	char *desc;

	kenter("%s,%*.*s,%zu,%s",
	       type, (int)namelen, (int)namelen, name, namelen, options);

	if (!name || namelen < 1 || namelen > 255)
		return -EINVAL;
	if (type && *type == '\0')
		return -EINVAL;

	/* construct the query key description as "[<type>:]<name>" */
	if (type)
		desc = kasprintf(GFP_KERNEL, "%s:%.*s", type, (int)namelen, name);
	else
		desc = kmemdup_nul(name, namelen, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	if (!options)
		options = "";
	kdebug("call request_key(,%s,%s)", desc, options);

	/* make the upcall, using special credentials to prevent the use of
	 * add_key() to preinstall malicious redirections
	 */
	scoped_with_creds(dns_resolver_cache)
		rkey = request_key_net(&key_type_dns_resolver, desc, net, options);
	kfree(desc);
	if (IS_ERR(rkey)) {
		ret = PTR_ERR(rkey);
		goto out;
	}

	down_read(&rkey->sem);
	set_bit(KEY_FLAG_ROOT_CAN_INVAL, &rkey->flags);
	rkey->perm |= KEY_USR_VIEW;

	ret = key_validate(rkey);
	if (ret < 0)
		goto put;

	/* If the DNS server gave an error, return that to the caller */
	ret = PTR_ERR(rkey->payload.data[dns_key_error]);
	if (ret)
		goto put;

	upayload = user_key_payload_locked(rkey);
	len = upayload->datalen;

	if (_result) {
		ret = -ENOMEM;
		*_result = kmemdup_nul(upayload->data, len, GFP_KERNEL);
		if (!*_result)
			goto put;
	}

	if (_expiry)
		*_expiry = rkey->expiry;

	ret = len;
put:
	up_read(&rkey->sem);
	if (invalidate)
		key_invalidate(rkey);
	key_put(rkey);
out:
	kleave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(dns_query);

static int __init init_dns_resolver(void)
{
	struct cred *cred;
	struct key *keyring;
	int ret;

	/*
	 * Create an override credential set with a special thread keyring in
	 * which DNS requests are cached.  This prevents malicious redirections
	 * from being installed with add_key().
	 */
	cred = prepare_kernel_cred(&init_task);
	if (!cred)
		return -ENOMEM;

	keyring = keyring_alloc(".dns_resolver",
				GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred,
				(KEY_POS_ALL & ~KEY_POS_SETATTR) |
				KEY_USR_VIEW | KEY_USR_READ,
				KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto failed_put_cred;
	}

	/*
	 * Instruct request_key() to use this special keyring as a cache for
	 * the results it looks up.
	 */
	set_bit(KEY_FLAG_ROOT_CAN_CLEAR, &keyring->flags);
	cred->thread_keyring = keyring;
	cred->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
	dns_resolver_cache = cred;

	kdebug("DNS resolver keyring: %d\n", key_serial(keyring));
	return 0;

failed_put_cred:
	put_cred(cred);
	return ret;
}

static void __exit exit_dns_resolver(void)
{
	key_revoke(dns_resolver_cache->thread_keyring);
	put_cred(dns_resolver_cache);
	/* Drain deferred credential and keyring destruction. */
	key_gc_flush();
}

module_init(init_dns_resolver);
module_exit(exit_dns_resolver);

MODULE_DESCRIPTION("DNS Resolver");
MODULE_AUTHOR("Wang Lei");
MODULE_LICENSE("GPL");

module_param_named(debug, dns_resolver_debug, uint, 0644);
MODULE_PARM_DESC(debug, "DNS Resolver debugging mask");
