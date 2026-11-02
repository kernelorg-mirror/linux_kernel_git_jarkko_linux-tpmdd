// SPDX-License-Identifier: GPL-2.0-or-later
/* Key garbage collector
 *
 * Copyright (C) 2009-2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/security.h>
#include <keys/keyring-type.h>
#include "internal.h"

/*
 * Delay between key revocation/expiry in seconds
 */
unsigned key_gc_delay = 5 * 60;

/*
 * Reaper for unused keys.
 */
static void key_garbage_collector(struct work_struct *work);
DECLARE_WORK(key_gc_work, key_garbage_collector);

/**
 * key_gc_flush - Drain the garbage collector RCU callbacks
 */
void key_gc_flush(void)
{
	do {
		rcu_barrier();
	} while (flush_work(&key_gc_work));
}
EXPORT_SYMBOL_GPL(key_gc_flush);

/*
 * Reaper for links from keyrings to dead keys.
 */
static void key_gc_timer_func(struct timer_list *);
static DEFINE_TIMER(key_gc_timer, key_gc_timer_func);

static time64_t key_gc_next_run = TIME64_MAX;
static unsigned long key_gc_flags;
#define KEY_GC_KEY_EXPIRED	0	/* A key expired and needs unlinking */
/*
 * Schedule a garbage collection run.
 * - time precision isn't particularly important
 */
void key_schedule_gc(time64_t gc_at)
{
	unsigned long expires;
	time64_t now = ktime_get_real_seconds();

	kenter("%lld", gc_at - now);

	if (gc_at <= now) {
		kdebug("IMMEDIATE");
		schedule_work(&key_gc_work);
	} else if (gc_at < key_gc_next_run) {
		kdebug("DEFERRED");
		key_gc_next_run = gc_at;
		expires = jiffies + (gc_at - now) * HZ;
		mod_timer(&key_gc_timer, expires);
	}
}

/*
 * Set the expiration time on a key.
 */
void key_set_expiry(struct key *key, time64_t expiry)
{
	key->expiry = expiry;
	if (expiry != TIME64_MAX) {
		if (!(key->type->flags & KEY_TYPE_INSTANT_REAP))
			expiry += key_gc_delay;
		key_schedule_gc(expiry);
	}
}

/*
 * Schedule a dead links collection run.
 */
void key_schedule_gc_links(void)
{
	set_bit(KEY_GC_KEY_EXPIRED, &key_gc_flags);
	schedule_work(&key_gc_work);
}

/*
 * Some key's cleanup time was met after it expired, so we need to get the
 * reaper to go through a cycle finding expired keys.
 */
static void key_gc_timer_func(struct timer_list *unused)
{
	kenter("");
	key_gc_next_run = TIME64_MAX;
	key_schedule_gc_links();
}

/*
 * Garbage collect a list of unreferenced, detached keys
 */
static noinline void key_gc_unused_keys(struct list_head *keys)
{
	while (!list_empty(keys)) {
		struct key *key =
			list_entry(keys->next, struct key, graveyard_link);
		struct module *owner = key->type->owner;
		short state = key->state;

		list_del(&key->graveyard_link);

		kdebug("- %u", key->serial);
		key_check(key);

#ifdef CONFIG_KEY_NOTIFICATIONS
		remove_watch_list(key->watchers, key->serial);
		key->watchers = NULL;
#endif

		/* Throw away the key data if the key is instantiated */
		if (state == KEY_IS_POSITIVE) {
			if (key->type->destroy)
				key->type->destroy(key);
		} else if (key->restrict_link) {
			if (key->restrict_link->keytype)
				module_put(key->restrict_link->keytype->owner);
			key_put(key->restrict_link->key);
			kfree(key->restrict_link);
		}

		security_key_free(key);

		atomic_dec(&key->user->nkeys);
		if (state != KEY_IS_UNINSTANTIATED)
			atomic_dec(&key->user->nikeys);

		key_user_put(key->user);
		key_put_tag(key->domain_tag);
		kfree(key->description);

		memzero_explicit(key, sizeof(*key));
		kmem_cache_free(key_jar, key);
		module_put(owner);
	}
}

/*
 * Garbage collector for unused keys.
 *
 * This is done in process context so that we don't have to disable interrupts
 * all over the place.  key_put() schedules this rather than trying to do the
 * cleanup itself, which means key_put() doesn't have to sleep.
 */
static void key_garbage_collector(struct work_struct *work)
{
	static LIST_HEAD(graveyard);
	u8 gc_state = 0;
#define KEY_GC_REAP_AGAIN	0x01	/* - Need another cycle */
#define KEY_GC_REAPING_LINKS	0x02	/* - We need to reap links */

	struct rb_node *cursor;
	struct key *key;
	time64_t new_timer, limit, expiry;

	kenter("[%lx]", key_gc_flags);

	limit = ktime_get_real_seconds();

	if (test_and_clear_bit(KEY_GC_KEY_EXPIRED, &key_gc_flags))
		gc_state |= KEY_GC_REAPING_LINKS;
	kdebug("new pass %x", gc_state);

	new_timer = TIME64_MAX;

	/* As only this function is permitted to remove things from the key
	 * serial tree, if cursor is non-NULL then it will always point to a
	 * valid node in the tree - even if lock got dropped.
	 */
	spin_lock(&key_serial_lock);
	cursor = rb_first(&key_serial_tree);

continue_scanning:
	while (cursor) {
		key = rb_entry(cursor, struct key, serial_node);
		cursor = rb_next(cursor);

		if (!test_bit_acquire(KEY_FLAG_USER_ALIVE, &key->flags)) {
			/* Clobber key->user after final put seen. */
			goto found_unreferenced_key;
		}

		expiry = key->expiry;
		if (expiry != TIME64_MAX) {
			if (!(key->type->flags & KEY_TYPE_INSTANT_REAP))
				expiry += key_gc_delay;
			if (expiry > limit && expiry < new_timer) {
				kdebug("will expire %x in %lld",
				       key_serial(key), key->expiry - limit);
				new_timer = key->expiry;
			}
		}

		if ((gc_state & KEY_GC_REAPING_LINKS) &&
		    key->type == &key_type_keyring)
			goto found_keyring;

		if (spin_is_contended(&key_serial_lock) || need_resched())
			goto contended;
	}

contended:
	spin_unlock(&key_serial_lock);

maybe_resched:
	if (cursor) {
		cond_resched();
		spin_lock(&key_serial_lock);
		goto continue_scanning;
	}

	/* We've completed the pass.  Set the timer if we need to and queue a
	 * new cycle if necessary.  We keep executing cycles until we find one
	 * where we didn't reap any keys.
	 */
	kdebug("pass complete");

	if (new_timer != TIME64_MAX) {
		new_timer += key_gc_delay;
		key_schedule_gc(new_timer);
	}

	if (!list_empty(&graveyard)) {
		/* Make sure that all pending keyring payload destructions are
		 * fulfilled and that people aren't now looking at dead or
		 * dying keys that they don't have a reference upon or a link
		 * to.
		 */
		kdebug("gc sync");
		synchronize_rcu();
		kdebug("gc keys");
		key_gc_unused_keys(&graveyard);
	}

	if (gc_state & KEY_GC_REAP_AGAIN)
		schedule_work(&key_gc_work);
	kleave(" [end %x]", gc_state);
	return;

	/* We found an unreferenced key - once we've removed it from the tree,
	 * we can safely drop the lock.
	 */
found_unreferenced_key:
	kdebug("unrefd key %d", key->serial);
	rb_erase(&key->serial_node, &key_serial_tree);
	spin_unlock(&key_serial_lock);

	list_add_tail(&key->graveyard_link, &graveyard);
	gc_state |= KEY_GC_REAP_AGAIN;
	goto maybe_resched;

	/* We found a keyring and we need to check the payload for links to
	 * dead or expired keys.  We don't flag another reap immediately as we
	 * have to wait for the old payload to be destroyed by RCU before we
	 * can reap the keys to which it refers.
	 */
found_keyring:
	spin_unlock(&key_serial_lock);
	keyring_gc(key, limit);
	goto maybe_resched;
}
