// SPDX-License-Identifier: GPL-2.0-only
#include "lldp.h"

#define MAC_FMT	"%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_VAR(x) x[0], x[1], x[2], x[3], x[4], x[5]

void
peer_delete(struct peer *peer)
{
	avl_delete(&peer->lldp->peers, &peer->avl);
	uloop_timeout_cancel(&peer->timer);
	free(peer->attr);
	free(peer);
	lldp_global.count_peers--;
}

static void
peer_timer_cb(struct uloop_timeout *timer)
{
	struct peer *peer = container_of(timer, struct peer, timer);

	ULOG_INFO("remove peer "MAC_FMT"\n", MAC_VAR(peer->addr));

	peer_delete(peer);
}

void
peer_upsert(struct lldp *lldp, __u8 *addr, int ttl, struct blob_attr *attr)
{
	struct peer *peer;

	peer = avl_find_element(&lldp->peers, addr, peer, avl);

	if (!peer) {
		if (lldp_global.count_peers >= lldp_global.max_peers)
			return;
		peer = malloc(sizeof(struct peer));
		if (!peer)
			return;
		memset(peer, 0, sizeof(*peer));
		memcpy(peer->addr, addr, ETH_ALEN);
		peer->avl.key = peer->addr;
		peer->timer.cb = peer_timer_cb;
		peer->lldp = lldp;
		avl_insert(&lldp->peers, &peer->avl);
		ULOG_INFO("new peer "MAC_FMT"\n", MAC_VAR(peer->addr));
		lldp_global.count_peers++;
	} else {
		free(peer->attr);
	}
	peer->ttl = ttl;
	peer->attr = blob_memdup(attr);
	peer->rx_count++;
	clock_gettime(CLOCK_MONOTONIC, &peer->seen);
	uloop_timeout_set(&peer->timer, peer->ttl * 1000);
}
