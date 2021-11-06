// SPDX-License-Identifier: GPL-2.0-only
#include "lldp.h"

static struct ubus_auto_conn conn;

enum network_attr {
	NETWORK_ADD,
	NETWORK_REMOVE,
	__NETWORK_MAX
};

static const struct blobmsg_policy network_policy[__NETWORK_MAX] = {
	[NETWORK_ADD]= { "add", BLOBMSG_TYPE_STRING },
	[NETWORK_REMOVE]= { "remove", BLOBMSG_TYPE_STRING },
};

static int
ubus_device_cb(struct ubus_context *ctx, struct ubus_object *obj,
	       struct ubus_request_data *req, const char *method,
	       struct blob_attr *msg)
{
	struct blob_attr *tb[__NETWORK_MAX];

	blobmsg_parse(network_policy, __NETWORK_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[NETWORK_ADD] && !tb[NETWORK_REMOVE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[NETWORK_ADD])
		if (!lldp_start(blobmsg_get_string(tb[NETWORK_ADD]), 0))
			return UBUS_STATUS_INVALID_ARGUMENT;

	if (tb[NETWORK_REMOVE])
		if (lldp_close(blobmsg_get_string(tb[NETWORK_REMOVE])))
			return UBUS_STATUS_INVALID_ARGUMENT;

	return UBUS_STATUS_OK;
}

static int
ubus_peers_cb(struct ubus_context *ctx, struct ubus_object *obj,
	      struct ubus_request_data *req, const char *method,
	      struct blob_attr *msg)
{
	struct timespec now;
	struct lldp *lldp;

	clock_gettime(CLOCK_MONOTONIC, &now);

	blob_buf_init(&b, 0);
	avl_for_each_element(&lldp_global.devices, lldp, avl) {
		struct peer *peer;
		void *c;

		if (avl_is_empty(&lldp->peers))
			continue;

		c = blobmsg_open_array(&b, lldp->ifname);
		avl_for_each_element(&lldp->peers, peer, avl) {
			void *c = blobmsg_open_table(&b, NULL);
			struct blob_attr *iter;
			int rem;

			blobmsg_add_u32(&b, "received", peer->rx_count);
			blobmsg_add_u32(&b, "last-seen", now.tv_sec - peer->seen.tv_sec);
			blobmsg_for_each_attr(iter, peer->attr, rem)
				blobmsg_add_blob(&b, iter);
			blobmsg_close_table(&b, c);
		}
		blobmsg_close_array(&b, c);
	}
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;
}

static int
ubus_local_cb(struct ubus_context *ctx, struct ubus_object *obj,
	      struct ubus_request_data *req, const char *method,
	      struct blob_attr *msg)
{
	struct lldp *lldp;

	blob_buf_init(&b, 0);
	avl_for_each_element(&lldp_global.devices, lldp, avl) {
		void *c = blobmsg_open_table(&b, lldp->ifname);
		struct blob_attr *iter;
		int rem;

		blobmsg_for_each_attr(iter, lldp->tlv_attr, rem)
			blobmsg_add_blob(&b, iter);
		blobmsg_close_table(&b, c);
	}
	ubus_send_reply(ctx, req, b.head);
	return UBUS_STATUS_OK;
}

static int
ubus_check_cb(struct ubus_context *ctx, struct ubus_object *obj,
	     struct ubus_request_data *req, const char *method,
	     struct blob_attr *msg)
{
	lldp_setup_chassis();

	return UBUS_STATUS_OK;
}

static const struct ubus_method lldp_methods[] = {
	UBUS_METHOD("device", ubus_device_cb, network_policy),
	UBUS_METHOD_NOARG("peers", ubus_peers_cb),
	UBUS_METHOD_NOARG("local", ubus_local_cb),
	UBUS_METHOD_NOARG("check_devices", ubus_check_cb),
};

static struct ubus_object_type ubus_object_type =
	UBUS_OBJECT_TYPE("lldp", lldp_methods);

static struct ubus_object ubus_object = {
	.name = "lldp",
	.type = &ubus_object_type,
	.methods = lldp_methods,
	.n_methods = ARRAY_SIZE(lldp_methods),
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ULOG_NOTE("connected to ubus\n");
	ubus_add_object(ctx, &ubus_object);
}

void
ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}

void
ubus_done(void)
{
	ubus_auto_shutdown(&conn);
}
