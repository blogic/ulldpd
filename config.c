// SPDX-License-Identifier: GPL-2.0-only
#include "lldp.h"
static struct blob_buf c;
void
config_load(void)
{
	enum {
		LLDP_ATTR_MGMT_IFACE,
		LLDP_ATTR_CHASSIS_ID,
		LLDP_ATTR_NAME,
		LLDP_ATTR_DESCRIPTION,
		LLDP_ATTR_TTL,
		LLDP_ATTR_REFRESH,
		LLDP_ATTR_REPEATER,
		LLDP_ATTR_BRIDGE,
		LLDP_ATTR_AP,
		LLDP_ATTR_ROUTER,
		LLDP_ATTR_STATION,
		LLDP_ATTR_DEVICES,
		LLDP_ATTR_MAX_PEERS,
		__LLDP_ATTR_MAX,
	};

	static const struct blobmsg_policy lldp_attrs[__LLDP_ATTR_MAX] = {
		[LLDP_ATTR_MGMT_IFACE] = { .name = "mgmt_iface", .type = BLOBMSG_TYPE_STRING },
		[LLDP_ATTR_CHASSIS_ID] = { .name = "chassis_id", .type = BLOBMSG_TYPE_STRING },
		[LLDP_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
		[LLDP_ATTR_DESCRIPTION] = { .name = "description", .type = BLOBMSG_TYPE_STRING },
		[LLDP_ATTR_TTL] = { .name = "ttl", .type = BLOBMSG_TYPE_INT32 },
		[LLDP_ATTR_REFRESH] = { .name = "refresh", .type = BLOBMSG_TYPE_INT32 },
		[LLDP_ATTR_REPEATER] = { .name = "repeater", .type = BLOBMSG_TYPE_BOOL },
		[LLDP_ATTR_BRIDGE] = { .name = "bridge", .type = BLOBMSG_TYPE_BOOL },
		[LLDP_ATTR_AP] = { .name = "ap", .type = BLOBMSG_TYPE_BOOL },
		[LLDP_ATTR_ROUTER] = { .name = "router", .type = BLOBMSG_TYPE_BOOL },
		[LLDP_ATTR_STATION] = { .name = "station", .type = BLOBMSG_TYPE_BOOL },
		[LLDP_ATTR_DEVICES] = { .name = "device", .type = BLOBMSG_TYPE_ARRAY },
		[LLDP_ATTR_MAX_PEERS] = { .name = "max_peers", .type = BLOBMSG_TYPE_INT32 },
	};

	const struct uci_blob_param_list lldp_attr_list = {
		.n_params = __LLDP_ATTR_MAX,
		.params = lldp_attrs,
	};

	struct blob_attr *tb[__LLDP_ATTR_MAX] = { 0 };
	struct uci_context *uci = uci_alloc_context();
	struct uci_package *package = NULL;

	if (!uci_load(uci, "lldp", &package)) {
		struct uci_element *e;

		uci_foreach_element(&package->sections, e) {
			struct uci_section *s = uci_to_section(e);

			if (strcmp(s->type, "global"))
				continue;

			blob_buf_init(&c, 0);
			uci_to_blob(&c, s, &lldp_attr_list);
			blobmsg_parse(lldp_attrs, __LLDP_ATTR_MAX, tb, blob_data(c.head), blob_len(c.head));

			if (!tb[LLDP_ATTR_MGMT_IFACE] || !tb[LLDP_ATTR_CHASSIS_ID]) {
				ULOG_ERR("management interface and chassis id are missing\n");
				exit(-1);
			}

			lldp_global.mgmt_iface = strdup(blobmsg_get_string(tb[LLDP_ATTR_MGMT_IFACE]));
			lldp_global.chassis_id = strdup(blobmsg_get_string(tb[LLDP_ATTR_CHASSIS_ID]));
			lldp_setup_chassis();

			if (tb[LLDP_ATTR_NAME])
				lldp_global.name = strdup(blobmsg_get_string(tb[LLDP_ATTR_NAME]));
			if (tb[LLDP_ATTR_DESCRIPTION])
				lldp_global.description = strdup(blobmsg_get_string(tb[LLDP_ATTR_DESCRIPTION]));
			if (tb[LLDP_ATTR_REFRESH])
				lldp_global.ttl = blobmsg_get_u32(tb[LLDP_ATTR_REFRESH]);
			if (tb[LLDP_ATTR_TTL])
				lldp_global.ttl = blobmsg_get_u32(tb[LLDP_ATTR_TTL]);
			if (tb[LLDP_ATTR_MAX_PEERS])
				lldp_global.max_peers = blobmsg_get_u32(tb[LLDP_ATTR_MAX_PEERS]);
			if (tb[LLDP_ATTR_REPEATER])
				lldp_global.capabilities[CAP_REPEATER] = 1;
			if (tb[LLDP_ATTR_BRIDGE])
				lldp_global.capabilities[CAP_BRIDGE] = 1;
			if (tb[LLDP_ATTR_AP])
				lldp_global.capabilities[CAP_AP] = 1;
			if (tb[LLDP_ATTR_ROUTER])
				lldp_global.capabilities[CAP_ROUTER] = 1;
			if (tb[LLDP_ATTR_STATION])
				lldp_global.capabilities[CAP_STATION] = 1;
			if (tb[LLDP_ATTR_DEVICES]) {
				struct blob_attr *a;
				int rem;

				blobmsg_for_each_attr(a, tb[LLDP_ATTR_DEVICES], rem)
					if (blobmsg_type(a) == BLOBMSG_TYPE_STRING)
						lldp_start(blobmsg_get_string(a), 0);
			}
		}
	}

	blob_buf_free(&c);

	uci_unload(uci, package);
	uci_free_context(uci);
}
