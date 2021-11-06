// SPDX-License-Identifier: GPL-2.0-only
#include "lldp.h"

struct blob_buf b;

struct lldp_global lldp_global = {
	.name = "OpenWrt",
	.description = "OpenWrt",
	.ttl = 120,
	.refresh = 30,
	.max_peers = 64,
};

int
main(int argc, char **argv)
{
	ulog_open(ULOG_STDIO | ULOG_SYSLOG, LOG_DAEMON, "lldp");

	memset(&b, 0, sizeof(b));

	avl_init(&lldp_global.devices, avl_strcmp, false, NULL);
	uloop_init();
	ubus_init();

	config_load();

	uloop_run();
	uloop_done();

	lldp_shutdown();
	blob_buf_free(&b);
	ubus_done();

	return 0;
}
