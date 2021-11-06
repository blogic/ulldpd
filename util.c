// SPDX-License-Identifier: GPL-2.0-only
#include "lldp.h"

void *
memdup(const void* mem, size_t size)
{
	void *out = malloc(size);

	if (out != NULL)
		memcpy(out, mem, size);

	return out;
}

int
avl_mac_cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, ETH_ALEN);
}

void
blobmsg_add_ipv4(struct blob_buf *b, const char *name, const __u8 *addr)
{
	char ip[16];

	snprintf(ip, sizeof(ip), "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	blobmsg_add_string(b, name, ip);
}

void
blobmsg_add_ipv6(struct blob_buf *b, const char *name, const __u16 *addr)
{
	char ip[40];

	snprintf(ip, sizeof(ip), "%x:%x:%x:%x:%x:%x:%x:%x",
		 ntohs(addr[0]), ntohs(addr[1]), ntohs(addr[2]), ntohs(addr[3]),
		 ntohs(addr[4]), ntohs(addr[5]), ntohs(addr[6]), ntohs(addr[7]));
	blobmsg_add_string(b, name, ip);
}

void
blobmsg_add_mac(struct blob_buf *b, const char *name, const __u8 *addr)
{
	char mac[18];

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
	        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	blobmsg_add_string(b, name, mac);
}
