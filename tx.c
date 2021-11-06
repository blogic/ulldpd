// SPDX-License-Identifier: GPL-2.0-only
#include "lldp.h"

static int
tlv_add_hdr(struct lldp_msg* msg, int *size, __u8 id, __u16 len)
{
	__u16 hdr = id;

	len &= 0x1ff;
	hdr <<= 9;
	hdr |= len;
	hdr = htons(hdr);

	memcpy(&msg->data[*size], &hdr, sizeof(hdr));
	*size += 2;

	return 0;
}

static int
tlv_add_data(struct lldp_msg* msg, int *size, void *data, int len)
{
	memcpy(&msg->data[*size], data, len);
	*size += len;

	return 0;
}

static void
tlv_add_chassis_id(struct lldp *lldp, struct lldp_msg* msg, int *size)
{
	__u8 subtype = 4;

	tlv_add_hdr(msg, size, TLV_CHASSIS_ID, 7);
	tlv_add_data(msg, size, &subtype, sizeof(subtype));
	tlv_add_data(msg, size, lldp_global.addr, sizeof(lldp_global.addr));
}

static void
tlv_add_port_id(struct lldp *lldp, struct lldp_msg* msg, int *size)
{
	__u8 subtype = 3;

	tlv_add_hdr(msg, size, TLV_PORT_ID, 7);
	tlv_add_data(msg, size, &subtype, sizeof(subtype));
	tlv_add_data(msg, size, lldp->addr, sizeof(lldp->addr));
}

static void
tlv_add_ttl(struct lldp *lldp, struct lldp_msg* msg, int *size)
{
	__u16 ttl = htons(lldp_global.ttl);

	tlv_add_hdr(msg, size, TLV_TTL, 2);
	tlv_add_data(msg, size, &ttl, sizeof(ttl));
}

static void
tlv_add_port_description(struct lldp *lldp, struct lldp_msg* msg, int *size)
{
	int len = strlen(lldp->ifname);

	tlv_add_hdr(msg, size, TLV_PORT_DESC, len);
	tlv_add_data(msg, size, lldp->ifname, len);
}

static void
tlv_add_system_name(struct lldp *lldp, struct lldp_msg* msg, int *size)
{
	int len = strlen(lldp_global.name);

	tlv_add_hdr(msg, size, TLV_SYS_NAME, len);
	tlv_add_data(msg, size, lldp_global.name, len);
}

static void
tlv_add_system_description(struct lldp *lldp, struct lldp_msg* msg, int *size)
{
	int len = strlen(lldp_global.description);

	tlv_add_hdr(msg, size, TLV_SYS_DESC, len);
	tlv_add_data(msg, size, lldp_global.description, len);
}

static void
tlv_add_capabilities(struct lldp *lldp, struct lldp_msg* msg, int *size)
{
	__u8 capabilities[4];
	int i;

	memset(capabilities, 0, sizeof(capabilities));
	for (i = CAP_REPEATER; i < __CAP_MAX; i++)
		if (lldp_global.capabilities[i] >= 0)
			capabilities[1] |= 1 << i;

	for (i = CAP_REPEATER; i < __CAP_MAX; i++)
		if (lldp_global.capabilities[i] > 0)
			capabilities[3] |= 1 << i;

	tlv_add_hdr(msg, size, TLV_CAPABILITIES, 4);
	tlv_add_data(msg, size, &capabilities, sizeof(capabilities));
}

static void
tlv_add_management_addr(struct lldp *lldp, struct lldp_msg* msg, int *size)
{
	__u8 head_v4[] = { 0x5, 0x1 };
	__u8 head_v6[] = { 0x11, 0x2 };
	__u8 tail_v4[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	__u8 tail_v6[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

	if (lldp_global.mgmt_ipv4_available) {
		tlv_add_hdr(msg, size, TLV_MGMT_ADDR, 12);
		tlv_add_data(msg, size, head_v4, sizeof(head_v4));
		tlv_add_data(msg, size, lldp_global.mgmt_ipv4, sizeof(lldp_global.mgmt_ipv4));
		tlv_add_data(msg, size, tail_v4, sizeof(tail_v4));
	}

	if (lldp_global.mgmt_ipv6_available) {
		tlv_add_hdr(msg, size, TLV_MGMT_ADDR, 24);
		tlv_add_data(msg, size, head_v6, sizeof(head_v6));
		tlv_add_data(msg, size, lldp_global.mgmt_ipv6, sizeof(lldp_global.mgmt_ipv6));
		tlv_add_data(msg, size, tail_v6, sizeof(tail_v6));
	}
}

int
tlv_build(struct lldp *lldp, struct lldp_msg* msg)
{
	int size = 0;

	tlv_add_chassis_id(lldp, msg, &size);
	tlv_add_port_id(lldp, msg, &size);
	tlv_add_ttl(lldp, msg, &size);
	tlv_add_port_description(lldp, msg, &size);
	tlv_add_system_name(lldp, msg, &size);
	tlv_add_system_description(lldp, msg, &size);
	tlv_add_capabilities(lldp, msg, &size);
	tlv_add_management_addr(lldp, msg, &size);
	tlv_add_hdr(msg, &size, TLV_END, 0);

	return size + sizeof(struct lldp_msg);
}
