// SPDX-License-Identifier: GPL-2.0-only
#include "lldp.h"

static struct lldp_tlv lldp_tlvs[TLV_MAX];
static int lldp_count;
static int ttl;

typedef int (*tlv_verify_t)(struct blob_buf *b, struct lldp_tlv *tlv);

static int
tlv_add_network_address(struct blob_buf *b, char *name, __u8 type, __u8 *data, int len)
{
	switch (type) {
	case 1:
		if (len != 4)
			return 0;
		blobmsg_add_ipv4(b, name, data);
		break;
	case 2:
		if (len != 16)
			return 0;
		blobmsg_add_ipv6(b, name, (__u16 *)data);
		break;
	default:
		return -1;
	}

	return 0;
}

static int
tlv_verify_chassis_id(struct blob_buf *b, struct lldp_tlv *tlv)
{
	switch (tlv->data[0]) {
	case 4:
		if (tlv->len != 7)
			return 1;

		blobmsg_add_mac(b, "chassis-id", &tlv->data[1]);
		break;
	case 5:
		return tlv_add_network_address(b, "chassis-id", tlv->data[1], &tlv->data[2], tlv->len - 2);
	default:
		return 1;
	}

	return 0;
}

static int
tlv_verify_port_id(struct blob_buf *b, struct lldp_tlv *tlv)
{
	switch (tlv->data[0]) {
	case 3:
		if (tlv->len != 7)
			return 1;

		blobmsg_add_mac(b, "port-id", &tlv->data[1]);
		break;
	case 5:
		return tlv_add_network_address(b, "port-id", tlv->data[1], &tlv->data[2], tlv->len - 2);
	default:
		return 1;
	}

	return 0;
}

static int
tlv_verify_ttl(struct blob_buf *b, struct lldp_tlv *tlv)
{
	if (tlv->len != 2)
		return 1;

	ttl = ntohs(*((__u16 *)tlv->data));
	blobmsg_add_u16(b, "ttl", ttl);

	return 0;
}

static int
tlv_verify_string(struct blob_buf *b, struct lldp_tlv *tlv, char *description)
{
	char name[256];

	if (!tlv->len || tlv->len > 255)
		return 1;

	memcpy(name, tlv->data, tlv->len);
	name[tlv->len] = '\0';

	blobmsg_add_string(b, description, name);

	return 0;
}

static int
tlv_verify_port_description(struct blob_buf *b, struct lldp_tlv *tlv)
{
	return tlv_verify_string(b, tlv, "port-description");
}

static int
tlv_verify_system_name(struct blob_buf *b, struct lldp_tlv *tlv)
{
	return tlv_verify_string(b, tlv, "system-name");
}

static int
tlv_verify_system_description(struct blob_buf *b, struct lldp_tlv *tlv)
{
	return tlv_verify_string(b, tlv, "system-description");
}

static int
tlv_verify_capabilities(struct blob_buf *b, struct lldp_tlv *tlv)
{
	const char *names[8] = {
		[1] = "repeater",
		[2] = "bridge",
		[3] = "access-point",
		[4] = "router",
		[5] = "telephone",
		[6] = "docsis",
		[7] = "station",
	};
	void *c;
	int i;

	if (tlv->len != 4)
		return 1;

	c = blobmsg_open_table(b, "capabilities");

	for (i = 1; i < 8; i++)
		if (tlv->data[1] & (1 << i) && names[i])
			blobmsg_add_u8(b, names[i], !!(tlv->data[3] & (1 << i)));

	blobmsg_close_array(b, c);

	return 0;
}

static int
tlv_verify_management_port(struct blob_buf *b, struct lldp_tlv *tlv)
{
	int oid_offset;

	if (tlv->len < 8)
		return 0;

	/* verify oid offset */
	oid_offset = tlv->data[0] + 1 + 1 + 4;
	if (tlv->len < oid_offset)
		return 0;

	/* verify full length */
	if (tlv->len < oid_offset + tlv->data[oid_offset])
		return 0;

	return tlv_add_network_address(b, "value", tlv->data[1], &tlv->data[2], tlv->data[0] - 1);
}

static tlv_verify_t tlv_verify_proto[] = {
	[TLV_CHASSIS_ID] = tlv_verify_chassis_id,
	[TLV_PORT_ID] = tlv_verify_port_id,
	[TLV_TTL] = tlv_verify_ttl,
	[TLV_PORT_DESC] = tlv_verify_port_description,
	[TLV_SYS_NAME] = tlv_verify_system_name,
	[TLV_SYS_DESC] = tlv_verify_system_description,
	[TLV_CAPABILITIES] = tlv_verify_capabilities,
};
static int tlv_verify_count = ARRAY_SIZE(tlv_verify_proto) - 1;

static int
tlv_consume(__u8 **data, int *len, int sz)
{
	if (*len < sz)
		return 1;

	*data += sz;
	*len -= sz;

	return 0;
}

static int
tlv_next(struct lldp_tlv *tlv, __u8 **data, int *len)
{
	__u16 hdr = **((__u16 **) data);

	if (tlv_consume(data, len, sizeof(__u16)))
		return 1;

	hdr = ntohs(hdr);

	tlv->id = hdr >> 9;
	tlv->len = hdr & 0x1ff;
	tlv->data = *data;

	return tlv_consume(data, len, tlv->len);
}

int
tlv_parse(struct lldp *lldp, struct blob_buf *b, __u8 *data, int len, int *_ttl)
{
	int has_vendor_tlv = 0;
	int has_mgmt_tlv = 0;
	int found[8];
	int i;

	len -= sizeof(struct lldp_msg);
	if (len <= 0)
		return 1;

	lldp_count = 0;
	memset(found, 0, sizeof(found));
	memset(lldp_tlvs, 0, sizeof(lldp_tlvs));

	/* scan the tlv and verify that the lengths are all valid */
	while (lldp_count < TLV_MAX && !tlv_next(&lldp_tlvs[lldp_count], &data, &len)) {
		if (!lldp_tlvs[lldp_count].id)
			break;
		switch (lldp_tlvs[lldp_count].id) {
		case TLV_MGMT_ADDR:
			has_mgmt_tlv = 1;
			break;
		case 127:
			has_vendor_tlv = 1;
			break;
		};
		lldp_count++;
	}

	/* verify that (4 <= lldp_count < TLV_MAX) and that the last tlv has an id of 0 */
	if (lldp_count < 4 || lldp_count >= TLV_MAX || lldp_tlvs[lldp_count].id)
		return 1;

	/* the first 3 tlvs have fixed ids */
	for (i = 0; i < 3; i++)
		if (lldp_tlvs[i].id != i + 1)
			return 1;

	blob_buf_init(b, 0);

	/* iterate over all tlvs that can only exist once */
	for (i = 0; i < lldp_count; i++) {
		struct lldp_tlv *tlv = &lldp_tlvs[i];

		/* tlv ids 1-7 can only be defined once */
		if (tlv->id >= TLV_MGMT_ADDR)
			continue;

		if (found[tlv->id])
			continue;
		found[tlv->id] = 1;

		/* check if we have a verifier for the tlv */
		if (tlv->id > tlv_verify_count || !tlv_verify_proto[tlv->id])
			continue;

		if (tlv_verify_proto[tlv->id](b, tlv))
			return 1;
	}

	/* iterate over all management address tlvs */
	if (has_mgmt_tlv) {
		void *c = blobmsg_open_array(b, "management-address");

		for (i = 0; i < lldp_count; i++) {
			struct lldp_tlv *tlv = &lldp_tlvs[i];

			/* we only want id 8 */
			if (tlv->id != TLV_MGMT_ADDR)
				continue;
			tlv_verify_management_port(b, tlv);
		}

		blobmsg_close_table(b, c);
	}

	/* iterate over all vendor tlvs */
	if (has_vendor_tlv) {
		/* ... */
	}

	if (_ttl)
		*_ttl = ttl;

//	fprintf(stderr, "RX (%s) -> %s\n", lldp->ifname, blobmsg_format_json(b->head, true));
	return 0;
}
