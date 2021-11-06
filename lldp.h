// SPDX-License-Identifier: GPL-2.0-only
#define __STDC_FORMAT_MACROS
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/sockios.h>
#include <linux/if_packet.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <netinet/ether.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <libubox/uloop.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <alloca.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <libubox/blobmsg_json.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubox/ulog.h>
#include <libubox/avl.h>
#include <libubus.h>
#include <uci.h>
#include <uci_blob.h>

#define ETHER_TYPE_LLDP		0x88cc
#define LLDP_BU_SZ		8192
#define TLV_MAX			64

enum {
	TLV_END = 0,
	TLV_CHASSIS_ID,
	TLV_PORT_ID,
	TLV_TTL,
	TLV_PORT_DESC,
	TLV_SYS_NAME,
	TLV_SYS_DESC,
	TLV_CAPABILITIES,
	TLV_MGMT_ADDR,
};

enum {
	CAP_OTHER = 0,
	CAP_REPEATER,
	CAP_BRIDGE,
	CAP_AP,
	CAP_ROUTER,
	CAP_TELEPHONE,
	CAP_DOCSIS,
	CAP_STATION,
	__CAP_MAX
};

struct lldp_global {
	struct avl_tree devices;
	__u8 addr[ETH_ALEN];
	int mgmt_ipv4_available;
	int mgmt_ipv6_available;
	__u8 mgmt_ipv4[4];
	__u8 mgmt_ipv6[16];
	char *mgmt_iface;
	char *chassis_id;
	char *name;
	char *description;
	int ttl;
	int refresh;
	int max_peers;
	int count_peers;

	int capabilities[__CAP_MAX];
};

struct lldp_msg {
	struct ethhdr eth;
	__u8 data[];
} __attribute__((packed));

struct lldp {
	struct avl_node avl;
	char ifname[IFNAMSIZ];
	__u8 addr[ETH_ALEN];
	int ifidx;
	struct uloop_fd fd;
	struct uloop_timeout timer;
	struct uloop_timeout restart;
	struct lldp_msg *tlv_data;
	int tlv_size;
	struct blob_attr *tlv_attr;
	struct avl_tree peers;

};

struct lldp_tlv {
	__u8 id;
	__u16 len;
	__u8 *data;
};

struct peer {
	struct lldp *lldp;
	__u8 addr[ETH_ALEN];
	struct avl_node avl;
	struct blob_attr *attr;
	int ttl;
	int rx_count;
	struct timespec seen;
	struct uloop_timeout timer;
};

extern struct blob_buf b;

extern struct lldp_global lldp_global;

extern struct lldp* lldp_start(char *ifname, int restart);
extern void lldp_setup_chassis(void);
extern int lldp_close(char *ifname);
extern void lldp_shutdown(void);

extern int tlv_parse(struct lldp *lldp, struct blob_buf *b, __u8 *data, int len, int *ttl);
extern int tlv_build(struct lldp *lldp, struct lldp_msg* msg);

extern void blobmsg_add_ipv4(struct blob_buf *bbuf, const char *name, const uint8_t* addr);
extern void blobmsg_add_ipv6(struct blob_buf *bbuf, const char *name, const uint16_t* addr);
extern void blobmsg_add_mac(struct blob_buf *bbuf, const char *name, const uint8_t* addr);

extern int avl_mac_cmp(const void *k1, const void *k2, void *ptr);

extern void peer_upsert(struct lldp *lldp, __u8 *addr, int ttl, struct blob_attr *attr);
extern void peer_delete(struct peer *peer);

extern int interface_add(struct ubus_context *ctx, char *name);

extern void *memdup(const void* mem, size_t size);

extern void ubus_init(void);
extern void ubus_done(void);

extern void config_load(void);
