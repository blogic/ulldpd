// SPDX-License-Identifier: GPL-2.0-only
#include "lldp.h"

/* tcpdump -dd "ether proto 0x88cc and (ether dst 01:80:c2:00:00:0e or ether dst 01:80:c2:00:00:03 or ether dst 01:80:c2:00:00:00)" */
static struct sock_filter lldp_sock_filter_insns[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 7, 0x000088cc },
	{ 0x20, 0, 0, 0x00000002 },
	{ 0x15, 2, 0, 0xc200000e },
	{ 0x15, 1, 0, 0xc2000003 },
	{ 0x15, 0, 3, 0xc2000000 },
	{ 0x28, 0, 0, 0x00000000 },
	{ 0x15, 0, 1, 0x00000180 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

static const struct sock_fprog sock_filter = {
	.len = ARRAY_SIZE(lldp_sock_filter_insns),
	.filter = lldp_sock_filter_insns,
};

static __u8 lldp_buffer[LLDP_BU_SZ];

static void
lldp_flush(struct lldp *lldp)
{
	struct peer *peer, *tmp;

        avl_for_each_element_safe(&lldp->peers, peer, avl, tmp)
		peer_delete(peer);

	uloop_timeout_cancel(&lldp->timer);
	uloop_timeout_cancel(&lldp->restart);
}

static void
lldp_cleanup(struct lldp *lldp)
{
	uloop_fd_delete(&lldp->fd);
	if (lldp->fd.fd > 0) {
		close(lldp->fd.fd);
		lldp->fd.fd = 0;
	}

	if (lldp->tlv_data) {
		free(lldp->tlv_data);
		lldp->tlv_data = NULL;
	}

	if (lldp->tlv_attr) {
		free(lldp->tlv_attr);
		lldp->tlv_attr = NULL;
	}
}


static void
lldp_delete(struct lldp *lldp)
{
	lldp_flush(lldp);
	lldp_cleanup(lldp);
	free(lldp);
}

int
lldp_close(char *ifname)
{
	struct lldp *lldp;

	lldp = avl_find_element(&lldp_global.devices, ifname, lldp, avl);
	if (!lldp)
		return 1;

	ULOG_INFO("removing device %s\n", ifname);

	avl_delete(&lldp_global.devices, &lldp->avl);
	lldp_delete(lldp);

	return 0;
}

void
lldp_shutdown(void)
{
	struct lldp *lldp, *tmp;

        avl_for_each_element_safe(&lldp_global.devices, lldp, avl, tmp)
		lldp_delete(lldp);
}

static void
lldp_cb(struct uloop_fd *fd, unsigned int events)
{
	struct lldp_msg *msg = (struct lldp_msg *)lldp_buffer;
	struct lldp *lldp = container_of(fd, struct lldp, fd);
	__u8 *data = msg->data;
	int ttl;

	do {
		int len = read(fd->fd, lldp_buffer, LLDP_BU_SZ);

		if (len <= 0) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				return;
			default:
				ULOG_ERR("lost %s\n", lldp->ifname);
				lldp_flush(lldp);
				uloop_timeout_set(&lldp->restart, 10 * 1000);
				return;
			}
			break;
		}
		blob_buf_init(&b, 0);

		if (!tlv_parse(lldp, &b, data, len, &ttl))
			peer_upsert(lldp, msg->eth.h_source, ttl, b.head);

	} while (true);
}

static int
lldp_send(struct lldp *lldp)
{
	static __u8 dest[] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e };
	struct lldp_msg *msg = (struct lldp_msg *) lldp->tlv_data;
	struct sockaddr_ll sock_addr;

	memset(&sock_addr, 0, sizeof(sock_addr));
	memcpy(msg->eth.h_dest, dest, ETH_ALEN);
	memcpy(msg->eth.h_source, lldp->addr, ETH_ALEN);
	msg->eth.h_proto = htons(ETHER_TYPE_LLDP);

	sock_addr.sll_ifindex = lldp->ifidx;
	sock_addr.sll_halen = ETH_ALEN;
	memcpy(sock_addr.sll_addr, dest, ETH_ALEN);

	if (sendto(lldp->fd.fd, msg, lldp->tlv_size, 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
		ULOG_ERR("failed to send on %s\n", lldp->ifname);
		return -1;
	}

	return 0;
}

static void
lldp_timer_cb(struct uloop_timeout *timer)
{
	struct lldp *lldp = container_of(timer, struct lldp, timer);

	lldp_send(lldp);
	uloop_timeout_set(timer, lldp_global.refresh * 1000);
}

static void
lldp_restart_cb(struct uloop_timeout *timer)
{
	struct lldp *lldp = container_of(timer, struct lldp, restart);

	ULOG_INFO("trying to restart %s\n", lldp->ifname);
	lldp_cleanup(lldp);
	if (!lldp_start(lldp->ifname, 1))
		uloop_timeout_set(timer, 10 * 1000);
}

static int
lldp_open(struct lldp *lldp, char *ifname)
{
	struct sockaddr_ll sa = {
                .sll_family = AF_PACKET,
        };
	struct packet_mreq mreq;
	struct ifreq ifr;

	memset(&mreq, 0, sizeof(mreq));

	lldp->fd.fd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_LLDP));
	if (lldp->fd.fd == -1) {
		ULOG_ERR("failed to open socket\n");
		return 1;
	}

	memset(&ifr, 0, sizeof (ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(lldp->fd.fd, SIOCGIFFLAGS, &ifr) < 0) {
                ULOG_ERR("failed to get ifflags for: %s\n", ifname);
                return 1;
        }

	if (!(ifr.ifr_flags & ( IFF_UP | IFF_RUNNING ))) {
		ULOG_ERR("device is not up: %s\n", ifname);
		return 1;
	}

	memset(&ifr, 0, sizeof (ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(lldp->fd.fd, SIOCGIFINDEX, &ifr) < 0) {
		ULOG_ERR("failed to get ifindex for: %s\n", ifname);
		return 1;
	}
	lldp->ifidx = ifr.ifr_ifindex;

	if (ioctl(lldp->fd.fd, SIOCGIFHWADDR, &ifr) < 0) {
		ULOG_ERR("failed to get mac for %s\n", ifname);
		return 1;
	}
	memcpy(lldp->addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

        sa.sll_ifindex = lldp->ifidx;
	if (bind(lldp->fd.fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		ULOG_ERR("failed to bind sock to %s\n", ifname);
		return 1;
	}

	mreq.mr_ifindex = lldp->ifidx;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 6;
	if (setsockopt(lldp->fd.fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       (void *)&mreq, (socklen_t) sizeof(mreq)) < 0) {
		ULOG_ERR("failed to  set PACKET_MR_PROMISC on %s\n", ifname);
		return 1;
	}

	if (setsockopt(lldp->fd.fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &sock_filter, sizeof(struct sock_fprog))) {
		ULOG_ERR("failed to attach filter to %s\n", ifname);
		return 1;
	}

	return 0;
}

struct lldp *
lldp_start(char *ifname, int restart)
{
	struct lldp_msg *msg = (struct lldp_msg *)lldp_buffer;
	struct lldp *lldp;

	memset(&lldp_buffer, 0, sizeof(lldp_buffer));
	lldp = avl_find_element(&lldp_global.devices, ifname, lldp, avl);
	if (!restart) {
		if (lldp) {
			ULOG_ERR("%s is already added\n", ifname);
			return NULL;
		}

		lldp = malloc(sizeof(*lldp));
		if (!lldp) {
			ULOG_ERR("failed to alloc socket memory\n");
			return NULL;
		}

		memset(lldp, 0, sizeof(*lldp));
		strncpy(lldp->ifname, ifname, sizeof(lldp->ifname));
		lldp->avl.key = lldp->ifname;
		lldp->timer.cb = lldp_timer_cb;
		lldp->restart.cb = lldp_restart_cb;
		lldp->fd.cb = lldp_cb;
		avl_init(&lldp->peers, avl_mac_cmp, false, NULL);
	}

	if ((!lldp_global.mgmt_ipv4_available && !lldp_global.mgmt_ipv6_available) ||
	    lldp_open(lldp, ifname)) {
		lldp_cleanup(lldp);
		uloop_timeout_set(&lldp->restart, 10 * 1000);
		return 0;
	}

	lldp->tlv_size = tlv_build(lldp, msg);
	lldp->tlv_data = memdup(msg, lldp->tlv_size);
	blob_buf_init(&b, 0);
	if (tlv_parse(lldp, &b, lldp->tlv_data->data, lldp->tlv_size, NULL)) {
		ULOG_ERR("failed to parse own TLV on %s\n", ifname);
		lldp_delete(lldp);
		return NULL;
	}
	lldp->tlv_attr = blob_memdup(b.head);

	uloop_fd_add(&lldp->fd, ULOOP_READ);
	uloop_timeout_set(&lldp->timer, 1000);

	if (restart) {
		ULOG_INFO("restarted device %s\n", ifname);
	} else {
		ULOG_INFO("added device %s\n", ifname);
		avl_insert(&lldp_global.devices, &lldp->avl);
	}

	return lldp;
}

static int
lldp_all_zero(__u8 *ptr, int sz)
{
	int i;

	for (i = 0; i < sz; i++)
		if (ptr[i] != 0x00)
			return 1;

	return 0;
}

void
lldp_setup_chassis(void)
{
	struct ether_addr *addr;
	struct ifaddrs *ifa;;

	if (getifaddrs(&ifa)) {
		ULOG_ERR("failed to get mgmt ips\n");
		exit(-1);
	}

	while (ifa) {
		__u8 fe80[] = { 0xfe, 0x80 };
		struct in6_addr *ipv6;

		if (!strcmp(ifa->ifa_name, lldp_global.mgmt_iface))
			switch(ifa->ifa_addr->sa_family) {
			case AF_INET:
				memcpy(lldp_global.mgmt_ipv4, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, 4);
				break;
			case AF_INET6:
				ipv6 = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
				if (!memcmp(ipv6, fe80, 2))
					memcpy(lldp_global.mgmt_ipv6, ipv6, 16);
			default:
				break;
			}

		ifa = ifa->ifa_next;
	}
	freeifaddrs(ifa);

	lldp_global.mgmt_ipv4_available = lldp_all_zero(lldp_global.mgmt_ipv4, 4);
	lldp_global.mgmt_ipv6_available = lldp_all_zero(lldp_global.mgmt_ipv6, 16);

	addr = ether_aton(lldp_global.chassis_id);
	memcpy(lldp_global.addr, addr->ether_addr_octet, ETH_ALEN);
}
