/*
 * Copyright (c) 2011 Mellanox Technologies. All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "eth_ipoib.h"
#include <linux/igmp.h>

/* according to the RFC in igmpv1/2/3, fixed daddr and options */
u8 daddr_ip[4] = {224, 0, 0, 1};
u8 options[4] = {0x94, 0x04, 0x00, 0x00};
u8 src_mc_eth_mac_addr[ETH_ALEN] = {0};

static inline char *__trans_mc_proto(unsigned short p)
{
	switch (p) {
	case IGMP_HOST_MEMBERSHIP_REPORT:
		return "IGMP_HOST_MEMBERSHIP_REPORT";
	case IGMPV2_HOST_MEMBERSHIP_REPORT:
		return "IGMPV2_HOST_MEMBERSHIP_REPORT";
	case IGMPV3_HOST_MEMBERSHIP_REPORT:
		return "IGMPV3_HOST_MEMBERSHIP_REPORT";
	default:
		pr_err("%s: not find 0x%x ", __func__, p);
	}
	return "UNKNOWN";
}

struct igmphdr *get_igmp_header(struct iphdr  *iph)
{
	return (struct igmphdr *)((u8 *)(iph) + (iph->ihl * 4));
}

static int get_igmp_type(struct iphdr  *iph)
{
	struct igmphdr  *igmph;
	igmph = get_igmp_header(iph);
	return igmph->type;
}

static inline int is_igmp_membership_report_packet(int igmp_type)
{
	if (igmp_type == IGMP_HOST_MEMBERSHIP_REPORT ||
	    igmp_type == IGMPV2_HOST_MEMBERSHIP_REPORT ||
	    igmp_type == IGMPV3_HOST_MEMBERSHIP_REPORT) {
		return 1;
	}
	return 0;
}

static __be32 *get_igmp_dst_address(struct igmphdr *igmph,
				    int igmp_type,
				    int index)
{
	pr_debug("%s: igmp_type = %s\n",
		 __func__,  __trans_mc_proto(igmp_type));
	switch (igmp_type) {
	case IGMP_HOST_MEMBERSHIP_REPORT:
	/*no break here.*/
	case IGMPV2_HOST_MEMBERSHIP_REPORT:
		return (__be32 *)(&(igmph->group));
	case IGMPV3_HOST_MEMBERSHIP_REPORT:
		return (__be32 *)(&(((struct igmpv3_report *)
				  (igmph))->grec[index].grec_mca));
	default:
		pr_debug("%s error igmp_type : 0x%x", __func__, igmp_type);
		break;
	}
	return 0;
}

void handle_igmp_join_req(struct slave *slave, struct iphdr  *iph)
{
	int igmp_type;
	struct igmphdr *igmph;
	u16 num_of_records;
	int i;
	__be32 *mc_ip_address;
	int ret;

	igmp_type = get_igmp_type(iph);
	if (!is_igmp_membership_report_packet(igmp_type)) {
		pr_debug("type:0x%x not handled\n", igmp_type);
		return;
	}

	igmph = get_igmp_header(iph);

	num_of_records = (igmp_type ==
			  IGMP_HOST_MEMBERSHIP_REPORT ||
			  igmp_type ==
			  IGMPV2_HOST_MEMBERSHIP_REPORT) ? 1 :
			  ntohs(((struct igmpv3_report *)(igmph))->ngrec);

	/* go over all the ip address */
	for (i = 0; i < num_of_records; i++) {
		mc_ip_address = get_igmp_dst_address(igmph, igmp_type, i);
		pr_debug("mc src ip(%d): %pI4\n",
			 *mc_ip_address, ((u8 *)mc_ip_address));
		ret = add_mc_neigh(slave, *mc_ip_address);
		if (ret)
			pr_err("%s: Failed to add mc (dev:%s). ret:%d\n",
			       __func__, slave->dev->name, ret);
	}
}

/*
 * The function creates igmp v2 packet, according to the next structure:
 *
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |      Type     | Max Resp Time |           Checksum            |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Group Address                         |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct sk_buff *gen_igmp_v2_query(struct slave *slave)
{
	struct sk_buff *skb;
	struct ethhdr  *ethhdr;
	struct iphdr   *iph;
	struct igmphdr *igmph;
	struct net_device *dev = master_upper_dev_get(slave->dev);
	u8 *p_options;
	int size;

	size = sizeof(struct igmphdr)
	+ sizeof(struct iphdr)
	+ sizeof(struct ethhdr)
	+ LL_RESERVED_SPACE(dev);

	skb = dev_alloc_skb(size);
	if (!skb) {
		pr_err("%s: %s no mem for igmp query skb\n",
		       __func__, slave->dev->name);
		return NULL;
	}

	skb_reserve(skb, LL_RESERVED_SPACE(dev));
	skb_reset_network_header(skb);
	skb->dev = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* eth headers */
	ip_eth_mc_map(*daddr_ip, src_mc_eth_mac_addr);
	ethhdr = (struct ethhdr *)skb_put(skb, sizeof(*ethhdr));
	memcpy(ethhdr->h_dest, src_mc_eth_mac_addr, ETH_ALEN);
	memcpy(ethhdr->h_source, dev->dev_addr, ETH_ALEN);
	/* set the admin-bit, the packet remains in the device */
	ethhdr->h_source[0] = ethhdr->h_source[0] | 0x2;

	ethhdr->h_proto = htons(ETH_P_IP);

	/* ip header */
	iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
	memset(iph, 0, sizeof(*iph));
	iph->ihl        = 6; /* includes options */
	iph->version    = IPVERSION;
	iph->tos        = 0;
	iph->tot_len    = htons((iph->ihl * 4) + sizeof(*igmph));
	iph->id         = htons(1);
	iph->frag_off   = 0;
	iph->ttl        = 1;
	iph->protocol   = IPPROTO_IGMP;
	iph->check      = 0;
	iph->saddr      = 0;
	memcpy((u8 *)(&(iph->daddr)), daddr_ip, 4);
	p_options = (u8 *)skb_put(skb, 4);
	memcpy(p_options, options, 4);
	iph->check = ip_fast_csum(iph, iph->ihl);

	/* igmp header */
	igmph = (struct igmphdr *)skb_put(skb, sizeof(*igmph));
	/* set time_to_response field */
	memset(igmph, 100, sizeof(*igmph));
	igmph->type = IGMP_HOST_MEMBERSHIP_QUERY;
	igmph->group = 0;
	igmph->csum = 0;
	igmph->csum = ip_compute_csum(igmph, sizeof(*igmph));

	skb->protocol = htons(ETH_P_IP);
	eth_type_trans(skb, skb->dev);
	skb->pkt_type = PACKET_MULTICAST;

	return skb;
}

int send_igmp_query(struct parent *parent, struct slave *slave,
		    enum igmp_ver igmp_ver)
{
	struct sk_buff *skb;
	int ret;
	int vlan_tag;

	switch (igmp_ver) {
	case IGMP_V2:
		skb = gen_igmp_v2_query(slave);
		break;
	default:
		pr_err("%s: No such igmp version: %d\n", __func__, igmp_ver);
		return -EINVAL;
	}

	if (!skb) {
		pr_err("%s failed to get skb\n", __func__);
		return -ENOMEM;
	}

	/* send the packet up to the guest via the recieve flow */
	vlan_tag = slave->vlan & 0xfff;

	ret = add_vlan_and_send(parent, vlan_tag, NULL, skb);
	if (ret != NET_XMIT_SUCCESS && ret != NET_XMIT_DROP) {
			pr_err("%s: %s Error RX for igmp packet, (ret = %d)\n",
			       __func__, slave->dev->name, ret);
			return ret;
	}
	return 0;
}

