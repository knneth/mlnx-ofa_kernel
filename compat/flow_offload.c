/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/flow_offload.h>
#include <net/pkt_cls.h>

#define FLOW_DISSECTOR_MATCH(__rule, __type, __out)				\
	const struct flow_match *__m = &(__rule)->match;			\
	struct flow_dissector *__d = (__m)->dissector;				\
										\
	(__out)->key = skb_flow_dissector_target(__d, __type, (__m)->key);	\
	(__out)->mask = skb_flow_dissector_target(__d, __type, (__m)->mask);	\

#ifndef HAVE_FLOW_RULE_MATCH_CVLAN
void flow_rule_match_basic(const struct flow_rule *rule,
			   struct flow_match_basic *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_BASIC, out);
}
EXPORT_SYMBOL(flow_rule_match_basic);

void flow_rule_match_control(const struct flow_rule *rule,
			     struct flow_match_control *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CONTROL, out);
}
EXPORT_SYMBOL(flow_rule_match_control);

void flow_rule_match_eth_addrs(const struct flow_rule *rule,
			       struct flow_match_eth_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_eth_addrs);

#ifdef HAVE_FLOW_DISSECTOR_KEY_VLAN
void flow_rule_match_vlan(const struct flow_rule *rule,
			  struct flow_match_vlan *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_VLAN, out);
}
EXPORT_SYMBOL(flow_rule_match_vlan);
#endif

void flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
				struct flow_match_ipv4_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_ipv4_addrs);

void flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
				struct flow_match_ipv6_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_ipv6_addrs);

void flow_rule_match_ip(const struct flow_rule *rule,
			struct flow_match_ip *out)
{
#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IP, out);
#endif
}
EXPORT_SYMBOL(flow_rule_match_ip);

void flow_rule_match_cvlan(const struct flow_rule *rule,
                           struct flow_match_vlan *out)
{
#ifdef HAVE_FLOW_DISSECTOR_KEY_CVLAN
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CVLAN, out);
#endif
}
EXPORT_SYMBOL(flow_rule_match_cvlan);

void flow_rule_match_ports(const struct flow_rule *rule,
			   struct flow_match_ports *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_PORTS, out);
}
EXPORT_SYMBOL(flow_rule_match_ports);

void flow_rule_match_tcp(const struct flow_rule *rule,
			 struct flow_match_tcp *out)
{
#ifdef HAVE_FLOW_DISSECTOR_KEY_TCP
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_TCP, out);
#endif
}
EXPORT_SYMBOL(flow_rule_match_tcp);

#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_KEYID
void flow_rule_match_icmp(const struct flow_rule *rule,
			  struct flow_match_icmp *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ICMP, out);
}
EXPORT_SYMBOL(flow_rule_match_icmp);
#endif

void flow_rule_match_mpls(const struct flow_rule *rule,
			  struct flow_match_mpls *out)
{
#ifdef HAVE_FLOW_DISSECTOR_KEY_MPLS
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_MPLS, out);
#endif
}
EXPORT_SYMBOL(flow_rule_match_mpls);

#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_KEYID
void flow_rule_match_enc_control(const struct flow_rule *rule,
				 struct flow_match_control *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_control);

void flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv4_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_ipv4_addrs);

void flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv6_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_ipv6_addrs);
#endif /* HAVE_FLOW_DISSECTOR_KEY_ENC_KEYID */

void flow_rule_match_enc_ip(const struct flow_rule *rule,
                            struct flow_match_ip *out)
{
#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_IP
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IP, out);
#endif
}
EXPORT_SYMBOL(flow_rule_match_enc_ip);

#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_KEYID
void flow_rule_match_enc_ports(const struct flow_rule *rule,
			       struct flow_match_ports *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_PORTS, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_ports);

void flow_rule_match_enc_keyid(const struct flow_rule *rule,
			       struct flow_match_enc_keyid *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_KEYID, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_keyid);
#endif /* HAVE_FLOW_DISSECTOR_KEY_ENC_KEYID */

void flow_rule_match_enc_opts(const struct flow_rule *rule,
                              struct flow_match_enc_opts *out)
{
        FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_OPTS, out);
}
EXPORT_SYMBOL(flow_rule_match_enc_opts);

void flow_rule_match_ct(const struct flow_rule *rule,
			struct flow_match_ct *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CT, out);
}
EXPORT_SYMBOL(flow_rule_match_ct);

#endif /* HAVE_FLOW_RULE_MATCH_CVLAN */

#ifndef HAVE_FLOW_RULE_MATCH_META
void flow_rule_match_meta(const struct flow_rule *rule,
			  struct flow_match_meta *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_META, out);
}
EXPORT_SYMBOL(flow_rule_match_meta);
#endif /* HAVE_FLOW_RULE_MATCH_META */

#ifndef HAVE_TC_SETUP_FLOW_ACTION
static void build_rule_match(struct tc_cls_flower_offload *f,
			     struct flow_match *match)
{
	match->dissector = f->dissector;
	match->mask = f->mask;
	match->key = f->key;
}

static int build_rule_action(struct tcf_exts *exts,
			     struct flow_rule *rule)
{
	return tc_setup_flow_action(&rule->action, exts);
}

struct flow_rule *__alloc_flow_rule(struct tcf_exts *exts,
				    void *priv, int size)
{
	struct flow_rule *rule;
	int num_ent;
	void *ret;
	int err;

	if (!exts) {
		pr_err_once("mlx5_core: %s: no exts\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	num_ent = tcf_exts_num_actions(exts);
	ret = kzalloc(size + sizeof(*rule) +
		      num_ent * sizeof(rule->action.entries[0]),
		      GFP_KERNEL);
	if (!ret)
		return ERR_PTR(-ENOMEM);

	rule = (struct flow_rule *)((uintptr_t)ret + size);
	rule->action.num_entries = num_ent;
	err = build_rule_action(exts, rule);
	if (err)
		goto out;

	if (priv)
		memcpy(ret, priv, size);
	rule->buff = ret;
	rule->priv = priv;
	rule->priv_size = size;

	return rule;

out:
	kfree(ret);
	return ERR_PTR(err);
}
EXPORT_SYMBOL(__alloc_flow_rule);

struct flow_rule *alloc_flow_rule(struct tc_cls_flower_offload **f)
{
	struct flow_rule *rule;

	rule = __alloc_flow_rule((*f)->exts, *f, sizeof(**f));
	if (IS_ERR(rule))
		return rule;

	build_rule_match(*f, &rule->match);

	*f = (struct tc_cls_flower_offload *)rule->buff;

	return rule;
}
EXPORT_SYMBOL(alloc_flow_rule);

void free_flow_rule(struct flow_rule *rule)
{
	if (rule->priv)
		memcpy(rule->priv, rule->buff, rule->priv_size);

	kfree(rule->buff);
}
EXPORT_SYMBOL(free_flow_rule);
#endif /* HAVE_TC_SETUP_FLOW_ACTION */
