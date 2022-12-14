#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <linux/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_tunnel_key.h>

#include <linux/if_arp.h>

#define TUNNEL_KEY_TAB_MASK     7
static struct tcf_common *tcf_tunnel_key_ht[TUNNEL_KEY_TAB_MASK + 1];
static u32 tunnel_key_idx_gen;
static DEFINE_RWLOCK(tunnel_key_lock);
static LIST_HEAD(tunnel_key_list);

static struct tcf_hashinfo tunnel_key_hash_info = {
	.htab	=	tcf_tunnel_key_ht,
	.hmask	=	TUNNEL_KEY_TAB_MASK,
	.lock	=	&tunnel_key_lock,
};

struct tcf_tunnel_key {
	struct tcf_common	common;
	int tcft_action;
	__be32 ipv4_src;
	__be32 ipv4_dst;
	__be16 dstport;
	u32 id;
};

static int tcf_tunnel_key_release(struct tcf_tunnel_key *t, int bind)
{
	if (t) {
		if (bind)
			t->tcf_bindcnt--;
		t->tcf_refcnt--;
		if (!t->tcf_bindcnt && t->tcf_refcnt <= 0) {
			tcf_hash_destroy(&t->common, &tunnel_key_hash_info);
			return 1;
		}
	}
	return 0;
}

static const struct nla_policy tunnel_key_policy[TCA_TUNNEL_KEY_MAX + 1] = {
	[TCA_TUNNEL_KEY_PARMS]	    = { .len = sizeof(struct tc_tunnel_key) },
	[TCA_TUNNEL_KEY_ENC_IPV4_SRC] = { .type = NLA_U32 },
	[TCA_TUNNEL_KEY_ENC_IPV4_DST] = { .type = NLA_U32 },
	[TCA_TUNNEL_KEY_ENC_IPV6_SRC] = { .len = sizeof(struct in6_addr) },
	[TCA_TUNNEL_KEY_ENC_IPV6_DST] = { .len = sizeof(struct in6_addr) },
	[TCA_TUNNEL_KEY_ENC_KEY_ID]   = { .type = NLA_U32 },
	[TCA_TUNNEL_KEY_ENC_DST_PORT] = { .type = NLA_U16 },
};

#define to_tunnel_key(pc) \
	container_of(pc, struct tcf_tunnel_key, common)
static int tcf_tunnel_key_init(struct net *net, struct nlattr *nla,
			   struct nlattr *est, struct tc_action *a, int ovr,
			   int bind)
{
	struct nlattr *tb[TCA_TUNNEL_KEY_MAX + 1];
	struct tc_tunnel_key *parm;
	struct tcf_tunnel_key *t;
	struct tcf_common *pc;
	int ret;

	if (nla == NULL)
		return -EINVAL;

	ret = nla_parse_nested(tb, TCA_TUNNEL_KEY_MAX, nla, tunnel_key_policy);
	if (ret < 0)
		return ret;

	if (tb[TCA_TUNNEL_KEY_PARMS] == NULL)
		return -EINVAL;

	parm = nla_data(tb[TCA_TUNNEL_KEY_PARMS]);
	pc = tcf_hash_check(parm->index, a, bind, &tunnel_key_hash_info);
	if (!pc) {
		pc = tcf_hash_create(parm->index, est, a, sizeof(*t), bind,
				     &tunnel_key_idx_gen, &tunnel_key_hash_info);
		if (IS_ERR(pc))
			return PTR_ERR(pc);
		ret = ACT_P_CREATED;
	} else {
		if (!ovr) {
			tcf_tunnel_key_release(to_tunnel_key(pc), bind);
			return -EEXIST;
		}
	}
	t = to_tunnel_key(pc);

	spin_lock_bh(&t->tcf_lock);
	t->tcf_action = parm->action;
	t->tcft_action = parm->t_action;
	if (tb[TCA_TUNNEL_KEY_ENC_IPV4_SRC])
		t->ipv4_src = nla_get_be32(tb[TCA_TUNNEL_KEY_ENC_IPV4_SRC]);
	if (tb[TCA_TUNNEL_KEY_ENC_IPV4_DST])
		t->ipv4_dst = nla_get_be32(tb[TCA_TUNNEL_KEY_ENC_IPV4_DST]);
	if (tb[TCA_TUNNEL_KEY_ENC_DST_PORT])
		t->dstport = nla_get_u16(tb[TCA_TUNNEL_KEY_ENC_DST_PORT]);
	if (tb[TCA_TUNNEL_KEY_ENC_KEY_ID])
		t->id = nla_get_u32(tb[TCA_TUNNEL_KEY_ENC_KEY_ID]);
	spin_unlock_bh(&t->tcf_lock);

	if (ret == ACT_P_CREATED) {
		tcf_hash_insert(pc, &tunnel_key_hash_info);
	}

	return ret;
}

static int tcf_tunnel_key_cleanup(struct tc_action *a, int bind)
{
	struct tcf_tunnel_key *t = a->priv;

	if (t)
		return tcf_tunnel_key_release(t, bind);
	return 0;
}

static int tcf_tunnel_key(struct sk_buff *skb, const struct tc_action *a,
		      struct tcf_result *res)
{
	struct tcf_tunnel_key *t = a->priv;

	spin_lock(&t->tcf_lock);
	t->tcf_tm.lastuse = jiffies;
	bstats_update(&t->tcf_bstats, skb);
	spin_unlock(&t->tcf_lock);

	return TC_ACT_OK; /* this will skip the redirect action after this,
			     and should continue the linux pipeline */
}

static int tcf_tunnel_key_dump(struct sk_buff *skb, struct tc_action *a, int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_tunnel_key *t = a->priv;
	struct tc_tunnel_key opt = {
		.index   = t->tcf_index,
		.action  = t->tcf_action,
		.refcnt  = t->tcf_refcnt - ref,
		.bindcnt = t->tcf_bindcnt - bind,
		.t_action = t->tcft_action,
	};
	struct tcf_t tcft;

	if (nla_put(skb, TCA_TUNNEL_KEY_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;
	tcft.install = jiffies_to_clock_t(jiffies - t->tcf_tm.install);
	tcft.lastuse = jiffies_to_clock_t(jiffies - t->tcf_tm.lastuse);
	tcft.expires = jiffies_to_clock_t(t->tcf_tm.expires);
	if (nla_put(skb, TCA_TUNNEL_KEY_TM, sizeof(tcft), &tcft))
		goto nla_put_failure;
	if (t->ipv4_src &&
	    nla_put_be32(skb, TCA_TUNNEL_KEY_ENC_IPV4_SRC, t->ipv4_src))
		goto nla_put_failure;
	if (t->ipv4_dst &&
	    nla_put_be32(skb, TCA_TUNNEL_KEY_ENC_IPV4_DST, t->ipv4_dst))
		goto nla_put_failure;
	if (t->dstport &&
	    nla_put_u16(skb, TCA_TUNNEL_KEY_ENC_DST_PORT, t->dstport))
		goto nla_put_failure;
	if (t->id &&
	    nla_put_u32(skb, TCA_TUNNEL_KEY_ENC_KEY_ID, t->id))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static struct tc_action_ops act_tunnel_key_ops = {
	.kind		=	"tunnel_key",
	.hinfo		=	&tunnel_key_hash_info,
	.type		=	TCA_ACT_TUNNEL_KEY,
	.capab		=	TCA_CAP_NONE,
	.owner		=	THIS_MODULE,
	.act		=	tcf_tunnel_key,
	.dump		=	tcf_tunnel_key_dump,
	.cleanup	=	tcf_tunnel_key_cleanup,
	.lookup		=	tcf_hash_search,
	.init		=	tcf_tunnel_key_init,
	.walk		=	tcf_generic_walker
};

static int __init tunnel_key_init_module(void)
{
	return tcf_register_action(&act_tunnel_key_ops);
}

static void __exit tunnel_key_cleanup_module(void)
{
	tcf_unregister_action(&act_tunnel_key_ops);
}

module_init(tunnel_key_init_module);
module_exit(tunnel_key_cleanup_module);

MODULE_AUTHOR("Based on original module by Amir Vadai <amir@vadai.me>");
MODULE_DESCRIPTION("ip tunnel manipulation actions - backport");
MODULE_LICENSE("GPL v2");
#ifdef RETPOLINE_MLNX
MODULE_INFO(retpoline, "Y");
#endif

