#ifndef _COMPAT_LINUX_BPF_H
#define _COMPAT_LINUX_BPF_H

#include "../../compat/config.h"

#ifdef HAVE_LINUX_BPF_H
#include_next <linux/bpf.h>

#ifndef HAVE_BPF_PROG_INC_EXPORTED
#define bpf_prog_inc LINUX_BACKPORT(bpf_prog_inc)
static inline struct bpf_prog *bpf_prog_inc(struct bpf_prog *prog)
{
	return bpf_prog_add(prog, 1);
}
#endif

#ifndef HAVE_BPF_PROG_SUB
struct bpf_prog;
#define bpf_prog_sub LINUX_BACKPORT(bpf_prog_sub)
void bpf_prog_sub(struct bpf_prog *prog, int i);
#endif

#endif /* HAVE_LINUX_BPF_H */

#ifndef XDP_PACKET_HEADROOM
#define XDP_PACKET_HEADROOM 256
#endif

#endif /* _COMPAT_LINUX_BPF_H */
