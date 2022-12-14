#ifndef COMPAT_SOCK_H
#define COMPAT_SOCK_H

#include_next <net/sock.h>

/* Include the autogenerated header file */
#include "../../compat/config.h"

#ifndef HAVE_SK_WAIT_DATA_3_PARAMS
#define sk_wait_data(a,b,c) sk_wait_data(a,b)
#endif

#ifndef HAVE_SKWQ_HAS_SLEEPER
#define skwq_has_sleeper wq_has_sleeper
#endif

#ifndef HAVE_SOCK_NO_LINGER
static inline void sock_no_linger(struct sock *sk)
{
	lock_sock(sk);
	sk->sk_lingertime = 0;
	sock_set_flag(sk, SOCK_LINGER);
	release_sock(sk);
}
#endif

#ifndef HAVE_SOCK_SET_PRIORITY
static inline void sock_set_priority(struct sock *sk, u32 priority)
{
	lock_sock(sk);
	sk->sk_priority = priority;
	release_sock(sk);
}
#endif

#ifndef HAVE_SOCK_SET_REUSEADDR
static inline void sock_set_reuseaddr(struct sock *sk)
{
	lock_sock(sk);
	sk->sk_reuse = SK_CAN_REUSE;
	release_sock(sk);
}
#endif

#endif /* COMPAT_SOCK_H */
