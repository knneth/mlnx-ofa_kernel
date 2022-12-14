#ifndef LINUX_3_10_COMPAT_H
#define LINUX_3_10_COMPAT_H

#include <linux/random.h>
#define random32() prandom_u32()


#endif /* LINUX_3_10_COMPAT_H */
