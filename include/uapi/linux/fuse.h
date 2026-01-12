#ifndef _COMPAT_UAPI_LINUX_FUSE_H
#define _COMPAT_UAPI_LINUX_FUSE_H

#include "../../../compat/config.h"

#include_next <uapi/linux/fuse.h>

#ifndef FUSE_DIRECT_IO_ALLOW_MMAP
#define FUSE_DIRECT_IO_ALLOW_MMAP (1ULL << 36)
#endif

#endif /* _COMPAT_UAPI_LINUX_FUSE_H */
