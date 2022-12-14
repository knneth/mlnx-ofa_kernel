#ifndef _COMPAT_LINUX_SUNRPC_RPC_RDMA_H
#define _COMPAT_LINUX_SUNRPC_RPC_RDMA_H

#include "../../../compat/config.h"

#include_next <linux/sunrpc/rpc_rdma.h>

#ifndef rpcrdma_version

#define RPCRDMA_VERSION                1
#define rpcrdma_version                cpu_to_be32(RPCRDMA_VERSION)

#define rdma_msg       cpu_to_be32(RDMA_MSG)
#define rdma_nomsg     cpu_to_be32(RDMA_NOMSG)
#define rdma_msgp      cpu_to_be32(RDMA_MSGP)
#define rdma_done      cpu_to_be32(RDMA_DONE)
#define rdma_error     cpu_to_be32(RDMA_ERROR)

#endif /* rpcrdma_version */

#ifndef HAVE_XDR_ENCODE_RDMA_SEGMENT
/**
 * xdr_encode_rdma_segment - Encode contents of an RDMA segment
 * @p: Pointer into a send buffer
 * @handle: The RDMA handle to encode
 * @length: The RDMA length to encode
 * @offset: The RDMA offset to encode
 *
 * Return value:
 *   Pointer to the XDR position that follows the encoded RDMA segment
 */
static inline __be32 *xdr_encode_rdma_segment(__be32 *p, u32 handle,
					      u32 length, u64 offset)
{
	*p++ = cpu_to_be32(handle);
	*p++ = cpu_to_be32(length);
	return xdr_encode_hyper(p, offset);
}

/**
 * xdr_encode_read_segment - Encode contents of a Read segment
 * @p: Pointer into a send buffer
 * @position: The position to encode
 * @handle: The RDMA handle to encode
 * @length: The RDMA length to encode
 * @offset: The RDMA offset to encode
 *
 * Return value:
 *   Pointer to the XDR position that follows the encoded Read segment
 */
static inline __be32 *xdr_encode_read_segment(__be32 *p, u32 position,
					      u32 handle, u32 length,
					      u64 offset)
{
	*p++ = cpu_to_be32(position);
	return xdr_encode_rdma_segment(p, handle, length, offset);
}
#endif

#ifndef HAVE_XDR_DECODE_RDMA_SEGMENT
/**
 * xdr_decode_rdma_segment - Decode contents of an RDMA segment
 * @p: Pointer to the undecoded RDMA segment
 * @handle: Upon return, the RDMA handle
 * @length: Upon return, the RDMA length
 * @offset: Upon return, the RDMA offset
 *
 * Return value:
 *   Pointer to the XDR item that follows the RDMA segment
 */
static inline __be32 *xdr_decode_rdma_segment(__be32 *p, u32 *handle,
					      u32 *length, u64 *offset)
{
	*handle = be32_to_cpup(p++);
	*length = be32_to_cpup(p++);
	return xdr_decode_hyper(p, offset);
}

/**
 * xdr_decode_read_segment - Decode contents of a Read segment
 * @p: Pointer to the undecoded Read segment
 * @position: Upon return, the segment's position
 * @handle: Upon return, the RDMA handle
 * @length: Upon return, the RDMA length
 * @offset: Upon return, the RDMA offset
 *
 * Return value:
 *   Pointer to the XDR item that follows the Read segment
 */
static inline __be32 *xdr_decode_read_segment(__be32 *p, u32 *position,
					      u32 *handle, u32 *length,
					      u64 *offset)
{
	*position = be32_to_cpup(p++);
	return xdr_decode_rdma_segment(p, handle, length, offset);
}
#endif

#ifndef HAVE_XDR_STREAM_ENCODE_ITEM_ABSENT
/**
 * xdr_pad_size - Calculate size of an object's pad
 * @n: Size of an object being XDR encoded (in bytes)
 *
 * This implementation avoids the need for conditional
 * branches or modulo division.
 *
 * Return value:
 *   Size (in bytes) of the needed XDR pad
 */
static inline size_t xdr_pad_size(size_t n)
{
	return xdr_align_size(n) - n;
}

/**
 * xdr_stream_encode_item_present - Encode a "present" list item
 * @xdr: pointer to xdr_stream
 *
 * Return values:
 *   On success, returns length in bytes of XDR buffer consumed
 *   %-EMSGSIZE on XDR buffer overflow
 */
static inline ssize_t xdr_stream_encode_item_present(struct xdr_stream *xdr)
{
	const size_t len = sizeof(__be32);
	__be32 *p = xdr_reserve_space(xdr, len);

	if (unlikely(!p))
		return -EMSGSIZE;
	*p = xdr_one;
	return len;
}

/**
 * xdr_stream_encode_item_absent - Encode a "not present" list item
 * @xdr: pointer to xdr_stream
 *
 * Return values:
 *   On success, returns length in bytes of XDR buffer consumed
 *   %-EMSGSIZE on XDR buffer overflow
 */
static inline int xdr_stream_encode_item_absent(struct xdr_stream *xdr)
{
	const size_t len = sizeof(__be32);
	__be32 *p = xdr_reserve_space(xdr, len);

	if (unlikely(!p))
		return -EMSGSIZE;
	*p = xdr_zero;
	return len;
}
#endif

#ifndef HAVE_XDR_ITEM_IS_ABSENT
/**
 * xdr_item_is_absent - symbolically handle XDR discriminators
 * @p: pointer to undecoded discriminator
 *
 * Return values:
 *   %true if the following XDR item is absent
 *   %false if the following XDR item is present
 */
static inline bool xdr_item_is_absent(const __be32 *p)
{
	return *p == xdr_zero;
}

/**
 * xdr_item_is_present - symbolically handle XDR discriminators
 * @p: pointer to undecoded discriminator
 *
 * Return values:
 *   %true if the following XDR item is present
 *   %false if the following XDR item is absent
 */
static inline bool xdr_item_is_present(const __be32 *p)
{
	return *p != xdr_zero;
}
#endif

#ifndef HAVE_SVC_RDMA_RECV_CTXT_RC_STREAM
/*
 *  * XDR sizes, in quads
 *   */
enum {
	rpcrdma_readseg_maxsz	= 1 + rpcrdma_segment_maxsz,
};
#endif

#endif /* _COMPAT_LINUX_SUNRPC_RPC_RDMA_H */
