/*
 * Copyright (c) 2012 Mellanox Technologies. All rights reserved.
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>

#define DRV_NAME	"9pnet_rdma"
#define DRV_VERSION	"5.1-2.3.7"
#define DRV_RELDATE	"14 Sep 2020"

MODULE_AUTHOR("Alaa Hleihel");
MODULE_DESCRIPTION("9pnet_rdma dummy kernel module");
MODULE_LICENSE("Dual BSD/GPL");
#ifdef RETPOLINE_MLNX
MODULE_INFO(retpoline, "Y");
#endif
MODULE_VERSION(DRV_VERSION);

static int __init _9pnet_rdma_init(void)
{
	return 0;
}

static void __exit _9pnet_rdma_cleanup(void)
{
}

module_init(_9pnet_rdma_init);
module_exit(_9pnet_rdma_cleanup);
