// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "zctap.h"

static DEFINE_XARRAY_ALLOC1(io_zctap_ifq_xa);

typedef int (*bpf_op_t)(struct net_device *dev, struct netdev_bpf *bpf);

static int __io_queue_mgmt(struct net_device *dev, struct io_zctap_ifq *ifq,
			   u16 *queue_id)
{
	struct netdev_bpf cmd;
	bpf_op_t ndo_bpf;
	int err;

	ndo_bpf = dev->netdev_ops->ndo_bpf;
	if (!ndo_bpf)
		return -EINVAL;

	cmd.command = XDP_SETUP_ZCTAP;
	cmd.zct.ifq = ifq;
	cmd.zct.queue_id = *queue_id;

	err = ndo_bpf(dev, &cmd);
	if (!err)
		*queue_id = cmd.zct.queue_id;

	return err;
}

static int io_open_zctap_ifq(struct io_zctap_ifq *ifq, u16 *queue_id)
{
	return __io_queue_mgmt(ifq->dev, ifq, queue_id);
}

static int io_close_zctap_ifq(struct io_zctap_ifq *ifq, u16 queue_id)
{
	return __io_queue_mgmt(ifq->dev, NULL, &queue_id);
}

static struct io_zctap_ifq *io_zctap_ifq_alloc(void)
{
	struct io_zctap_ifq *ifq;

	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;

	ifq->queue_id = -1;
	return ifq;
}

static void io_zctap_ifq_free(struct io_zctap_ifq *ifq)
{
	if (ifq->queue_id != -1)
		io_close_zctap_ifq(ifq, ifq->queue_id);
	if (ifq->dev)
		dev_put(ifq->dev);
	if (ifq->id)
		xa_erase(&io_zctap_ifq_xa, ifq->id);
	kfree(ifq);
}

int io_register_ifq(struct io_ring_ctx *ctx,
		    struct io_uring_ifq_req __user *arg)
{
	struct io_uring_ifq_req req;
	struct io_zctap_ifq *ifq;
	int id, err;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	ifq = io_zctap_ifq_alloc();
	if (!ifq)
		return -ENOMEM;
	ifq->ctx = ctx;
	ifq->fill_bgid = req.fill_bgid;

	err = -ENODEV;
	ifq->dev = dev_get_by_index(&init_net, req.ifindex);
	if (!ifq->dev)
		goto out;

	err = io_open_zctap_ifq(ifq, &req.queue_id);
	if (err)
		goto out;
	ifq->queue_id = req.queue_id;

	/* aka idr */
	err = xa_alloc(&io_zctap_ifq_xa, &id, ifq,
		       XA_LIMIT(1, PAGE_SIZE - 1), GFP_KERNEL);
	if (err)
		goto out;
	ifq->id = id;
	req.ifq_id = id;

	err = xa_err(xa_store(&ctx->zctap_ifq_xa, id, ifq, GFP_KERNEL));
	if (err)
		goto out;

	if (copy_to_user(arg, &req, sizeof(req))) {
		xa_erase(&ctx->zctap_ifq_xa, id);
		err = -EFAULT;
		goto out;
	}

	return 0;

out:
	io_zctap_ifq_free(ifq);
	return err;
}

int io_unregister_zctap_ifq(struct io_ring_ctx *ctx, unsigned long index)
{
	struct io_zctap_ifq *ifq;

	ifq = xa_erase(&ctx->zctap_ifq_xa, index);
	if (!ifq)
		return -EINVAL;

	io_zctap_ifq_free(ifq);
	return 0;
}

int io_unregister_ifq(struct io_ring_ctx *ctx,
		      struct io_uring_ifq_req __user *arg)
{
	struct io_uring_ifq_req req;

	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	return io_unregister_zctap_ifq(ctx, req.ifq_id);
}
