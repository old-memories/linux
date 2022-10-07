// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/nospec.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "zctap.h"
#include "rsrc.h"
#include "kbuf.h"

static DEFINE_XARRAY_ALLOC1(io_zctap_ifq_xa);

typedef int (*bpf_op_t)(struct net_device *dev, struct netdev_bpf *bpf);

static u64 zctap_page_info(u16 region_id, u16 pgid, u16 ifq_id)
{
	return (u64)region_id << 32 | (u64)pgid << 16 | ifq_id;
}

static u16 zctap_page_region_id(const struct page *page)
{
	return (page_private(page) >> 32) & 0xffff;
}

static u16 zctap_page_id(const struct page *page)
{
	return (page_private(page) >> 16) & 0xffff;
}

static u16 zctap_page_ifq_id(const struct page *page)
{
	return page_private(page) & 0xffff;
}

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

struct io_ifq_region {
	struct file		*file;
	struct io_zctap_ifq	*ifq;
	__u64			addr;
	__u32			len;
	__u32			bgid;
};

struct ifq_region {
	struct io_mapped_ubuf	*imu;
	u64			start;
	u64			end;
	int			count;
	int			imu_idx;
	int			nr_pages;
	u8			*page_uref;
	struct page		*page[];
};

static void io_add_page_uref(struct ifq_region *ifr, u16 pgid)
{
	if (WARN_ON(!ifr))
		return;

	if (WARN_ON(pgid < ifr->imu_idx))
		return;

	ifr->page_uref[pgid - ifr->imu_idx]++;
}

static bool io_put_page_last_uref(struct ifq_region *ifr, u64 addr)
{
	int idx;

	if (WARN_ON(addr < ifr->start || addr > ifr->end))
		return false;

	idx = (addr - ifr->start) >> PAGE_SHIFT;

	if (WARN_ON(!ifr->page_uref[idx]))
		return false;

	return --ifr->page_uref[idx] == 0;
}

int io_provide_ifq_region_prep(struct io_kiocb *req,
			       const struct io_uring_sqe *sqe)
{
	struct io_ifq_region *r = io_kiocb_to_cmd(req, struct io_ifq_region);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_mapped_ubuf *imu;
	u32 index;

	if (!(req->flags & REQ_F_BUFFER_SELECT))
		return -EINVAL;

	r->addr = READ_ONCE(sqe->addr);
	r->len = READ_ONCE(sqe->len);
	index = READ_ONCE(sqe->fd);

	if (!r->addr || r->addr & ~PAGE_MASK)
		return -EFAULT;

	if (!r->len || r->len & ~PAGE_MASK)
		return -EFAULT;

	r->ifq = xa_load(&ctx->zctap_ifq_xa, index);
	if (!r->ifq)
		return -EFAULT;

	/* XXX for now, only allow one region per ifq. */
	if (r->ifq->region)
		return -EFAULT;

	if (unlikely(req->buf_index >= ctx->nr_user_bufs))
		return -EFAULT;
	index = array_index_nospec(req->buf_index, ctx->nr_user_bufs);
	imu = ctx->user_bufs[index];

	if (r->addr < imu->ubuf || r->addr + r->len > imu->ubuf_end)
		return -EFAULT;
	req->imu = imu;

	io_req_set_rsrc_node(req, ctx, 0);

	return 0;
}

int io_provide_ifq_region(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ifq_region *r = io_kiocb_to_cmd(req, struct io_ifq_region);
	struct ifq_region *ifr;
	int i, id, idx, nr_pages;
	struct page *page;
	u64 info;

	nr_pages = r->len >> PAGE_SHIFT;
	idx = (r->addr - req->imu->ubuf) >> PAGE_SHIFT;

	ifr = kvmalloc(struct_size(ifr, page, nr_pages), GFP_KERNEL);
	if (!ifr)
		return -ENOMEM;

	ifr->page_uref = kvmalloc_array(nr_pages, sizeof(u8), GFP_KERNEL);
	if (!ifr->page_uref) {
		kvfree(ifr);
		return -ENOMEM;
	}

	ifr->nr_pages = nr_pages;
	ifr->imu_idx = idx;
	ifr->count = nr_pages;
	ifr->imu = req->imu;
	ifr->start = r->addr;
	ifr->end = r->addr + r->len;

	id = r->ifq->id;
	for (i = 0; i < nr_pages; i++, idx++) {
		page = req->imu->bvec[idx].bv_page;
		if (PagePrivate(page))
			goto out;
		SetPagePrivate(page);
		info = zctap_page_info(r->bgid, idx + i, id);
		set_page_private(page, info);
		ifr->page[i] = page;
		ifr->page_uref[i] = 0;
	}

	WRITE_ONCE(r->ifq->region,  ifr);

	return 0;
out:
	while (i--) {
		page = req->imu->bvec[idx + i].bv_page;
		ClearPagePrivate(page);
		set_page_private(page, 0);
	}

	kvfree(ifr->page_uref);
	kvfree(ifr);

	return -EEXIST;
}
