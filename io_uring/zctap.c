// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/nospec.h>
#include <net/tcp.h>

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

/* gets a user-supplied buffer from the fill queue */
static struct page *io_zctap_get_buffer(struct io_zctap_ifq *ifq)
{
	struct io_kiocb req = {
		.ctx = ifq->ctx,
		.buf_index = ifq->fill_bgid,
	};
	struct io_mapped_ubuf *imu;
	struct ifq_region *ifr;
	size_t len;
	u64 addr;
	int idx;

	len = 0;
	ifr = ifq->region;
	imu = ifr->imu;

	addr = io_zctap_buffer(&req, &len);
	if (!addr)
		goto fail;

	/* XXX poor man's implementation of io_import_fixed */

	if (addr < ifr->start || addr + len > ifr->end)
		goto fail;

	idx = (addr - ifr->start) >> PAGE_SHIFT;

	return imu->bvec[ifr->imu_idx + idx].bv_page;

fail:
	/* warn and just drop buffer */
	WARN_RATELIMIT(1, "buffer addr %llx invalid", addr);
	return NULL;
}

struct page *io_zctap_ifq_get_page(struct io_zctap_ifq *ifq,
				   unsigned int order)
{
	struct ifq_region *ifr = ifq->region;

	if (WARN_RATELIMIT(order != 1, "order %d", order))
		return NULL;

	if (ifr->count)
		return ifr->page[--ifr->count];

	return io_zctap_get_buffer(ifq);
}

unsigned long io_zctap_ifq_get_bulk(struct io_zctap_ifq *ifq,
				    unsigned long nr_pages,
				    struct page **page_array)
{
	struct ifq_region *ifr = ifq->region;
	int count;

	count = min_t(unsigned long, nr_pages, ifr->count);
	if (count) {
		ifr->count -= count;
		memcpy(page_array, &ifr->page[ifr->count],
		       count * sizeof(struct page *));
	}

	return count;
}

bool io_zctap_ifq_put_page(struct io_zctap_ifq *ifq, struct page *page)
{
	struct ifq_region *ifr = ifq->region;

	/* if page is not usermapped, then throw an error */

	/* sanity check - leak pages here if hit */
	if (WARN_RATELIMIT(ifr->count >= ifr->nr_pages, "page overflow"))
		return true;

	ifr->page[ifr->count++] = page;

	return true;
}

static inline bool
zctap_skb_ours(struct sk_buff *skb)
{
	return skb->pp_recycle;
}

struct zctap_read_desc {
	struct iov_iter *iter;
	struct ifq_region *ifr;
	u32 iov_space;
	u32 iov_limit;
	u32 recv_limit;

	struct io_kiocb req;
	u8 *buf;
	size_t offset;
	size_t buflen;

	struct io_zctap_ifq *ifq;
	u16 ifq_id;
	u16 copy_bgid;			/* XXX move to register ifq? */
};

static int __zctap_get_user_buffer(struct zctap_read_desc *ztr, int len)
{
	if (!ztr->buflen) {
		ztr->req = (struct io_kiocb) {
			.ctx = ztr->ifq->ctx,
			.buf_index = ztr->copy_bgid,
		};

		ztr->buf = (u8 *)io_zctap_buffer(&ztr->req, &ztr->buflen);
		ztr->offset = 0;
	}
	return len > ztr->buflen ? ztr->buflen : len;
}

static int zctap_copy_data(struct zctap_read_desc *ztr, int len, u8 *kaddr)
{
	struct io_uring_zctap_iov zov;
	u32 space;
	int err;

	space = ztr->iov_space + sizeof(zov);
	if (space > ztr->iov_limit)
		return 0;

	len = __zctap_get_user_buffer(ztr, len);
	if (!len)
		return -ENOBUFS;

	err = copy_to_user(ztr->buf + ztr->offset, kaddr, len);
	if (err)
		return -EFAULT;

	zov = (struct io_uring_zctap_iov) {
		.off = ztr->offset,
		.len = len,
		.bgid = ztr->copy_bgid,
		.bid = ztr->req.buf_index,
		.ifq_id = ztr->ifq_id,
	};

	if (copy_to_iter(&zov, sizeof(zov), ztr->iter) != sizeof(zov))
		return -EFAULT;

	ztr->offset += len;
	ztr->buflen -= len;

	ztr->iov_space = space;

	return len;
}

static int zctap_copy_frag(struct zctap_read_desc *ztr, struct page *page,
			   int off, int len, int id,
			   struct io_uring_zctap_iov *zov)
{
	u8 *kaddr;
	int err;

	len = __zctap_get_user_buffer(ztr, len);
	if (!len)
		return -ENOBUFS;

	if (id == 0) {
		kaddr = kmap(page) + off;
		err = copy_to_user(ztr->buf + ztr->offset, kaddr, len);
		kunmap(page);
	} else {
		kaddr = page_address(page) + off;
		err = copy_to_user(ztr->buf + ztr->offset, kaddr, len);
	}

	if (err)
		return -EFAULT;

	*zov = (struct io_uring_zctap_iov) {
		.off = ztr->offset,
		.len = len,
		.bgid = ztr->copy_bgid,
		.bid = ztr->req.buf_index,
		.ifq_id = ztr->ifq_id,
	};

	ztr->offset += len;
	ztr->buflen -= len;

	return len;
}

static int zctap_recv_frag(struct zctap_read_desc *ztr,
			   const skb_frag_t *frag, int off, int len)
{
	struct io_uring_zctap_iov zov;
	struct page *page;
	int id, pgid;
	u32 space;

	space = ztr->iov_space + sizeof(zov);
	if (space > ztr->iov_limit)
		return 0;

	page = skb_frag_page(frag);
	id = zctap_page_ifq_id(page);
	off += skb_frag_off(frag);

	if (likely(id == ztr->ifq_id)) {
		pgid = zctap_page_id(page);
		io_add_page_uref(ztr->ifr, pgid);
		zov = (struct io_uring_zctap_iov) {
			.off = off,
			.len = len,
			.bgid = zctap_page_region_id(page),
			.bid = pgid,
			.ifq_id = id,
		};
	} else {
		len = zctap_copy_frag(ztr, page, off, len, id, &zov);
		if (len <= 0)
			return len;
	}

	if (copy_to_iter(&zov, sizeof(zov), ztr->iter) != sizeof(zov))
		return -EFAULT;

	ztr->iov_space = space;

	return len;
}

/* Our version of __skb_datagram_iter  -- should work for UDP also. */
static int
zctap_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
	       unsigned int offset, size_t len)
{
	struct zctap_read_desc *ztr = desc->arg.data;
	unsigned start, start_off;
	struct sk_buff *frag_iter;
	int i, copy, end, ret = 0;

	if (ztr->iov_space >= ztr->iov_limit) {
		desc->count = 0;
		return 0;
	}
	if (len > ztr->recv_limit)
		len = ztr->recv_limit;

	start = skb_headlen(skb);
	start_off = offset;

	if (offset < start) {
		copy = start - offset;
		if (copy > len)
			copy = len;

		/* copy out linear data */
		ret = zctap_copy_data(ztr, copy, skb->data + offset);
		if (ret < 0)
			goto out;
		offset += ret;
		len -= ret;
		if (len == 0 || ret != copy)
			goto out;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag;

		WARN_ON(start > offset + len);

		frag = &skb_shinfo(skb)->frags[i];
		end = start + skb_frag_size(frag);

		if (offset < end) {
			copy = end - offset;
			if (copy > len)
				copy = len;

			ret = zctap_recv_frag(ztr, frag, offset - start, copy);
			if (ret < 0)
				goto out;

			offset += ret;
			len -= ret;
			if (len == 0 || ret != copy)
				goto out;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if (offset < end) {
			int off;

			copy = end - offset;
			if (copy > len)
				copy = len;

			off = offset - start;
			ret = zctap_recv_skb(desc, frag_iter, off, copy);
			if (ret < 0)
				goto out;

			offset += ret;
			len -= ret;
			if (len == 0 || ret != copy)
				goto out;
		}
		start = end;
	}

out:
	if (offset == start_off)
		return ret;
	return offset - start_off;
}

static int __io_zctap_tcp_read(struct sock *sk, struct zctap_read_desc *zrd)
{
	read_descriptor_t rd_desc = {
		.arg.data = zrd,
		.count = 1,
	};

	return tcp_read_sock(sk, &rd_desc, zctap_recv_skb);
}

static int io_zctap_tcp_recvmsg(struct sock *sk, struct zctap_read_desc *zrd,
				int flags, int *addr_len)
{
	size_t used;
	long timeo;
	int ret;

	ret = used = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	while (zrd->recv_limit) {
		ret = __io_zctap_tcp_read(sk, zrd);
		if (ret < 0)
			break;
		if (!ret) {
			if (used)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			if (!skb_queue_empty(&sk->sk_receive_queue))
				break;
			sk_wait_data(sk, &timeo, NULL);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		zrd->recv_limit -= ret;
		used += ret;

		if (!timeo)
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);

	/* XXX, handle timestamping */

	if (used)
		return used;

	return ret;
}

int io_zctap_recv(struct io_zctap_ifq *ifq, struct socket *sock,
		  struct msghdr *msg, int flags, u32 datalen, u16 copy_bgid)
{
	struct sock *sk = sock->sk;
	struct zctap_read_desc zrd = {
		.iov_limit = msg_data_left(msg),
		.recv_limit = datalen,
		.iter = &msg->msg_iter,
		.ifq = ifq,
		.ifq_id = ifq->id,
		.copy_bgid = copy_bgid,
		.ifr = ifq->region,
	};
	const struct proto *prot;
	int addr_len = 0;
	int ret;

	if (flags & MSG_ERRQUEUE)
		return -EOPNOTSUPP;

	prot = READ_ONCE(sk->sk_prot);
	if (prot->recvmsg != tcp_recvmsg)
		return -EPROTONOSUPPORT;

	sock_rps_record_flow(sk);

	ret = io_zctap_tcp_recvmsg(sk, &zrd, flags, &addr_len);
	if (ret >= 0) {
		msg->msg_namelen = addr_len;
		ret = zrd.iov_space;
	}
	return ret;
}
