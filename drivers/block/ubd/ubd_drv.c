// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace block device - block device which IO is handled from userspace
 *
 * Take full use of io_uring passthrough command for communicating with
 * ubd userspace daemon(ubdsrvd) for handling basic IO request.
 *
 * Copyright 2022 Ming Lei <ming.lei@redhat.com>
 *
 * (part of code stolen from loop.c)
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/writeback.h>
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/ioprio.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/io_uring.h>
#include <linux/blk-mq.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <uapi/linux/ubd_cmd.h>

#define UBD_MINORS		(1U << MINORBITS)

struct ubd_cmd {
	unsigned char data[16];
};

/* io cmd is active: sqe cmd is received, and its cqe isn't done */
#define UBD_IO_FLAG_ACTIVE	0x01

/*
 * FETCH io cmd is completed via cqe, and the io cmd is being handled by
 * ubdsrv, and not committed yet
 */
#define UBD_IO_FLAG_OWNED_BY_SRV 0x02

struct ubd_io {
	/* userspace buffer address from io cmd */
	__u64	addr;
	unsigned int flags;
	int res;

	struct io_uring_cmd *cmd;
};

struct ubd_queue {
	int q_id;
	int q_depth;

	char *io_cmd_buf;

	unsigned max_io_sz;
	bool aborted;
	struct ubd_io ios[0];
};

struct ubd_device {
	struct gendisk		*ub_disk;
	struct request_queue	*ub_queue;

	char	                *__queues;

	unsigned short          queue_size;
	unsigned short          bs_shift;
	unsigned int            max_io_buf_sz;
	struct ubdsrv_ctrl_dev_info	dev_info;

	struct task_struct	*ub_daemon;

	struct blk_mq_tag_set	tag_set;

	struct cdev		cdev;
	struct device		cdev_dev;

	atomic_t		ch_open_cnt;
	int			ub_number;

	struct mutex		mutex;
};

static dev_t ubd_chr_devt;
static struct class *ubd_chr_class;

static DEFINE_IDR(ubd_index_idr);
static DEFINE_MUTEX(ubd_ctl_mutex);

static struct miscdevice ubd_misc;

static inline struct ubd_queue *ubd_get_queue(struct ubd_device *dev, int qid)
{
       return (struct ubd_queue *)&(dev->__queues[qid * dev->queue_size]);
}

static inline bool ubd_rq_need_copy(struct request *rq)
{
	return rq->bio && bio_has_data(rq->bio);
}

static inline bool ubd_support_zero_copy(struct ubd_device *ub)
{
	return ub->dev_info.flags & (1ULL << UBD_F_SUPPORT_ZERO_COPY);
}

static inline struct ubdsrv_io_desc *ubd_get_iod(struct ubd_queue *ubq, int tag)
{
	return (struct ubdsrv_io_desc *)
		&(ubq->io_cmd_buf[tag * sizeof(struct ubdsrv_io_desc)]);
}

static inline char *ubd_queue_cmd_buf(struct ubd_device *ub, int q_id)
{
	return ubd_get_queue(ub, q_id)->io_cmd_buf;
}

static inline int ubd_queue_cmd_buf_size(struct ubd_device *ub, int q_id)
{
	struct ubd_queue *ubq = ubd_get_queue(ub, q_id);

	return round_up(ubq->q_depth * sizeof(struct ubdsrv_io_desc), PAGE_SIZE);
}

static inline unsigned int ubd_queue_max_io_size(struct ubd_device *ub)
{
	return round_up(ub->max_io_buf_sz, PAGE_SIZE);
}

static int ubd_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ubd_release(struct gendisk *disk, fmode_t mode)
{
}

static const struct block_device_operations ub_fops = {
	.owner =	THIS_MODULE,
	.open =		ubd_open,
	.release =	ubd_release,
};

#define UBD_MAX_PIN_PAGES	32

static void ubd_release_pages(struct ubd_device *ub, struct page **pages,
		int nr_pages)
{
	int i;

	for (i = 0; i < nr_pages; i++)
		put_page(pages[i]);
}

static int ubd_pin_user_pages(struct ubd_device *ub, u64 start_vm,
		struct page **pages, unsigned nr_pages, bool to_rq)
{
	unsigned int gup_flags = to_rq ? 0 : FOLL_WRITE;

	return get_user_pages_fast(start_vm, nr_pages, gup_flags, pages);
}

/* todo: need flush cache */
static inline unsigned ubd_copy_bv(struct bio_vec *bv, void **bv_addr,
		void *pg_addr, unsigned *pg_off,
		unsigned *pg_len, bool to_bv)
{
	unsigned len = min_t(unsigned, bv->bv_len, *pg_len);

	if (*bv_addr == NULL)
		*bv_addr = kmap_local_page(bv->bv_page);

	if (to_bv)
		memcpy(*bv_addr + bv->bv_offset, pg_addr + *pg_off, len);
	else
		memcpy(pg_addr + *pg_off, *bv_addr + bv->bv_offset, len);

	bv->bv_offset += len;
	bv->bv_len -= len;
	*pg_off += len;
	*pg_len -= len;

	if (!bv->bv_len) {
		kunmap_local(*bv_addr);
		*bv_addr = NULL;
	}

	return len;
}

/* 
 * copy data for WRITE and READ:
 * WRITE: copy rq pages to ubdsrv buffer pointed by io->addr
 * READ: copy ubdsrv buffer pointed by io->addr to rq pages
 */
static int ubd_copy_pages(struct ubd_device *ub, struct request *rq)
{
	struct ubd_queue *ubq = rq->mq_hctx->driver_data;
	struct ubd_io *io = &ubq->ios[rq->tag];
	struct page *pgs[UBD_MAX_PIN_PAGES];
	const bool to_rq = !op_is_write(rq->cmd_flags);
	struct req_iterator req_iter;
	struct bio_vec bv;
	unsigned long start = io->addr, left = rq->__data_len;
	unsigned int idx = 0, pg_len = 0, pg_off = 0;
	int nr_pin = 0;
	void *pg_addr = NULL;
	struct page *curr = NULL;

	rq_for_each_segment(bv, rq, req_iter) {
		unsigned len, bv_off = bv.bv_offset, bv_len = bv.bv_len;
		void *bv_addr = NULL;

refill:
		if (pg_len == 0) {
			unsigned int off = 0;

			if (pg_addr) {
				kunmap_local(pg_addr);
				if (!to_rq)
					set_page_dirty_lock(curr);
				pg_addr = NULL;
			}

			/* refill pages */
			if (idx >= nr_pin) {
				unsigned int max_pages;

				ubd_release_pages(ub, pgs, nr_pin);

				off = start & (PAGE_SIZE - 1);
				max_pages = (off + left + PAGE_SIZE - 1) >>
					PAGE_SHIFT;				
				nr_pin = min_t(unsigned, UBD_MAX_PIN_PAGES, max_pages);
				nr_pin = ubd_pin_user_pages(ub, start, pgs,
						nr_pin, to_rq);
				if (nr_pin < 0)
					return nr_pin;
				idx = 0;
			}
			pg_off = off;
			pg_len = min(PAGE_SIZE - off, left);
			off = 0;
			curr = pgs[idx++];
			pg_addr = kmap_local_page(curr);
		}

		len = ubd_copy_bv(&bv, &bv_addr, pg_addr, &pg_off, &pg_len,
				to_rq);
		/* either one of the two has been consumed */
		WARN_ON_ONCE(bv.bv_len && pg_len);
		start += len;
		left -= len;

		/* overflow */
		WARN_ON_ONCE(left > rq->__data_len);
		WARN_ON_ONCE(bv.bv_len > bv_len);
		if (bv.bv_len)
			goto refill;

		bv.bv_len = bv_len;
		bv.bv_offset = bv_off;
	}
	if (pg_addr) {
		kunmap_local(pg_addr);
		if (!to_rq)
			set_page_dirty_lock(curr);
	}
	ubd_release_pages(ub, pgs, nr_pin);

	WARN_ON_ONCE(left != 0);

	return 0;
}

/* TODO: zero copy support */
static int ubd_unmap_io(struct request *req)
{
	struct ubd_device *ub = req->q->queuedata;

	/* copy user buffer to request pages for READ */	
	if (!op_is_write(req->cmd_flags) && ubd_rq_need_copy(req))
		return ubd_copy_pages(ub, req);
	return 0;
}

static int ubd_setup_iod(struct ubd_queue *ubq, struct request *req)
{
	struct ubdsrv_io_desc *iod = ubd_get_iod(ubq, req->tag);
	u32 flags = req->cmd_flags & ~REQ_OP_MASK;
	u32 ubd_op;

	switch (req_op(req)) {
	case REQ_OP_READ:
		ubd_op = UBD_IO_OP_READ;
		break;
	case REQ_OP_WRITE:
		ubd_op = UBD_IO_OP_WRITE;
		break;
	case REQ_OP_FLUSH:
		ubd_op = UBD_IO_OP_FLUSH;
		break;
	case REQ_OP_DISCARD:
		ubd_op = UBD_IO_OP_DISCARD;
		break;
	case REQ_OP_WRITE_SAME:
		ubd_op = UBD_IO_OP_WRITE_SAME;
		break;
	case REQ_OP_WRITE_ZEROES:
		ubd_op = UBD_IO_OP_WRITE_ZEROES;
		break;
	default:
		return BLK_STS_IOERR;
	}

	/* need to translate since kernel may change */
	iod->op_flags = ubd_op | flags;
	iod->sectors = blk_rq_sectors(req);
	iod->start_sector = blk_rq_pos(req);

	return BLK_STS_OK;
}

static blk_status_t ubd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	int ret = UBD_IO_RES_OK;
	struct ubd_queue *ubq = hctx->driver_data;
	struct ubd_device *ub = hctx->queue->queuedata;
	struct request *rq = bd->rq;
	struct ubd_io *io = &ubq->ios[rq->tag];
	blk_status_t res;

	//trace_printk("ubq %p(%d) rq %p(%d) io %p",
	//		ubq, hctx->queue_num, rq, rq->tag, io);

	/* this io cmd slot isn't active, so have to fail this io */
	if (WARN_ON_ONCE(!(io->flags & UBD_IO_FLAG_ACTIVE)))
		return BLK_STS_IOERR;

	WARN_ON_ONCE(bd->rq->__data_len > ubd_queue_max_io_size(ub));

	/* fill iod to slot in io cmd buffer */
	res = ubd_setup_iod(ubq, rq);
	if (res != BLK_STS_OK)
		return BLK_STS_IOERR;

	blk_mq_start_request(bd->rq);

	/* mark this cmd owned by ubdsrv */
	io->flags |= UBD_IO_FLAG_OWNED_BY_SRV;

	/*
	 * clear ACTIVE since we are done with this sqe/cmd slot
	 *
	 * We can only accept io cmd in case of being not active.
	 */
	io->flags &= ~UBD_IO_FLAG_ACTIVE;

	/*
	 * todo:
	 *    1) memory ordering between operating io->flags & io_uring done?
	 *    2) batching completion
	 *    3) for write request, writing data to iod->addr which is passed
	 *    from ubdsrv; or here we remap rq pages to ubsrv vm space, and
	 *    return the mapped address to ubdsrv via iod->addr, then it is
	 *    totally zero copy, but 4k block size has to be applied.
	 */
#ifdef DEBUG
	printk("%s: complete: cmd op %d q_id %d tag %d ret %x "
			"io_flags %x addr %llx io_op %d\n",
			__func__, io->cmd->cmd_op, ubq->q_id, rq->tag, ret, io->flags,
			ubd_get_iod(ubq, rq->tag)->addr,
			ubdsrv_get_op(ubd_get_iod(ubq, rq->tag)));
#endif
	/* tell ubdsrv one io request is coming */
	io_uring_cmd_done(io->cmd, ret);

	return BLK_STS_OK;
}

static void ubd_complete_rq(struct request *req)
{
	struct ubd_queue *ubq = req->mq_hctx->driver_data;
	struct ubd_io *io = &ubq->ios[req->tag];

	ubd_unmap_io(req);

	blk_mq_end_request(req, io->res >= 0 ? BLK_STS_OK : BLK_STS_IOERR);
}

static int ubd_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
		unsigned int hctx_idx)
{
	struct ubd_device *ub = hctx->queue->queuedata;
	struct ubd_queue *ubq = ubd_get_queue(ub, hctx->queue_num);

	hctx->driver_data = ubq;
	return 0;
}

static const struct blk_mq_ops ubd_mq_ops = {
	.queue_rq       = ubd_queue_rq,
	.init_hctx	= ubd_init_hctx,
};

static int ubd_ch_open(struct inode *inode, struct file *filp)
{
	struct ubd_device *ub = container_of(inode->i_cdev,
			struct ubd_device, cdev);

	if (atomic_cmpxchg(&ub->ch_open_cnt, 0, 1) == 0) {
		filp->private_data = ub;
		return 0;
	}
	return -EBUSY;
}

static int ubd_ch_release(struct inode *inode, struct file *filp)
{
	struct ubd_device *ub = filp->private_data;

	while (atomic_cmpxchg(&ub->ch_open_cnt, 1, 0) != 1) {
		cpu_relax();
	}
	filp->private_data = NULL;
	return 0;
}

/* map pre-allocated per-queue cmd buffer to ubdsrv daemon */
static int ubd_ch_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct ubd_device *ub = filp->private_data;
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned max_sz = UBD_MAX_QUEUE_DEPTH * sizeof(struct ubdsrv_io_desc);
	unsigned long pfn;
	unsigned long end = UBDSRV_CMD_BUF_OFFSET + 
			ub->dev_info.nr_hw_queues * max_sz;
	unsigned long phys_off = vma->vm_pgoff << PAGE_SHIFT;
	int q_id;

	if(phys_off < UBDSRV_CMD_BUF_OFFSET || phys_off >= end)
		return -EINVAL;

	q_id = (phys_off - UBDSRV_CMD_BUF_OFFSET) / max_sz;

	if (phys_off != UBDSRV_CMD_BUF_OFFSET + q_id * max_sz)
		return -EINVAL;

#ifdef DEBUG
	printk("%s: qid %d, pid %d, addr %lx pg_off %lx sz %lu\n",
			__func__, q_id, current->pid, vma->vm_start,
			phys_off, sz);
#endif

	if (sz != ubd_queue_cmd_buf_size(ub, q_id))
		return -EINVAL;

	pfn = virt_to_phys(ubd_queue_cmd_buf(ub, q_id)) >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
}

static void ubd_commit_completion(struct ubd_device *ub,
		struct ubdsrv_io_cmd *ub_cmd)
{
	u32 qid = ub_cmd->q_id, tag = ub_cmd->tag;
	struct ubd_queue *ubq = ubd_get_queue(ub, qid);
	struct ubd_io *io = &ubq->ios[tag];
	struct request *req;

	/* now this cmd slot is owned by nbd driver */
	io->flags &= ~UBD_IO_FLAG_OWNED_BY_SRV;
	io->res = ub_cmd->result;

	/* find the io request and complete */
	req = blk_mq_tag_to_rq(ub->tag_set.tags[qid], ub_cmd->tag);

	if (req && likely(!blk_should_fake_timeout(req->q))) {
		ubd_complete_rq(req);
	}
}

static int ubd_ch_handle_get_data(struct ubd_device *ub,
		struct ubdsrv_io_cmd *ub_cmd)
{
	struct request *req;

	req = blk_mq_tag_to_rq(ub->tag_set.tags[ub_cmd->q_id], ub_cmd->tag);
	if (!req)
		return -1;

	if (!op_is_write(req->cmd_flags) || !ubd_rq_need_copy(req))
		return 0;

	/* copy request pages to user buffer for WRITE */	
	return ubd_copy_pages(ub, req);
}

static int ubd_ch_async_cmd(struct io_uring_cmd *cmd)
{
	struct ubdsrv_io_cmd *ub_cmd = (struct ubdsrv_io_cmd *)cmd->cmd;
	struct ubd_device *ub = cmd->file->private_data;
	struct ubd_queue *ubq;
	struct ubd_io *io;
	u32 cmd_op = cmd->cmd_op;
	unsigned tag = ub_cmd->tag;
	unsigned q_id = ub_cmd->q_id;
	int ret = -EINVAL;
	
	ubq = ubd_get_queue(ub, q_id);
	
	WARN_ON_ONCE(tag >= ubq->q_depth);

	io = &ubq->ios[tag];

#ifdef DEBUG
	printk("%s: receieved: cmd op %d, q_id %d "
			"tag %d ret %x io_flags %x\n", __func__,
			cmd->cmd_op, q_id, tag, ret, io->flags);
#endif
	/* there is pending io cmd, something must be wrong */
	if (io->flags & UBD_IO_FLAG_ACTIVE) {
		ret = -EBUSY;
		goto cmd_done;
	}

	switch (cmd_op) {
	case UBD_IO_FETCH_REQ:
		/*
		 * The io is being handled by server, so COMMIT_RQ is expected
		 * instead of FETCH_REQ
		 */
		if (io->flags & UBD_IO_FLAG_OWNED_BY_SRV)
			goto cmd_done;
		
		/* Since UBD_IO_FETCH_REQ is always sent in the first round,
		 * ubd_drv does not set io->addr
		 */
		io->cmd = cmd;
		io->flags |= UBD_IO_FLAG_ACTIVE;
		break;
	case UBD_IO_GET_DATA:
		/* GET_DATA is basically stateless */
		if (!(io->flags & UBD_IO_FLAG_OWNED_BY_SRV))
			goto cmd_done;
		/* 
		 * (1) ubd_drv tells(returns a cqe) ubdsrv an incoming
		 *     WRITE request with data size
		 * 
		 * (2) ubdsrv should alloc a new userspace buf addr
		 *     (addr is ub_cmd->addr) and data to be written stored in it
		 * 
		 * (3) ubdsrv tells(issues a sqe with UBD_IO_GET_DATA)
		 *     ubd_drv to copy data into the buf for a WRITE request
		 * 
		 * (4) ubd_drv copys data into it(ubd_ch_handle_get_data) and 
		 *     issues the WRITE request(returns a cqe) to ubdsrv again
		 * 
		 * (5) ubdsrv handles the request and tells
		 *     (issues a sqe with UBD_IO_COMMIT_AND_FETCH_REQ) 
		 *     ubd_drv the result
		 * 
		 * (6) ubd_drv completes the request
		 */
		io->addr = ub_cmd->addr;
		
		if (!ubd_ch_handle_get_data(ub, ub_cmd))
			ret = UBD_IO_RES_OK;
		goto cmd_done;
	case UBD_IO_COMMIT_AND_FETCH_REQ:
		if (!(io->flags & UBD_IO_FLAG_OWNED_BY_SRV))
			goto cmd_done;
		
		io->flags |= UBD_IO_FLAG_ACTIVE;
		io->cmd = cmd;
		
		/* 
		 * (1) ubd_drv tells(returns a cqe) ubdsrv an incoming
		 *     READ request with data size
		 * 
		 * (2) ubdsrv should alloc a new userspace buf 
		 *     (addr is ub_cmd->addr) and data to be read stored in it
		 * 
		 * (3) ubdsrv tells(issues a sqe with UBD_IO_COMMIT_AND_FETCH_REQ) 
		 *     ubd_drv to copy data from it for a READ request
		 * 
		 * (4) ubd_drv copys data from it and the request is completed
		 */
		io->addr = ub_cmd->addr;
		
		ubd_commit_completion(ub, ub_cmd);
		
#if 0
		/* if ubq->aborted, do not FETCH requests any more */
		if(unlikely(ubq->aborted)) {
			ret = UBD_IO_RES_ABORT;
			goto out;
		}
#endif
		break;
	default:
		goto cmd_done;
	}
	return -EIOCBQUEUED;

cmd_done:
	io->flags &= ~UBD_IO_FLAG_ACTIVE;
	io_uring_cmd_done(cmd, ret);
#ifdef DEBUG
	printk("%s: complete: cmd op %d, q_id %d "
			"tag %d ret %x io_flags %x "
			"io_op %d\n", __func__,
			cmd_op, q_id, tag, ret,
			io->flags, ubdsrv_get_op(ubd_get_iod(ubq, tag)));
#endif
	return -EIOCBQUEUED;
}

static const struct file_operations ubd_ch_fops = {
	.owner = THIS_MODULE,
	.open = ubd_ch_open,
	.release = ubd_ch_release,
	.llseek = no_llseek,
	.async_cmd = ubd_ch_async_cmd,
	.mmap = ubd_ch_mmap,
};

static void ubd_deinit_queue(struct ubd_device *ub, int q_id)
{
	int size = ubd_queue_cmd_buf_size(ub, q_id);
	struct ubd_queue *ubq = ubd_get_queue(ub, q_id);

	if (ubq->io_cmd_buf)
		free_pages((unsigned long)ubq->io_cmd_buf, get_order(size));
}

static int ubd_init_queue(struct ubd_device *ub, int q_id)
{
	struct ubd_queue *ubq = ubd_get_queue(ub, q_id);
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO;
	void *ptr;
	int size;

	ubq->q_id = q_id;
	ubq->q_depth = ub->dev_info.queue_depth;
	size = ubd_queue_cmd_buf_size(ub, q_id);

	ptr = (void *) __get_free_pages(gfp_flags, get_order(size));
	if (!ptr)
		return -ENOMEM;

	/*
	 * check in ubdsrv side, so we can make sure that cmd buf is setup
	 * successfully
	 */
	strcpy(ptr, "UBD");
	ubq->io_cmd_buf = ptr;
	return 0;
}

static void ubd_deinit_queues(struct ubd_device *ub)
{
	int nr_queues = ub->dev_info.nr_hw_queues;
	int i;

	if (!ub->__queues)
		return;

	for (i = 0; i < nr_queues; i++)
		ubd_deinit_queue(ub, i);
	kfree(ub->__queues);
}

static int ubd_init_queues(struct ubd_device *ub)
{
	int nr_queues = ub->dev_info.nr_hw_queues;
	int depth = ub->dev_info.queue_depth;
	int ubq_size = sizeof(struct ubd_queue) + depth * sizeof(struct ubd_io);
	int i, ret = -ENOMEM;

	ub->queue_size = ubq_size;
	ub->__queues = kcalloc(nr_queues, ubq_size, GFP_KERNEL);
	if (!ub->__queues)
		return ret;

	for (i = 0; i < nr_queues; i++) {
		if (ubd_init_queue(ub, i))
			goto fail;
	}
	return 0;

 fail:
	ubd_deinit_queues(ub);
	return ret;
}

static void ubd_cdev_rel(struct device *dev)
{
	struct ubd_device *ub = container_of(dev, struct ubd_device, cdev_dev);

	blk_mq_free_tag_set(&ub->tag_set);
	mutex_lock(&ubd_ctl_mutex);
	idr_remove(&ubd_index_idr, ub->ub_number);
	mutex_unlock(&ubd_ctl_mutex);

	ubd_deinit_queues(ub);

	kfree(ub);
}

static int ubd_add_chdev(struct ubd_device *ub)
{
	struct device *dev = &ub->cdev_dev;
	int minor = ub->ub_number;
	int ret;

	dev->parent = ubd_misc.this_device;
	ret = dev_set_name(dev, "ubdc%d", minor);
	if (ret)
		return ret;

	dev->devt = MKDEV(MAJOR(ubd_chr_devt), minor);
	dev->class = ubd_chr_class;
	dev->release = ubd_cdev_rel;
	device_initialize(dev);

	cdev_init(&ub->cdev, &ubd_ch_fops);
	ret = cdev_device_add(&ub->cdev, dev);
	if (ret) {
		put_device(dev);
		return -1;
	}
	return 0;
}

/* add disk & cdev */
static int ubd_add_dev(struct ubd_device *ub)
{
	struct gendisk *disk;
	int err = -ENOMEM;
	int bsize;

	bsize = ub->dev_info.block_size;
	ub->bs_shift = ilog2(bsize);
	ub->max_io_buf_sz = ub->dev_info.rq_max_blocks << ub->bs_shift;

	ub->dev_info.nr_hw_queues = min_t(unsigned int,
			ub->dev_info.nr_hw_queues, nr_cpu_ids);

	if (ubd_init_queues(ub))
		return err;

	ub->tag_set.ops = &ubd_mq_ops;
	ub->tag_set.nr_hw_queues = ub->dev_info.nr_hw_queues;
	ub->tag_set.queue_depth = ub->dev_info.queue_depth;
	ub->tag_set.numa_node = NUMA_NO_NODE;
	ub->tag_set.cmd_size = sizeof(struct ubd_cmd);
	ub->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	ub->tag_set.driver_data = ub;

	/*
	 * zero copy need to map request into ubdsrv's vm space, so may
	 * sleep when mapping request
	 */
	ub->tag_set.flags |= BLK_MQ_F_BLOCKING;

	err = blk_mq_alloc_tag_set(&ub->tag_set);
	if (err)
		goto out_deinit_queues;

	disk = ub->ub_disk = blk_mq_alloc_disk(&ub->tag_set, ub);
	if (IS_ERR(disk)) {
		err = PTR_ERR(disk);
		goto out_cleanup_tags;
	}
	ub->ub_queue = ub->ub_disk->queue;

	ub->ub_queue->queuedata = ub;

	blk_queue_logical_block_size(ub->ub_queue, bsize);
	blk_queue_physical_block_size(ub->ub_queue, bsize);
	blk_queue_io_min(ub->ub_queue, bsize);

	blk_queue_max_hw_sectors(ub->ub_queue, ub->dev_info.rq_max_blocks <<
			(ub->bs_shift - 9));
	set_capacity(ub->ub_disk, ub->dev_info.dev_blocks << (ub->bs_shift - 9));

	ub->ub_queue->limits.discard_granularity = 0;


	disk->fops		= &ub_fops;
	disk->private_data	= ub;
	disk->queue		= ub->ub_queue;
	sprintf(disk->disk_name, "ubdb%d", ub->ub_number);

	mutex_init(&ub->mutex);

	/* add char dev so that ubdsrv daemon can be setup */
	err = ubd_add_chdev(ub);
	if (err)
		goto out_cleanup_disk;

	/* don't expose disk now until we got start command from cdev */

	return 0;

out_cleanup_disk:
	blk_cleanup_disk(ub->ub_disk);
out_cleanup_tags:
	blk_mq_free_tag_set(&ub->tag_set);
out_deinit_queues:
	ubd_deinit_queues(ub);
	return err;
}

static void ubd_remove(struct ubd_device *ub)
{
	/* we may not start disk yet*/
	if (disk_live(ub->ub_disk))
		del_gendisk(ub->ub_disk);
	blk_cleanup_disk(ub->ub_disk);
	cdev_device_del(&ub->cdev, &ub->cdev_dev);
	put_device(&ub->cdev_dev);
}

static struct ubd_device *ubd_find_device(int idx)
{
	struct ubd_device *ub = NULL;

	if (idx < 0) {
		pr_warn_once("deleting an unspecified ubd device is not supported.\n");
		return NULL;
	}

	if (mutex_lock_killable(&ubd_ctl_mutex))
		return NULL;
	ub = idr_find(&ubd_index_idr, idx);
	mutex_unlock(&ubd_ctl_mutex);

	return ub;
}

static int __ubd_alloc_dev_number(struct ubd_device *ub, int idx)
{
	int i = idx;
	int err;

	/* allocate id, if @id >= 0, we're requesting that specific id */
	if (i >= 0) {
		err = idr_alloc(&ubd_index_idr, ub, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&ubd_index_idr, ub, 0, 0, GFP_KERNEL);
	}

	if (err >= 0)
		ub->ub_number = err;

	return err;
}

static struct ubd_device *ubd_create_dev(int idx)
{
	struct ubd_device *ub = NULL;
	int ret;

	ub = kzalloc(sizeof(*ub), GFP_KERNEL);
	if (!ub)
		return ERR_PTR(-ENOMEM);

	ret = mutex_lock_killable(&ubd_ctl_mutex);
	if (ret)
		goto free_mem;

	if (idx >= 0 && idr_find(&ubd_index_idr, idx)) {
		ret = -EEXIST;
		goto unlock;
	}

	ret = __ubd_alloc_dev_number(ub, idx);
unlock:
	mutex_unlock(&ubd_ctl_mutex);
free_mem:
	if (ret < 0) {
		kfree(ub);
		return ERR_PTR(ret);
	}
	return ub;
}

/* has to be called disk is dead or frozen */
static int ubd_abort_queue(struct ubd_device *ub, int qid)
{
	int ret = UBD_IO_RES_ABORT;
	struct ubd_queue *q = ubd_get_queue(ub, qid);
	int i;

	q->aborted = true;

	for (i = 0; i < q->q_depth; i++) {
		struct ubd_io *io = &q->ios[i];

		if (io->flags & UBD_IO_FLAG_ACTIVE) {
			io->flags &= ~UBD_IO_FLAG_ACTIVE;
			io_uring_cmd_done(io->cmd, ret);
		}
	}
	return 0;
}

/* has to be called disk is dead or frozen */
static int ubd_active_io_cmd_cnt(struct ubd_device *ub, int qid)
{
	struct ubd_queue *q = ubd_get_queue(ub, qid);
	int i, cnt = 0;

	for (i = 0; i < q->q_depth; i++) {
		struct ubd_io *io = &q->ios[i];

		if (io->flags & UBD_IO_FLAG_ACTIVE)
			cnt++;
	}

	return cnt;
}

static bool ubd_queue_ready(struct ubd_device *ub, int qid)
{
	return ubd_active_io_cmd_cnt(ub, qid) == ub->dev_info.queue_depth;
}

static bool ubd_queues_ready(struct ubd_device *ub)
{
	struct ubdsrv_ctrl_dev_info *info = &ub->dev_info;
	int cnt = 0;
	int i;

	for (i = 0; i < info->nr_hw_queues; i++)
		cnt += ubd_queue_ready(ub, i);

	return cnt == info->nr_hw_queues;
}

static int ubd_ctrl_stop_dev(struct ubd_device *ub, struct io_uring_cmd *cmd)
{
	int ret = 0;
	int i;

	mutex_lock(&ub->mutex);
	if (!disk_live(ub->ub_disk))
		goto unlock;

	del_gendisk(ub->ub_disk);
	
	for(i=0; i < ub->dev_info.nr_hw_queues; i++)
		ret += ubd_abort_queue(ub, i);
 unlock:
	mutex_unlock(&ub->mutex);
#ifdef DEBUG
	printk("%s: ret %d on %d queues\n", __func__, ret, ub->dev_info.nr_hw_queues);
#endif
	return ret;
}

static int ubd_ctrl_start_dev(struct ubd_device *ub, struct io_uring_cmd *cmd)
{
	int ret = -EINVAL;
	unsigned long end = jiffies + 3 * HZ;

	mutex_lock(&ub->mutex);

	if (disk_live(ub->ub_disk))
		goto unlock;
	while (time_before(jiffies, end)) {
		if (ubd_queues_ready(ub)) {
			ret = 0;
			break;
		}
		msleep(100);
	}
 unlock:
	mutex_unlock(&ub->mutex);
#ifdef DEBUG
	printk("%s: device io ready, ret: %d\n", __func__, ret);
#endif
	if (ret == 0)
		ret = add_disk(ub->ub_disk);

	return ret;
}

static void ubd_dump(struct io_uring_cmd *cmd)
{
#ifdef DEBUG
	struct ubdsrv_ctrl_dev_info *info = (struct ubdsrv_ctrl_dev_info *)cmd->cmd;

	printk("%s: cmd_op %x cmd_len %d, dev id %d flags %llx\n",
			__func__, cmd->cmd_op, cmd->cmd_len,
			info->dev_id, info->flags);

	printk("\t nr_hw_queues %d queue_depth %d block size %d dev_capacity %lld\n",
			info->nr_hw_queues, info->queue_depth,
			info->block_size, info->dev_blocks);
#endif
}

static bool ubd_ctrl_cmd_validate(struct io_uring_cmd *cmd)
{
	/* Fix me: validate all ctrl commands */
	return  true;
}

static int ubd_ctrl_async_cmd(struct io_uring_cmd *cmd)
{
	struct ubdsrv_ctrl_dev_info *info = (struct ubdsrv_ctrl_dev_info *)cmd->cmd;
	unsigned ret = -EINVAL;
	u32 cmd_op = cmd->cmd_op;
	struct ubd_device *ub;

	ubd_dump(cmd);

	if (!ubd_ctrl_cmd_validate(cmd))
		goto cmd_done;

	ret = -ENODEV;
	switch (cmd_op) {
	case UBD_CMD_START_DEV:
		ub = ubd_find_device(info->dev_id);
		if (!ub)
			goto cmd_done;
		if (!ubd_ctrl_start_dev(ub, cmd))
			ret = UBD_CTRL_CMD_RES_OK;
		break;
	case UBD_CMD_STOP_DEV:
		ub = ubd_find_device(info->dev_id);
		if (!ub)
			goto cmd_done;
		if (!ubd_ctrl_stop_dev(ub, cmd))
			ret = UBD_CTRL_CMD_RES_OK;
		break;
	case UBD_CMD_GET_DEV_INFO:
		if (info->len < sizeof(*info)|| !info->addr) {
			ret = -EINVAL;
			goto cmd_done;
		}
		ub = ubd_find_device(info->dev_id);
		if (ub) {
			if (copy_to_user((void __user *)info->addr,
						(void *)&ub->dev_info,
						sizeof(*info)))
				ret = -EFAULT;
			else
				ret = UBD_CTRL_CMD_RES_OK;
		}
		break;
	/*
	* If dev_id is set by ubd_drv but dev_info fails to return to userspace,
	* the userspace part cannot reference this device any more so we have to
	* remove the ubd_dev right now.
	*/
	case UBD_CMD_ADD_DEV:
		if (info->len < sizeof(*info)|| !info->addr) {
			ret = -EINVAL;
			goto cmd_done;
		}
		ub = ubd_create_dev(info->dev_id);
		if (!IS_ERR_OR_NULL(ub)) {
			memcpy(&ub->dev_info, info, sizeof(*info));

			/* update device id */
			ub->dev_info.dev_id = ub->ub_number;

			if (ubd_add_dev(ub) || copy_to_user(
						(void __user *)info->addr,
						(void *)&ub->dev_info,
						sizeof(*info)))
				ubd_remove(ub);
			else 
				ret = UBD_CTRL_CMD_RES_OK;
		}
		break;
	case UBD_CMD_DEL_DEV:
		ub = ubd_find_device(info->dev_id);
		if (ub) {
			ubd_remove(ub);
			ret = UBD_CTRL_CMD_RES_OK;
		}
		break;
	default:
		break;
	};
cmd_done:
	io_uring_cmd_done(cmd, ret);
	return -EIOCBQUEUED;
}

static const struct file_operations ubd_ctl_fops = {
	.open		= nonseekable_open,
	.async_cmd      = ubd_ctrl_async_cmd,
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};

static struct miscdevice ubd_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "ubd-control",
	.fops		= &ubd_ctl_fops,
};

static int __init ubd_init(void)
{
	int ret;

	ret = misc_register(&ubd_misc);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&ubd_chr_devt, 0, UBD_MINORS, "ubd-char");
	if (ret)
		goto unregister_mis;

	ubd_chr_class = class_create(THIS_MODULE, "ubd-char");
	if (IS_ERR(ubd_chr_class)) {
		ret = PTR_ERR(ubd_chr_class);
		goto free_chrdev_region;
	}
	return 0;

free_chrdev_region:
	unregister_chrdev_region(ubd_chr_devt, UBD_MINORS);
unregister_mis:
	misc_deregister(&ubd_misc);
	return ret;
}

static void __exit ubd_exit(void)
{
	struct ubd_device *ub;
	int id;

	class_destroy(ubd_chr_class);

	misc_deregister(&ubd_misc);

	idr_for_each_entry(&ubd_index_idr, ub, id)
		ubd_remove(ub);

	idr_destroy(&ubd_index_idr);
	unregister_chrdev_region(ubd_chr_devt, UBD_MINORS);
}

module_init(ubd_init);
module_exit(ubd_exit);

MODULE_AUTHOR("Ming Lei <ming.lei@redhat.com>");
MODULE_LICENSE("GPL");
