// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZCTAP_H
#define IOU_ZCTAP_H

int io_register_ifq(struct io_ring_ctx *ctx,
		    struct io_uring_ifq_req __user *arg);
int io_unregister_ifq(struct io_ring_ctx *ctx,
		      struct io_uring_ifq_req __user *arg);
int io_unregister_zctap_ifq(struct io_ring_ctx *ctx, unsigned long index);

int io_provide_ifq_region_prep(struct io_kiocb *req,
                               const struct io_uring_sqe *sqe);
int io_provide_ifq_region(struct io_kiocb *req, unsigned int issue_flags);

int io_recvzc(struct io_kiocb *req, unsigned int issue_flags);
int io_recvzc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_zctap_recv(struct io_zctap_ifq *ifq, struct socket *sock,
		  struct msghdr *msg, int flags, u32 datalen, u16 copy_bgid);

#endif
