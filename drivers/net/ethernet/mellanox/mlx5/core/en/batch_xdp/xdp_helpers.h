#ifndef FARBOD_MLX5E_BATCH_XDP_HELPER_H
#define FARBOD_MLX5E_BATCH_XDP_HELPER_H

/* This file has some xdp helpers, mainly from /en/xdp.c file that is used in
 * batch aware interface
 * */

#ifdef CONFIG_XDP_BATCHING

#include "en/xdp.h"

enum {
	MLX5E_XDP_CHECK_OK = 1,
	MLX5E_XDP_CHECK_START_MPWQE = 2,
};

static int fs_mlx5e_xmit_xdp_frame_check_stop_room(struct mlx5e_xdpsq *sq, int stop_room)
{
	if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc, stop_room))) {
		/* SQ is full, ring doorbell */
		mlx5e_xmit_xdp_doorbell(sq);
		sq->stats->full++;
		return -EBUSY;
	}

	return MLX5E_XDP_CHECK_OK;
}

static u16 fs_mlx5e_xdpsq_get_next_pi(struct mlx5e_xdpsq *sq, u16 size)
{
	struct mlx5_wq_cyc *wq = &sq->wq;
	u16 pi, contig_wqebbs;

	pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	contig_wqebbs = mlx5_wq_cyc_get_contig_wqebbs(wq, pi);
	if (unlikely(contig_wqebbs < size)) {
		struct mlx5e_xdp_wqe_info *wi, *edge_wi;

		wi = &sq->db.wqe_info[pi];
		edge_wi = wi + contig_wqebbs;

		/* Fill SQ frag edge with NOPs to avoid WQE wrapping two pages. */
		for (; wi < edge_wi; wi++) {
			*wi = (struct mlx5e_xdp_wqe_info) {
				.num_wqebbs = 1,
				.num_pkts = 0,
			};
			mlx5e_post_nop(wq, sq->sqn, &sq->pc);
		}
		sq->stats->nops += contig_wqebbs;

		pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	}

	return pi;
}

static bool
fs_mlx5e_xmit_xdp_frame(struct mlx5e_xdpsq *sq, struct mlx5e_xmit_data *xdptxd,
		     int check_result, struct xsk_tx_metadata *meta)
{
	struct mlx5e_xmit_data_frags *xdptxdf =
		container_of(xdptxd, struct mlx5e_xmit_data_frags, xd);
	struct mlx5_wq_cyc       *wq   = &sq->wq;
	struct mlx5_wqe_ctrl_seg *cseg;
	struct mlx5_wqe_data_seg *dseg;
	struct mlx5_wqe_eth_seg *eseg;
	struct mlx5e_tx_wqe *wqe;

	dma_addr_t dma_addr = xdptxd->dma_addr;
	u32 dma_len = xdptxd->len;
	u16 ds_cnt, inline_hdr_sz;
	unsigned int frags_size;
	u8 num_wqebbs = 1;
	int num_frags = 0;
	bool inline_ok;
	bool linear;
	u16 pi;
	int i;

	struct mlx5e_xdpsq_stats *stats = sq->stats;

	inline_ok = sq->min_inline_mode == MLX5_INLINE_MODE_NONE ||
		dma_len >= MLX5E_XDP_MIN_INLINE;
	frags_size = xdptxd->has_frags ? xdptxdf->sinfo->xdp_frags_size : 0;

	if (unlikely(!inline_ok || sq->hw_mtu < dma_len + frags_size)) {
		stats->err++;
		return false;
	}

	inline_hdr_sz = 0;
	if (sq->min_inline_mode != MLX5_INLINE_MODE_NONE)
		inline_hdr_sz = MLX5E_XDP_MIN_INLINE;

	linear = !!(dma_len - inline_hdr_sz);
	ds_cnt = MLX5E_TX_WQE_EMPTY_DS_COUNT + linear + !!inline_hdr_sz;

	/* check_result must be 0 if xdptxd->has_frags is true. */
	if (!check_result) {
		int stop_room = 1;

		if (xdptxd->has_frags) {
			ds_cnt += xdptxdf->sinfo->nr_frags;
			num_frags = xdptxdf->sinfo->nr_frags;
			num_wqebbs = DIV_ROUND_UP(ds_cnt, MLX5_SEND_WQEBB_NUM_DS);
			/* Assuming MLX5_CAP_GEN(mdev, max_wqe_sz_sq) is big
			 * enough to hold all fragments.
			 */
			stop_room = MLX5E_STOP_ROOM(num_wqebbs);
		}

		check_result = fs_mlx5e_xmit_xdp_frame_check_stop_room(sq, stop_room);
	}
	if (unlikely(check_result < 0))
		return false;

	pi = fs_mlx5e_xdpsq_get_next_pi(sq, num_wqebbs);
	wqe = mlx5_wq_cyc_get_wqe(wq, pi);
	net_prefetchw(wqe);

	cseg = &wqe->ctrl;
	eseg = &wqe->eth;
	dseg = wqe->data;

	/* copy the inline part if required */
	if (inline_hdr_sz) {
		memcpy(eseg->inline_hdr.start, xdptxd->data, sizeof(eseg->inline_hdr.start));
		memcpy(dseg, xdptxd->data + sizeof(eseg->inline_hdr.start),
		       inline_hdr_sz - sizeof(eseg->inline_hdr.start));
		dma_len  -= inline_hdr_sz;
		dma_addr += inline_hdr_sz;
		dseg++;
	}

	/* write the dma part */
	if (linear) {
		dseg->addr       = cpu_to_be64(dma_addr);
		dseg->byte_count = cpu_to_be32(dma_len);
		dseg->lkey       = sq->mkey_be;
		dseg++;
	}

	cseg->opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | MLX5_OPCODE_SEND);

	memset(&cseg->trailer, 0, sizeof(cseg->trailer));
	memset(eseg, 0, sizeof(*eseg) - sizeof(eseg->trailer));

	eseg->inline_hdr.sz = cpu_to_be16(inline_hdr_sz);

	for (i = 0; i < num_frags; i++) {
		skb_frag_t *frag = &xdptxdf->sinfo->frags[i];
		dma_addr_t addr;

		addr = xdptxdf->dma_arr ? xdptxdf->dma_arr[i] :
			page_pool_get_dma_addr(skb_frag_page(frag)) +
			skb_frag_off(frag);

		dseg->addr = cpu_to_be64(addr);
		dseg->byte_count = cpu_to_be32(skb_frag_size(frag));
		dseg->lkey = sq->mkey_be;
		dseg++;
	}

	cseg->qpn_ds = cpu_to_be32((sq->sqn << 8) | ds_cnt);

	sq->db.wqe_info[pi] = (struct mlx5e_xdp_wqe_info) {
		.num_wqebbs = num_wqebbs,
		.num_pkts = 1,
	};

	sq->pc += num_wqebbs;

	xsk_tx_metadata_request(meta, &mlx5e_xsk_tx_metadata_ops, eseg);

	sq->doorbell_cseg = cseg;

	stats->xmit++;
	return true;
}

static void fs_mlx5e_xdp_mpwqe_complete(struct mlx5e_xdpsq *sq)
{
	struct mlx5_wq_cyc       *wq    = &sq->wq;
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	struct mlx5_wqe_ctrl_seg *cseg = &session->wqe->ctrl;
	u16 ds_count = session->ds_count;
	u16 pi = mlx5_wq_cyc_ctr2ix(wq, sq->pc);
	struct mlx5e_xdp_wqe_info *wi = &sq->db.wqe_info[pi];

	cseg->opmod_idx_opcode =
		cpu_to_be32((sq->pc << 8) | MLX5_OPCODE_ENHANCED_MPSW);
	cseg->qpn_ds = cpu_to_be32((sq->sqn << 8) | ds_count);

	wi->num_wqebbs = DIV_ROUND_UP(ds_count, MLX5_SEND_WQEBB_NUM_DS);
	wi->num_pkts   = session->pkt_count;

	sq->pc += wi->num_wqebbs;

	sq->doorbell_cseg = cseg;

	session->wqe = NULL; /* Close session */
}

static void fs_mlx5e_xdp_mpwqe_session_start(struct mlx5e_xdpsq *sq)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	struct mlx5e_xdpsq_stats *stats = sq->stats;
	struct mlx5e_tx_wqe *wqe;
	u16 pi;

	pi = fs_mlx5e_xdpsq_get_next_pi(sq, sq->max_sq_mpw_wqebbs);
	wqe = MLX5E_TX_FETCH_WQE(sq, pi);
	net_prefetchw(wqe->data);

	*session = (struct mlx5e_tx_mpwqe) {
		.wqe = wqe,
		.bytes_count = 0,
		.ds_count = MLX5E_TX_WQE_EMPTY_DS_COUNT,
		.ds_count_max = sq->max_sq_mpw_wqebbs * MLX5_SEND_WQEBB_NUM_DS,
		.pkt_count = 0,
		.inline_on = mlx5e_xdp_get_inline_state(sq, session->inline_on),
	};

	stats->mpwqe++;
}

static int fs_mlx5e_xmit_xdp_frame_check_mpwqe(struct mlx5e_xdpsq *sq)
{
	if (unlikely(!sq->mpwqe.wqe)) {
		if (unlikely(!mlx5e_wqc_has_room_for(&sq->wq, sq->cc, sq->pc,
						     sq->stop_room))) {
			/* SQ is full, ring doorbell */
			mlx5e_xmit_xdp_doorbell(sq);
			sq->stats->full++;
			return -EBUSY;
		}

		return MLX5E_XDP_CHECK_START_MPWQE;
	}

	return MLX5E_XDP_CHECK_OK;
}

static bool
fs_mlx5e_xmit_xdp_frame_mpwqe(struct mlx5e_xdpsq *sq, struct mlx5e_xmit_data *xdptxd,
			   int check_result, struct xsk_tx_metadata *meta)
{
	struct mlx5e_tx_mpwqe *session = &sq->mpwqe;
	struct mlx5e_xdpsq_stats *stats = sq->stats;
	struct mlx5e_xmit_data *p = xdptxd;
	struct mlx5e_xmit_data tmp;

	if (xdptxd->has_frags) {
		BUG_ON(true);
		// struct mlx5e_xmit_data_frags *xdptxdf =
		// 	container_of(xdptxd, struct mlx5e_xmit_data_frags, xd);

		// if (!!xdptxd->len + xdptxdf->sinfo->nr_frags > 1) {
		// 	/* MPWQE is enabled, but a multi-buffer packet is queued for
		// 	 * transmission. MPWQE can't send fragmented packets, so close
		// 	 * the current session and fall back to a regular WQE.
		// 	 */
		// 	if (unlikely(sq->mpwqe.wqe))
		// 		fs_mlx5e_xdp_mpwqe_complete(sq);
		// 	return fs_mlx5e_xmit_xdp_frame(sq, xdptxd, 0, meta);
		// }
		// if (!xdptxd->len) {
		// 	skb_frag_t *frag = &xdptxdf->sinfo->frags[0];

		// 	tmp.data = skb_frag_address(frag);
		// 	tmp.len = skb_frag_size(frag);
		// 	tmp.dma_addr = xdptxdf->dma_arr ? xdptxdf->dma_arr[0] :
		// 		page_pool_get_dma_addr(skb_frag_page(frag)) +
		// 		skb_frag_off(frag);
		// 	p = &tmp;
		// }
	}

	if (unlikely(p->len > sq->hw_mtu)) {
		stats->err++;
		return false;
	}

	if (!check_result)
		check_result = fs_mlx5e_xmit_xdp_frame_check_mpwqe(sq);
	if (unlikely(check_result < 0))
		return false;

	if (check_result == MLX5E_XDP_CHECK_START_MPWQE) {
		/* Start the session when nothing can fail, so it's guaranteed
		 * that if there is an active session, it has at least one dseg,
		 * and it's safe to complete it at any time.
		 */
		fs_mlx5e_xdp_mpwqe_session_start(sq);
		xsk_tx_metadata_request(meta, &mlx5e_xsk_tx_metadata_ops, &session->wqe->eth);
	}

	mlx5e_xdp_mpwqe_add_dseg(sq, p, stats);

	if (unlikely(mlx5e_xdp_mpwqe_is_full(session)))
		fs_mlx5e_xdp_mpwqe_complete(sq);

	stats->xmit++;
	return true;
}


static inline bool
fs_mlx5e_xmit_xdp_buff(struct mlx5e_xdpsq *sq, struct mlx5e_rq *rq,
		    struct xdp_buff *xdp)
{
	struct page *page = virt_to_page(xdp->data);
	struct mlx5e_xmit_data_frags xdptxdf = {};
	struct mlx5e_xmit_data *xdptxd;
	struct xdp_frame *xdpf;
	dma_addr_t dma_addr;
	int i;

	xdpf = xdp_convert_buff_to_frame(xdp);
	if (unlikely(!xdpf))
		return false;

	xdptxd = &xdptxdf.xd;
	xdptxd->data = xdpf->data;
	xdptxd->len  = xdpf->len;
	xdptxd->has_frags = xdp_frame_has_frags(xdpf);

	if (xdp->rxq->mem.type == MEM_TYPE_XSK_BUFF_POOL) {
		BUG_ON(true); // FARBOD: not implemented
		// /* The xdp_buff was in the UMEM and was copied into a newly
		//  * allocated page. The UMEM page was returned via the ZCA, and
		//  * this new page has to be mapped at this point and has to be
		//  * unmapped and returned via xdp_return_frame on completion.
		//  */

		// /* Prevent double recycling of the UMEM page. Even in case this
		//  * function returns false, the xdp_buff shouldn't be recycled,
		//  * as it was already done in xdp_convert_zc_to_xdp_frame.
		//  */
		// __set_bit(MLX5E_RQ_FLAG_XDP_XMIT, rq->flags); /* non-atomic */

		// if (unlikely(xdptxd->has_frags))
		// 	return false;

		// dma_addr = dma_map_single(sq->pdev, xdptxd->data, xdptxd->len,
		// 			  DMA_TO_DEVICE);
		// if (dma_mapping_error(sq->pdev, dma_addr)) {
		// 	xdp_return_frame(xdpf);
		// 	return false;
		// }

		// xdptxd->dma_addr = dma_addr;

		// if (unlikely(!INDIRECT_CALL_2(sq->xmit_xdp_frame, mlx5e_xmit_xdp_frame_mpwqe,
		// 			      mlx5e_xmit_xdp_frame, sq, xdptxd, 0, NULL)))
		// 	return false;

		// /* xmit_mode == MLX5E_XDP_XMIT_MODE_FRAME */
		// mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
		// 		     (union mlx5e_xdp_info) { .mode = MLX5E_XDP_XMIT_MODE_FRAME });
		// mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
		// 		     (union mlx5e_xdp_info) { .frame.xdpf = xdpf });
		// mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
		// 		     (union mlx5e_xdp_info) { .frame.dma_addr = dma_addr });
		// return true;
	}

	/* Driver assumes that xdp_convert_buff_to_frame returns an xdp_frame
	 * that points to the same memory region as the original xdp_buff. It
	 * allows to map the memory only once and to use the DMA_BIDIRECTIONAL
	 * mode.
	 */

	dma_addr = page_pool_get_dma_addr(page) + (xdpf->data - (void *)xdpf);
	dma_sync_single_for_device(sq->pdev, dma_addr, xdptxd->len, DMA_BIDIRECTIONAL);

	if (xdptxd->has_frags) {
		printk("farbod: batch xdp: xdp has frags\n");
		BUG_ON(true);
		/* xdptxdf.sinfo = xdp_get_shared_info_from_frame(xdpf); */
		/* xdptxdf.dma_arr = NULL; */

		/* for (i = 0; i < xdptxdf.sinfo->nr_frags; i++) { */
		/* 	skb_frag_t *frag = &xdptxdf.sinfo->frags[i]; */
		/* 	dma_addr_t addr; */
		/* 	u32 len; */

		/* 	addr = page_pool_get_dma_addr(skb_frag_page(frag)) + */
		/* 		skb_frag_off(frag); */
		/* 	len = skb_frag_size(frag); */
		/* 	dma_sync_single_for_device(sq->pdev, addr, len, */
		/* 				   DMA_BIDIRECTIONAL); */
		/* } */
	}

	xdptxd->dma_addr = dma_addr;

	if (unlikely(!INDIRECT_CALL_2(sq->xmit_xdp_frame,
					fs_mlx5e_xmit_xdp_frame_mpwqe,
					fs_mlx5e_xmit_xdp_frame, sq, xdptxd,
					0, NULL)))
		return false;

	/* xmit_mode == MLX5E_XDP_XMIT_MODE_PAGE */
	mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
			     (union mlx5e_xdp_info) { .mode = MLX5E_XDP_XMIT_MODE_PAGE });

	if (xdptxd->has_frags) {
		BUG_ON(true);
		/* mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo, */
		/* 		     (union mlx5e_xdp_info) */
		/* 		     { .page.num = 1 + xdptxdf.sinfo->nr_frags }); */
		/* mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo, */
		/* 		     (union mlx5e_xdp_info) { .page.page = page }); */
		/* for (i = 0; i < xdptxdf.sinfo->nr_frags; i++) { */
		/* 	skb_frag_t *frag = &xdptxdf.sinfo->frags[i]; */

		/* 	mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo, */
		/* 			     (union mlx5e_xdp_info) */
		/* 			     { .page.page = skb_frag_page(frag) }); */
		/* } */
	} else {
		mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
				     (union mlx5e_xdp_info) { .page.num = 1 });
		mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
				     (union mlx5e_xdp_info) { .page.page = page });
	}

	return true;
}

#endif

#endif
