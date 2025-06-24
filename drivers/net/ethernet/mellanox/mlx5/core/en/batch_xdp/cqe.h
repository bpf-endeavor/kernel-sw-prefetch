#ifndef EN_BATCH_XDP_CQE_H_
#define EN_BATCH_XDP_CQE_H_

#ifdef CONFIG_XDP_BATCHING

static inline __attribute__((always_inline))
void fs_finilize_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe,
		struct skb_buff *skb)
{
	if (!skb) {
		/* probably for XDP */
		u8 flags = QUEUE_GET_XDP_STATE(rq, falgs, pkt_index);
		if (__test_and_clear_bit(MLX5E_RQ_FLAG_XDP_XMIT, rq->flags))
			wi->frag_page->frags++;
		goto wq_cyc_pop;
	}

	mlx5e_complete_rx_cqe(rq, cqe, cqe_bcnt, skb);

	if (mlx5e_cqe_regb_chain(cqe))
		if (!mlx5e_tc_update_skb_nic(cqe, skb)) {
			dev_kfree_skb_any(skb);
			goto wq_cyc_pop;
		}

	napi_gro_receive(rq->cq.napi, skb);

wq_cyc_pop:
	mlx5_wq_cyc_pop(wq);
}

static inline __attribute__((always_inline))
struct sk_buff *fs_create_skb_linear(struct mlxe_rq *rq, u32 index)
{
	struct sk_buff *skb = NULL;
	struct xdp_buff *xdp = QUEUE_GET_XDP_BUFF(rq, index);
	u16 rx_headroom =xdp->data - xdp->data_hard_start;
	u32 metasize = xdp->data - xdp->data_meta;
	u16 cqe_bcnt = xdp->data_end - xdp->data;
	void *va = xdp->data_hard_start;

	frag_size = MLX5_SKB_FRAG_SZ(rx_headroom + cqe_bcnt);
	skb = mlx5e_build_linear_skb(rq, va, frag_size, rx_headroom, cqe_bcnt,
			metasize);
	if (unlikely(!skb))
		return NULL;

	/* queue up for recycling/reuse */
	skb_mark_for_recycle(skb);
	frag_page->frags++;

	return skb;
}

static inline __attribute__((always_inline))
struct sk_buff *fs_create_skb_nonlinear(struct mlxe_rq *rq, u32 index)
{
	// unpack some state
	u32 act = rq->batch.actions[index];
	u8 flags = QUEUE_GET_XDP_STATE(rq, flags, index);
	struct mlx5e_wqe_frag_info *head_wi, *wi;
	wi = QUEUE_GET_XDP_STATE(rq, wi_wqe, index);
	head_wi = QUEUE_GET_XDP_STATE(rq, head_wi, index);
	struct xdp_buff *xdp = QUEUE_GET_XDP_BUFF(rq, index);

	if (act != XDP_PASS) {
		if (__test_and_clear_bit(MLX5E_RQ_FLAG_XDP_XMIT, rq->flags)) {
			struct mlx5e_wqe_frag_info *pwi;

			for (pwi = head_wi; pwi < wi; pwi++)
				pwi->frag_page->frags++;
		}
		return NULL; /* page/packet was consumed by XDP */
	}

	struct sk_buff *skb;
	skb = mlx5e_build_linear_skb(rq, xdp->data_hard_start, rq->buff.frame0_sz,
				     xdp->data - xdp->data_hard_start,
				     xdp->data_end - xdp->data,
				     xdp->data - xdp->data_meta);
	if (unlikely(!skb))
		return NULL;

	skb_mark_for_recycle(skb);
	head_wi->frag_page->frags++;

	if (xdp_buff_has_frags(xdp)) {
		struct skb_shared_info *sinfo;
		sinfo = xdp_get_shared_info_from_buff(xdp);
		u32 truesize = QUEUE_GET_XDP_STATE(rq, truesize, index);

		/* sinfo->nr_frags is reset by build_skb, calculate again. */
		xdp_update_skb_shared_info(skb, wi - head_wi - 1,
					   sinfo->xdp_frags_size, truesize,
					   xdp_buff_is_frag_pfmemalloc(xdp));

		for (struct mlx5e_wqe_frag_info *pwi = head_wi + 1; pwi < wi; pwi++)
			pwi->frag_page->frags++;
	}

	return skb;
}

// first half: below is code for before running the batch aware XDP program ---

static void fs_batch_desc_cqe_linear(struct mlx5e_rq *rq,
	struct mlx5e_wqe_frag_info *wi, struct mlx5_cqe64 *cqe, u32 cqe_bcnt)
{
	// farbod: remember which path we are taking
	u32 pkt_index = rq->xdp_rx_batch->batch.size;
	QUEUE_GET_XDP_STATE(rq, cqe_type, pkt_index) = cqe_is_linear;
	QUEUE_GET_XDP_STATE(rq, cqe, pkt_index) = cqe;
	QUEUE_GET_XDP_STATE(rq, wi_wqe, pkt_index) = wi;
	QUEUE_GET_XDP_STATE(rq, head_wi, pkt_index) = wi;

	struct mlx5e_frag_page *frag_page = wi->frag_page;
	u16 rx_headroom = rq->buff.headroom;
	struct bpf_prog *prog;
	struct sk_buff *skb;
	u32 metasize = 0;
	void *va, *data;
	dma_addr_t addr;
	u32 frag_size;

	va             = page_address(frag_page->page) + wi->offset;
	data           = va + rx_headroom;
	frag_size      = MLX5_SKB_FRAG_SZ(rx_headroom + cqe_bcnt);

	addr = page_pool_get_dma_addr(frag_page->page);
	dma_sync_single_range_for_cpu(rq->pdev, addr, wi->offset,
				      frag_size, rq->buff.map_dir);
	// defer prefetching to later (we are not running the XDP program now)
	// net_prefetch(data);

	// defer prefetching to later (we are not running the XDP program now)
	// net_prefetchw(va); /* xdp_frame data area */

	u32 frame_sz = rq->buff.frame0_sz;
	struct xdp_buff *xdp = QUEUE_GET_XDP_BUFF(rq, pkt_index);
	xdp_init_buff(xdp, frame_sz, &rq->xdp_rxq);
	xdp_prepare_buff(xdp, va, rx_headroom, cqe_bcnt, true);
	rq->buff.actions[pkt_index] = XDP_ABORTED;
	rq->buff.size++;
}

static void fs_batch_desc_cqe_nonlinear(struct mlx5e_rq *rq,
	struct mlx5e_wqe_frag_info *wi, struct mlx5_cqe64 *cqe, u32 cqe_bcnt)
{
	// farbod: remember which path we are taking
	u32 pkt_index = rq->xdp_rx_batch->batch.size;
	QUEUE_GET_XDP_STATE(rq, cqe_type, pkt_index) = cqe_is_nonlinear;
	QUEUE_GET_XDP_STATE(rq, cqe, pkt_index) = cqe;
	QUEUE_GET_XDP_STATE(rq, head_wi, pkt_index) = wi;

	struct mlx5e_rq_frag_info *frag_info = &rq->wqe.info.arr[0];
	struct mlx5e_wqe_frag_info *head_wi = wi;
	u16 rx_headroom = rq->buff.headroom;
	struct mlx5e_frag_page *frag_page;
	struct skb_shared_info *sinfo;
	struct mlx5e_xdp_buff mxbuf;
	u32 frag_consumed_bytes;
	struct bpf_prog *prog;
	struct sk_buff *skb;
	dma_addr_t addr;
	u32 truesize;
	void *va;

	frag_page = wi->frag_page;

	va = page_address(frag_page->page) + wi->offset;
	frag_consumed_bytes = min_t(u32, frag_info->frag_size, cqe_bcnt);

	addr = page_pool_get_dma_addr(frag_page->page);
	dma_sync_single_range_for_cpu(rq->pdev, addr, wi->offset,
				      rq->buff.frame0_sz, rq->buff.map_dir);

	u32 frame_sz = rq->buff.frame0_sz;
	struct xdp_buff *xdp = QUEUE_GET_XDP_BUFF(rq, pkt_index);
	xdp_init_buff(xdp, frame_sz, &rq->xdp_rxq);
	xdp_prepare_buff(xdp, va, rx_headroom, frag_consumed_bytes, true);

	sinfo = xdp_get_shared_info_from_buff(&mxbuf.xdp);
	truesize = 0;

	cqe_bcnt -= frag_consumed_bytes;
	frag_info++;
	wi++;

	while (cqe_bcnt) {
		frag_page = wi->frag_page;

		frag_consumed_bytes = min_t(u32, frag_info->frag_size, cqe_bcnt);

		mlx5e_add_skb_shared_info_frag(rq, sinfo, xdp, frag_page,
					       wi->offset, frag_consumed_bytes);
		truesize += frag_info->frag_stride;

		cqe_bcnt -= frag_consumed_bytes;
		frag_info++;
		wi++;
	}

	QUEUE_GET_XDP_STATE(rq, truesize, pkt_index) = truesize;
	QUEUE_GET_XDP_STATE(rq, wi_wqe, pkt_index) = wi;
	rq->buff.actions[pkt_index] = XDP_ABORTED;
	rq->buff.size++;
}

static void fs_handle_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	struct mlx5_wq_cyc *wq = &rq->wqe.wq;
	struct mlx5e_wqe_frag_info *wi;
	u32 cqe_bcnt;
	u16 ci;
	u32 pkt_index = rq->xdp_rx_batch->batch.size;

	ci       = mlx5_wq_cyc_ctr2ix(wq, be16_to_cpu(cqe->wqe_counter));
	wi       = get_frag(rq, ci);
	cqe_bcnt = be32_to_cpu(cqe->byte_cnt);

	if (unlikely(MLX5E_RX_ERR_CQE(cqe))) {
		rq->stats->wqe_err++;
		mlx5_wq_cyc_pop(wq);
		return;
	}

	QUEUE_GET_XDP_STATE(rq, cqe, pkt_index) = cqe_bcnt;

	if (rq->wq.skb_from_cqe == mlx5e_skb_from_cqe_linear) {
		fs_batch_desc_cqe_linear(rq, wi, cqe, cqe_bcnt);
	} else if (rq->wq.skb_from_cqe == mlx5e_skb_from_cqe_nonlinear) {
		fs_batch_desc_cqe_nonlinear(rq, wi, cqe, cqe_bcnt);
	} else {
		printk("XDP batch aware processing: unexpected skb_from_cqe function (in fs_hdndle_rx_cqe)\n");
		BUG_ON (true);
	}
}
#else
// Batch XDP is not enabled
#endif // CONFIG_XDP_BATCHING
#endif // EN_BATCH_XDP_CQE_H_
