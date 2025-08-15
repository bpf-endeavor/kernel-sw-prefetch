#ifndef EN_BATCH_XDP_MPWRQ_H_
#define EN_BATCH_XDP_MPWRQ_H_

#ifdef CONFIG_XDP_BATCHING

/* I'm not sure how exactly mpwrq works. But it seems as part of cleaning
 * proces we need to update a cursor. This code should do that for the work
 * queues we see while preparing a batch.
 *
 * Not all CQEs, and hence WQs we see are a packet (maybe there is an error or
 * ...) That is the reason we keep their state separate from batch of packets.
 * */
static void check_and_inc_mpwrq(struct mlx5e_rq *rq)
{
	u16 sz = rq->xdp_rx_batch->wqe_ids.size;
	for (u16 k = 0; k < sz; k++) {
		u16 wqe_id = rq->xdp_rx_batch->wqe_ids.id[k];
		struct mlx5e_mpw_info *wi = mlx5e_get_mpw_info(rq, wqe_id);

		if (likely(wi->consumed_strides < rq->mpwqe.num_strides))
			return;

		// we have released this work queue, do not repeat it if its id
		// is in the list multiple times.
		wi->consumed_strides = 0;

		struct mlx5_wq_ll *wq = &rq->mpwqe.wq;
		struct mlx5e_rx_wqe_ll *wqe = mlx5_wq_ll_get_wqe(wq, wqe_id);
		mlx5_wq_ll_pop(wq, be16_to_cpu(wqe_id), &wqe->next.next_wqe_index);
	}
}


// second half: functions below are called after we have run the batch aware
// XDP program --------------------------------------------------------------
//

static void fs_finilize_rx_cqe_mpwrq(struct mlx5e_rq *rq, int b_index,
		struct sk_buff *skb)
{
	if (!skb)
		return;

	struct mlx5_cqe64 *cqe = QUEUE_GET_XDP_STATE(rq, cqe, b_index);
	u32 cqe_bcnt = QUEUE_GET_XDP_STATE(rq, cqe_bcnt, b_index);

	mlx5e_complete_rx_cqe(rq, cqe, cqe_bcnt, skb);

	if (mlx5e_cqe_regb_chain(cqe)) {
		if (!mlx5e_tc_update_skb_nic(cqe, skb)) {
			dev_kfree_skb_any(skb);
			return;
		}
	}

	napi_gro_receive(rq->cq.napi, skb);
}

static
struct sk_buff *fs_create_skb_mpwrq_linear(struct mlx5e_rq *rq, u32 index)
{
	struct mlx5e_frag_page *frag_page;
	struct mlx5e_mpw_info *wi;
	u32 page_idx;

	u32 act = QUEUE_GET_XDP_ACT(rq, index);
	if (act != XDP_PASS) {

		// TODO: Is this the right place to free the page?
		if (act == XDP_DROP) {
			wi = QUEUE_GET_XDP_STATE(rq, wi_mpw, index);
			page_idx = QUEUE_GET_XDP_STATE(rq, page_index, index);
			frag_page = &wi->alloc_units.frag_pages[page_idx];
			frag_page->frags--;
			// TODO: do I need to free things here, or will the driver do it later?
			// if (frag_page->frags == 0) {
			// 	struct page* page = frag_page->page;
			// 	/* No need to check ((page->pp_magic & ~0x3UL) == PP_SIGNATURE)
			// 	 * as we know this is a page_pool page.
			// 	 */
			// 	page_pool_recycle_direct(page->pp, page);
			// }
		}

		return NULL; /* page/packet was consumed by XDP */
	}

	wi = QUEUE_GET_XDP_STATE(rq, wi_mpw, index);
	page_idx = QUEUE_GET_XDP_STATE(rq, page_index, index);
	frag_page = &wi->alloc_units.frag_pages[page_idx];

	struct xdp_buff *xdp = QUEUE_GET_XDP_BUFF(rq, index);

	u16 rx_headroom = xdp->data - xdp->data_hard_start;
	u32 metasize = xdp->data - xdp->data_meta;
	u16 cqe_bcnt = xdp->data_end - xdp->data;
	
	u32 frag_size = MLX5_SKB_FRAG_SZ(rx_headroom + cqe_bcnt);
	u32 head_offset = QUEUE_GET_XDP_STATE(rq, head_offset, index);
	void *va = page_address(frag_page->page) + head_offset;
	struct sk_buff *skb;
	skb = mlx5e_build_linear_skb(rq, va, frag_size, rx_headroom, cqe_bcnt,
			metasize);
	if (unlikely(!skb))
		return NULL;

	/* queue up for recycling/reuse */
	skb_mark_for_recycle(skb);
	/* frag_page->frags++; */

	return skb;
}

static
struct sk_buff *fs_create_skb_mpwrq_nolinear(struct mlx5e_rq *rq, u32 index)
{
	struct xdp_buff *xdp = QUEUE_GET_XDP_BUFF(rq, index);
	u32 act = QUEUE_GET_XDP_ACT(rq, index);
	u16 cqe_bcnt = QUEUE_GET_XDP_STATE(rq, cqe_bcnt, index);
	u16 headlen = min_t(u16, MLX5E_RX_MAX_HEAD, cqe_bcnt);
	u32 page_idx = QUEUE_GET_XDP_STATE(rq, page_index, index);
	u32 count_page = QUEUE_GET_XDP_STATE(rq, count_page, index);
	struct mlx5e_mpw_info *wi = QUEUE_GET_XDP_STATE(rq, wi_mpw, index);
	u32 truesize = QUEUE_GET_XDP_STATE(rq, truesize, index);

	struct mlx5e_frag_page *head_page = &wi->alloc_units.frag_pages[page_idx];
	struct mlx5e_frag_page *frag_page = head_page + count_page;

	if (act != XDP_PASS) {
		long unsigned int *flags_ptr = (long unsigned int *)&QUEUE_GET_XDP_STATE(rq, flags, index);
		if (__test_and_clear_bit(MLX5E_RQ_FLAG_XDP_XMIT, flags_ptr)) {
			struct mlx5e_frag_page *pfp;

			for (pfp = head_page; pfp < frag_page; pfp++)
				pfp->frags++;

			wi->linear_page.frags++;
		}
		mlx5e_page_release_fragmented(rq, &wi->linear_page);
		return NULL; /* page/packet was consumed by XDP */
	}

	struct sk_buff *skb;
	skb = mlx5e_build_linear_skb(rq, xdp->data_hard_start,
			xdp->frame_sz,
			xdp->data - xdp->data_hard_start, 0,
			xdp->data - xdp->data_meta);
	if (unlikely(!skb)) {
		mlx5e_page_release_fragmented(rq, &wi->linear_page);
		return NULL;
	}

	skb_mark_for_recycle(skb);
	wi->linear_page.frags++;
	mlx5e_page_release_fragmented(rq, &wi->linear_page);

	struct skb_shared_info *sinfo;
	sinfo = xdp_get_shared_info_from_buff(xdp);

	if (xdp_buff_has_frags(xdp)) {
		struct mlx5e_frag_page *pagep;

		/* sinfo->nr_frags is reset by build_skb, calculate again. */
		xdp_update_skb_shared_info(skb, frag_page - head_page,
				sinfo->xdp_frags_size, truesize,
				xdp_buff_is_frag_pfmemalloc(xdp));

		pagep = head_page;
		do
			pagep->frags++;
		while (++pagep < frag_page);
	}
	__pskb_pull_tail(skb, headlen);

	return skb;
}

// first half: below is code for before running the batch aware XDP program ---
static
void fs_batch_desc_mpwrq_nonlinear(struct mlx5e_rq *rq,
			struct mlx5e_mpw_info *wi, struct mlx5_cqe64 *cqe,
			u16 cqe_bcnt, u32 head_offset, u32 page_idx)
{
	// farbod: remember which path we are taking
	u32 pkt_index = rq->xdp_rx_batch->batch.size;
	XDP_BATCH_ASSERT(pkt_index < XDP_MAX_BATCH_SIZE);
	QUEUE_GET_XDP_STATE(rq, cqe_type, pkt_index) = cqe_is_nonlinear;
	QUEUE_GET_XDP_STATE(rq, wi_mpw, pkt_index) = wi;

	struct mlx5e_frag_page *frag_page = &wi->alloc_units.frag_pages[page_idx];
	u32 frag_offset    = head_offset;
	u32 byte_cnt       = cqe_bcnt;
	struct skb_shared_info *sinfo;
	unsigned int truesize = 0;
	u32 linear_frame_sz;
	u16 linear_data_len;
	u16 linear_hr;
	void *va;

	if (unlikely(mlx5e_page_alloc_fragmented(rq, &wi->linear_page))) {
		rq->stats->buff_alloc_err++;

		/* if (likely(wi->consumed_strides < rq->mpwqe.num_strides)) */
		/* 	return; */

		/* struct mlx5e_rx_wqe_ll *wqe; */
		/* struct mlx5_wq_ll *wq; */
		/* wq  = &rq->mpwqe.wq; */
		/* wqe = mlx5_wq_ll_get_wqe(wq, be16_to_cpu(cqe->wqe_id)); */
		/* mlx5_wq_ll_pop(wq, cqe->wqe_id, &wqe->next.next_wqe_index); */
		/* return; */
	}

	va = page_address(wi->linear_page.page);
	linear_hr = XDP_PACKET_HEADROOM;
	linear_data_len = 0;
	linear_frame_sz = MLX5_SKB_FRAG_SZ(linear_hr + MLX5E_RX_MAX_HEAD);

	struct xdp_buff *xdp = QUEUE_GET_XDP_BUFF(rq, pkt_index);
	xdp_init_buff(xdp, linear_frame_sz, &rq->xdp_rxq);
	xdp_prepare_buff(xdp, va, linear_hr, linear_data_len, true);

	sinfo = xdp_get_shared_info_from_buff(xdp);

	u32 k = 0;
	while (byte_cnt) {
		/* Non-linear mode, hence non-XSK, which always uses PAGE_SIZE. */
		u32 pg_consumed_bytes = min_t(u32, PAGE_SIZE - frag_offset, byte_cnt);

		if (test_bit(MLX5E_RQ_STATE_SHAMPO, &rq->state))
			truesize += pg_consumed_bytes;
		else
			truesize += ALIGN(pg_consumed_bytes, BIT(rq->mpwqe.log_stride_sz));

		mlx5e_add_skb_shared_info_frag(rq, sinfo, xdp, frag_page, frag_offset,
					       pg_consumed_bytes);
		byte_cnt -= pg_consumed_bytes;
		frag_offset = 0;
		frag_page++;
		k++;
	}

	QUEUE_GET_XDP_STATE(rq, count_page, pkt_index) = k;
	QUEUE_GET_XDP_STATE(rq, truesize, pkt_index) = truesize;
	QUEUE_GET_XDP_ACT(rq, pkt_index) = XDP_ABORTED;
	rq->xdp_rx_batch->batch.size++;
}

static
void fs_batch_desc_mpwrq_linear(struct mlx5e_rq *rq, struct mlx5e_mpw_info *wi,
				struct mlx5_cqe64 *cqe, u16 cqe_bcnt,
				u32 head_offset, u32 page_idx)
{
	// farbod: remember which path we are taking
	u32 pkt_index = rq->xdp_rx_batch->batch.size;
	XDP_BATCH_ASSERT(pkt_index < XDP_MAX_BATCH_SIZE);
	QUEUE_GET_XDP_STATE(rq, cqe_type, pkt_index) = cqe_is_linear;
	QUEUE_GET_XDP_STATE(rq, wi_mpw, pkt_index) = wi;
	QUEUE_GET_XDP_STATE(rq, count_page, pkt_index) = 1;

	struct mlx5e_frag_page *frag_page = &wi->alloc_units.frag_pages[page_idx];
	u16 rx_headroom = rq->buff.headroom;
	void *va, *data;
	dma_addr_t addr;
	u32 frag_size;

	/* Check packet size. Note LRO doesn't use linear SKB */
	if (unlikely(cqe_bcnt > rq->hw_mtu)) {
		rq->stats->oversize_pkts_sw_drop++;
		return;

		/* if (likely(wi->consumed_strides < rq->mpwqe.num_strides)) */
		/* 	return; */

		/* struct mlx5e_rx_wqe_ll *wqe; */
		/* struct mlx5_wq_ll *wq; */
		/* wq  = &rq->mpwqe.wq; */
		/* wqe = mlx5_wq_ll_get_wqe(wq, be16_to_cpu(cqe->wqe_id)); */
		/* mlx5_wq_ll_pop(wq, cqe->wqe_id, &wqe->next.next_wqe_index); */
		/* return; */
	}

	va             = page_address(frag_page->page) + head_offset;
	data           = va + rx_headroom;
	frag_size      = MLX5_SKB_FRAG_SZ(rx_headroom + cqe_bcnt);

	addr = page_pool_get_dma_addr(frag_page->page);
	dma_sync_single_range_for_cpu(rq->pdev, addr, head_offset,
				      frag_size, rq->buff.map_dir);

	struct xdp_buff *xdp = QUEUE_GET_XDP_BUFF(rq, pkt_index);
	u32 frame_sz = rq->buff.frame0_sz;
	xdp_init_buff(xdp, frame_sz, &rq->xdp_rxq);
	xdp_prepare_buff(xdp, va, rx_headroom, cqe_bcnt, true);

	QUEUE_GET_XDP_ACT(rq, pkt_index) = XDP_ABORTED;
	rq->xdp_rx_batch->batch.size++;
	// we are holding this page until we pass it to XDP
	frag_page->frags++;
}

static
void fs_handle_rx_cqe_mpwrq(struct mlx5e_rq *rq, struct mlx5_cqe64 *cqe)
{
	u16 cstrides       = mpwrq_get_cqe_consumed_strides(cqe);
	u16 wqe_id         = be16_to_cpu(cqe->wqe_id);
	struct mlx5e_mpw_info *wi = mlx5e_get_mpw_info(rq, wqe_id);
	u16 stride_ix      = mpwrq_get_cqe_stride_index(cqe);
	u32 wqe_offset     = stride_ix << rq->mpwqe.log_stride_sz;
	u32 head_offset    = wqe_offset & ((1 << rq->mpwqe.page_shift) - 1);
	u32 page_idx       = wqe_offset >> rq->mpwqe.page_shift;
	/* struct mlx5e_rx_wqe_ll *wqe; */
	/* struct mlx5_wq_ll *wq; */
	u16 cqe_bcnt;

	u16 tmp_index = rq->xdp_rx_batch->wqe_ids.size++;
	rq->xdp_rx_batch->wqe_ids.id[tmp_index] = wqe_id;

	wi->consumed_strides += cstrides;

	if (unlikely(MLX5E_RX_ERR_CQE(cqe))) {
		mlx5e_handle_rx_err_cqe(rq, cqe);
		/* if (likely(wi->consumed_strides < rq->mpwqe.num_strides)) */
		/* 	return; */

		/* wq  = &rq->mpwqe.wq; */
		/* wqe = mlx5_wq_ll_get_wqe(wq, wqe_id); */
		/* mlx5_wq_ll_pop(wq, cqe->wqe_id, &wqe->next.next_wqe_index); */
		return;
	}

	if (unlikely(mpwrq_is_filler_cqe(cqe))) {
		struct mlx5e_rq_stats *stats = rq->stats;

		stats->mpwqe_filler_cqes++;
		stats->mpwqe_filler_strides += cstrides;

		/* if (likely(wi->consumed_strides < rq->mpwqe.num_strides)) */
		/* 	return; */

		/* wq  = &rq->mpwqe.wq; */
		/* wqe = mlx5_wq_ll_get_wqe(wq, wqe_id); */
		/* mlx5_wq_ll_pop(wq, cqe->wqe_id, &wqe->next.next_wqe_index); */
		return;
	}

	cqe_bcnt = mpwrq_get_cqe_byte_cnt(cqe);

	u32 pkt_index = rq->xdp_rx_batch->batch.size;
	XDP_BATCH_ASSERT(pkt_index < XDP_MAX_BATCH_SIZE);
	QUEUE_GET_XDP_STATE(rq, cqe, pkt_index) = cqe;
	QUEUE_GET_XDP_STATE(rq, cqe_bcnt, pkt_index) = cqe_bcnt;
	QUEUE_GET_XDP_STATE(rq, page_index, pkt_index) = page_idx;
	QUEUE_GET_XDP_STATE(rq, head_offset, pkt_index) = head_offset;

	if (rq->mpwqe.skb_from_cqe_mpwrq == mlx5e_skb_from_cqe_mpwrq_linear) {
		// NOTE: In my test environment this is the path
		/* printk("mpwrq linear"); */
		fs_batch_desc_mpwrq_linear(rq, wi, cqe, cqe_bcnt, head_offset, page_idx);
	} else if (rq->mpwqe.skb_from_cqe_mpwrq == mlx5e_skb_from_cqe_mpwrq_nonlinear) {
		printk("mpwrq nonlinear");
		fs_batch_desc_mpwrq_nonlinear(rq, wi, cqe, cqe_bcnt, head_offset, page_idx);
	} else {
		// I have not implemented the mlx5e_xsk_skb_from_cqe_mpwrq_linear
		printk("XDP batch aware processing: unexpected skb_from_cqe function (in fs_hdndle_rx_cqe_mpwrq)\n");
		BUG_ON(true);
	}
}
#else
// Batch XDP is not enabled
#endif // CONFIG_XDP_BATCHING
#endif // EN_BATCH_XDP_MPWRQ_H_
