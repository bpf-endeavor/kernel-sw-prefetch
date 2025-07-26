#ifndef FARBOD_MLX5E_BATCH_XDP_HELPER_H
#define FARBOD_MLX5E_BATCH_XDP_HELPER_H

/* This file has some xdp helpers, mainly from /en/xdp.c file that is used in
 * batch aware interface
 * */

#ifdef CONFIG_XDP_BATCHING

#include "en/xdp.h"

static inline bool
mlx5e_xmit_xdp_buff(struct mlx5e_xdpsq *sq, struct mlx5e_rq *rq,
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
		/* The xdp_buff was in the UMEM and was copied into a newly
		 * allocated page. The UMEM page was returned via the ZCA, and
		 * this new page has to be mapped at this point and has to be
		 * unmapped and returned via xdp_return_frame on completion.
		 */

		/* Prevent double recycling of the UMEM page. Even in case this
		 * function returns false, the xdp_buff shouldn't be recycled,
		 * as it was already done in xdp_convert_zc_to_xdp_frame.
		 */
		__set_bit(MLX5E_RQ_FLAG_XDP_XMIT, rq->flags); /* non-atomic */

		if (unlikely(xdptxd->has_frags))
			return false;

		dma_addr = dma_map_single(sq->pdev, xdptxd->data, xdptxd->len,
					  DMA_TO_DEVICE);
		if (dma_mapping_error(sq->pdev, dma_addr)) {
			xdp_return_frame(xdpf);
			return false;
		}

		xdptxd->dma_addr = dma_addr;

		if (unlikely(!INDIRECT_CALL_2(sq->xmit_xdp_frame, mlx5e_xmit_xdp_frame_mpwqe,
					      mlx5e_xmit_xdp_frame, sq, xdptxd, 0, NULL)))
			return false;

		/* xmit_mode == MLX5E_XDP_XMIT_MODE_FRAME */
		mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
				     (union mlx5e_xdp_info) { .mode = MLX5E_XDP_XMIT_MODE_FRAME });
		mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
				     (union mlx5e_xdp_info) { .frame.xdpf = xdpf });
		mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
				     (union mlx5e_xdp_info) { .frame.dma_addr = dma_addr });
		return true;
	}

	/* Driver assumes that xdp_convert_buff_to_frame returns an xdp_frame
	 * that points to the same memory region as the original xdp_buff. It
	 * allows to map the memory only once and to use the DMA_BIDIRECTIONAL
	 * mode.
	 */

	dma_addr = page_pool_get_dma_addr(page) + (xdpf->data - (void *)xdpf);
	dma_sync_single_for_device(sq->pdev, dma_addr, xdptxd->len, DMA_BIDIRECTIONAL);

	if (xdptxd->has_frags) {
		xdptxdf.sinfo = xdp_get_shared_info_from_frame(xdpf);
		xdptxdf.dma_arr = NULL;

		for (i = 0; i < xdptxdf.sinfo->nr_frags; i++) {
			skb_frag_t *frag = &xdptxdf.sinfo->frags[i];
			dma_addr_t addr;
			u32 len;

			addr = page_pool_get_dma_addr(skb_frag_page(frag)) +
				skb_frag_off(frag);
			len = skb_frag_size(frag);
			dma_sync_single_for_device(sq->pdev, addr, len,
						   DMA_BIDIRECTIONAL);
		}
	}

	xdptxd->dma_addr = dma_addr;

	if (unlikely(!INDIRECT_CALL_2(sq->xmit_xdp_frame, mlx5e_xmit_xdp_frame_mpwqe,
				      mlx5e_xmit_xdp_frame, sq, xdptxd, 0, NULL)))
		return false;

	/* xmit_mode == MLX5E_XDP_XMIT_MODE_PAGE */
	mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
			     (union mlx5e_xdp_info) { .mode = MLX5E_XDP_XMIT_MODE_PAGE });

	if (xdptxd->has_frags) {
		mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
				     (union mlx5e_xdp_info)
				     { .page.num = 1 + xdptxdf.sinfo->nr_frags });
		mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
				     (union mlx5e_xdp_info) { .page.page = page });
		for (i = 0; i < xdptxdf.sinfo->nr_frags; i++) {
			skb_frag_t *frag = &xdptxdf.sinfo->frags[i];

			mlx5e_xdpi_fifo_push(&sq->db.xdpi_fifo,
					     (union mlx5e_xdp_info)
					     { .page.page = skb_frag_page(frag) });
		}
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
