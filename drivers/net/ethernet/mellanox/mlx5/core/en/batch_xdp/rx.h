#ifndef FARBOD_MLX5E_BATCH_RX_H
#ifdef CONFIG_XDP_BATCHING

/*
 * June, 2025; Farbod:
 * This is my attempt in implementing a batch aware XDP interface for MLX5
 * driver. My understanding of the NIC-driver interaction is weak but Here some
 * notes (mostly to myself) about what I've learnt and want to do in this
 * implementation.
 *
 * == Disclaimer ==
 * What is wrong with my approach? I've  tried to apply changes to the driver
 * without fully understanding the intricacies of its communication protocol
 * with the hardware. I applied some general functions on the source code,
 * breaking and reorganizing the order of stuff. It does not grauntee the
 * correctnes. Making this work will be painful. I have commited time and
 * energy. Hopefully I won't regret it.
 *
 * == Execution Paths ==
 * The MLX5e original path is:
 *     poll_rx_cq -> process_basic/enhanced_cqe -> hdnle_rx_cqe ->
 *                                                          skb_from_cqe
 *
 * The idea is to change it as below when we have a batch aware xdp program:
 *     poll_rx_cq -> process_basic/enhanced_cqe -> handle_rx_cqe ->
 *       batch_desc -> run_xdp_batch_proc -> create_skb -> finalize processing
 *
 * There're multiple implementation of these functions based on flags and
 * enabled features. Descriptors we receave are either ``basic'' or ``enhanced''.
 *     - Basic: the descriptor may be ``compressed'' or not.
 *         - The CQE could have a ``linear'' payload or ``nonlinear''
 *     - Enhanced: -- to be writtn --
 *
 * == Code Organization ==
 * - poll_rx_cq is just an entry function. it is called by the NAPI subsystem,
 *   and if there is a batch aware XDP program attached, the control flow is
 *   diverted to here.
 *
 * - ``process cqe'' functions loop over the batch of CQE and call appropriate
 *   handlers. Notice that ``work_done'' counter maintained in the loop does
 *   not represent the number of packets we have in the batch. Some of the CQEs
 *   are for reporting errors and or other controlling messages.
 *
 *   In ``process cqe'' functions, after getting the CQE the ``wq->cc'' is
 *   increased (e.g., by calling mlx5_wq_ll_pop) which means at next iteration,
 *   we are fetching the next CQE.
 *       -- NOTE: it seams the mpwrq (or striding rq) is similar to what X2DP
 *          is doing. It allows multiple packets to be placed on a large buffer.
 *
 * - ``handle_rx_cqe'' converts a CQE to a DMAed memory address (it is
 *   completed when in batch_desc)
 *
 * - ``batch desc'' The batching function should prepare the rq.xdp_rx_batch
 *    invoking the batch aware XDP program
 * */

/* These macros help with packig/unpackig state of each packet in the batch */
#define QUEUE_GET_XDP_STATE(rq, name, i) rq->xdp_rx_batch->S[i].name
#define QUEUE_GET_XDP_BUFF(rq, i) &rq->xdp_rx_batch->batch.buffs[i]
#define QUEUE_GET_XDP_ACT(rq, i) rq->xdp_rx_batch->batch.actions[i]

// move the MPWRQ CQE handling to another file to avoid confusion
#include "en/batch_xdp/mpwrq.h"
// move the normal CQE handling to another file to avoid confusion
#include "en/batch_xdp/cqe.h"

static inline __attribute__((always_inline))
void clear_the_batch(struct mlx5e_rq *rq)
{
	rq->xdp_rx_batch->batch.size = 0;
}

static
void fs_indirect_call_finalize_rx_cqe(struct mlx5e_rq *rq, struct mlx5_cqwq *cqwq)
{
	u32 sz = rq->xdp_rx_batch->batch.size;
	struct sk_buff *skb;

	if (rq->handle_rx_cqe == mlx5e_handle_rx_cqe_mpwrq) {
		for (int i = 0; i < sz; i++) {
			enum cqe_type cqe_type = QUEUE_GET_XDP_STATE(rq, cqe_type, i);
			if (cqe_type == cqe_is_linear) {
				skb = fs_create_skb_mpwrq_linear(rq, i);
			} else {
				skb = fs_create_skb_mpwrq_nolinear(rq, i);
			}
			fs_finilize_rx_cqe_mpwrq(rq, i, skb);
		}
	} else if (rq->handle_rx_cqe == mlx5e_handle_rx_cqe) {
		for (int i = 0; i < sz; i++) {
			// continue creating SKB from XDP descriptor
			enum cqe_type cqe_type = QUEUE_GET_XDP_STATE(rq, cqe_type, i);
			if (cqe_type == cqe_is_linear) {
				skb = fs_create_skb_linear(rq, i);
			} else {
				skb = fs_create_skb_nonlinear(rq, i);
			}
			// process the SKB through the network stack
			fs_finilize_rx_cqe(rq, i, skb);
		}
	} else {
		// there is the fs_finilize_rx_cqe_mpwrq_shampo(rq, i)
		// there is a handle_rx_cqe_rep, are there more?
		printk("XDP batch aware processing: unexpected rx handler, finalize\n");
		BUG_ON (true);
	}

	// It is important to reset the number of descriptors in the batch
	clear_the_batch(rq);
}

/* Check which function was being called before and select the
 * related batching function.
 *
 * (I guess this function is better to be inlined.)
 * */
static inline __attribute__((always_inline))
void fs_indirect_call_handle_rx_cqe(struct mlx5e_rq *rq,
		struct mlx5_cqe64 *cqe)
{
	if (rq->handle_rx_cqe == mlx5e_handle_rx_cqe_mpwrq) {
		fs_handle_rx_cqe_mpwrq(rq, cqe);
	} else if (rq->handle_rx_cqe == mlx5e_handle_rx_cqe) {
		fs_handle_rx_cqe(rq, cqe);
	} else {
		// There is the fs_batch_rx_cqe_mpwrq_shampo(rq, cqe)
		// There is a handle_rx_cqe_rep, are there more?
		printk("XDP batch aware processing: unexpected rx handler\n");
		BUG_ON (true);
	}
}

static int process_enhanced_cqe_comp(struct mlx5e_rq *rq,
						 struct mlx5_cqwq *cqwq, int budget_rem)
{
	struct mlx5_cqe64 *cqe, *title_cqe = NULL;
	struct mlx5e_cq_decomp *cqd = &rq->cqd;
	int work_done = 0;

	cqe = mlx5_cqwq_get_cqe_enhanced_comp(cqwq);
	if (!cqe)
		return work_done;

	if (cqd->last_cqe_title &&
	    (mlx5_get_cqe_format(cqe) == MLX5_COMPRESSED)) {
		rq->stats->cqe_compress_blks++;
		cqd->last_cqe_title = false;
	}

	do {
		if (mlx5_get_cqe_format(cqe) == MLX5_COMPRESSED) {
			if (title_cqe) {
				mlx5e_read_enhanced_title_slot(rq, title_cqe);
				title_cqe = NULL;
				rq->stats->cqe_compress_blks++;
			}
			work_done +=
				mlx5e_decompress_enhanced_cqe(rq, cqwq, cqe,
							      budget_rem - work_done);
			continue;
		}
		title_cqe = cqe;
		mlx5_cqwq_pop(cqwq);

		fs_indirect_call_handle_rx_cqe(rq, cqe);
		work_done++;
	} while (work_done < budget_rem &&
		 (cqe = mlx5_cqwq_get_cqe_enhanced_comp(cqwq)));

	/* last cqe might be title on next poll bulk */
	if (title_cqe) {
		mlx5e_read_enhanced_title_slot(rq, title_cqe);
		cqd->last_cqe_title = true;
	}

	return work_done;
}

static inline u32 fs_mlx5e_decompress_cqes_cont(struct mlx5e_rq *rq,
				 struct mlx5_cqwq *wq, int update_owner_only, int budget_rem)
{
	struct mlx5e_cq_decomp *cqd = &rq->cqd;
	u32 cqcc = wq->cc + update_owner_only;
	u32 cqe_count;
	u32 i;

	cqe_count = min_t(u32, cqd->left, budget_rem);

	for (i = update_owner_only; i < cqe_count;
	     i++, cqd->mini_arr_idx++, cqcc++) {
		if (cqd->mini_arr_idx == MLX5_MINI_CQE_ARRAY_SIZE)
			mlx5e_read_mini_arr_slot(wq, cqd, cqcc);

		mlx5e_decompress_cqe_no_hash(rq, wq, cqcc);
		fs_indirect_call_handle_rx_cqe(rq, &cqd->title);
	}
	mlx5e_cqes_update_owner(wq, cqcc - wq->cc);
	wq->cc = cqcc;
	cqd->left -= cqe_count;
	rq->stats->cqe_compress_pkts += cqe_count;

	return cqe_count;
}

static inline
u32 fs_mlx5e_decompress_cqes_start(struct mlx5e_rq *rq, struct mlx5_cqwq *wq,
		int budget_rem)
{
	struct mlx5e_cq_decomp *cqd = &rq->cqd;
	u32 cc = wq->cc;

	mlx5e_read_title_slot(rq, wq, cc);
	mlx5e_read_mini_arr_slot(wq, cqd, cc + 1);
	mlx5e_decompress_cqe(rq, wq, cc);

	fs_indirect_call_handle_rx_cqe(rq, &cqd->title);
	cqd->mini_arr_idx++;

	return fs_mlx5e_decompress_cqes_cont(rq, wq, 1, budget_rem);
}

static
int process_basic_cqe_comp(struct mlx5e_rq *rq, struct mlx5_cqwq *cqwq,
		int budget_rem)
{
	struct mlx5_cqe64 *cqe;
	int work_done = 0;

	if (rq->cqd.left)
		work_done += mlx5e_decompress_cqes_cont(rq, cqwq, 0, budget_rem);

	while (work_done < budget_rem && (cqe = mlx5_cqwq_get_cqe(cqwq))) {
		if (mlx5_get_cqe_format(cqe) == MLX5_COMPRESSED) {
			work_done +=
				fs_mlx5e_decompress_cqes_start(rq, cqwq,
							    budget_rem - work_done);
			continue;
		}

		mlx5_cqwq_pop(cqwq);
		fs_indirect_call_handle_rx_cqe(rq, cqe);
		work_done++;
	}

	return work_done;
}

// Maximum value is limited by the XDP_MAX_BATCH_SIZE
#define MLX5_XDP_BATCH_SIZE 8
static_assert(MLX5_XDP_BATCH_SIZE <= XDP_MAX_BATCH_SIZE);

/* Entry function of xdp batching feature
 * @param rq: rx queue
 * ...
 * @param prog: a batch aware XDP program attached to rx queue
 * */
static int batch_xdp_poll_rx_cq(struct mlx5e_rq *rq, struct mlx5_cqwq *cqwq,
		int budget, struct bpf_prog *prog)
{
	u32 work_done = 0;
	// TODO: check if this looping helps or not
	while (work_done < budget) {
		u32 w = 0;
		u32 mini_budget = min_t(u32, budget - work_done, MLX5_XDP_BATCH_SIZE);

		if (test_bit(MLX5E_RQ_STATE_MINI_CQE_ENHANCED, &rq->state)) {
			w = process_enhanced_cqe_comp(rq, cqwq, mini_budget);
		} else {
			w = process_basic_cqe_comp(rq, cqwq, mini_budget);
		}

		if (w == 0) {
			// if there are no more work to do, then terminate the NAPI
			break;
		}
		work_done += w;

		// prefetch the packets
		struct xdp_batch_buff *batch = &rq->xdp_rx_batch->batch;
		for (int i = 0; i < batch->size; i++) {
			net_prefetch(batch->buffs[i].data);
			net_prefetch(batch->buffs[i].data_hard_start);
		}

		// run the batch aware XDP program
		bpf_prog_run(prog, batch);

		// create the SKBs and pass packets to network stack (or not if XDP has
		// consumed it)
		fs_indirect_call_finalize_rx_cqe(rq, cqwq);
	}
	return work_done;
}
#else
// this feature is disabled at compile time
#endif // CONFIG_XDP_BATCHING
#endif // FARBOD_MLX5E_BATCH_RX_H

