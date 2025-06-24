#ifndef EN_BATCH_XDP_RQ_STATE_H_
#define EN_BATCH_XDP_RQ_STATE_H_
#ifdef CONFIG_XDP_BATCHING

enum cqe_type {
	cqe_is_linear,
	cqe_is_nonlinear,
};

// Farbod: this state thing looks ridiculous. Can I do better?
struct fs_mlx5_pre_pkt_state {
	// keep track of which buffer it was
	enum cqe_type cqe_type;
	struct mlx5_cqe64 *cqe;

	union {
		struct mlx5e_wqe_frag_info *wi_wqe; // used in normal CQE
		struct mlx5e_mpw_info *wi_mpw; // used in MPWRQ
	};

	union {
		struct mlx5e_wqe_frag_info *head_wi; // used in the cqe_nonlinear path
		struct {
			// used in MPWRQ
			u32 page_index; // indicates the offset into the strides
			u32 count_page; // indicates number of pages of strides used
		};
	};

	u32 cqe_bcnt;
	u32 truesize; // used in the cqe_nonlinear path
	// it is originally part of the mlx5e_rq but we need it per each pacekt
	DECLARE_BITMAP(flags, 8);
	u32 head_offset; // used in MPWRQ
};

struct mlx5_xdp_recv_batch {
	struct xdp_batch_buff batch;
	struct fs_mlx5_pre_pkt_state S[XDP_MAX_BATCH_SIZE];
};
#endif // CONFIG_XDP_BATCHING
#endif // EN_BATCH_XDP_RQ_STATE_H_
