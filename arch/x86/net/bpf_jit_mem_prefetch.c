#include "bpf_jit_mem_prefetch.h"
#include <linux/proc_fs.h>

#ifdef CONFIG_BPF_JIT_PREFETCH

typedef struct bpf_prog *(*prefetch_fn)(struct bpf_prog *prog);
struct prefetching_algo {
	const char *name;
	prefetch_fn fn;
};

static struct bpf_prog *__prefetch_k_before(struct bpf_prog *prog);
static struct bpf_prog *__prefetch_next_packet(struct bpf_prog *prog);

/*
 * Expose  /proc/bpf_jit_sw_prefetch_* file to control some paramters.
 * ===========================================================================
 * */
static bool is_sw_prefetching_enable = false;
static int sw_prefetch_k = 3;
static int sw_prefetch_mbuf_size = 4096;

/* Using this function pointer to control which algorithm we are using */
#define COUNT_ALGO 2
static int sw_prefetch_algo_index = 0;
static struct prefetching_algo algorithms[COUNT_ALGO] = {
	{.name = "K-Before", .fn = __prefetch_k_before,},
	{.name = "Next-Pkt", .fn = __prefetch_next_packet,},
};

static ssize_t _write_sw_prefetch(struct file *file, const char __user *ubuf,
		size_t count, loff_t *ppos)
{
	int num, i, c;
	char buf[32];
	if(*ppos > 0 || count > 32)
		return -EFAULT;
	if(copy_from_user(buf, ubuf, count))
		return -EFAULT;
	num = sscanf(buf, "%d", &i);
	if(num != 1)
		return -EFAULT;
	if (i > 0)
		is_sw_prefetching_enable = true;
	if (i < 1)
		is_sw_prefetching_enable = false;
	c = strnlen(buf, 32);
	*ppos = c;
	return c;
}

static ssize_t _read_sw_prefetch(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char buf[32];
	int len=0;
	if(*ppos > 0 || count < 32)
		return 0;
	int i = is_sw_prefetching_enable ? 1 : 0;
	len += sprintf(buf,"sw-prefetch-enable = %d\n", i);
	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static struct proc_ops _sw_prefetch_enable_proc_file_op =
{
	.proc_read = _read_sw_prefetch,
	.proc_write = _write_sw_prefetch,
};

static ssize_t _write_sw_prefetch_k(struct file *file, const char __user *ubuf,
		size_t count, loff_t *ppos)
{
	int num, i, c;
	char buf[32];
	if(*ppos > 0 || count > 32)
		return -EFAULT;
	if(copy_from_user(buf, ubuf, count))
		return -EFAULT;
	num = sscanf(buf, "%d", &i);
	if(num != 1)
		return -EFAULT;
	if (i < 1)
		return -EFAULT;
	sw_prefetch_k = i;
	c = strnlen(buf, 32);
	*ppos = c;
	return c;
}

static ssize_t _read_sw_prefetch_k(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char buf[32];
	int len=0;
	if(*ppos > 0 || count < 32)
		return 0;
	len += sprintf(buf,"sw-prefetch-k = %d\n", sw_prefetch_k);
	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static struct proc_ops _sw_prefetch_k_proc_file_op =
{
	.proc_read = _read_sw_prefetch_k,
	.proc_write = _write_sw_prefetch_k,
};

static ssize_t _write_sw_prefetch_algol(struct file *file, const char __user *ubuf,
		size_t count, loff_t *ppos)
{
	int num, i, c;
	char buf[32];
	if(*ppos > 0 || count > 32)
		return -EFAULT;
	if(copy_from_user(buf, ubuf, count))
		return -EFAULT;
	num = sscanf(buf, "%d", &i);
	if(num != 1)
		return -EFAULT;
	if (i < 0 || i >= COUNT_ALGO)
		return -EFAULT;
	sw_prefetch_algo_index = i;
	c = strnlen(buf, 32);
	*ppos = c;
	return c;
}

static ssize_t _read_sw_prefetch_algol(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	char buf[256];
	int len=0;
	if (*ppos > 0 || count < 32)
		return 0;
	len += sprintf(buf,
			"sw-prefetch-algol = %s\n0: K-before\n1: Next-Pkt\n",
			algorithms[sw_prefetch_algo_index].name);
	if (copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static struct proc_ops _sw_prefetch_algol_proc_file_op =
{
	.proc_read = _read_sw_prefetch_algol,
	.proc_write = _write_sw_prefetch_algol,
};

static void __initialize_prefetching_proc(void)
{
	struct proc_dir_entry *ent;
	ent = proc_create("bpf_jit_sw_prefetch_enable", 0660, NULL,
				&_sw_prefetch_enable_proc_file_op);
	if (ent == NULL) {
		printk("Failed to create /proc/bpf_jit_sw_prefetch_enable\n");
	}

	ent = proc_create("bpf_jit_sw_prefetch_k", 0660, NULL,
				&_sw_prefetch_k_proc_file_op);
	if (ent == NULL) {
		printk("Failed to create /proc/bpf_jit_sw_prefetch_k\n");
	}

	ent = proc_create("bpf_jit_sw_prefetch_algol", 0660, NULL,
				&_sw_prefetch_algol_proc_file_op);
	if (ent == NULL) {
		printk("Failed to create /proc/bpf_jit_sw_prefetch_algol\n");
	}
}
/* ========================================================================= */

/* Extended instruction are 16 bytes (multiple struct bpf_insn). We should be
 * careful not to insert prefetch in between of them.
 * */
static bool __is_extended_insn(struct bpf_insn *insn)
{
	switch(BPF_CLASS(insn->code)) {
		case BPF_ALU64: /* fallthrough */
		case BPF_JMP:
			return true;
			break;
		case BPF_LD:  /* fallthrough */
		case BPF_LDX: /* fallthrough */
		case BPF_ST:  /* fallthrough */
		case BPF_STX:
			if (BPF_SIZE(insn->code) == BPF_DW)
				return true;
			break;
		default:
			return false;
	}
	return false;
}

static int
__find_latest_reg_assign(struct bpf_prog *prog, int end_index, __u8 reg,
		int *index_out)
{
	if (end_index > prog->len || reg > __MAX_BPF_REG) {
		return -EINVAL;
	}
	/* some registers are set in the prologue.
	 * If we do not find an assignment to the register, then the register
	 * can be used for prefetching from begining of the program.
	 * */
	int match = 0;
	struct bpf_insn *insn = prog->insnsi;
	for (int i = 0; i < end_index; i++, insn++) {
		if (insn->dst_reg != reg)
			continue;
		int op = insn->code;
		if (BPF_CLASS(op) != BPF_LDX && BPF_CLASS(op) != BPF_ALU &&
				BPF_CLASS(op) != BPF_ALU64) {
			continue;
		}
		match = i;
	}
	*index_out = match;
	return 0;
}

static inline void
__prepare_prefetch_inst(struct bpf_insn *p, struct bpf_insn *load)
{
	p->code = BPF_PREFETCH;
	p->dst_reg = 0x0;
	p->src_reg = load->src_reg;
	p->off = load->off;
	p->imm = 0;
}

static struct bpf_prog *__bpf_prog_clone_create(struct bpf_prog *fp_other,
					      gfp_t gfp_extra_flags)
{
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO | gfp_extra_flags;
	struct bpf_prog *fp;

	fp = __vmalloc((fp_other->pages) * PAGE_SIZE, gfp_flags);
	if (fp != NULL) {
		/* aux->prog still points to the fp_other one, so
		 * when promoting the clone to the real program,
		 * this still needs to be adapted.
		 * */
		memcpy(fp, fp_other, fp_other->pages * PAGE_SIZE);
	}

	return fp;
}

static int __fix_prev_inst_jmp_if_needed(struct bpf_insn *insn)
{
	/* Currently there is no helper function to just insert a new
	 * instruction to the list of programs. To have an insert effect we
	 * submit a patch of size two with first instruciton being the old
	 * instruction after which the new instruction will be added. The
	 * second instruciton of the patch is what we actually are inserting.
	 *
	 * This causes trouble when the first/old instruction is a jump/call.
	 * because the helpers assume these instructions do not need
	 * modification, we need to update the jump address ourself. This is
	 * what this function is doing.
	 * */
	if (bpf_pseudo_func(insn)) {
		if (insn->imm <= 0)
			return 0; /* nothing to do */
		if (((s64)insn->imm) + 1 > S32_MAX) {
			/* overflow will occur */
			return -ERANGE;
		}
		insn->imm += 1;
		return 0; /* okay */
	}
	u8 code = insn->code;
	if ((BPF_CLASS(code) != BPF_JMP && BPF_CLASS(code) != BPF_JMP32) ||
			BPF_OP(code) == BPF_EXIT) {
		return 0; /* nothing to do */
	}
	/* Adjust offset of jmps if we cross patch boundaries. */
	if (BPF_OP(code) == BPF_CALL) {
		if (insn->src_reg != BPF_PSEUDO_CALL)
			return 0; /* nothing to do */
		if (insn->imm <= 0)
			return 0; /* nothing to do */
		if (((s64)insn->imm) + 1 > S32_MAX) {
			/* overflow will occur */
			return -ERANGE;
		}
		insn->imm += 1;
	} else {
		s64 off_max, off;

		if (insn->code == (BPF_JMP32 | BPF_JA)) {
			off = insn->imm;
			off_max = S32_MAX;
		} else {
			off = insn->off;
			off_max = S16_MAX;
		}

		if (off <= 0)
			return 0; /* nothing to do */
		off += 1;

		if (off > off_max)
			return -ERANGE;
		if (insn->code == (BPF_JMP32 | BPF_JA))
			insn->imm = off;
		else
			insn->off = off;
	}
	return 0;
}

static struct bpf_prog *__prefetch_k_before(struct bpf_prog *prog)
{
	if (prog->len == 0 || prog->sw_prefetch)
		return prog;

	int ret = 0;
	int insn_cnt = 0;
	struct bpf_prog *clone = NULL;
	struct bpf_prog *tmp = NULL;
	struct bpf_insn *insn = NULL;
	struct bpf_insn insn_buff[2];

	memset(insn_buff, 0, sizeof(insn_buff));

	/* Clone bpf_prog structure */
	clone = __bpf_prog_clone_create(prog, GFP_USER);
	if (!clone) {
		printk("bpf_jit_prefetch: failed to clone the program\n");
		return ERR_PTR(-ENOMEM);
	}
	insn_cnt = clone->len;
	insn = clone->insnsi;

	/* Go through instructions. Find instructions that load from memory.
	 * Find the latest assignment to the base register they use.
	 * If the distance between assignment and load instruction is more than
	 * K, then attempt to prefetch the memory address K instruction before
	 * loading it.
	 * */
	for (int i = 0; i < insn_cnt; i++, insn++) {
		__u8 opcode = insn->code;
		if (!(  opcode == (BPF_LDX | BPF_MEM | BPF_DW) ||
			opcode == (BPF_LDX | BPF_MEM | BPF_W)  ||
			opcode == (BPF_LDX | BPF_MEM | BPF_H)  ||
			opcode == (BPF_LDX | BPF_MEM | BPF_B) )) {
			continue;
		}
		/* The operation is: dst = *(unsigned size *) (src + offset)
		 * we are attempting to prefetch (src + offset).
		 * */
		int ass_index = -1;
		ret = __find_latest_reg_assign(clone, i, insn->src_reg,
				&ass_index);
		if (ret != 0) {
			printk("Unexpected: Failed to find the latest assignment to register!\n");
			continue;
		}
		__u16 dist = i - ass_index;
		/* printk("Load inst distance from last assignment is %u [ass: %d  cur: %d] (reg: %d)\n", dist, ass_index, i, insn->src_reg); */
		if (dist < sw_prefetch_k)
			continue;
		/* ideally we want to insert the prefetch K instruction before
		 * load, it is possible for the K-before instruction to be 64-bit.
		 * If the load instrution is 64-bit we must move further back.
		 * Otherwise we split the wide instruction (64-bit instruction
		 * is built from two instruction next to each other) corrupting
		 * the values.
		 *
		 * We must make sure that we do not go further back than
		 * assignment instruction.
		 * */
		int insn_off = i - sw_prefetch_k;
		while(__is_extended_insn(&clone->insnsi[insn_off]) &&
				ass_index < insn_off) {
			insn_off--;
		}
		if (insn_off <= ass_index) {
			/* Did not found a suitable position */
			continue;
		}
		memcpy(&insn_buff[0], &clone->insnsi[insn_off],
				sizeof(struct bpf_insn));
		ret = __fix_prev_inst_jmp_if_needed(&insn_buff[0]);
		if (ret != 0) {
			/* Overflow when updating jump/call
			 * Ignore this prefetching opportunity (I am not sure
			 * if moving further back is a good idea or not)
			 * */
			continue;
		}
		__prepare_prefetch_inst(&insn_buff[1], insn);
		const int rewritten = 2;
		/* Replace instruction at target offset with itself and a
		 * prefetch instruction
		 * */
		tmp = bpf_patch_insn_single(clone /* program */,
				insn_off  /* replace offset */,
				insn_buff /* instructions to overwrite */,
				rewritten /*number of instructions */);
		if (IS_ERR(tmp)) {
			printk("bpf_jit_prefetch: failed to patch the instructions\n");
			bpf_jit_prog_release_other(prog, clone);
			return tmp;
		}
		clone = tmp;
		int insn_delta = rewritten - 1;
		/* Update the insn pointer to the new instruction array (and
		 * correct position).
		 * */
		insn = clone->insnsi + i + insn_delta;
		insn_cnt += insn_delta;
		i += insn_delta;
	}

	clone->sw_prefetch = 1;
	/* printk("The new program has %d instructions (orig: %d)", clone->len, prog->len); */
	return clone;
}

/* XDP_MD buffers are allocated from a ring and each element is 4096 bytes
 * */
static struct bpf_prog *__prefetch_next_packet(struct bpf_prog *prog)
{
	if (prog->len == 0 || prog->sw_prefetch)
		return prog;

	/* int ret = 0; */
	int insn_cnt = 0;
	struct bpf_prog *clone = NULL;
	struct bpf_prog *tmp = NULL;
	struct bpf_insn *insn = NULL;
	struct bpf_insn insn_buff[2];

	memset(insn_buff, 0, sizeof(insn_buff));

	/* Clone bpf_prog structure */
	clone = __bpf_prog_clone_create(prog, GFP_USER);
	if (!clone) {
		printk("bpf_jit_prefetch: failed to clone the program\n");
		return ERR_PTR(-ENOMEM);
	}
	insn_cnt = clone->len;
	insn = clone->insnsi;

	/* Go through instructions. Find instructions that load from memory.
	 * Find the latest assignment to the base register they use.
	 * If the distance between assignment and load instruction is more than
	 * K, then attempt to prefetch the memory address K instruction before
	 * loading it.
	 * */
	for (int i = 0; i < insn_cnt; i++, insn++) {
		__u8 opcode = insn->code;
		if (!(  opcode == (BPF_LDX | BPF_MEM | BPF_DW) ||
			opcode == (BPF_LDX | BPF_MEM | BPF_W)  ||
			opcode == (BPF_LDX | BPF_MEM | BPF_H)  ||
			opcode == (BPF_LDX | BPF_MEM | BPF_B) )) {
			continue;
		}
		/* The operation is: dst = *(unsigned size *) (src + offset)
		 * we prefetch src + [THE ASSUMED PACKET RING ELEMENT SIZE] + offset.
		 * */
		memcpy(&insn_buff[0], &clone->insnsi[i],
				sizeof(struct bpf_insn));
		/* NOTE: We are sure the insn_buff[0] does not requre fixing */
		__prepare_prefetch_inst(&insn_buff[1], insn);
		/* NOTE: when current packet is the last one in the ring we
		 * will prefetch a wrong address
		 * */
		insn_buff[0].off += sw_prefetch_mbuf_size;
		const int rewritten = 2;
		/* Replace instruction at target offset with itself and a
		 * prefetch instruction
		 * */
		tmp = bpf_patch_insn_single(clone /* program */,
				i  /* replace offset */,
				insn_buff /* instructions to overwrite */,
				rewritten /*number of instructions */);
		if (IS_ERR(tmp)) {
			printk("bpf_jit_prefetch: failed to patch the instructions\n");
			bpf_jit_prog_release_other(prog, clone);
			return tmp;
		}
		clone = tmp;
		int insn_delta = rewritten - 1;
		/* Update the insn pointer to the new instruction array (and
		 * correct position).
		 * */
		insn = clone->insnsi + i + insn_delta;
		insn_cnt += insn_delta;
		i += insn_delta;
	}

	clone->sw_prefetch = 1;
	/* printk("The new program has %d instructions (orig: %d)", clone->len, prog->len); */
	return clone;
}

struct bpf_prog *bpf_x86_jit_mem_prefetch(struct bpf_prog *prog)
{
	static int __first_time_running_prefetch = 1;
	if (__first_time_running_prefetch == 1) {
		__first_time_running_prefetch = 0;
		__initialize_prefetching_proc();
	}

	/* NOTE: Limit prefetching to XDP programs for now. */
	if (prog->type != BPF_PROG_TYPE_XDP || !is_sw_prefetching_enable) {
		return prog;
	}

	int original_len = prog->len;
	struct bpf_prog *tmp = algorithms[sw_prefetch_algo_index].fn(prog);
	if (IS_ERR(tmp)) {
		printk("Failed in JIT prefetch pass\n");
		return prog;
	}
	printk("Farbod: at JIT prefetch pass: orig insn_cnt: %d  new insn_cnt: %d  changes: %d\n",
		original_len, tmp->len, tmp->len - original_len);
	return tmp;
}
#endif
