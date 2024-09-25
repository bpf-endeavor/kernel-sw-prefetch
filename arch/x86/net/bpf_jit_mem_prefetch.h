#ifndef __BPF_JIT_MEM_PREFETCH_H
#define __BPF_JIT_MEM_PREFETCH_H
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/memory.h>
#include <linux/vmalloc.h>

#ifdef CONFIG_BPF_JIT_PREFETCH
/* BPF_PREFETCH  is defined as follows.
 * Its opcode is defined as LDX class with ATOMIC mode and the size is DW.
 * The src_reg holds the base register used in prefetching.
 * The dst_reg must be zero
 * The off would hold the offset value of memory address.
 * The imm must be zero
 * */
#define BPF_PREFETCH (BPF_LDX | BPF_ATOMIC |BPF_DW)
/* static inline bool __is_bpf_prefetch(struct bpf_insn *i) */
/* { */
/* 	if ((i->code == BPF_PREFETCH) && (i->dst_reg == 0x0) && (i->imm == 0)) { */
/* 		return true; */
/* 	} */
/* 	return false; */
/* } */
#endif


/* Entry function to prefetching phase */
struct bpf_prog *bpf_x86_jit_mem_prefetch(struct bpf_prog *prog);

#endif /* __BPF_JIT_MEM_PREFETCH_H */
