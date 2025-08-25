#ifdef CONFIG_XDP_BATCHING

/* NOTE: Only main.c should include this file */

#ifndef EN_BATCH_XDP_PROCFS_H_
#define EN_BATCH_XDP_PROCFS_H_

#include <linux/proc_fs.h>
#include "en/batch_xdp/rq_state.h"
u32 xdp_batch_size = 8; /* default batch size */

static struct proc_dir_entry *xdp_batch_ent = NULL;

static ssize_t _write_xdp_batch_size(struct file *file,
		const char __user *ubuf, size_t count, loff_t *ppos)
{
	int num, i, c;
	char buf[64];

	if(*ppos > 0 || count > 63)
		return -EFAULT;

	if(copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0'; /* null terminate the string */

	num = sscanf(buf, "%d", &i);
	if(num != 1)
		return -EFAULT;

	if (i > MLX5_XDP_BATCH_SIZE)
		return -EFAULT;

	xdp_batch_size = i;
	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t _read_xdp_batch_size(struct file *file,
		char __user *ubuf, size_t count, loff_t *ppos)
{
	char buf[64];
	int len = 0;
	if(*ppos > 0 || count < 64)
		return 0;

	int val = xdp_batch_size;
	len += sprintf(buf, "batch size = %d (Max: %d)\n",
			val, MLX5_XDP_BATCH_SIZE);

	if(copy_to_user(ubuf, buf, len))
		return -EFAULT;

	*ppos = len;
	return len;
}

static struct proc_ops _xdp_batch_proc_file_op =
{
	.proc_read = _read_xdp_batch_size,
	.proc_write = _write_xdp_batch_size,
};

static inline void xdp_batch_procfs_setup(void)
{
	/* Create a proc file */
	xdp_batch_ent = proc_create("mlx5_xdp_batch", 0660, NULL,
			&_xdp_batch_proc_file_op);
}

static inline void xdp_batch_procfs_remove(void)
{
	/* Remove the proc file */
	if (xdp_batch_ent != NULL)
		proc_remove(xdp_batch_ent);
}
#endif

#endif
