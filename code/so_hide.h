#ifndef _SO_HIDE_H_
#define _SO_HIDE_H_

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/string.h>

#if !defined(__nocfi)
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif

/* 要隐藏的 so 名称，可通过 ioctl 动态设置 */
static char target_so_name[128] = "lib10218.so";

struct maps_hide_data {
	struct seq_file *m;
	size_t saved_count;
	bool hit;
};

/* 检查 VMA 是否属于目标 so */
static inline bool vma_matches_target(struct vm_area_struct *vma)
{
	struct file *file;
	char buf[256];
	char *path;

	if (!vma)
		return false;

	file = vma->vm_file;
	if (!file)
		return false;

	path = d_path(&file->f_path, buf, sizeof(buf));
	if (IS_ERR(path))
		return false;

	/* 使用安全比较，防止路径超长 */
	return strnstr(path, target_so_name, sizeof(buf)) != NULL;
}

/* kretprobe entry handler：记录序列文件当前写入位置 */
static int __nocfi hide_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct maps_hide_data *d = (void *)ri->data;
	struct seq_file *m = (struct seq_file *)regs->regs[0];
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];

	d->m = m;
	d->saved_count = m->count;
	d->hit = vma_matches_target(vma);
	return 0;
}

/* kretprobe handler：如果匹配目标则回滚 count，丢弃输出 */
static int __nocfi hide_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct maps_hide_data *d = (void *)ri->data;

	if (d->hit && d->m)
		d->m->count = d->saved_count;

	return 0;
}

/* 定义三个 kretprobe，分别挂钩 maps/smaps/numa_maps 的 show 函数 */
static struct kretprobe krp_show_map = {
	.handler	= hide_ret,
	.entry_handler	= hide_entry,
	.data_size	= sizeof(struct maps_hide_data),
	.maxactive	= 20,
	.kp.symbol_name = "show_map",
};

static struct kretprobe krp_show_smap = {
	.handler	= hide_ret,
	.entry_handler	= hide_entry,
	.data_size	= sizeof(struct maps_hide_data),
	.maxactive	= 20,
	.kp.symbol_name = "show_smap",
};

static struct kretprobe krp_show_numa_map = {
	.handler	= hide_ret,
	.entry_handler	= hide_entry,
	.data_size	= sizeof(struct maps_hide_data),
	.maxactive	= 20,
	.kp.symbol_name = "show_numa_map",
};

static inline int hide_so_init(void)
{
	int ret;

	ret = register_kretprobe(&krp_show_map);
	if (ret < 0) {
		pr_err("hide_so: show_map hook failed: %d\n", ret);
		return ret;
	}

	ret = register_kretprobe(&krp_show_smap);
	if (ret < 0) {
		pr_err("hide_so: show_smap hook failed: %d\n", ret);
		goto err_smap;
	}

	/* numa map 可能不存在，忽略错误 */
	ret = register_kretprobe(&krp_show_numa_map);
	if (ret < 0) {
		pr_warn("hide_so: show_numa_map hook failed: %d (ignored)\n", ret);
		krp_show_numa_map.kp.addr = NULL; /* 标记未注册 */
	}

	pr_info("hide_so: hooks installed, hiding '%s'\n", target_so_name);
	return 0;

err_smap:
	unregister_kretprobe(&krp_show_map);
	return ret;
}

static inline void hide_so_exit(void)
{
	if (krp_show_numa_map.kp.addr)
		unregister_kretprobe(&krp_show_numa_map);
	unregister_kretprobe(&krp_show_smap);
	unregister_kretprobe(&krp_show_map);
	pr_info("hide_so: hooks removed\n");
}

#endif /* _SO_HIDE_H_ */