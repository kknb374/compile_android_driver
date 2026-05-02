// dream.c —— 优化版（整合 atomic 隐藏PID、utils、安全错误码）
#include "comm.h"
#include "process.h"
#include "memory.h"
#include "hide.h"
#include "so_hide.h"
#include "trace.h"
#include "hook.h"
#include "kmmap.h"
#include "utils.h"              // 新增：公共工具（get_user_regs 等）
#include <linux/kprobes.h>
#include <linux/atomic.h>

MODULE_LICENSE("GPL");

/* 隐藏 PID 改用原子变量，避免并发问题 */
atomic_t target_hide_pid = ATOMIC_INIT(0);

/* ---- ioctl 劫持入口 ---- */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *user_regs;
    unsigned long cmd, arg;
    int ret_val = 0;

    user_regs = get_user_regs(regs);   // 统一获取用户态寄存器

    cmd = user_regs->regs[1];
    arg = user_regs->regs[2];

    switch (cmd) {

    case OP_CMD_CHECK:
        ret_val = 100;
        break;

    case OP_CMD_SC: {
        SC_PID sp;
        if (copy_from_user(&sp, (void __user *)arg, sizeof(sp))) {
             ret_val = -EFAULT;
             break;
        }
        sc_block_pid = sp.pid;
        ret_val = 0;
        break;
    }

    case OP_CMD_PID: {
        GET_PID gp;
        char name_buf[0x100];
        if (copy_from_user(&gp, (void __user *)arg, sizeof(gp))) {
            ret_val = -EFAULT;
            break;
        }
        memset(name_buf, 0, sizeof(name_buf));
        if (copy_from_user(name_buf, (void __user *)gp.name, sizeof(name_buf) - 1)) {
            ret_val = -EFAULT;
            break;
        }
        gp.pid = get_name_pid(name_buf);
        if (gp.pid == -1) {
            ret_val = -ESRCH;
            break;
        }
        if (copy_to_user((void __user *)arg, &gp, sizeof(gp)))
            ret_val = -EFAULT;
        else
            ret_val = 0;
        break;
    }

    case OP_CMD_HIDE: {
        HIDE_PID hp;
        if (copy_from_user(&hp, (void __user *)arg, sizeof(hp))) {
            ret_val = -EFAULT;
            break;
        }
        atomic_set(&target_hide_pid, hp.pid);
        ret_val = 0;
        break;
    }

    case OP_CMD_BASE: {
        MODULE_BASE mb;
        char name_buf[0x100];
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb))) {
            ret_val = -EFAULT;
            break;
        }
        memset(name_buf, 0, sizeof(name_buf));
        if (copy_from_user(name_buf, (void __user *)mb.name, sizeof(name_buf) - 1)) {
            ret_val = -EFAULT;
            break;
        }
        mb.base = get_module_base(mb.pid, name_buf);
        if (mb.base == 0) {
            ret_val = -ENOENT;
            break;
        }
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            ret_val = -EFAULT;
        else
            ret_val = 0;
        break;
    }

    case OP_CMD_READ: {
        COPY_MEMORY cm;
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) {
            ret_val = -EFAULT;
            break;
        }
        ret_val = read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EIO;
        break;
    }

    case OP_CMD_WRITE: {
        COPY_MEMORY cm;
        void *kbuf = NULL;
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) {
            ret_val = -EFAULT;
            break;
        }
        if (cm.size <= 0 || cm.size > 4096) {
            ret_val = -EINVAL;
            break;
        }
        kbuf = kmalloc(cm.size, GFP_KERNEL);
        if (!kbuf) {
            ret_val = -ENOMEM;
            break;
        }
        if (copy_from_user(kbuf, (void __user *)cm.buffer, cm.size)) {
            kfree(kbuf);
            ret_val = -EFAULT;
            break;
        }
        ret_val = write_process_memory(cm.pid, cm.addr, kbuf, cm.size) ? 0 : -EIO;
        kfree(kbuf);
        break;
    }

    case OP_CMD_UNHIDE:
        atomic_set(&target_hide_pid, 0);
        ret_val = 0;
        break;

    case OP_CMD_HD:
        hidem();
        ret_val = 0;
        break;

    case OP_CMD_UHD:
        showm();
        ret_val = 0;
        break;

    case OP_CMD_HS: {
        HIDE_SO hs;
        char name_buf[0x100];
        if (copy_from_user(&hs, (void __user *)arg, sizeof(hs))) {
            ret_val = -EFAULT;
            break;
        }
        memset(name_buf, 0, sizeof(name_buf));
        if (copy_from_user(name_buf, (void __user *)hs.name, sizeof(name_buf) - 1)) {
            ret_val = -EFAULT;
            break;
        }
        strlcpy(target_so_name, name_buf, sizeof(target_so_name));
        ret_val = 0;
        break;
    }

    case OP_CMD_HOOK_ATTACH: {
        HOOK_ATTACH ha;
        if (copy_from_user(&ha, (void __user *)arg, sizeof(ha))) {
            ret_val = -EFAULT;
            break;
        }
        ret_val = hook_do_attach(ha.pid, ha.target_addr);
        break;
    }

    case OP_CMD_HOOK_DETACH:
        hook_do_detach();
        ret_val = 0;
        break;

    case OP_CMD_HOOK_SET_ROT: {
        HOOK_SET_ROT hr;
        if (copy_from_user(&hr, (void __user *)arg, sizeof(hr))) {
            ret_val = -EFAULT;
            break;
        }
        if (hr.stack_count > STACK_ROT_MAX)
            hr.stack_count = STACK_ROT_MAX;
        ret_val = hook_set_rot(&hr);
        break;
    }

    case OP_CMD_HOOK_STATUS: {
        HOOK_STATUS hs;
        hook_get_status(&hs);
        if (copy_to_user((void __user *)arg, &hs, sizeof(hs)))
            ret_val = -EFAULT;
        else
            ret_val = 0;
        break;
    }

    default:
        return 0;
    }

    regs->regs[0] = ret_val;
    regs->pc = regs->regs[30];
    return 1;
}

static struct kprobe kp = {
    .symbol_name = "__arm64_sys_ioctl",
    .pre_handler = handler_pre,
};

/* ---- 模块加载/卸载 ---- */
static int __init my_init(void)
{
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[DREAM] kprobe register failed: %d\n", ret);
        return ret;
    }

    if (setup_hook() != 0) {
        printk(KERN_ERR "[DREAM] hide process hook failed\n");
    }

    if (page_setup_hook() != 0) {
        printk(KERN_ERR "[DREAM] shadow breakpoint hook failed\n");
        unregister_kprobe(&kp);
        return -EFAULT;
    }

    if (hide_so_init() != 0) {
        printk(KERN_ERR "[DREAM] hide so hook failed\n");
    }

    if (sc_block_init() != 0) {
        printk(KERN_ERR "[DREAM] sc_block init failed\n");
    }

    printk(KERN_INFO "[DREAM] Loaded (optimized)\n");
    return 0;
}

static void __exit my_exit(void)
{
    page_uninstall_hook();
    uninstall_hook();
    unregister_kprobe(&kp);
    hide_so_exit();
    sc_block_exit();
    printk(KERN_INFO "[DREAM] Unloaded\n");
}

module_init(my_init);
module_exit(my_exit);