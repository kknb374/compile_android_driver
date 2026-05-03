// dream.c (安全写入版，不会黑屏)
#include "comm.h"
#include "process.h"
#include "memory.h"
#include "hide.h"
#include "so_hide.h"
#include "trace.h"
#include "hook.h"
#include "kmmap.h"
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");

int target_hide_pid = 0;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *user_regs = regs;
    unsigned long cmd, arg;
    int ret_val = 0;

    if (regs->regs[0] > 0xffffff0000000000UL) {
        struct pt_regs *ctx = (struct pt_regs *)regs->regs[0];
        if ((unsigned long)ctx > 0xffff000000000000UL)
            user_regs = ctx;
    }

    cmd = user_regs->regs[1];
    arg = user_regs->regs[2];
    switch (cmd) {

    case OP_CMD_CHECK:
        ret_val = 100;
        break;

    case OP_CMD_SC: {
        SC_PID sp;
        if (copy_from_user(&sp, (void __user *)arg, sizeof(sp))) {
             ret_val = -1; 
             break; 
        }
        sc_block_pid=sp.pid;
        ret_val = 0;
        break;
    }
    case OP_CMD_PID: {
        GET_PID gp;
        char name_buf[0x100];
        if (copy_from_user(&gp, (void __user *)arg, sizeof(gp))) { ret_val = -1; break; }
        memset(name_buf, 0, sizeof(name_buf));
        if (copy_from_user(name_buf, (void __user *)gp.name, sizeof(name_buf) - 1)) { ret_val = -1; break; }
        gp.pid = get_name_pid(name_buf);
        if (gp.pid == -1) { ret_val = -1; break; }
        if (copy_to_user((void __user *)arg, &gp, sizeof(gp))) ret_val = -1;
        else ret_val = 0;
        break;
    }

    case OP_CMD_HIDE: {
        HIDE_PID hp;
        if (copy_from_user(&hp, (void __user *)arg, sizeof(hp))) { ret_val = -1; break; }
        target_hide_pid = hp.pid;
        ret_val = 0;
        break;
    }

    case OP_CMD_BASE: {
        MODULE_BASE mb;
        char name_buf[0x100];
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb))) { ret_val = -1; break; }
        memset(name_buf, 0, sizeof(name_buf));
        if (copy_from_user(name_buf, (void __user *)mb.name, sizeof(name_buf) - 1)) { ret_val = -1; break; }
        mb.base = get_module_base(mb.pid, name_buf);
        if (mb.base == 0) { ret_val = -1; break; }
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb))) ret_val = -1;
        else ret_val = 0;
        break;
    }

    case OP_CMD_READ: {
        COPY_MEMORY cm;
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) { ret_val = -1; break; }
        ret_val = read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -1;
        break;
    }

    // ==================== 稳定写入命令（调用安全函数） ====================
    case OP_CMD_WRITE: {
        COPY_MEMORY cm;
        void *kbuf = NULL;
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            { ret_val = -1; break; }
        if (cm.size <= 0 || cm.size > 4096)
            { ret_val = -1; break; }
        kbuf = kmalloc(cm.size, GFP_KERNEL);
        if (!kbuf)
            { ret_val = -1; break; }
        if (copy_from_user(kbuf, (void __user *)cm.buffer, cm.size)) {
            kfree(kbuf);
            ret_val = -1;
            break;
        }
        ret_val = write_process_memory_safe(cm.pid, cm.addr, kbuf, cm.size) ? 0 : -1;
        kfree(kbuf);
        break;
    }

    case OP_CMD_UNHIDE:
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
        if (copy_from_user(&hs, (void __user *)arg, sizeof(hs))) { ret_val = -1; break; }
        memset(name_buf, 0, sizeof(name_buf));
        if (copy_from_user(name_buf, (void __user *)hs.name, sizeof(name_buf) - 1)) { ret_val = -1; break; }
        strlcpy(target_so_name, name_buf, sizeof(target_so_name));
        ret_val = 0;
        break;
    }

    case OP_CMD_HOOK_ATTACH: {
        HOOK_ATTACH ha;
        if (copy_from_user(&ha, (void __user *)arg, sizeof(ha))) { ret_val = -1; break; }
        ret_val = hook_do_attach(ha.pid, ha.target_addr);
        break;
    }

    case OP_CMD_HOOK_DETACH:
        hook_do_detach();
        ret_val = 0;
        break;

    case OP_CMD_HOOK_SET_ROT: {
        HOOK_SET_ROT hr;
        if (copy_from_user(&hr, (void __user *)arg, sizeof(hr))) { ret_val = -1; break; }
        if (hr.stack_count > STACK_ROT_MAX)
            hr.stack_count = STACK_ROT_MAX;
        ret_val = hook_set_rot(&hr);
        break;
    }

    case OP_CMD_HOOK_STATUS: {
        HOOK_STATUS hs;
        hook_get_status(&hs);
        if (copy_to_user((void __user *)arg, &hs, sizeof(hs)))
            ret_val = -1;
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

static int __init my_init(void)
{
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "[DREAM] kprobe register failed: %d\n", ret);
        return ret;
    }

    if(setup_hook()!=0){
        printk(KERN_ERR "[DREAM] hide process failed\n");
    }

    if (page_setup_hook() != 0) {
        printk(KERN_ERR "[DREAM] setup_hook failed\n");
        unregister_kprobe(&kp);
        return -1;
    }

    if (hide_so_init() != 0) {
        printk(KERN_ERR "[DREAM] hide so hook failed\n");
    }
    if(sc_block_init()!=0){
        printk(KERN_ERR "[DREAM] register sc_block\n");
    }

    printk(KERN_INFO "[DREAM] Loaded (Kprobe + ShadowPage)\n");
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
