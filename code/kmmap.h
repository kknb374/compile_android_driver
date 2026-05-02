#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/ptrace.h>

static int sc_block_pid = 0;

static inline void sc_block_set_pid(int pid)
{
    WRITE_ONCE(sc_block_pid, pid);
}

static int sc_mmap_pre(struct kprobe *p, struct pt_regs *regs)
{
    int pid;
    unsigned long aligned;

    pid = READ_ONCE(sc_block_pid);
    if (!pid)
        return 0;
    if (current->tgid != pid)
        return 0;
    if (regs->regs[0])
        return 0;
    if (regs->regs[3] != 0x3)
        return 0;

    aligned = PAGE_ALIGN(regs->regs[2]);
    if (aligned < (800UL * 1024) || aligned > (950UL * 1024))
        return 0;

    if (regs->regs[7])
        *(unsigned long *)regs->regs[7] = 0;

    regs->regs[0] = 0;
    regs->pc      = regs->regs[30];
    return 1;
}

static struct kprobe sc_kp_mmap = {
    .symbol_name = "do_mmap",
    .pre_handler = sc_mmap_pre,
};

static int sc_block_init(void)
{
    return register_kprobe(&sc_kp_mmap);
}

static void sc_block_exit(void)
{
    unregister_kprobe(&sc_kp_mmap);
}

