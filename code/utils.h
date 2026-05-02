#ifndef _UTILS_H_
#define _UTILS_H_

#include <linux/types.h>
#include <asm/ptrace.h>

static inline struct pt_regs *get_user_regs(struct pt_regs *regs)
{
    if (regs->regs[0] > 0xffffff0000000000UL) {
        struct pt_regs *ctx = (struct pt_regs *)regs->regs[0];
        if ((unsigned long)ctx > 0xffff000000000000UL)
            return ctx;
    }
    return regs;
}

#endif
