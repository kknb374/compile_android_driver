#ifndef _UTILS_H_
#define _UTILS_H_

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/ptrace.h>

/* ------- 获取用户态寄存器上下文 ------- */
static inline struct pt_regs *get_user_regs(struct pt_regs *regs)
{
    if (regs->regs[0] > 0xffffff0000000000UL) {
        struct pt_regs *ctx = (struct pt_regs *)regs->regs[0];
        if ((unsigned long)ctx > 0xffff000000000000UL)
            return ctx;
    }
    return regs;
}

/* ------- 安全写只读内存（通过临时映射） ------- */
static inline int write_ro_memory(void *addr, const void *value, size_t size)
{
    struct page *page;
    void *waddr;
    unsigned long offset;
    pte_t *pte;

    pte = lookup_address((unsigned long)addr, NULL);
    if (!pte || pte_none(*pte) || !pte_present(*pte))
        return -EFAULT;

    page = pte_page(*pte);
    offset = offset_in_page(addr);

    waddr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if (!waddr)
        return -ENOMEM;

    memcpy(waddr + offset, value, size);

    /* 刷新缓存，使指令侧可见 */
    __flush_icache_range((unsigned long)waddr + offset,
                         (unsigned long)waddr + offset + size);
    vunmap(waddr);
    return 0;
}

/* ------- 解析 kallsyms 符号地址（快速版） ------- */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static inline unsigned long resolve_symbol(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;

    if (register_kprobe(&kp) < 0)
        return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

#endif /* _UTILS_H_ */