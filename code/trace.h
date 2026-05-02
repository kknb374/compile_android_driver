#ifndef _TRACE_H_
#define _TRACE_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/preempt.h>
#include <linux/slab.h>

#include <asm/ptrace.h>
#include <linux/pgtable.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/fpsimd.h>
#include <asm/esr.h>
#include <asm/debug-monitors.h>

#include "comm.h"

/* ================================================================
 *  版本兼容层
 * ================================================================ */
#ifndef LINUX_VERSION_MAJOR
#define LINUX_VERSION_MAJOR      (LINUX_VERSION_CODE >> 16)
#define LINUX_VERSION_PATCHLEVEL (((LINUX_VERSION_CODE) >> 8) & 0xFF)
#define LINUX_VERSION_SUBLEVEL   ((LINUX_VERSION_CODE) & 0xFF)
#endif

#ifndef PTE_UXN
#define PTE_UXN (_AT(pteval_t, 1) << 54)
#endif

#ifndef TIF_FOREIGN_FPSTATE
#define TIF_FOREIGN_FPSTATE  6
#endif

#ifndef pte_offset_kernel
static inline pte_t *__dream_pte_offset(pmd_t *pmd, unsigned long addr)
{
    return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(addr);
}
#define pte_offset_kernel(dir, addr) __dream_pte_offset(dir, addr)
#endif

static inline unsigned long dream_untagged_addr(unsigned long addr)
{
    return addr & GENMASK_ULL(55, 0);
}

/* ================================================================
 *  原子 PTE 写
 * ================================================================ */
static inline void raw_pte_write(pte_t *ptep, pte_t pte)
{
    WRITE_ONCE(*ptep, pte);
    dsb(ishst);
    isb();
}

/* ================================================================
 *  hook_entry
 * ================================================================ */
struct hook_entry {
    unsigned long    vaddr;
    unsigned long    target_vaddr;
    struct mm_struct *mm;
    pid_t            pid;
    pte_t           *ptep;
    pte_t            orig_pte;
    atomic_t         step_count;
    spinlock_t       entry_lock;

    u32              rot[3];
    u32              stack_rot[STACK_ROT_MAX];
    u32              stack_count;
    u32              stack_offset;

    bool             active;
    u64              hit_count;
};

static __maybe_unused struct hook_entry *g_entry;
static __maybe_unused DEFINE_SPINLOCK(g_lock);

/* ================================================================
 *  kallsyms 解析
 * ================================================================ */
typedef unsigned long (*kln_t)(const char *);
static __maybe_unused kln_t my_kln;
static __maybe_unused u64  *p_kimage_voffset;

struct fault_info {
    int (*fn)(unsigned long, unsigned long, struct pt_regs *);
    int  sig;
    int  code;
    const char *name;
};

static __maybe_unused struct fault_info *g_fi;
static __maybe_unused int (*orig_fn)(unsigned long, unsigned long, struct pt_regs *);

typedef void *(*vmap_t)(struct page **, unsigned int, unsigned long, pgprot_t);
typedef void  (*vunmap_t)(const void *);
static __maybe_unused vmap_t   my_vmap;
static __maybe_unused vunmap_t my_vunmap;

static __maybe_unused void (*my_ss_enable)(struct task_struct *);
static __maybe_unused void (*my_ss_disable)(struct task_struct *);
static __maybe_unused void (*my_reg_step)(struct step_hook *);
static __maybe_unused void (*my_unreg_step)(struct step_hook *);

static __maybe_unused bool hook_installed;
static __maybe_unused bool step_registered;

static int resolve_kln(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    my_kln = (kln_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

#define KSYM(var, name) do {                                     \
    var = (typeof(var))my_kln(name);                             \
    if (!var) pr_warn("dream: ⚠ %s not found\n", name);         \
} while (0)

static void resolve_step_hooks(void)
{
    KSYM(my_reg_step,   "register_user_step_hook");
    KSYM(my_unreg_step, "unregister_user_step_hook");
    if (!my_reg_step) {
        KSYM(my_reg_step,   "register_step_hook");
        KSYM(my_unreg_step, "unregister_step_hook");
    }
}

/* ================================================================
 *  vmap 写只读页
 * ================================================================ */
static int write_via_vmap(void *kaddr, void *value)
{
    u64 phys;
    unsigned long offset;
    struct page *page;
    void *mapped;
    void **wp;

    if (!p_kimage_voffset) return -EINVAL;

    phys   = (u64)kaddr - *p_kimage_voffset;
    offset = phys & ~PAGE_MASK;
    page   = phys_to_page(phys & PAGE_MASK);

    mapped = my_vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if (!mapped) return -ENOMEM;

    wp = (void **)(mapped + offset);
    WRITE_ONCE(*wp, value);
    dsb(ishst);
    isb();

    my_vunmap(mapped);
    return 0;
}

/* ================================================================
 *  页表遍历
 * ================================================================ */
static pte_t *get_pte(struct mm_struct *mm, unsigned long va)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;

    return pte_offset_kernel(pmd, va);
}

/* ================================================================
 *  FPSIMD 注入 (汇编错误已修复)
 * ================================================================ */
static noinline void inject_fpsimd(u32 rot0, u32 rot1, u32 rot2)
{
    struct user_fpsimd_state *st = &current->thread.uw.fpsimd_state;

    preempt_disable();

    asm volatile(
        "stp q0,  q1,  [%0, #16 *  0]\n"
        "stp q2,  q3,  [%0, #16 *  2]\n"
        "stp q4,  q5,  [%0, #16 *  4]\n"
        "stp q6,  q7,  [%0, #16 *  6]\n"
        "stp q8,  q9,  [%0, #16 *  8]\n"
        "stp q10, q11, [%0, #16 * 10]\n"
        "stp q12, q13, [%0, #16 * 12]\n"
        "stp q14, q15, [%0, #16 * 14]\n"
        "stp q16, q17, [%0, #16 * 16]\n"
        "stp q18, q19, [%0, #16 * 18]\n"
        "stp q20, q21, [%0, #16 * 20]\n"
        "stp q22, q23, [%0, #16 * 22]\n"
        "stp q24, q25, [%0, #16 * 24]\n"
        "stp q26, q27, [%0, #16 * 26]\n"
        "stp q28, q29, [%0, #16 * 28]\n"
        "stp q30, q31, [%0, #16 * 30]\n"
        : : "r"(&st->vregs[0])
        : "memory"
    );

    {
        u64 fpcr64, fpsr64;
        u32 fpcr, fpsr;
        asm volatile("mrs %0, fpcr" : "=r"(fpcr64));
        asm volatile("mrs %0, fpsr" : "=r"(fpsr64));
        fpcr = (u32)fpcr64;
        fpsr = (u32)fpsr64;
        st->fpcr = fpcr;
        st->fpsr = fpsr;
    }

    ((u32 *)&st->vregs[3])[0] = rot0;
    ((u32 *)&st->vregs[4])[0] = rot1;
    ((u32 *)&st->vregs[5])[0] = rot2;

    set_thread_flag(TIF_FOREIGN_FPSTATE);

    preempt_enable();
}

/* ================================================================
 *  栈注入
 * ================================================================ */
static void inject_stack(struct pt_regs *regs,
                         const u32 *values, u32 count, u32 offset)
{
    void __user *sp_target;
    unsigned long nbytes;

    if (count == 0 || count > STACK_ROT_MAX)
        return;

    nbytes    = (unsigned long)count * sizeof(u32);
    sp_target = (void __user *)(regs->sp + offset);

    if (copy_to_user(sp_target, values, nbytes) != 0)
        pr_warn_once("dream: stack inject copy_to_user failed\n");
}

/* ================================================================
 *  fault handler
 * ================================================================ */
static int handle_fault(unsigned long addr, unsigned long esr,
                        struct pt_regs *regs)
{
    unsigned long flags;
    struct hook_entry *e;
    unsigned long page_addr = addr & PAGE_MASK;

    bool do_reg_inject   = false;
    bool do_stack_inject = false;
    u32 inj_rot[3]                = {0};
    u32 inj_stack[STACK_ROT_MAX]  = {0};
    u32 inj_stack_count  = 0;
    u32 inj_stack_offset = 0;

    pte_t cur_pte, new_pte;
    pteval_t ptv;

    if (!current->mm || !user_mode(regs))
        return 0;
    if (ESR_ELx_EC(esr) != ESR_ELx_EC_IABT_LOW)
        return 0;

    spin_lock_irqsave(&g_lock, flags);

    e = g_entry;
    if (!e || !e->active ||
        e->mm != current->mm ||
        e->vaddr != page_addr) {
        spin_unlock_irqrestore(&g_lock, flags);
        return 0;
    }

    spin_lock(&e->entry_lock);
    e->hit_count++;

    {
        unsigned long clean_pc     = regs->pc & 0xFFFFFFFFFFFFUL;
        unsigned long clean_target = e->target_vaddr & 0xFFFFFFFFFFFFUL;

        if (clean_pc == clean_target) {
            if (e->rot[0] | e->rot[1] | e->rot[2]) {
                inj_rot[0] = e->rot[0];
                inj_rot[1] = e->rot[1];
                inj_rot[2] = e->rot[2];
                do_reg_inject = true;
            }
            if (e->stack_count > 0 && e->stack_count <= STACK_ROT_MAX) {
                memcpy(inj_stack, e->stack_rot,
                       e->stack_count * sizeof(u32));
                inj_stack_count  = e->stack_count;
                inj_stack_offset = e->stack_offset;
                do_stack_inject  = true;
            }
        }
    }

    cur_pte = READ_ONCE(*(e->ptep));
    ptv = pte_val(cur_pte);
    ptv &= ~PTE_UXN;
    new_pte = __pte(ptv);
    raw_pte_write(e->ptep, new_pte);
    local_flush_tlb_all();

    if (my_ss_enable)
        my_ss_enable(current);
    atomic_inc(&e->step_count);

    spin_unlock(&e->entry_lock);
    spin_unlock_irqrestore(&g_lock, flags);

    if (do_reg_inject)
        inject_fpsimd(inj_rot[0], inj_rot[1], inj_rot[2]);
    if (do_stack_inject)
        inject_stack(regs, inj_stack, inj_stack_count, inj_stack_offset);

    return 1;
}

/* ================================================================
 *  single-step callback
 * ================================================================ */
static int step_cb(struct pt_regs *regs, unsigned long esr)
{
    struct hook_entry *e;
    bool handled = false;
    unsigned long flags;

    if (!user_mode(regs))
        return DBG_HOOK_ERROR;

    spin_lock_irqsave(&g_lock, flags);

    e = g_entry;
    if (!e || !e->active || e->mm != current->mm) {
        spin_unlock_irqrestore(&g_lock, flags);
        return DBG_HOOK_ERROR;
    }

    if (atomic_read(&e->step_count) > 0) {
        spin_lock(&e->entry_lock);
        atomic_dec(&e->step_count);

        if (atomic_read(&e->step_count) == 0) {
            pte_t cur = READ_ONCE(*(e->ptep));
            pteval_t ptv = pte_val(cur);
            ptv |= PTE_UXN;
            raw_pte_write(e->ptep, __pte(ptv));
            local_flush_tlb_all();
        }

        handled = true;
        spin_unlock(&e->entry_lock);
    }

    spin_unlock_irqrestore(&g_lock, flags);

    if (handled) {
        if (my_ss_disable)
            my_ss_disable(current);
        return DBG_HOOK_HANDLED;
    }
    return DBG_HOOK_ERROR;
}

static struct step_hook step_desc = {
    .fn = step_cb,
};

/* ================================================================
 *  hooked fault_info 入口
 * ================================================================ */
static int hooked_fn(unsigned long far, unsigned long esr,
                     struct pt_regs *regs)
{
    if (handle_fault(dream_untagged_addr(far), esr, regs))
        return 0;
    return orig_fn(far, esr, regs);
}

/* ================================================================
 *  fault_info 索引 + 验证
 * ================================================================ */
static const int fidx[] = { 0x0d, 0x0e, 0x0f };
#define N_FIDX ARRAY_SIZE(fidx)

static bool validate_fault_info(void)
{
    struct fault_info *fi = &g_fi[0x0f];
    if (fi->sig != 11 || fi->code != 2 || !fi->fn) {
        pr_err("dream: ❌ fault_info layout mismatch "
               "(sig=%d code=%d fn=%ps)\n",
               fi->sig, fi->code, fi->fn);
        return false;
    }
    return true;
}

/* ================================================================
 *  公开 API (必须保留，被 dream.c 调用)
 * ================================================================ */
int hook_do_attach(pid_t pid, unsigned long addr)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct hook_entry *e, *old;
    pte_t *ptep;
    unsigned long vaddr = addr & PAGE_MASK;
    unsigned long flags;
    pte_t new_pte;
    pteval_t ptv;

    pr_info("dream: [attach] pid=%d target=0x%lx\n", pid, addr);

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) { rcu_read_unlock(); return -ESRCH; }
    mm = get_task_mm(task);
    rcu_read_unlock();
    if (!mm) return -EINVAL;

    mmap_read_lock(mm);
    ptep = get_pte(mm, vaddr);
    if (!ptep || pte_none(READ_ONCE(*ptep))) {
        mmap_read_unlock(mm);
        mmput(mm);
        return -EFAULT;
    }

    e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e) { mmap_read_unlock(mm); mmput(mm); return -ENOMEM; }

    e->vaddr        = vaddr;
    e->target_vaddr = addr;
    e->mm           = mm;
    e->pid          = pid;
    e->ptep         = ptep;
    e->orig_pte     = READ_ONCE(*ptep);
    e->active       = true;
    e->hit_count    = 0;
    e->stack_count  = 0;
    e->stack_offset = 0;
    atomic_set(&e->step_count, 0);
    spin_lock_init(&e->entry_lock);

    new_pte = e->orig_pte;
    ptv = pte_val(new_pte);
    ptv |= PTE_UXN;
    new_pte = __pte(ptv);

    spin_lock_irqsave(&g_lock, flags);
    old = g_entry;
    g_entry = e;
    raw_pte_write(ptep, new_pte);
    spin_unlock_irqrestore(&g_lock, flags);

    flush_tlb_mm(mm);
    mmap_read_unlock(mm);

    if (old) {
        if (old->mm && old->ptep) {
            mmap_read_lock(old->mm);
            raw_pte_write(old->ptep, old->orig_pte);
            mmap_read_unlock(old->mm);
            flush_tlb_mm(old->mm);
        }
        if (old->mm) mmput(old->mm);
        kfree(old);
    }

    pr_info("dream: [attach] ✅ pid=%d target=0x%lx UXN=SET\n", pid, addr);
    return 0;
}

void hook_do_detach(void)
{
    unsigned long flags;
    struct hook_entry *e;

    spin_lock_irqsave(&g_lock, flags);
    e = g_entry;
    g_entry = NULL;
    spin_unlock_irqrestore(&g_lock, flags);

    if (!e) return;

    if (e->mm && e->ptep) {
        mmap_read_lock(e->mm);
        raw_pte_write(e->ptep, e->orig_pte);
        mmap_read_unlock(e->mm);
        flush_tlb_mm(e->mm);
    }
    if (e->mm) mmput(e->mm);

    pr_info("dream: [detach] ✅ hits=%llu\n", e->hit_count);
    kfree(e);
}

int hook_set_rot(const HOOK_SET_ROT *r)
{
    unsigned long flags;
    struct hook_entry *e;

    spin_lock_irqsave(&g_lock, flags);
    e = g_entry;
    if (e) {
        spin_lock(&e->entry_lock);
        e->rot[0] = r->rot[0];
        e->rot[1] = r->rot[1];
        e->rot[2] = r->rot[2];
        e->stack_count  = r->stack_count;
        e->stack_offset = r->stack_offset;
        if (r->stack_count > 0 && r->stack_count <= STACK_ROT_MAX)
            memcpy(e->stack_rot, r->stack_rot,
                   r->stack_count * sizeof(u32));
        spin_unlock(&e->entry_lock);
    }
    spin_unlock_irqrestore(&g_lock, flags);

    return e ? 0 : -ENOENT;
}

int hook_get_status(HOOK_STATUS *s)
{
    unsigned long flags;
    struct hook_entry *e;

    memset(s, 0, sizeof(*s));

    spin_lock_irqsave(&g_lock, flags);
    e = g_entry;
    if (e) {
        s->active       = e->active;
        s->armed        = e->active;
        s->pid          = e->pid;
        s->vaddr        = e->vaddr;
        s->target_addr  = e->target_vaddr;
        s->rot[0]       = e->rot[0];
        s->rot[1]       = e->rot[1];
        s->rot[2]       = e->rot[2];
        s->stack_rot[0] = e->stack_rot[0];
        s->stack_rot[1] = e->stack_rot[1];
        s->stack_rot[2] = e->stack_rot[2];
        s->stack_count  = e->stack_count;
        s->stack_offset = e->stack_offset;
        s->hit_count    = e->hit_count;
    }
    spin_unlock_irqrestore(&g_lock, flags);

    return 0;
}

int page_setup_hook(void)
{
    unsigned long fi_addr;
    int i, ret;

    pr_info("dream: [hook] setup (kernel %d.%d.%d)\n",
            LINUX_VERSION_MAJOR, LINUX_VERSION_PATCHLEVEL,
            LINUX_VERSION_SUBLEVEL);

    ret = resolve_kln();
    if (ret) return ret;

    KSYM(my_vmap,          "vmap");
    KSYM(my_vunmap,        "vunmap");
    KSYM(p_kimage_voffset, "kimage_voffset");
    KSYM(my_ss_enable,     "user_enable_single_step");
    KSYM(my_ss_disable,    "user_disable_single_step");

    resolve_step_hooks();

    if (!my_vmap || !my_vunmap || !p_kimage_voffset ||
        !my_ss_enable || !my_ss_disable ||
        !my_reg_step || !my_unreg_step) {
        pr_err("dream: [hook] critical symbols missing\n");
        return -ENOENT;
    }

    fi_addr = my_kln("fault_info");
    if (!fi_addr) {
        pr_err("dream: [hook] fault_info not found\n");
        return -ENOENT;
    }
    g_fi = (struct fault_info *)fi_addr;

    if (!validate_fault_info())
        return -EINVAL;

    orig_fn = g_fi[0x0f].fn;

    my_reg_step(&step_desc);
    step_registered = true;

    for (i = 0; i < N_FIDX; i++) {
        ret = write_via_vmap(&g_fi[fidx[i]].fn, hooked_fn);
        if (ret) {
            while (--i >= 0)
                write_via_vmap(&g_fi[fidx[i]].fn, orig_fn);
            my_unreg_step(&step_desc);
            step_registered = false;
            return ret;
        }
    }
    hook_installed = true;
    g_entry = NULL;

    pr_info("dream: [hook] ✅ fault_info hooked + step registered\n");
    return 0;
}

void page_uninstall_hook(void)
{
    int i;

    hook_do_detach();
    synchronize_rcu();

    if (step_registered && my_unreg_step) {
        my_unreg_step(&step_desc);
        step_registered = false;
    }

    if (hook_installed && orig_fn) {
        for (i = 0; i < N_FIDX; i++)
            write_via_vmap(&g_fi[fidx[i]].fn, orig_fn);
        synchronize_rcu();
        hook_installed = false;
    }

    pr_info("dream: [hook] ✅ uninstalled\n");
}

#endif /* _TRACE_H_ */
