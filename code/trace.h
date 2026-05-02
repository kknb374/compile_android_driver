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

static struct hook_entry *g_entry;
static DEFINE_SPINLOCK(g_lock);

/* ================================================================
 *  kallsyms 解析
 * ================================================================ */
typedef unsigned long (*kln_t)(const char *);
static kln_t my_kln;
static u64  *p_kimage_voffset;

struct fault_info {
    int (*fn)(unsigned long, unsigned long, struct pt_regs *);
    int  sig;
    int  code;
    const char *name;
};

static struct fault_info *g_fi;
static int (*orig_fn)(unsigned long, unsigned long, struct pt_regs *);

typedef void *(*vmap_t)(struct page **, unsigned int, unsigned long, pgprot_t);
typedef void  (*vunmap_t)(const void *);
static vmap_t   my_vmap;
static vunmap_t my_vunmap;

static void (*my_ss_enable)(struct task_struct *);
static void (*my_ss_disable)(struct task_struct *);
static void (*my_reg_step)(struct step_hook *);
static void (*my_unreg_step)(struct step_hook *);

static bool hook_installed;
static bool step_registered;

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
 *  FPSIMD 注入 (已修复汇编错误)
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

/* ... 以下其余部分与原始 trace.h 保持一致 ... */
// 由于篇幅，请确保后面有完整的 handle_fault, step_cb, hook_do_attach 等函数原样不变。
// 最简单做法：用我给你的这个片段替换掉你 trace.h 里的 inject_fpsimd 函数即可，
// 其余不动。
