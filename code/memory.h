#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <linux/ktime.h>
#include <asm/tlbflush.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <linux/highmem.h>
#include <linux/sched/mm.h>

/* ---------- 内部辅助 ---------- */

/* 刷新一页的缓存，确保物理/虚拟一致性 */
static inline void flush_cache_page(void *vaddr, size_t size)
{
	unsigned long start = (unsigned long)vaddr;
	unsigned long end = start + size;
	unsigned long a, line_size;

	asm volatile("mrs %0, ctr_el0" : "=r"(line_size));
	line_size = 4 << ((line_size >> 16) & 0xf);
	start &= ~(line_size - 1);
	end = ALIGN(end, line_size);

	for (a = start; a < end; a += line_size)
		asm volatile("dc civac, %0" : : "r"(a) : "memory");

	asm volatile("dsb sy" ::: "memory");
	asm volatile("isb" ::: "memory");
}

/* 遍历用户态页表，返回物理地址（调用者需持有 mmap_lock） */
static phys_addr_t translate_linear_address_locked(struct mm_struct *mm,
						   uintptr_t va)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;

	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;

	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
		return 0;

	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return 0;

	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte) || !pte_present(*pte))
		return 0;

	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}

/* 带锁的版本，供外部使用 */
static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
	phys_addr_t pa;

	mmap_read_lock(mm);
	pa = translate_linear_address_locked(mm, va);
	mmap_read_unlock(mm);

	return pa;
}

/* ---------- 物理内存读写 ---------- */

/* 从物理地址读数据到用户缓冲区 */
static bool read_physical_address(uintptr_t pa, void *buffer, size_t size)
{
	struct page *page;
	void *virt_addr;
	unsigned long offset;
	size_t copy_size;
	bool ret = false;

	if (!pfn_valid(__phys_to_pfn(pa)))
		return false;
	if (pa + size > __pa(high_memory))
		return false;

	page = pfn_to_page(__phys_to_pfn(pa));
	if (PageReserved(page)) {
		pr_warn("memory: Reserved page at 0x%lx\n", pa);
		return false;
	}

	virt_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!virt_addr) {
		pr_err("memory: vmap failed for PA 0x%lx\n", pa);
		return false;
	}

	offset = pa & ~PAGE_MASK;
	copy_size = min(size, (size_t)(PAGE_SIZE - offset));

	if (copy_to_user(buffer, virt_addr + offset, copy_size) != 0)
		goto out;

	ret = true;

out:
	flush_cache_page(virt_addr, PAGE_SIZE);
	vunmap(virt_addr);
	return ret;
}

/* 向物理地址写入数据（来自用户缓冲区） */
static bool write_physical_address(uintptr_t pa, const void *buffer, size_t size)
{
	struct page *page;
	void *virt_addr;
	unsigned long offset;
	size_t copy_size;
	bool ret = false;

	if (!pfn_valid(__phys_to_pfn(pa)))
		return false;
	if (pa + size > __pa(high_memory))
		return false;

	page = pfn_to_page(__phys_to_pfn(pa));
	if (PageReserved(page)) {
		pr_warn("memory: Reserved page at 0x%lx\n", pa);
		return false;
	}

	virt_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!virt_addr) {
		pr_err("memory: vmap failed for PA 0x%lx\n", pa);
		return false;
	}

	offset = pa & ~PAGE_MASK;
	copy_size = min(size, (size_t)(PAGE_SIZE - offset));

	if (copy_from_user(virt_addr + offset, buffer, copy_size) != 0)
		goto out;

	flush_cache_page(virt_addr, PAGE_SIZE);
	ret = true;

out:
	vunmap(virt_addr);
	return ret;
}

/* ---------- 进程内存读写（高层接口） ---------- */

/* 读取进程虚拟地址处的内存，结果放入 buffer */
static bool read_process_memory(pid_t pid, uintptr_t addr,
				void *buffer, size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	bool result = false;

	if (!buffer || size == 0)
		return false;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return false;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		return false;

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return false;
	}

	mmap_read_lock(mm);
	pa = translate_linear_address_locked(mm, addr);
	if (pa)
		result = read_physical_address(pa, buffer, size);
	mmap_read_unlock(mm);

	mmput(mm);
	put_task_struct(task);
	return result;
}

/* 写入进程虚拟地址处的内存，数据从 buffer 复制 */
static bool write_process_memory(pid_t pid, uintptr_t addr,
				 const void *buffer, size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	bool result = false;

	if (!buffer || size == 0)
		return false;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return false;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		return false;

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return false;
	}

	mmap_read_lock(mm);
	pa = translate_linear_address_locked(mm, addr);
	if (pa) {
		result = write_physical_address(pa, buffer, size);
		/* 关键：通知目标进程 TLB 该页已变化 */
		if (result)
			flush_tlb_mm_range(mm, addr & PAGE_MASK,
					   PAGE_ALIGN(addr + size) - (addr & PAGE_MASK),
					   PAGE_SHIFT, false);
	}
	mmap_read_unlock(mm);

	mmput(mm);
	put_task_struct(task);
	return result;
}

#endif /* _MEMORY_H_ */