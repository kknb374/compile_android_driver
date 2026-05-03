#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <asm/cpu.h>
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

extern struct mm_struct *get_task_mm(struct task_struct *task);
extern void mmput(struct mm_struct *);

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		return 0;
	}
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}

static inline int kvalid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count <= __pa(high_memory);
}

static inline void flush_cache_ranges(unsigned long addr, size_t size)
{
	unsigned long start, end, line_size, a;

	asm volatile("mrs %0, ctr_el0" : "=r"(line_size));
	line_size = 4 << ((line_size >> 16) & 0xf);
	start = addr & ~(line_size - 1);
	end = (addr + size + line_size - 1) & ~(line_size - 1);
	asm volatile("dmb sy" ::: "memory");

	for (a = start; a < end; a += line_size)
	{
		asm volatile("dc civac, %0" : : "r"(a));
	}
	asm volatile("dsb sy" ::: "memory");
	asm volatile("isb" ::: "memory");
}

bool read_physical_address(uintptr_t pa, void *buffer, size_t size)
{
	struct page *page;
	void *virt_addr;
	unsigned long offset;
	size_t copy_size;
	unsigned long addr;

	if (!pfn_valid(__phys_to_pfn(pa)))
	{
		return false;
	}
	if (!kvalid_phys_addr_range(pa, size))
	{
		return false;
	}
	page = pfn_to_page(__phys_to_pfn(pa));
	if (PageReserved(page))
	{
		printk(KERN_WARNING "Reserved page at 0x%lx\n", pa);
		return false;
	}
	virt_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!virt_addr)
	{
		printk(KERN_ERR "vmap failed for PA 0x%lx\n", pa);
		return false;
	}
	offset = pa & ~PAGE_MASK;
	copy_size = min(size, (size_t)(PAGE_SIZE - offset));
	if(copy_to_user(buffer,virt_addr + offset,copy_size)!=0){
		for (addr = (unsigned long)virt_addr;addr < (unsigned long)virt_addr + PAGE_SIZE;addr += 64)
		{
			asm volatile("dc civac, %0" : : "r"(addr) : "memory");
		}
		asm volatile("dsb sy" ::: "memory");
		asm volatile("isb" ::: "memory");
		vunmap(virt_addr);
		return false;
	}
	for (addr = (unsigned long)virt_addr;addr < (unsigned long)virt_addr + PAGE_SIZE;addr += 64)
	{
		asm volatile("dc civac, %0" : : "r"(addr) : "memory");
	}
	asm volatile("dsb sy" ::: "memory");
	asm volatile("isb" ::: "memory");
	vunmap(virt_addr);
	return true;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	bool result = false;
	phys_addr_t pa;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return false;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return false;
	}

	pa = translate_linear_address(mm, addr);
	if (pa)
	{
		result = read_physical_address(pa, buffer, size);
	}
	mmput(mm);
	put_task_struct(task);
	return result;
}

// ==================== 安全写入（无物理页操作） ====================
static inline bool write_process_memory_safe(pid_t pid, uintptr_t addr,
					    const void *buffer, size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	int ret = -1;

	pid_struct = find_get_pid(pid);
	if (!pid_struct) return false;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task) return false;

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return false;
	}

	ret = access_process_vm(task, addr, (void *)buffer, size,
				FOLL_FORCE | FOLL_WRITE);
	mmput(mm);
	put_task_struct(task);
	return (ret == (int)size);
}

#endif /* _MEMORY_H_ */
