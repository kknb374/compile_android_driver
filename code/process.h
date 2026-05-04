#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/miscdevice.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rcupdate.h>

#define ARC_PATH_MAX 256
extern struct mm_struct *get_task_mm(struct task_struct *task);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);
#endif

uintptr_t get_module_base(pid_t pid, char *name)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	uintptr_t base_addr = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	struct vma_iterator vmi;
#endif

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return 0;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return 0;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return 0;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma)
#else
	for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
	{
		char buf[ARC_PATH_MAX];
		char *path_nm = "";

		if (vma->vm_file)
		{
			path_nm =
				file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
			if (!strcmp(kbasename(path_nm), name))
			{
				base_addr = vma->vm_start;
				break;
			}
		}
	}

	mmput(mm);
	return base_addr;
}


int get_task_cmdline_simple(struct task_struct *task, char *buffer, int buflen)
{
    struct mm_struct *mm;
    int len = 0;
    int i;
    if (!task || !buffer || buflen <= 0) {
        return 0;
    }
    mm = get_task_mm(task);
    if (!mm) {
        return 0;
    }
    if (mm->arg_start < mm->arg_end) {
        len = mm->arg_end - mm->arg_start;
        if (len >= buflen) {
            len = buflen - 1;
        }
        
        len = access_process_vm(task, mm->arg_start, buffer, len, FOLL_FORCE);
        if (len > 0) {
            buffer[len] = '\0';
            for (i = 0; i < len; i++) {
                if (buffer[i] == '\0') {
                    buffer[i] = ' ';
                }
            }
        }
    }
    mmput(mm);
    return len;
}


pid_t get_name_pid(char *name) {
    struct task_struct *task;
    char *buffer;
    int ret;
    pid_t pid = -1;
    buffer = kmalloc(4096, GFP_KERNEL);
    if (!buffer) {
        return -1;
    }
    rcu_read_lock();
    for_each_process(task) {
        if (!task->mm || task == &init_task) {
            continue;
        }
        ret = get_task_cmdline_simple(task, buffer, 4096);
        if (ret > 0 && strstr(buffer, name) != NULL) {
            pid = task->pid;
            break;
        }
    }
    rcu_read_unlock();
    kfree(buffer);
    return pid;
}
