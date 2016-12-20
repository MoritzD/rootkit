#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <linux/reboot.h>
#include "../sysmap.h"		// for sys_call_table address this is Device spesific
#include <asm/kvm_para.h>

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "

unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; // Address of the Syscall table from sysmap

static int __init init_mod(void)
{	
	printk("inserting...\n");
	kvm_hypercall1(99,20);
	return 0;
}

static void __exit  exit_mod(void)
{
	printk("exiting...\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
