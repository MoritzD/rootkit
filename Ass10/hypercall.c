#include <linux/moduleloader.h>
#include <asm/io.h>
#include <linux/unistd.h>
#include <linux/reboot.h>
//#include "../sysmap.h"		// for sys_call_table address this is Device spesific
#include <asm/kvm_para.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/gfp.h>

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "

//unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; // Address of the Syscall table from sysmap

void testfunction(void){
	printk("This is the testfunction beeing Executed\n");
}

static int __init init_mod(void)
{	
	//void (*testf) (void) = (void*) testfunction;
	//unsigned long* testp;
	int* a;// = 10;
	a = (int*) __get_free_page(GFP_KERNEL);
	a[0] = 10;
	printk("inserting...\n");
	printk("Value %d, GVA %p GPA: %llx\n", a[0],  a, (long long unsigned )virt_to_phys(a));
	kvm_hypercall1(88,virt_to_phys(a));
	msleep(1000);
	printk("Value %d, adress %p\n", a[0], a);
	a[0] = 11;
	printk("After write: Value %d, adress %p\n", a[0], a);
	
	//kvm_hypercall1(88,virt_to_phys(a));
	//msleep(1000);
	//printk("Value %d, adress %p\n", a[0], a);
	//a[0] = 12;
	//printk("After write: Value %d, adress %p\n", a[0], a);
	
	//printk("running test function: \n");
	//testfunction();
	//printk("Reading from page: %lx\n", *(unsigned long *) testf);
	//printk("hypercall for %lx\n",(unsigned long) testf);
	//kvm_hypercall1(88, (unsigned long) testf);
	
	//printk("done modifying, running test function again\n");
	//testfunction();
	//printk("Reading from page again: %lx\n", *(unsigned long*) testf);
/*	testp = (unsigned long*) testf;
	// *testp = (*(unsigned long*) testf) | 0x00000000000000FF;
	printk("Reading from page once again after written to it: %lx\n", *(unsigned long*) testf);
*/
	free_page((unsigned long)a);
	printk("done\n");
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
