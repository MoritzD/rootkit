#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <linux/reboot.h>
//#include "../sysmap.h"		// for sys_call_table address this is Device spesific
#include <linux/slab.h>
#include <asm/kvm_para.h>
#include <linux/random.h>
#include <linux/delay.h>


#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "

struct BTS {
	u64* base;
	u64* index;
	u64* max;
	u64 interruptTreshold;
	u64* rest[6];
}__attribute__((packed));

struct BTS* bts;
char* newPage;

static int __init init_mod(void)
{	
	int i;
	get_random_bytes(&i, sizeof(i));
	printk("inserting...\n");	
	bts = (struct BTS*) __get_free_page(GFP_KERNEL); //kmalloc(sizeof(struct BTS), GFP_DMA);	
	newPage = (char*) __get_free_pages(GFP_KERNEL,9);
	bts->base = (u64*) newPage;
	bts->index = (u64*) newPage;
	bts->max = (u64*) newPage + 0xFFFF0;//(((2<<11))-16);
	printk("bts: pointer: %p  base: 0x%llx, index: 0x%llx, max: 0x%llx newPage at: %p\n", bts,bts->base,bts->index,bts->max,newPage);
	msleep(1000);
	kvm_hypercall1(77,(unsigned long) bts);


	if(i > 200) {
		printk("%s: i > 200 %x\n",__func__,i);		
	} else {
		printk("%s: i <= 200 %x\n",__func__,i);		
	}

	
	printk("bts: base: 0x%llx, index: 0x%llx, max: 0x%llx \n",bts->base,bts->index,bts->max);
	if(bts->base != bts->index){
		printk("recorded jump\n");
		printk("Jump: %llx -> %llx predict: %llx\n", bts->base[0], bts->base[1], bts->base[2]);
		}
	kvm_hypercall1(78,(unsigned long) bts);
	printk("Deaktivated debug controll again\n");
	return 0;
}

static void __exit  exit_mod(void)
{
	printk("exiting...\n");
	if(newPage != NULL) {
		free_pages((long unsigned) newPage,9);
		printk("Page freed\n");
		}
	printk("done \n\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
