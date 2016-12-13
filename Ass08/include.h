#ifndef INCLUDE_H
#define INCLUDE_H

#include <linux/moduleloader.h>
#include <linux/unistd.h>

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "
#define DEBUG

#ifdef DEBUG
#define DEBUGMSG(...) printk(__VA_ARGS__)
#else
#define DEBUGMSG(...)
#endif
extern unsigned long *sys_call_table;

// struct dev so compiler seems sattisfyed
struct linux_dirent {   
	unsigned long   d_ino;   
	unsigned long   d_off;   
	unsigned short  d_reclen;   
	char            d_name[];   
//	char			pad;
//	char			d_type;
}; 

int make_rw(unsigned long address);
int make_ro(unsigned long address);


#endif // INCLUDE_H
