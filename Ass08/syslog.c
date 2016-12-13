#include "syslog.h"
#include <linux/net.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/inet_connection_sock.h>
#include <linux/inet.h>
#include "include.h"

#define BUFFERSIZE 100

bool enabled = false;
static struct socket* syslogsocket = NULL;
unsigned int syslogIP = 0;
unsigned short syslogPort = 514;
int currentPID = 0;
char buffer[BUFFERSIZE];

void syslog(char* string)
{
	// Take string and put to buffer. If buffer is full: send it; if string contains \n send it
	int len = strlen(string);
	if(len > BUFFERSIZE) {
		DEBUGMSG("message to long for buffer\n");
		return;
	}
	if(currentPID == 0) { // Very first message
		currentPID = current->pid;
		sprintf(buffer, "%d:", current->pid);	
	}
	if(currentPID != current->pid) {
		DEBUGMSG("different pid: %d; %d\n", currentPID, current->pid);
		sendSyslog(buffer);
		currentPID = current->pid;
		sprintf(buffer, "%d:", current->pid);
	}
	if(len + strlen(buffer) > BUFFERSIZE) {
		DEBUGMSG("buffer full\n");
		sendSyslog(buffer);
		sprintf(buffer, "%d:", current->pid);
		strcat(buffer, string);
		if(strchr(string, '\r')){
			sendSyslog(buffer);
			sprintf(buffer, "%d:", current->pid);
		}
		return;
	}	
	if(strchr(string, '\r')){
//		DEBUGMSG("newline detected\n");
		strcat(buffer, string);
		sendSyslog(buffer);
		sprintf(buffer, "%d:", current->pid);
		return;
	}
//	DEBUGMSG("appending\n");
//	DEBUGMSG("%d\n", string[0]);
	strcat(buffer, string);
}

void sendSyslog(char* string)
{
	if(!enabled){
		return;
	}

	struct msghdr msg;
	struct iovec iov;
	struct iov_iter ioviter;
	mm_segment_t oldfs;
	struct sockaddr_in to;
	int len;
	memset(&to,0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = syslogIP;  
	to.sin_port = htons(syslogPort);
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
	len = sock_sendmsg(syslogsocket, &msg);//, strlen(string));
	set_fs(oldfs);
}


int init_syslog(void)
{	
	u8 IP[4];
	if (sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &syslogsocket) < 0) {
		DEBUGMSG("server: Error creating clientsocket.n" );
		return -EIO;
	}
	in4_pton("10.0.3.3", -1, IP, -1, NULL);
	syslogIP = *((unsigned int*) IP);
	enabled = true;
	DEBUGMSG("Syslog: Set up!\n");
	return 0;
}
void exit_syslog(void) 
{
	if (syslogsocket)
		sock_release(syslogsocket);
}

