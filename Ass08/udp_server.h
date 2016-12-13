#ifndef UDPSERVER_H
#define UDPSERVER_H
 
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

/* Socket stuff */


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

#endif
