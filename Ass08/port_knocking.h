#ifndef PORTKNOCKING_H
#define PORTKNOCKING_H

#include <linux/inet.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <linux/netfilter_bridge.h>

#include <linux/module.h>
#include <linux/moduleparam.h>
#include "include.h"

/* the port for which knocking is enabled */
extern unsigned int port;
extern unsigned int knockports[3];
module_param(port, uint, 0000);
MODULE_PARM_DESC(port, "port on which must be knocked");


const struct tcphdr *nf_reject_ip_tcphdr_get(struct sk_buff *oldskb,
		struct tcphdr *_oth, int hook);
void nf_reject_ip_tcphdr_put(struct sk_buff *nskb, const struct sk_buff *oldskb,
		const struct tcphdr *oth);
struct iphdr *nf_reject_iphdr_put(struct sk_buff *nskb,
		const struct sk_buff *oldskb,
		__u8 protocol, int ttl);
void nf_send_reset(struct net *net, struct sk_buff *oldskb, int hook);
bool needToBlock(struct sk_buff* skb);
unsigned int knocking_hook(void *priv,
							struct sk_buff *skb,
							const struct nf_hook_state *state);
int init_port_knocking(void);
void exit_port_knocking(void);

#endif
