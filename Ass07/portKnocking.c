#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/icmp.h>
#include <net/ip.h>
//#include <net/netfilter/ipv4/nf_reject.h>
//#include <uapi/linux/tcp.h>


#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <linux/kernel.h>



#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/icmp.h>



#include <linux/module.h>
#include <linux/moduleparam.h>


#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "

int status = 0;
bool closeConnection = false;

unsigned int IP;
/*char* IPString = "8.8.8.8";
module_param(IPString, charp, 0000);
MODULE_PARM_DESC(IPString, "IP address that is allowed to knock.");
*/
/* the port for which knocking is enabled */
unsigned int port=1234;
unsigned int knockports[3] = {2345,3456,1233};
module_param(port, uint, 0000);
MODULE_PARM_DESC(port, "port on which must be knocked");


/* information for netfilter hooks */
static struct nf_hook_ops hook;
unsigned long time;

/*static inline __sum16 tcp_v4_check(int len, __be32 saddr,
                                   __be32 daddr, __wsum base)
{
        return csum_tcpudp_magic(saddr,daddr,len,IPPROTO_TCP,base);
}
*/

const struct tcphdr *nf_reject_ip_tcphdr_get(struct sk_buff *oldskb,
		struct tcphdr *_oth, int hook)
{
	const struct tcphdr *oth;

	/* IP header checks: fragment. */
	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
		return NULL;

	if (ip_hdr(oldskb)->protocol != IPPROTO_TCP)
		return NULL;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
			sizeof(struct tcphdr), _oth);
	if (oth == NULL)
		return NULL;

	/* No RST for RST. */
	if (oth->rst)
		return NULL;

	/* Check checksum */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
		return NULL;

	return oth;
}


void nf_reject_ip_tcphdr_put(struct sk_buff *nskb, const struct sk_buff *oldskb,
		const struct tcphdr *oth)
{
	struct iphdr *niph = ip_hdr(nskb);
	struct tcphdr *tcph;

	skb_reset_transport_header(nskb);
	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source    = oth->dest;
	tcph->dest      = oth->source;
	tcph->doff      = sizeof(struct tcphdr) / 4;

	if (oth->ack) {
		tcph->seq = oth->ack_seq;
	} else {
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				oldskb->len - ip_hdrlen(oldskb) -
				(oth->doff << 2));
		tcph->ack = 1;
	}

	tcph->rst       = 1;
	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
			niph->daddr, 0);
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)tcph - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);
}
struct iphdr *nf_reject_iphdr_put(struct sk_buff *nskb,
		const struct sk_buff *oldskb,
		__u8 protocol, int ttl)
{
	struct iphdr *niph, *oiph = ip_hdr(oldskb);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version   = 4;
	niph->ihl       = sizeof(struct iphdr) / 4;
	niph->tos       = 0;
	niph->id        = 0;
	niph->frag_off  = htons(IP_DF);
	niph->protocol  = protocol;
	niph->check     = 0;
	niph->saddr     = oiph->daddr;
	niph->daddr     = oiph->saddr;
	niph->ttl       = ttl;

	nskb->protocol = htons(ETH_P_IP);

	return niph;
}




/* Send RST reply */
void nf_send_reset(struct net *net, struct sk_buff *oldskb, int hook)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	const struct tcphdr *oth;
	struct tcphdr _oth;

	oth = nf_reject_ip_tcphdr_get(oldskb, &_oth, hook);
	if (!oth)
		return;

	if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		return;

	oiph = ip_hdr(oldskb);

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb)
		return;

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	skb_reserve(nskb, LL_MAX_HEADER);
	niph = nf_reject_iphdr_put(nskb, oldskb, IPPROTO_TCP,
			ip4_dst_hoplimit(skb_dst(nskb)));
	nf_reject_ip_tcphdr_put(nskb, oldskb, oth);

	if (ip_route_me_harder(net, nskb, RTN_UNSPEC))
		goto free_nskb;

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	/* If we use ip_local_out for bridged traffic, the MAC source on
	 * the RST will be ours, instead of the destination's.  This confuses
	 * some routers/firewalls, and they drop the packet.  So we need to
	 * build the eth header using the original destination's MAC as the
	 * source, and send the RST packet directly.
	 */
	if (oldskb->nf_bridge) {
		struct ethhdr *oeth = eth_hdr(oldskb);

		nskb->dev = nf_bridge_get_physindev(oldskb);
		niph->tot_len = htons(nskb->len);
		ip_send_check(niph);
		if (dev_hard_header(nskb, nskb->dev, ntohs(nskb->protocol),
					oeth->h_source, oeth->h_dest, nskb->len) < 0)
			goto free_nskb;
		dev_queue_xmit(nskb);
	} else
#endif
		ip_local_out(net, nskb->sk, nskb);

	return;

free_nskb:
	kfree_skb(nskb);
}





/*
void parseIP(char* strIP)
{
	int err = 0;
	u8 IParray[4];
	printk("hiding ip: %s\n", strIP);
	err = in4_pton(strIP, -1, IParray, -1, NULL);
	if(err == 0) {
		printk("Could not parse IP address!!!!!!!!!!\n");
		return;
	}
	printk("parsed PI!\n");
	IP = *((unsigned int*) IParray);
	printk("hideThisIP = %u\n", IP);
	}
 */
bool needToBlock(struct sk_buff* skb)
{
	struct iphdr* hdr = (struct iphdr*) skb_network_header(skb);
	struct tcphdr* tcpheader = (struct tcphdr*) skb_transport_header(skb);

	if(ntohs(tcpheader->dest) == knockports[0]) {
		IP = hdr->saddr;
		printk("Registert new IPaddress: %u\n", IP);
		printk("knocked on: %u\n", knockports[0]);
		status = 1;
	}
	else if(ntohs(tcpheader->dest) == knockports[1]) {
		if(hdr->saddr == IP) {
			if(status == 1){
				printk("knocked on: %u\n", knockports[1]);
				status = 2;
			} else 
				status = 0;
		}
	}
	else if(ntohs(tcpheader->dest) == knockports[2]) {
		if(hdr->saddr == IP) {
			if( status == 2) {
				printk("knocked on: %u\n", knockports[2]);
				status = 3;
				printk("Port %u now opend and ready to be used\n", port);
				time = jiffies;
				printk("Time: %lu hz: %d\n", time, HZ);
			} else 
				status = 0;
		}
	}
	else if(ntohs(tcpheader->dest) == port) {
		if(hdr->saddr == IP) {
			if(closeConnection){
				closeConnection = false;
				status = 0;
				printk("Accepted last package, port closes now!!!\n");
				if(tcpheader->ack) {
					printk("package was an Ack package\n");
				}

				return false;
			}
			if(status == 3) {
				if(jiffies > time + 5*250){
					printk("Time outed; package to late! %lu > %lu\n",jiffies, time+5*250);
					status = 0;
					return true;
				}
				time = jiffies;
				printk("Port %u open\n", port);
				if(tcpheader->fin) {
					printk("Final Package received accepting one more package...\n");
					closeConnection = true;
					//status = 0;
				}
				return false;
			} else 
				status = 0;
		}
		printk("Port %u closed\n", port);
		return true;

	}
	else {// any other port
		if(hdr->saddr == IP) { // causes problem since ssh connection will trigger this...
			if(ntohs(tcpheader->dest) == 22){	// thats why we ignore port 22 now... (only for debuging setup)
				//printk("%d\n",ntohs(tcpheader->dest));
				return false;
			}
			status = 0;
			printk("Port %u closed again\n", port);
		}	
	}
	return false;
}

unsigned int knocking_hook(void *priv,
							struct sk_buff *skb,
							const struct nf_hook_state *state)
{

	struct iphdr *hdr = (struct iphdr *) skb_network_header(skb);
	if(hdr->protocol == IPPROTO_TCP){
		//printk("inside knocking_hook (tcp)\n");
		if(needToBlock(skb)){
			nf_send_reset(state->net, skb, hook.hooknum);
			printk("droped packet because of portKnocking\n");
			return NF_DROP;

		}
	}
	
	return NF_ACCEPT;
}


static int __init init_mod(void)
{	
	int ret = 0;
	printk("inserting...\n");
	printk("Port: %u\n", port);
	//parseIP(IPString);
	
	hook.hook = knocking_hook;		// The function
	hook.hooknum = NF_INET_LOCAL_IN;	// Gemme all!!!
	hook.pf = PF_INET;			// but only ipv4
	hook.priority = NF_IP_PRI_FIRST;	// respect my prioritah

		// Hock it!
	ret = nf_register_hook(&hook);

	if(ret < 0) {
		printk("Error startup port knocking  %d\n", ret);
		return ret;
	}

	return 0;
}

static void __exit  exit_mod(void)
{
	printk("exiting...\n");
		// unhook  netfilter hook */
	nf_unregister_hook(&hook);
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
