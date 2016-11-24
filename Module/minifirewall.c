#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

char* rules_array[] = {"128.230.171.184:80", "64.30.136.201:*", "10.0.2.72:23", NULL};

static struct nf_hook_ops nfho; // net filter hook option struct
struct sk_buff *sock_buff;      // socket kernel buffer
struct udphdr *udp_header;      // udp header struct
struct tcphdr *tcp_header;      // tcp header struct
struct iphdr *ip_header;        // ip header struct

unsigned char proto_number;
unsigned char *source_ip;
unsigned char *dest_ip;
unsigned char *source_port;
unsigned char *dest_port;

struct Rule {
	unsigned int direction;      // 1 = in, 2 = out
	unsigned char *source_ip;    // NULL = any
	unsigned char *dest_ip;      // NULL = any
	unsigned char *source_port;  // NULL = any
	unsigned char *dest_port;    // NULL = any
	unsigned char proto_number;  // 0 = any
};
struct Rule rule;

char* ip_str_to_bytes(char ip_address[]){
    // split ip_address into 4 pieces
    char* pieces[4];
    char *r = kmalloc(strlen(ip_address)+1, GFP_KERNEL);
    strcpy(r, ip_address);
    int i = 0 ;
    char *tok = r;
    char *end = r;
    while (tok != NULL) {
        strsep(&end, ".");
        pieces[i] = tok;
        i++;
        tok = end;
    }
    // compine the pieces into one array after converting them to bytes
    char* bytes = (char *) kmalloc(sizeof(char) * 4, GFP_KERNEL);
    kstrtoint(pieces[0], 10, &bytes[0]);
    kstrtoint(pieces[1], 10, &bytes[1]);
    kstrtoint(pieces[2], 10, &bytes[2]);
    kstrtoint(pieces[3], 10, &bytes[3]);
    return bytes;
}

char* port_str_to_bytes(char* port_number){
    char* bytes = (char *) kmalloc(sizeof(char) * 2, GFP_KERNEL);
    int port_number_int;
    kstrtoint(port_number, 10, &port_number_int);
    bytes[0] = (port_number_int >> 8) & 0xFF;
    bytes[1] = port_number_int & 0xFF;
    return bytes;
}

char check_rule(char rule_str[]){
	// ---------------- split the rule into pieces----------------
	char* pieces[2];
    char *r = kmalloc(strlen(rule_str)+1, GFP_KERNEL);
    strcpy(r, rule_str);
    int i = 0 ;
    char *tok = r;
    char *end = r;
    while (tok != NULL) {
        strsep(&end, ":");
        pieces [i] = tok;
        i++;
        tok = end;
    }

	// ----------------fill in rule structure----------------
	rule.direction = 2;  
	rule.source_ip = NULL;

	// if dest_ip is "*" then assign NULL to its value so we ignore it the rule matching
	if (strcmp(pieces [0], "*") == 0){
		rule.dest_ip = NULL;
	} else {
		rule.dest_ip = ip_str_to_bytes(pieces [0]);
	}

	rule.source_port = NULL; 

	// if dest_port is "*" then assign NULL to its value so we ignore it the rule matching
	if (strcmp(pieces [1], "*") == 0){
		rule.dest_port = NULL;
	} else {
		rule.dest_port = port_str_to_bytes(pieces [1]);
	}

	rule.proto_number = 0; 

	// ----------------rule matching----------------
	if (
			(rule.source_ip == NULL || source_ip == *(unsigned int*) rule.source_ip)
			&&
			(rule.dest_ip == NULL || dest_ip == *(unsigned int*) rule.dest_ip)
			&&
			(rule.source_port == NULL || source_port == *(unsigned short*) rule.source_port)
			&&
			(rule.dest_port == NULL || dest_port == *(unsigned short*) rule.dest_port)
			&&
			(rule.proto_number == 0 || proto_number == rule.proto_number)
			)
	{
		return 0;
	}
	return 1;
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {

	// Note : you have to change nfho.hooknum manually to switch between filtering incoming and outgoing packages


	sock_buff = skb;
	ip_header = (struct iphdr *) skb_network_header(sock_buff); // grab network header using accessor

	if (!sock_buff) {    // if we dont have a valid sock_buff, accept the packet
		return NF_ACCEPT;
	}

	//  get packet details
	proto_number = ip_header->protocol;
	source_ip = ip_header->saddr;
	dest_ip = ip_header->daddr;

	printk(KERN_INFO "------------------------------------------------------------\n");
	switch (proto_number) {
		case 6:    // TCP protocol
			//tcp_header = (struct tcphdr *) (skb_transport_header(sock_buff) + 20);  //grab transport header
			tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl); //grab transport header
			source_port = tcp_header->source;
			dest_port = tcp_header->dest;
			printk(KERN_INFO "tcp packet \n");
			break;
		case 17:   // UDP protocol
			//udp_header = (struct udphdr *) (skb_transport_header(sock_buff) + 20); //grab transport header
			udp_header= (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl); //grab transport header
			source_port = udp_header->source;
			dest_port = udp_header->dest;
			printk(KERN_INFO "udp packet \n"); 
			break;
		default:
			printk(KERN_INFO "uknown protocol packet \n");
	}


	// iterate through the rules to see if any if the match
	char* rule_str = rules_array[0];
	int c = 0;

	while (rule_str != NULL){
		if (check_rule(rule_str) == 0){
			printk(KERN_INFO "packet dropped because of rule match \n");
			return NF_DROP;
		}
		c++;
		rule_str = rules_array[c];
	}

	return NF_ACCEPT; // if none of the rules match, accept the packet
}

int init_module() {
	printk(KERN_INFO "MiniFirewall module inserted \n");
	nfho.hook = hook_func;
	//nfho.hooknum = NF_INET_PRE_ROUTING; // for filtering incoming packages
	nfho.hooknum = NF_INET_POST_ROUTING;  // for filtering outgoing packages
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
	return 0;
}

void cleanup_module() {
	printk(KERN_INFO "MiniFirewall module removed \n");
	nf_unregister_hook(&nfho);
}
