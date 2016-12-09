#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
  
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("This module is a mini-firewall for android.");

#define MAX_INCOMING_RULES		PAGE_SIZE
#define MAX_OUTGOING_RULES		PAGE_SIZE
 
//array to store incoming rules
static char* rules_array_inc[MAX_INCOMING_RULES];
static int next_entry_inc_rules;
static int space_avail_inc;
static struct proc_dir_entry *inc_proc_entry;
//File Ops are defined after the read write methods

//array to store outgoing rules
static char* rules_array_out[MAX_OUTGOING_RULES];
static int next_entry_out_rules;
static int space_avail_out;
static struct proc_dir_entry *out_proc_entry;
//File ops are defined after the read write methods

static struct nf_hook_ops nfho_out; 	// net filter hook option struct for outgoing packets
static struct nf_hook_ops nfho_inc;	// net filter hook option struct for incoming packets
struct sk_buff *sock_buff;      	// socket kernel buffer
struct udphdr *udp_header;      	// udp header struct
struct tcphdr *tcp_header;      	// tcp header struct
struct iphdr *ip_header;        	// ip header struct

struct Rule {
	int direction;      // 1 = in, 2 = out
	unsigned char *source_ip;    // NULL = any
	unsigned char *dest_ip;      // NULL = any
	unsigned char *source_port;  // NULL = any
	unsigned char *dest_port;    // NULL = any
	unsigned char proto_number;  // 0 = any
};
struct Rule packet_rule;

//This function prints incoming rules to user at /proc/inc_rules
static int read_inc_rule(struct seq_file *sfile, void *v){
	char * rule_ptr = rules_array_inc[0];
	int counter = 0;
	while(rule_ptr != NULL){
		seq_printf(sfile, "%s\n", rule_ptr);
		counter++;
		rule_ptr = rules_array_inc[counter];
	}	
	return 0;
}
//this function is called first when users wants to read inc_rules
static int open_inc_rules(struct inode *inode, struct file *filp){
	return single_open(filp, read_inc_rule, NULL);
}

//This function write incoming rules from user to /proc/inc_rules
ssize_t write_inc_rule(struct file *filp, const char __user *buff, size_t len, loff_t *f_pos){
	//Get a variable
	char *input_str=kmalloc(sizeof(char)*25, GFP_KERNEL);
	if(!input_str){
		printk(KERN_INFO "Couldn't allocate memory\n");
	}
	memset(input_str,'\0',25);
	//Copy input into that variable
	copy_from_user(input_str,buff,len);
	//save that point out array to that variable
	rules_array_inc[next_entry_inc_rules]=input_str;
	//increment total count
	next_entry_inc_rules++;
	rules_array_inc[next_entry_inc_rules]=NULL;
	return len;
}

//This function reads outgoing rules from /proc/out_rules to the user
static int read_out_rule(struct seq_file *sfile, void *v){
	char * rule_ptr = rules_array_out[0];
	int counter = 0;
	while(rule_ptr != NULL){
		seq_printf(sfile, "%s\n", rule_ptr);
		counter++;
		rule_ptr = rules_array_out[counter];
	}	
	return 0;
}

static int open_out_rules(struct inode *inode, struct file *filp){
	return single_open(filp, read_out_rule, NULL);
}

//This function write outgoing rules from user to /proc/out_rules
ssize_t write_out_rule(struct file *filp, const char __user *buff, size_t len, loff_t *f_pos){
	//Get a variable
	char *input_str=kmalloc(sizeof(char)*25, GFP_KERNEL);
	if(!input_str){
		printk(KERN_INFO "Couldn't allocate memory\n");
	}
	memset(input_str,'\0',25);
	//Copy input into that variable
	copy_from_user(input_str,buff,len);
	//save that point out array to that variable
	rules_array_out[next_entry_out_rules]=input_str;
	//increment total count
	next_entry_out_rules++;
	rules_array_out[next_entry_out_rules]=NULL;
	return len;
}

static struct file_operations inc_file_ops={
	.open = open_inc_rules,
	.owner = THIS_MODULE,
	.read = seq_read,
	.write = write_inc_rule,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct file_operations out_file_ops={
	.open = open_out_rules,
	.owner = THIS_MODULE,
	.read = seq_read,
	.write = write_out_rule,
	.llseek = seq_lseek,
	.release = seq_release,
};

//This function sets up all the virtual files in /proc directory
int setupfiles(void){

	if(!rules_array_inc || !rules_array_out){
		printk(KERN_INFO "Couldn't allocate space for rules!\n'");
		return -1;
	}else{
		//setting the memory to 0. Getting rid of garbage
		memset(rules_array_inc, 0, MAX_INCOMING_RULES);
		memset(rules_array_out, 0, MAX_OUTGOING_RULES);

		//Initializing some default values to the incoming rules
		rules_array_inc[0]="128.230.190.80:80";
		rules_array_inc[1]="64.30.136.201:*";
		rules_array_inc[2]="10.0.2.72:23";
		rules_array_inc[3]=NULL;

		//Intializing some default values to outgoing rules
		rules_array_out[0]="128.230.171.184:80";
		rules_array_out[1]="64.30.136.201:*";
		rules_array_out[2]="10.0.2.72:23";
		rules_array_out[3]= NULL;

		//Creating proc entries
		inc_proc_entry = proc_create("inc_rules", 0666, NULL, &inc_file_ops);
		out_proc_entry = proc_create("out_rules", 0666, NULL, &out_file_ops);

		if(inc_proc_entry == NULL || out_proc_entry == NULL){
			printk(KERN_INFO "Couldn't create a proc entry!\n'");
			vfree(rules_array_inc);
			vfree(rules_array_out);
			return -1;
		}else{
			//Initializations
			next_entry_inc_rules = 3;
			next_entry_out_rules = 3;
			space_avail_inc = MAX_INCOMING_RULES-3;
			space_avail_out = MAX_OUTGOING_RULES-3;

			printk(KERN_INFO "Finished created virtual files\n");
		}
	}
}

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

	//construct to store the pieces and the rule
	struct Rule input_rule;
	
	if(packet_rule.direction == 1){
		//Things to check for incoming packet
		//setting up the things that dont matter
		input_rule.direction = 0;	
		input_rule.dest_ip= NULL;
		input_rule.dest_port = NULL;
		input_rule.proto_number = 0;

		//setting up the destination for given rule	
		// if source_ip is "*" then assign NULL to its value so we ignore it the rule matching
		if (strcmp(pieces [0], "*") == 0){
			input_rule.source_ip = NULL;
		} else {
			input_rule.source_ip = ip_str_to_bytes(pieces [0]);
		}

		// if source_port is "*" then assign NULL to its value so we ignore it the rule matching
		if (strcmp(pieces [1], "*") == 0){
			input_rule.source_port = NULL;
		} else {
			input_rule.source_port = port_str_to_bytes(pieces [1]);
		}
		if (
				(input_rule.source_ip == NULL || packet_rule.source_ip == *(unsigned int*) input_rule.source_ip)
				&&
				(input_rule.dest_ip == NULL || packet_rule.dest_ip == *(unsigned int*) input_rule.dest_ip)
				&&
				(input_rule.source_port == NULL || packet_rule.source_port == *(unsigned short*) input_rule.source_port)
				&&
				(input_rule.dest_port == NULL || packet_rule.dest_port == *(unsigned short*) input_rule.dest_port)
			){
				return 0;
		}else{
			return 1;
		}
	}else{
		//Things to check for outgoing packet

		//setting up the things that dont matter
		input_rule.direction = 0;	
		input_rule.source_ip = NULL;
		input_rule.source_port = NULL;
		input_rule.proto_number = 0;

		//setting up the destination for given rule	
		// if dest_ip is "*" then assign NULL to its value so we ignore it the rule matching
		if (strcmp(pieces [0], "*") == 0){
			input_rule.dest_ip = NULL;
		} else {
			input_rule.dest_ip = ip_str_to_bytes(pieces [0]);
		}

		// if dest_port is "*" then assign NULL to its value so we ignore it the rule matching
		if (strcmp(pieces [1], "*") == 0){
			input_rule.dest_port = NULL;
		} else {
			input_rule.dest_port = port_str_to_bytes(pieces [1]);
		}
		if (
				(input_rule.source_ip == NULL || packet_rule.source_ip == *(unsigned int*) input_rule.source_ip)
				&&
				(input_rule.dest_ip == NULL || packet_rule.dest_ip == *(unsigned int*) input_rule.dest_ip)
				&&
				(input_rule.source_port == NULL || packet_rule.source_port == *(unsigned short*) input_rule.source_port)
				&&
				(input_rule.dest_port == NULL || packet_rule.dest_port == *(unsigned short*) input_rule.dest_port)
				&&
				(input_rule.proto_number == 0 || packet_rule.proto_number == input_rule.proto_number)
			){
				return 0;
		}else{
			return 1;
		}
	}	
}

unsigned int handle_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	//set the direction to outgoing
	packet_rule.direction = 2;
	
	// Note : you have to change nfho.hooknum manually to switch between filtering incoming and outgoing packages
	sock_buff = skb;
	ip_header = (struct iphdr *) skb_network_header(sock_buff); // grab network header using accessor

	if (!sock_buff) {    // if we dont have a valid sock_buff, accept the packet
		return NF_ACCEPT;
	}

	packet_rule.proto_number = ip_header->protocol;
	packet_rule.source_ip = ip_header->saddr;
	packet_rule.dest_ip = ip_header->daddr;

	switch (packet_rule.proto_number) {
		case 6:    // TCP protocol
			//tcp_header = (struct tcphdr *) (skb_transport_header(sock_buff) + 20);  //grab transport header
			tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl); //grab transport header
			packet_rule.source_port = tcp_header->source;
			packet_rule.dest_port = tcp_header->dest;
			//printk(KERN_INFO "tcp packet \n");
			break;
		case 17:   // UDP protocol
			//udp_header = (struct udphdr *) (skb_transport_header(sock_buff) + 20); //grab transport header
			udp_header= (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl); //grab transport header
			packet_rule.source_port = udp_header->source;
			packet_rule.dest_port = udp_header->dest;
			//printk(KERN_INFO "udp packet \n"); 
			break;
		default:
			printk(KERN_INFO "uknown protocol packet \n");
	}

	//Choose the outgoing rules array
	char* rule_str = rules_array_out[0];

	// iterate through the rules to see if any if the match
	int c = 0;
	while (rule_str != NULL){
		if (check_rule(rule_str) == 0){
			printk(KERN_INFO "------------------------------------------------------------\n");
			printk(KERN_INFO "Outgoing packet dropped!");
			return NF_DROP;
		}
		c++;
		rule_str = rules_array_out[c];
	}
	return NF_ACCEPT; // if none of the rules match, accept the packet
	
}

unsigned int handle_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	//set the direction for incoming packets
	packet_rule.direction = 1;
	
	// Note : you have to change nfho.hooknum manually to switch between filtering incoming and outgoing packages
	sock_buff = skb;
	ip_header = (struct iphdr *) skb_network_header(sock_buff); // grab network header using accessor

	if (!sock_buff) {    // if we dont have a valid sock_buff, accept the packet
		return NF_ACCEPT;
	}

	packet_rule.proto_number = ip_header->protocol;
	packet_rule.source_ip = ip_header->saddr;
	packet_rule.dest_ip = ip_header->daddr;

	switch (packet_rule.proto_number) {
		case 6:    // TCP protocol
			//tcp_header = (struct tcphdr *) (skb_transport_header(sock_buff) + 20);  //grab transport header
			tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl); //grab transport header
			packet_rule.source_port = tcp_header->source;
			packet_rule.dest_port = tcp_header->dest;
			//printk(KERN_INFO "tcp packet \n");
			break;
		case 17:   // UDP protocol
			//udp_header = (struct udphdr *) (skb_transport_header(sock_buff) + 20); //grab transport header
			udp_header= (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl); //grab transport header
			packet_rule.source_port = udp_header->source;
			packet_rule.dest_port = udp_header->dest;
			//printk(KERN_INFO "udp packet \n"); 
			break;
		default:
			printk(KERN_INFO "uknown protocol packet \n");
	}
	
	
	//Choose incoming rules array
	char* rule_str = rules_array_inc[0];

	// iterate through the rules to see if any if the match
	int c = 0;
	while (rule_str != NULL){
		if (check_rule(rule_str) == 0){
			printk(KERN_INFO "------------------------------------------------------------\n");
			printk(KERN_INFO "Incoming packet dropped!");
			return NF_DROP;
		}
		c++;
		rule_str = rules_array_inc[c];
	}
	return NF_ACCEPT; // if none of the rules match, accept the packet

}

int init_module() {
	printk(KERN_INFO "MiniFirewall module inserted! \n");
	//set up virtual files
	int result = setupfiles();
	
	//setting up the hoook for outgoing packets
	nfho_out.hook = handle_out;
	nfho_out.hooknum = NF_INET_POST_ROUTING;  // for filtering outgoing packages
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);

	//setting up the hook for incoming packets
	nfho_inc.hook = handle_in;
	nfho_inc.hooknum = NF_INET_PRE_ROUTING;
	nfho_inc.pf = PF_INET;
	nfho_inc.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_inc);
	return 0;
}

void cleanup_module() {
	remove_proc_entry("inc_rules", NULL);
	remove_proc_entry("out_rules", NULL);
	printk(KERN_INFO "Removed proc entries \n");
	nf_unregister_hook(&nfho_out);
	nf_unregister_hook(&nfho_inc);
	printk(KERN_INFO "Deregistered hooks \n");
	printk(KERN_INFO "MiniFirewall module removed \n");
}
