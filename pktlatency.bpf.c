//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "pktlatency.h"
// #include "task_struct_utils.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";



#define AF_INET 2
#define AF_INET6 10
#define ETH_P_IP	0x0800
#define ETH_HLEN	14		/* Total octets in header.	 */
#define _C(src, a, ...)		BPF_CORE_READ(src, a, ##__VA_ARGS__)
#define _U(src, a, ...)		BPF_PROBE_READ_USER(src, a, ##__VA_ARGS__)
#define IP_H_LEN	(sizeof(struct iphdr))

#define MY_BPF_HASH(name, key_type, value_type) \
struct {													\
	__uint(type, BPF_MAP_TYPE_HASH); \
	__uint(key_size, sizeof(key_type)); \
	__uint(value_size, sizeof(value_type)); \
	__uint(max_entries, 65535); \
	__uint(map_flags, 0); \
} name SEC(".maps");

#define _(src)							\
({								\
	typeof(src) tmp;					\
	bpf_probe_read_kernel(&tmp, sizeof(src), &(src));	\
	tmp;							\
})

const struct kern_evt *kern_evt_unused __attribute__((unused));
const struct conn_evt_t *conn_evt_t_unused __attribute__((unused));
const enum conn_type_t *conn_type_t_unused __attribute__((unused));
const enum endpoint_role_t *endpoint_role_unused  __attribute__((unused));
const enum traffic_direction_t *traffic_direction_t_unused __attribute__((unused));
const enum traffic_protocol_t *traffic_protocol_t_unused __attribute__((unused));

static __always_inline bool skb_l2_check(u16 header)
{
	return !header || header == (u16)~0U;
}
static __always_inline bool skb_l4_check(u16 l4, u16 l3)
{
	return l4 == 0xFFFF || l4 <= l3;
}
static __always_inline struct tcphdr* parse_tcp_hdr(struct iphdr* iph, void* data_end) {
    struct tcphdr* tcph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }
    if ((void*)iph + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return NULL;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return NULL;
    }
    tcph = (struct tcphdr*)((void*)iph + sizeof(struct iphdr));
    return tcph;
}
static __always_inline u8 get_ip_header_len(u8 h)
{
	u8 len = (h & 0x0F) * 4;
	return len > IP_H_LEN ? len: IP_H_LEN;
}
const __u32 target_port = 6379;
const __u32 bytes_interval = 5;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sock_key));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} sock_xmit_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sock_key));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} sock_recm_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sock_key));
	__uint(value_size, sizeof(struct conn_id_s_t));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} sock_key_conn_id_map SEC(".maps");

MY_BPF_HASH(conn_info_map, uint64_t, struct conn_info_t);

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<24);
} rb SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} conn_evt_rb SEC(".maps");

static __always_inline int has_divisible_number(u64 l, u64 r, u64 x) {
	if (l % x == 0) {
		return l;
	} else {
		u64 n = (l / x + 1) * x;
		if (n < r) {
			return n;
		}
		return 0;
	}
}


static __always_inline int get_netns(struct sk_buff *skb)
{	
	if (!skb) {
		return 0;
	}
	struct net_device *dev;
	u32 inode;
	struct net *ns;

	if (!bpf_core_field_exists(possible_net_t, net))
		return 0;


	dev = _C(skb, dev);
	if (!dev) {
		struct sock *sk = _C(skb, sk);
		if (!sk)
			goto no_ns;
		ns = _C(sk, __sk_common.skc_net.net);
	} else {
		ns = _C(dev, nd_net.net);
	}

	if (!ns)
		goto no_ns;

	inode = _C(ns, ns.inum);
	return inode;
no_ns:
	return 0;
}
static __always_inline struct sock_key reverse_sock_key(struct sock_key* key) {
	struct sock_key copy;
	copy.dip = key->sip;
	copy.dport = key->sport;
	copy.sip = key->dip;
	copy.sport = key->dport;
	copy.family = key->family;
	return copy;
}
static void __always_inline parse_kern_evt_body(u32 seq, struct sock_key* key, u32 cur_seq, u32 len, char* func_name, enum step_t step) {
	struct kern_evt* evt = bpf_ringbuf_reserve(&rb, sizeof(struct kern_evt), 0); 
	if(!evt) {
		return;
	}
	struct conn_id_s_t* conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, key);
	if (conn_id_s == NULL) {
		bpf_ringbuf_discard(evt, 0);
		return;
	}
	bpf_core_read(&evt->conn_id_s, sizeof(struct conn_id_s_t), conn_id_s);
	evt->seq = cur_seq; 
	u32 bl_bdr = evt->seq;
	// u32 doff = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff);
	// u64 hdr_len = doff << 2;
	u32 br_bdr = bl_bdr + len;
	evt->len = br_bdr - bl_bdr; 
	evt->is_sample = has_divisible_number(bl_bdr, br_bdr, bytes_interval); 
	evt->ts = bpf_ktime_get_ns();
	evt->step = step;
	my_strcpy(evt->func_name, func_name, FUNC_NAME_LIMIT);
	bpf_ringbuf_submit(evt, 0);
}
static __always_inline void  report_kern_evt(u32 seq, struct sock_key* key,struct tcphdr* tcp, int size, char* func_name, enum step_t step) {
	struct kern_evt* evt = bpf_ringbuf_reserve(&rb, sizeof(struct kern_evt), 0); 
	if(!evt) {
		return;
	}
	struct conn_id_s_t* conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, key);
	if (conn_id_s == NULL) {
		bpf_ringbuf_discard(evt, 0);
		return;
	}
	bpf_core_read(&evt->conn_id_s, sizeof(struct conn_id_s_t), conn_id_s);
	evt->seq = (uint64_t)(bpf_ntohl(_(tcp->seq)) - seq); 
	// evt->tcp_seq = bpf_ntohl(_(tcp->seq));
	u32 bl_bdr = evt->seq;
	u32 doff = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff);
	u64 hdr_len = doff << 2;
	u32 br_bdr = bl_bdr + size - hdr_len;
	evt->len = br_bdr - bl_bdr;
	evt->is_sample = has_divisible_number(bl_bdr, br_bdr, bytes_interval);
	evt->ts = bpf_ktime_get_ns();
	evt->step = step;
	my_strcpy(evt->func_name, func_name, FUNC_NAME_LIMIT);

	bpf_ringbuf_submit(evt, 0);
	// evt->inode = get_netns(skb);
}
static void __always_inline report_syscall_evt(uint64_t seq, struct conn_id_s_t *conn_id_s, uint32_t len, enum step_t step) {
	struct kern_evt* evt = bpf_ringbuf_reserve(&rb, sizeof(struct kern_evt), 0); 
	if(!evt || !conn_id_s) {
		return;
	}
	evt->conn_id_s = *conn_id_s;
	evt->seq = seq;
	evt->len = len;
	evt->step = step;
	evt->ts = bpf_ktime_get_ns();
	char *func_name = "syscall";
	my_strcpy(evt->func_name, func_name, FUNC_NAME_LIMIT);
	bpf_ringbuf_submit(evt, 0);
}


static void __always_inline report_conn_evt(struct conn_info_t *conn_info, enum conn_type_t type) {
	struct conn_evt_t* evt = bpf_ringbuf_reserve(&conn_evt_rb, sizeof(struct conn_evt_t), 0); 	
	if (!evt) {
		return;
	}
	evt->conn_info = *conn_info;
	evt->conn_type = type;
	evt->ts = bpf_ktime_get_ns();
	bpf_ringbuf_submit(evt, 0);
}

static void __always_inline debug_evt(struct kern_evt* evt, char* func_name) {
	// bpf_printk("KPROBE ENTRY, func: %s, lip: %d, dip:%d",func_name, evt.key->sip, evt.key->dip);
	// bpf_printk("KPROBE ENTRY, lport: %d, dport:%d, seq: %u", evt.key->sport, evt.key->dport, evt->tcp_seq);
	// bpf_printk("KPROBE ENTRY init_seq = %u, cur_seq: %u, len: %d\n",evt->init_seq, evt->cur_seq,evt->data_len);
	// bpf_printk("is_sample: %d, ts: %u, inode: %d\n", evt->is_sample, evt->ts, evt->inode);
}
#define DEBUG 0
// #define KERN_EVENT_HANDLE(evt, func_name) \
// 	if(DEBUG) { \
// 		debug_evt(evt, func_name); \
// 	} else { \
// 		report_kern_evt(evt, func_name); \
// 	} 
static void __always_inline parse_sock_key_rcv_sk(struct sock* sk, struct sock_key* key) {

	key->sip = _C(sk, __sk_common.skc_daddr);
	key->dip = _C(sk, __sk_common.skc_rcv_saddr);
	key->dport =  _C(sk, __sk_common.skc_num);
	key->sport = bpf_ntohs(_C(sk, __sk_common.skc_dport));
	// key->family = _C(sk, __sk_common.skc_family);
	key->family = 0;
}
static void __always_inline parse_sock_key_rcv(struct sk_buff *skb, struct sock_key* key) {

	struct sock* sk = _(skb->sk);
	parse_sock_key_rcv_sk(sk, key);
}
static void __always_inline print_sock_key(struct sock_key* key) {
	bpf_printk("print_sock_key port: sport:%u, dport:%u", key->sport, key->dport);
	bpf_printk("print_sock_key addr: saddr:%u, daddr:%u", key->sip, key->dip);
	bpf_printk("print_sock_key family: family:%u", key->family);
}
static void __always_inline parse_sock_key_sk(struct sock* sk, struct sock_key* key) {
	key->dip = _C(sk, __sk_common.skc_daddr);
	key->sip = _C(sk, __sk_common.skc_rcv_saddr);
	key->sport =  _C(sk, __sk_common.skc_num);
	key->dport = bpf_ntohs(_C(sk, __sk_common.skc_dport));
	// key->family = _C(sk, __sk_common.skc_family);
	key->family = 0;
}
static void __always_inline parse_sock_key(struct sk_buff *skb, struct sock_key* key) {

	struct sock* sk = _(skb->sk);
	parse_sock_key_sk(sk, key);
}

static void __always_inline parse_sk_l3l4(struct sock_key *key, struct iphdr *ipv4, 
	struct tcphdr *tcp) {
	u32 saddr, daddr;
	saddr = _(ipv4->saddr);
	daddr = _(ipv4->daddr);
	u16 sport = bpf_htons(_(tcp->source));
	u16 dport = bpf_htons(_(tcp->dest));
	key->sip = saddr;
	key->dip = daddr;
	key->sport = sport;
	key->dport = dport;
	key->family = 0;
}

static __inline bool should_trace_conn(struct conn_info_t *conn_info) {
	// conn_info->laddr.in4.sin_port
	// bpf_printk("conn_info->laddr.in4.sin_port: %d, %d", 
	// 	conn_info->laddr.in4.sin_port,conn_info->raddr.in4.sin_port);
	// if (conn_info->laddr.in4.sin_port == target_port || 
	// 	conn_info->raddr.in4.sin_port == target_port) {
	// 		return true;
	// }

	return conn_info->protocol != kProtocolUnknown;
}
static bool __always_inline should_trace_sock_key(struct sock_key *key) {
	struct conn_id_s_t *conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, key);
	if (conn_id_s == NULL) {
		// 可能还在握手
		return true;
	}
	struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &conn_id_s->tgid_fd);
	if (conn_info == NULL) {
		// why?
		return true;
	}
	return should_trace_conn(conn_info);
}
static __always_inline int parse_skb(struct sk_buff *skb, char* func_name, bool sk_not_ready, enum step_t step) {
	struct sock* sk = _(skb->sk);
	struct sock_common sk_cm = _C(sk, __sk_common);
	u32 inital_seq = 0;
	struct sock_key key = {0};
	if (sk && sk_cm.skc_addrpair && !sk_not_ready) {
		parse_sock_key(skb, &key);
		int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
		if (found == NULL) { 
			return 0;
		}
		if (!should_trace_sock_key(&key)) {
			return 0;
		}
		bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
	} 

	u16 network_header = _C(skb, network_header);
	u16 mac_header = _C(skb, mac_header);
	u16 trans_header = _C(skb, transport_header);
	
	// bpf_printk("%s, len: %u, data_len: %u",func_name, _C(skb, len), _C(skb, data_len));
	// bpf_printk("%s, mac_header: %d", func_name,mac_header);
	// bpf_printk("%s, network_header: %d", func_name,network_header);
	// bpf_printk("%s, trans_header: %d", func_name,trans_header);
	// bpf_printk("data:%d,end: %d, tail: %d",_(skb->data) - _(skb->head), _(skb->end), _(skb->tail));

	bool is_l2 = !skb_l2_check(mac_header);
	// bpf_printk("%s, skb_l2_check: %d", func_name, is_l2);
	void* data = _C(skb, head);
	void* ip = data + network_header;
	void *l3;
	void* l4 = NULL;
	if (is_l2) {
		goto __l2;
	} else {
		u16 l3_proto = bpf_ntohs(_C(skb, protocol));
		// bpf_printk("%s, l3_proto: %x", func_name, l3_proto);
		if (l3_proto == ETH_P_IP) {
			// bpf_printk("%s, is_ip: %d", func_name, 1);
			l3 = data + network_header;
			goto __l3;
		} else if (mac_header == network_header) {
			l3 = data + network_header;
			l3_proto = ETH_P_IP;
			goto __l3;
		}
		// bpf_printk("%s, is_ip: %d", func_name,0);
		goto err;
	}
	__l2: if (mac_header != network_header) {
		struct ethhdr *eth = data + mac_header;
		l3 = (void *)eth + ETH_HLEN;
		u16 l3_proto = bpf_ntohs(_(eth->h_proto));
		// bpf_printk("%s, l3_proto: %x",func_name, l3_proto);
		if (l3_proto == ETH_P_IP) {
	__l3:	
			if (!skb_l4_check(trans_header, network_header)) {
				// 存在l4
				// bpf_printk("%s, skb_l4_check: %d",func_name, 0);
				l4 = data + trans_header;
			}
			struct iphdr *ipv4 = ip;
			u32 len  = bpf_ntohs(_C(ipv4, tot_len));
			u8 ip_hdr_len = get_ip_header_len(_(((u8 *)ip)[0])); 
			// bpf_printk("%s, ip_hdr_len: %d, tot_len: %d",func_name, ip_hdr_len, len);
			l4 = l4 ? l4 : ip + ip_hdr_len;
			u8 proto_l4 = _(ipv4->protocol);
			// bpf_printk("%s, l4p: %d",func_name, proto_l4);
			if (proto_l4 == IPPROTO_TCP) {
				struct tcphdr *tcp = l4;
				if (!inital_seq) {
					// 在这里补充sk
					parse_sk_l3l4(&key, ipv4, tcp);
					// bpf_printk("%s, dport12: %d",func_name, key.dport);
					// if (key.dport != target_port && key.sport != target_port) {
					// 	goto err;
					// }
					if (!should_trace_sock_key(&key)) {
						goto err;
					}
					int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
					if (found == NULL) {
						goto err;
					}
					bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
				}
				report_kern_evt(inital_seq, &key, tcp, len - ip_hdr_len, func_name, step);
				return 1;
			} else {
				// bpf_printk("%s, not match: %d", func_name, _(ipv4->saddr));
			}
		}
	}
	err:return BPF_OK;
}
SEC("xdp")
int xdp_proxy(struct xdp_md *ctx){
	// bpf_printk("xdp");
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) {
		bpf_printk("xdp2 data + sizeof(struct ethhdr) > data_end");
		return XDP_PASS;
	}
	u16 l3_proto = _C(eth, h_proto);
	// bpf_printk("xdp, l3_proto: %x", l3_proto);
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
	{
		bpf_printk("xdp2 data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end");
		return XDP_ABORTED;
	}
	if (iph->protocol != IPPROTO_TCP)
	{
		// bpf_printk("xdp2 iph->protocol != IPPROTO_TCP, %x", iph->protocol);
		return XDP_PASS;
	}
	struct tcphdr* th = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
		bpf_printk("xdp2 data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end");
		return XDP_ABORTED;
	}
	
	struct sock_key key = {0};
	key.sip = iph->saddr;
	key.dip = iph->daddr;
	key.sport = bpf_ntohs(th->source);
	key.dport = bpf_ntohs(th->dest);
	key.family = 0;
	int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
	if (found == NULL || !should_trace_sock_key(&key)) {
		// bpf_printk("xdp key.dport != target_port, %u,%u", key.dport, key.sport);
		return XDP_PASS;
	}
	u32 inital_seq;
	if (found == NULL) {
		inital_seq = bpf_ntohl(th->seq);
		bpf_map_update_elem(&sock_xmit_map, &key,&inital_seq, BPF_NOEXIST);
		// bpf_printk("xdp not found!, seq: %u", inital_seq);
		// bpf_printk("xdp, not found!, sip: %u, dip:%u", bpf_ntohl(key.sip), bpf_ntohl(key.dip));
		// bpf_printk("xdp, not found!, sport:%d, dport:%d, family:%d", key.sport, key.dport,key.family);
	} else {
		bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
		bpf_printk("xdp found!, seq: %u", inital_seq);
	}
	u32 len = data_end - data - (sizeof(struct ethhdr) + sizeof(struct iphdr));
	// bpf_printk("xdp, skb: %x", data);
	report_kern_evt(inital_seq, &key, th, len, "xdp", NIC_IN);
	// KERN_EVENT_HANDLE(&evt, "xdp");
	return XDP_PASS;
}
struct client {
    uint64_t id;            /* Client incremental unique ID. */
    uint64_t flags;         /* Client flags: CLIENT_* macros. */
    void *conn;
    int resp;               /* RESP protocol version. Can be 2 or 3. */
    void *db;            /* Pointer to currently SELECTed DB. */
    void *name;             /* As set by CLIENT SETNAME. */
    void *lib_name;         /* The client library name as set by CLIENT SETINFO. */
    void *lib_ver;          /* The client library version as set by CLIENT SETINFO. */
    char* querybuf;           /* Buffer we use to accumulate client queries. */
    size_t qb_pos; 
};

struct  _writeToClient_args {
	struct client* cli;
	ssize_t* nritten;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct  _writeToClient_args));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} _writeToClient_args_map SEC(".maps");

// BPF_MAP_TYPE_ARRAY 当前正在处理的命令，是这个socket上多少个bytes


struct seq_range {
	uint64_t seq;
	uint32_t len;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct seq_range));
	__uint(max_entries, 1);
	__uint(map_flags, 0);
} cur_redis_req SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(void*));
	__uint(value_size, sizeof(uint64_t));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} redis_response_seq SEC(".maps");

SEC("uprobe//usr/local/bin/redis-server:_writeToClient")
int BPF_UPROBE(_writeToClient) {
	ssize_t* nritten = (ssize_t*)PT_REGS_PARM2(ctx);
	struct _writeToClient_args args = {0};
	args.cli  = (struct client*)PT_REGS_PARM1(ctx);
	args.nritten = nritten;
	u32 key = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&_writeToClient_args_map, &key, &args, BPF_NOEXIST);
	
	bpf_printk("_writeToClient");
	return BPF_OK;
}

SEC("uretprobe//usr/local/bin/redis-server:_writeToClient")
int BPF_URETPROBE(_writeToClientReturn) {
	u32 key = bpf_get_current_pid_tgid();
	struct _writeToClient_args *args = bpf_map_lookup_elem(&_writeToClient_args_map, &key);
	if (!args) {
		return BPF_OK;
	}
	bpf_map_delete_elem(&_writeToClient_args_map, &key);
	ssize_t* p = args->nritten;
	ssize_t _n ;
	bpf_probe_read_user(&_n, sizeof(ssize_t), p);

	struct client* cli = args->cli;
	void* conn = _U(cli, conn);
	uint64_t *seq = bpf_map_lookup_elem(&redis_response_seq, &conn);
	uint64_t final_seq ;
	if (seq) {
		final_seq = *seq + _n;
		// bpf_printk("redis:_addReplyToBufferOrListReturn, seq: %d, len: %d", *seq, len);
	} else {
		final_seq = _n+1;
		// bpf_printk("redis:_addReplyToBufferOrListReturn, seq: %d, len: %d", 1, len);
	}
	bpf_map_update_elem(&redis_response_seq, &conn, &final_seq, BPF_ANY);
	
	int cmd_key = 1;
	struct seq_range *sr = bpf_map_lookup_elem(&cur_redis_req, &cmd_key);
	if (!sr) {
		bpf_printk("_writeToClientReturn not found");
		return BPF_OK;
	}

	bpf_printk("_writeToClientReturn, seq: %u, len: %u", seq?*seq:1, _n);
	bpf_printk("_writeToClientReturn, cli seq: %u, cli len: %u",sr->seq, sr->len);
	return BPF_OK;
}
struct  processMultibulkBuffer_args {
	struct client* cli;
	size_t pos;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct processMultibulkBuffer_args));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} processMultibulkBufferReturn_args_map SEC(".maps");
struct  _addReplyToBufferOrList_args {
	struct client* cli;
	size_t len;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct  _addReplyToBufferOrList_args));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} _addReplyToBufferOrList_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(void*));
	__uint(value_size, sizeof(uint64_t));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} redis_client_seq SEC(".maps");


SEC("uprobe//usr/local/bin/redis-server:_addReplyToBufferOrList")
int BPF_UPROBE(_addReplyToBufferOrList){
	// void* client_p = PT_REGS_PARM1(ctx);
	// struct client* cli = (struct client*) client_p;
	// size_t len = PT_REGS_PARM3(ctx);
	// struct _addReplyToBufferOrList_args args = {0};
	// args.cli = cli;
	// args.len = len;
	// u32 key = bpf_get_current_pid_tgid();
	// bpf_map_update_elem(&_addReplyToBufferOrList_args_map, &key, &args, BPF_NOEXIST);
	return BPF_OK;
}

SEC("uretprobe//usr/local/bin/redis-server:_addReplyToBufferOrList")
int BPF_URETPROBE(_addReplyToBufferOrListReturn){
	// u32 key = bpf_get_current_pid_tgid();
	// struct _addReplyToBufferOrList_args *args = bpf_map_lookup_elem(&_addReplyToBufferOrList_args_map, &key);
	// if (!args) {
	// 	return BPF_OK;
	// }
	// bpf_map_delete_elem(&_addReplyToBufferOrList_args_map, &key);
	// struct client* cli = args->cli;
	// void* conn = _U(cli, conn);
	// size_t len = args->len;
	// uint64_t *seq = bpf_map_lookup_elem(&redis_response_seq, &conn);
	// uint64_t final_seq ;
	// if (seq) {
	// 	final_seq = *seq + len;
	// 	// bpf_printk("redis:_addReplyToBufferOrListReturn, seq: %d, len: %d", *seq, len);
	// } else {
	// 	final_seq = len+1;
	// 	// bpf_printk("redis:_addReplyToBufferOrListReturn, seq: %d, len: %d", 1, len);
	// }
	// bpf_map_update_elem(&redis_response_seq, &conn, &final_seq, BPF_ANY);
	return BPF_OK;
}

SEC("uprobe//usr/local/bin/redis-server:processMultibulkBuffer")
int BPF_KPROBE(processMultibulkBuffer){
	void* client_p = (void*)PT_REGS_PARM1(ctx);
	bpf_printk("redis:processMultibulkBuffer,p1:%x", client_p);
	struct client* cli = (struct client*) client_p;
	uint64_t id = _U(cli,id);
	void* conn = _U(cli,conn);
	bpf_printk("redis:processMultibulkBuffer, cli_id:%d, %x", id, _U(cli,querybuf));
	bpf_printk("redis:processMultibulkBuffer, pos: %d", _U(cli,qb_pos));
	u32 key = bpf_get_current_pid_tgid();
	struct processMultibulkBuffer_args value = {0};
	value.cli = cli;
	value.pos = _U(cli,qb_pos);
	bpf_map_update_elem(&processMultibulkBufferReturn_args_map, &key, &value, BPF_NOEXIST);
	
	
	return BPF_OK;
}

SEC("uretprobe//usr/local/bin/redis-server:processMultibulkBuffer")
int BPF_KRETPROBE(processMultibulkBufferReturn){
	u32 key = bpf_get_current_pid_tgid();
	struct processMultibulkBuffer_args *value = bpf_map_lookup_elem(&processMultibulkBufferReturn_args_map, &key);
	if (!value) {
		return BPF_OK;
	}
	struct client* cli = value->cli;
	void* conn = _U(cli, conn);
	size_t pos = value->pos;
	bpf_map_delete_elem(&processMultibulkBufferReturn_args_map, &key);
	size_t cur_pos = _U(value->cli,qb_pos);
	size_t len = cur_pos - pos;
	// bpf_printk("redis:processMultibulkBuffer, process len: %d", len);
	uint64_t *seq = bpf_map_lookup_elem(&redis_client_seq, &conn);
	uint64_t final_seq;
	if (seq) {
		final_seq = *seq + len;
		bpf_printk("redis:processMultibulkBufferReturn, seq: %d, len: %d", *seq, len);
	} else {
		final_seq = len + 1;
		bpf_printk("redis:processMultibulkBufferReturn, seq: %d, len: %d", 1, len);
	}
	bpf_map_update_elem(&redis_client_seq, &conn, &final_seq, BPF_ANY);
	// 在这里设置当前处理的命令
	int cmd_key = 1;
	struct seq_range sr = {0};
	sr.seq = seq ? *seq : 1;
	sr.len = len;
	bpf_map_update_elem(&cur_redis_req, &cmd_key, &sr, BPF_ANY);
	// report seq + len
	return BPF_OK;
}


SEC("uprobe//usr/local/bin/redis-server:connSocketRead")
int BPF_UPROBE(connSocketRead){
	void* base = (void*)PT_REGS_PARM2(ctx);
	bpf_printk("redis:connSocketRead,p1:%x, buf: %x, p3: %d", PT_REGS_PARM1(ctx),base,PT_REGS_PARM3(ctx));
	return BPF_OK;
}



SEC("kprobe/__skb_datagram_iter")
int BPF_KPROBE(skb_copy_datagram_iter, struct sk_buff *skb, int offset, struct iov_iter *to, int len) {
	struct sock_key key = {0};
	parse_sock_key_rcv(skb, &key);
	int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
	if (!found) {
		// bpf_printk("skb_copy_datagram_iter, not found!, sip: %u, dip:%u", bpf_ntohl(key.sip), bpf_ntohl(key.dip));
		// bpf_printk("skb_copy_datagram_iter, not found!, sport:%d, dport:%d,family:%d", key.sport, key.dport, key.family);
		return BPF_OK;
	}
	if (!should_trace_sock_key(&key)) {
		return BPF_OK;
	}
	u32 inital_seq;
	bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
	// bpf_printk("skb_copy_datagram_iter, found!, sip: %u, dip:%u", bpf_ntohl(key.sip), bpf_ntohl(key.dip));
	// bpf_printk("skb_copy_datagram_iter, found!, sport:%d, dport:%d,family:%d", key.sport, key.dport, key.family);
	// bpf_printk("skb_copy_datagram_iter, init_seq: %u, iter_type: %d", inital_seq, _(to->iter_type));

	char* p_cb = _(skb->cb);
	struct tcp_skb_cb *cb = (struct tcp_skb_cb *)&p_cb[0];
	u32 seq = cb->seq + offset;
	// bpf_printk("skb_copy_datagram_iter, seq: %u, off: %u, len: %u", cb->seq, offset, len);
	parse_kern_evt_body(inital_seq, &key, seq - inital_seq, len, "skb_copy_datagram_iter", USER_COPY);
	// parse_skb(skb, "skb_copy_datagram_iter", 0);
	// if (_(to->iter_type) == ITER_IOVEC) {
	// 	struct iovec *iov = _(to->iov);
	// 	bpf_printk("skb_copy_datagram_iter, addr: %x, off: %x ,len: %d", _(iov->iov_base), _(to->iov_offset), _(iov->iov_len));
	// }
	return BPF_OK;
}

SEC("kprobe/tcp_queue_rcv")
int BPF_KPROBE(tcp_queue_rcv, struct sock *sk, struct sk_buff *skb) {
	// parse_skb(skb, "tcp_queue_rcv", 0, kTcpIn);
	return BPF_OK;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
	// parse_skb(skb, "tcp_rcv_established", 0, kTcpIn);
	return BPF_OK;
}  
  
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb) { 
	parse_skb(skb, "tcp_v4_do_rcv", 1, TCP_IN);
	return BPF_OK;
}
 
SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv, struct sk_buff *skb) {
	// parse_skb(skb, "tcp_v4_rcv", 1);
	return BPF_OK;
}

#ifdef FOR_OTHER_MACHINE 
SEC("kprobe/ip_rcv_core.isra.0")
#else
SEC("kprobe/ip_rcv_core")
#endif 
int BPF_KPROBE(ip_rcv_core, struct sk_buff *skb) {
	parse_skb(skb, "ip_rcv_core", 1, IP_IN);
	return BPF_OK;
} 
// 出队之后，发送到设备
SEC("kprobe/dev_hard_start_xmit")
int BPF_KPROBE(dev_hard_start_xmit, struct sk_buff *first) {
	struct sk_buff *skb = first;
	for (int i = 0; i < 16; i++) {
		int ret = parse_skb(skb, "dev_hard_start_xmit", 0, DEV_OUT);
		// if (ret) bpf_printk("dev_hard_start_xmit, final: %d", i);
		skb = _(skb->next);
		if (!skb) {
			
			return 0;
		}
	}
	
	return 0;
}
// 进入qdisc之前
SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(dev_queue_xmit, struct sk_buff *skb) {
	parse_skb(skb, "dev_queue_xmit", 0, QDISC_OUT);
	return 0;
}

SEC("kprobe/ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit, struct sock *sk, struct sk_buff *skb)
{
	struct sock_key key = {0};
	parse_sock_key(skb, &key);
	// 如果map里有才进行后面的步骤
	int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
	if (found == NULL || !should_trace_sock_key(&key)) {
		// bpf_printk("kp, lip: %d, dip:%d", key.sip, key.dip);
		// bpf_printk("ip_queue_xmit, lport: %d, dport:%d", key.sport, key.dport);
		return 0;
	}
	u32 inital_seq;
	if (found == NULL) {
		struct tcphdr* tcp = (struct tcphdr*)_C(skb, data);
		inital_seq = bpf_ntohl(_(tcp->seq)); 
		bpf_map_update_elem(&sock_xmit_map, &key,&inital_seq, BPF_NOEXIST);
		// bpf_printk("not found!, seq: %u", inital_seq);
	} else {
		bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
		// bpf_printk("found!, seq: %u", inital_seq);
	}

	struct tcphdr* tcp = (struct tcphdr*)_C(skb, data);
	report_kern_evt(inital_seq, &key, tcp, _C(skb, len), "ip_queue_xmit", IP_OUT);
	// KERN_EVENT_HANDLE(&evt, "ip_queue_xmit");
	return 0;
}

SEC("raw_tp/tcp_destroy_sock")
int BPF_PROG(tcp_destroy_sock, struct sock *sk)
{
	struct sock_key key = {0};
	// parse_sock_key_sk(sk, &key);
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	parse_sock_key_sk(sk,&key);
	key.sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	int err;
	err = bpf_map_delete_elem(&sock_xmit_map, &key);
	bpf_map_delete_elem(&sock_recm_map, &key);
	struct conn_id_s_t *conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, &key);
	uint64_t tgid_fd;
	if (conn_id_s != NULL) {
		tgid_fd = conn_id_s->tgid_fd;
		struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
		if (conn_info != NULL) {
			report_conn_evt(conn_info, kClose);
		}
		bpf_map_delete_elem(&conn_info_map, &tgid_fd);
		bpf_map_delete_elem(&sock_key_conn_id_map, &key);
		struct sock_key rev_key = reverse_sock_key(&key);
		bpf_map_delete_elem(&sock_key_conn_id_map, &rev_key);
	}
	if (!err) {
		bpf_printk("tcp_destroy_sock, sock destory, %d, %d", key.sport, key.dport);
	}
	return BPF_OK;
}

MY_BPF_HASH(accept_args_map, uint64_t, struct accept_args)
MY_BPF_HASH(connect_args_map, uint64_t, struct connect_args)
MY_BPF_HASH(close_args_map, uint64_t, struct close_args)
MY_BPF_HASH(write_args_map, uint64_t, struct data_args)
MY_BPF_HASH(read_args_map, uint64_t, struct data_args)


static __inline void read_sockaddr_kernel(struct conn_info_t* conn_info,
                                          const struct socket* socket) {
  // Use BPF_PROBE_READ_KERNEL_VAR since BCC cannot insert them as expected.
  struct sock* sk = _C(socket, sk);

  struct sock_common sk_common = _(sk->__sk_common);
  uint16_t family = sk_common.skc_family;
  uint16_t lport = sk_common.skc_num;
  uint16_t rport = bpf_ntohs(sk_common.skc_dport);

  conn_info->laddr.in4.sin_family = family;
  conn_info->raddr.in4.sin_family = family;

  if (family == AF_INET) {
    conn_info->laddr.in4.sin_port = lport;
    conn_info->raddr.in4.sin_port = rport;
	conn_info->laddr.in4.sin_addr.s_addr = sk_common.skc_rcv_saddr;
	conn_info->raddr.in4.sin_addr.s_addr = sk_common.skc_daddr;
  } 
}


static __inline void init_conn_id(uint32_t tgid, int32_t fd, struct conn_id_t* conn_id) {
  conn_id->upid.tgid = tgid;
  conn_id->upid.start_time_ticks = 0;
//   conn_id->upid.start_time_ticks = get_tgid_start_time();
  conn_id->fd = fd;
  conn_id->tsid = bpf_ktime_get_ns();
}
static __inline void init_conn_info(uint32_t tgid, int32_t fd, struct conn_info_t* conn_info) {
  init_conn_id(tgid, fd, &conn_info->conn_id);
  conn_info->role = kRoleUnknown;
  conn_info->laddr.in4.sin_family = PX_AF_UNKNOWN;
  conn_info->raddr.in4.sin_family = PX_AF_UNKNOWN;
}

static __inline uint64_t gen_tgid_fd(uint32_t tgid, int fd) {
  return ((uint64_t)tgid << 32) | (uint32_t)fd;
}
static __always_inline struct tcp_sock *get_socket_from_fd(int fd_num) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct files_struct *files = _(task->files);
	struct fdtable *fdt = _(files->fdt);
	struct file **fd = _(fdt->fd);
	void *file;
	bpf_probe_read(&file, sizeof(file), fd + fd_num);
	struct file *__file = (struct file *)file;
	void *private_data = _(__file->private_data);
	if (private_data == NULL) {
		return NULL;
	}
	struct socket *socket = (struct socket *) private_data;
	short socket_type = _(socket->type);
	struct file *socket_file = _(socket->file);
	void *check_file;
	struct tcp_sock *sk;
	struct socket __socket;
	if (socket_file != file) {
		// check_file = __socket.wq;
		sk = _(socket->file);
	} else {
		check_file = _(socket->file);
		sk = _(socket->sk);
	}
	if ((socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) &&
	    check_file == file /*&& __socket.state == SS_CONNECTED */) {
		return sk;
	}
	return NULL;
}

static __inline void submit_new_conn(struct pt_regs* ctx, uint32_t tgid, int32_t fd,
const struct sockaddr* addr, const struct socket* socket,
enum endpoint_role_t role) {
	struct conn_info_t conn_info = {};
	uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
	init_conn_info(tgid, fd, &conn_info);
	if (socket != NULL) {
		read_sockaddr_kernel(&conn_info, socket);
		// bpf_printk("read_sockaddr_kernel laddr: port:%u", conn_info.laddr.in4.sin_port);
		// bpf_printk("read_sockaddr_kernel raddr: port:%u", conn_info.raddr.in4.sin_port);
	} else if (addr != NULL) {
		bpf_probe_read_user(&conn_info.raddr, sizeof(union sockaddr_t), addr);
		struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
		conn_info.raddr.in4.sin_port = bpf_ntohs(conn_info.raddr.in4.sin_port);
		// conn_info.raddr = *((union sockaddr_t*)addr);
	} else {
		bpf_printk("raddr: null");
	}
	struct tcp_sock * tcp_sk = get_socket_from_fd(fd);
	struct sock_key key;
	parse_sock_key_sk((struct sock*)tcp_sk, &key);
	// print_sock_key(&key);
	if (socket == NULL) {
		conn_info.laddr.in4.sin_addr.s_addr = key.sip;
		conn_info.laddr.in4.sin_port = key.sport;
		conn_info.raddr.in4.sin_addr.s_addr = key.dip;
		conn_info.raddr.in4.sin_port = key.dport;
	}
	// bpf_printk("submit_new_conn laddr: port:%u", conn_info.laddr.in4.sin_port);
	// bpf_printk("submit_new_conn raddr: port:%u", conn_info.raddr.in4.sin_port);

	conn_info.role = role;
	if (should_trace_conn(&conn_info)) {
		bpf_printk("read_sockaddr_kernel lport: %u, dport: %u, tgid_fd:%x", conn_info.laddr.in4.sin_port, conn_info.raddr.in4.sin_port, tgid_fd);
		bpf_map_update_elem(&conn_info_map, &tgid_fd, &conn_info, BPF_ANY);
		struct conn_id_s_t conn_id_s = {};
		conn_id_s.direct = role == kRoleClient ? kEgress : kIngress;
		conn_id_s.tgid_fd = tgid_fd;
		bpf_map_update_elem(&sock_key_conn_id_map, &key, &conn_id_s, BPF_NOEXIST);
		struct sock_key rev = reverse_sock_key(&key);
		struct conn_id_s_t conn_id_s_rev = {};
		conn_id_s_rev.direct = role == kRoleClient ? kIngress : kEgress;
		conn_id_s_rev.tgid_fd = tgid_fd;
		bpf_map_update_elem(&sock_key_conn_id_map, &rev, &conn_id_s_rev, BPF_NOEXIST);
		report_conn_evt(&conn_info, kConnect);
	}

	// struct sock_key key;
	// if (role == kRoleServer) {
	// 	key.sip = conn_info.raddr.in4.sin_addr.s_addr;
	// 	key.dip = conn
	// }
}

// static __inline void update_traffic_class(struct conn_info_t* conn_info,enum traffic_direction_t direction, const char* buf,size_t count) {
// 	if (conn_info == NULL) {
// 		return
// 	} 
// }

static __always_inline void process_syscall_close(struct pt_regs* ctx, struct close_args *args, uint64_t id) {
	uint32_t tgid = id >> 32;
	int  ret_val = PT_REGS_RC_CORE(ctx);
	if (args->fd < 0) {
		bpf_printk("close syscall args->fd:%d", args->fd);
		return;
	}
	if (ret_val < 0) {
		bpf_printk("close syscall ret_val:%u", ret_val);
		return;
	}
	uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
	struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	if (conn_info == NULL) {
		return;
	}
	bpf_printk("close syscall tgid_fd:%u", tgid_fd);
	
	report_conn_evt(conn_info, kClose);

	bpf_map_delete_elem(&conn_info_map, &tgid_fd);
	
	struct sock_key key;
	key.sip = conn_info->laddr.in4.sin_addr.s_addr;
	key.sport = conn_info->laddr.in4.sin_port;
	key.dip = conn_info->raddr.in4.sin_addr.s_addr;
	key.dport = conn_info->raddr.in4.sin_port;
	key.family = 0;
	bpf_map_delete_elem(&sock_key_conn_id_map, &key);
	struct sock_key rev_key = reverse_sock_key(&key);
	bpf_map_delete_elem(&sock_key_conn_id_map, &rev_key);
}

static __always_inline void process_syscall_connect(struct pt_regs* ctx, struct connect_args *args, uint64_t id) {
	uint32_t tgid = id >> 32;
	int  ret_val = PT_REGS_RC_CORE(ctx);
	if (ret_val < 0 && ret_val != -EINPROGRESS) {
    	return;
  	}
	if (args->fd < 0) {
		return;
	}
	submit_new_conn(ctx, tgid, args->fd, args->addr, NULL, kRoleClient );
}
static __always_inline void process_syscall_accept(struct pt_regs* ctx, struct accept_args *args, uint64_t id) {
	uint32_t tgid = id >> 32;
	int  ret_fd = PT_REGS_RC_CORE(ctx);
	if (ret_fd < 0) {
		// bpf_printk("process_syscall_accept, ret_fd: %d, socket:%d", -ret_fd,args->sock_alloc_socket);
		return;
	}
	// bpf_printk("process_syscall_accept, ret_fd: %d, socket:%d", ret_fd,args->sock_alloc_socket);
	submit_new_conn(ctx, tgid, ret_fd, args->addr, args->sock_alloc_socket, kRoleServer );
}

static __always_inline void process_syscall_data(struct pt_regs* ctx, struct data_args *args, uint64_t id, enum traffic_direction_t direct,
	ssize_t bytes_count) {
	uint32_t tgid = id >> 32;
	uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
	struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	if (!conn_info) {
		return;
	}
	if (conn_info->protocol == kProtocolUnset) {
		struct protocol_message_t protocol_message = infer_protocol(args->buf, bytes_count, conn_info);
		// conn_info->protocol = protocol_message.protocol;
		bpf_printk("[protocol infer]: %d", conn_info->protocol);
		report_conn_evt(conn_info, kProtocolInfer);
		if (conn_info->raddr.in4.sin_port == 6379 && bytes_count > 16) {
			char buf[1] = {};
			bpf_probe_read_user(buf, 1, args->buf);
			bpf_printk("test, redis first byte is: %c", buf[0]);
		}
	}
	if (!should_trace_conn(conn_info)) {
		return;
	}
	bpf_printk("start trace data!, bytes_count:%d,func:%d", bytes_count, args->source_fn);
	uint64_t seq = (direct == kEgress ? conn_info->write_bytes : conn_info->read_bytes) + 1;
	struct conn_id_s_t conn_id_s;
	conn_id_s.tgid_fd = tgid_fd;
	conn_id_s.direct = direct;
	enum step_t step = direct == kEgress ? SYSCALL_OUT : SYSCALL_IN;
	report_syscall_evt(seq, &conn_id_s, bytes_count, step);
	
	if (direct == kEgress) {
		conn_info->write_bytes += bytes_count;
	} else {
		conn_info->read_bytes += bytes_count;
	}

	// struct data_evt* evt = bpf_ringbuf_reserve(&data_rb, sizeof(struct data_evt), 0);
	// if (!evt) {
	// 	bpf_printk("process_syscall_data loss evt!");
	// 	return;
	// } 
	// evt->attr.conn_id = conn_info->conn_id;
	// evt->attr.fd = args->fd;
	// evt->attr.direct = direct;
	// evt->attr.fn = args->source_fn;
	// evt->attr.origin_len = bytes_count;
	// evt->attr.seq = (direct == kEgress ? conn_info->write_bytes : conn_info->read_bytes) + 1;
	// evt->attr.ts = bpf_ktime_get_ns();

	// if (bytes_count <= 0) {
	// 	bpf_ringbuf_discard(evt, 0);
	// 	return;
	// }
	// int copied_bytes;
	// if (bytes_count > sizeof(evt->msg)) {
	// 	copied_bytes = sizeof(evt->msg);
	// } else {
	// 	copied_bytes = bytes_count;
	// }

	// if (direct == kEgress) {
	// 	conn_info->write_bytes += bytes_count;
	// } else {
	// 	conn_info->read_bytes += bytes_count;
	// }
	
	// bpf_probe_read(&evt->msg, copied_bytes, args->buf);
	// evt->attr.data_len = copied_bytes;
	// bpf_ringbuf_submit(evt, 0);
}

SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(security_socket_sendmsg_enter) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct data_args *args = bpf_map_lookup_elem(&write_args_map, &id);

	if (args) {
		args->sock_event = true;
	}
	return 0;
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(security_socket_recvmsg_enter) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct data_args *args = bpf_map_lookup_elem(&read_args_map, &id);

	if (args) {
		args->sock_event = true;
	}
	return 0;
}

// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
//                  struct sockaddr *src_addr, socklen_t *addrlen);
SEC("kprobe/__sys_recvfrom")
int BPF_KPROBE(recvfrom_enter,  uint32_t fd, char* buf) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	args.fd = fd;
	args.buf = buf;
	args.source_fn = kSyscallRecvFrom;
	bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/__sys_recvfrom")
int BPF_KRETPROBE(recvfrom_return) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = PT_REGS_RC_CORE((struct pt_regs*)ctx);

	struct data_args *args = bpf_map_lookup_elem(&read_args_map, &id);
	if (args != NULL) {
		process_syscall_data((struct pt_regs*)ctx, args, id, kIngress, bytes_count);
	}

	bpf_map_delete_elem(&read_args_map, &id);
	return 0;
}

SEC("kprobe/__x64_sys_read")
int BPF_KPROBE(read_enter,  uint32_t fd, char* buf) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	args.fd = fd;
	args.buf = buf;
	args.source_fn = kSyscallRead;
	bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/__x64_sys_read")
int BPF_KRETPROBE(read_return) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = PT_REGS_RC_CORE((struct pt_regs*)ctx);

	struct data_args *args = bpf_map_lookup_elem(&read_args_map, &id);
	if (args != NULL && args->sock_event) {
		process_syscall_data((struct pt_regs*)ctx, args, id, kIngress, bytes_count);
	}

	bpf_map_delete_elem(&read_args_map, &id);
	return 0;
}

// ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
//                const struct sockaddr *dest_addr, socklen_t addrlen);
SEC("kprobe/__sys_sendto")
int BPF_KPROBE(sendto_enter, unsigned int sockfd, char* buf) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	args.fd = sockfd;
	args.buf = buf;
	args.source_fn = kSyscallSendTo;
	bpf_map_update_elem(&write_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/__sys_sendto")
int BPF_KRETPROBE(sendto_return) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = PT_REGS_RC_CORE((struct pt_regs*)ctx);

	struct data_args *args = bpf_map_lookup_elem(&write_args_map, &id);
	if (args != NULL ) {
		process_syscall_data(ctx, args, id, kEgress, bytes_count);
	}

	bpf_map_delete_elem(&write_args_map, &id);
	return 0;
}

SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(write_enter, unsigned int fd, char* buf, size_t count) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	args.fd = fd;
	args.buf = buf;
	args.source_fn = kSyscallWrite;
	bpf_map_update_elem(&write_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/__x64_sys_write")
int BPF_KRETPROBE(write_return) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = PT_REGS_RC_CORE(ctx);

	struct data_args *args = bpf_map_lookup_elem(&write_args_map, &id);
	if (args != NULL && args->sock_event) {
		process_syscall_data((struct pt_regs*)ctx, args, id, kEgress, bytes_count);
	}

	bpf_map_delete_elem(&write_args_map, &id);
	return 0;
}

// int close(int fd);
SEC("kprobe/__x64_sys_close")
int BPF_KPROBE(close_entry, unsigned int sockfd) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct close_args args = {0};
	args.fd = PT_REGS_PARM1_CORE_SYSCALL(ctx);
	bpf_map_update_elem(&close_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/__x64_sys_close")
int BPF_KRETPROBE(sys_close_ret)
{
	uint64_t id = bpf_get_current_pid_tgid();
	struct close_args *args = bpf_map_lookup_elem(&close_args_map, &id);
	if (args != NULL) {
		process_syscall_close((struct pt_regs*)ctx, args, id);
	}	
	bpf_map_delete_elem(&close_args_map, &id);
	return 0;
}


//int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
SEC("kprobe/__sys_connect")
int BPF_KPROBE(connect_entry, int sockfd, const struct sockaddr* addr) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct connect_args args = {0};
	args.fd = sockfd;
	args.addr = addr;
	bpf_map_update_elem(&connect_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/__sys_connect")
int BPF_KRETPROBE(sys_connect_ret)
{
	uint64_t id = bpf_get_current_pid_tgid();
	struct connect_args *args = bpf_map_lookup_elem(&connect_args_map, &id);
	if (args != NULL) {
		process_syscall_connect(ctx, args, id);
	}	
	bpf_map_delete_elem(&connect_args_map, &id);
	return 0;
}

SEC("ksyscall/accept4")
int BPF_KSYSCALL(accept4_entry, int sockfd, struct sockaddr* addr) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct accept_args args = {0};
	args.addr = addr;
	bpf_map_update_elem(&accept_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/sock_alloc") 
int BPF_KRETPROBE(sock_alloc_ret)
{
	uint64_t id = bpf_get_current_pid_tgid();
	struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &id);
	if (!args) {
		return 0;
	}
	if (!args->sock_alloc_socket) {
		args->sock_alloc_socket = (struct socket*) PT_REGS_RC_CORE(ctx);
	}

	return 0;
}

SEC("kretprobe/__sys_accept4")
int BPF_KRETPROBE(sys_accept4_ret)
// SEC("tracepoint/syscalls/sys_exit_accept4")
// int _sys_exit_accept4(struct pt_regs* ctx)
{
	uint64_t id = bpf_get_current_pid_tgid();
	struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &id);
	if (args != NULL) {
		process_syscall_accept(ctx, args, id);
	}	
	bpf_map_delete_elem(&accept_args_map, &id);
	return 0;
}


// SEC("sockops")
// int bpf_sockmap(struct bpf_sock_ops *skops) {
// 	if (skops->family != AF_INET && skops->family != AF_INET6) {
// 		return BPF_OK;
// 	}
// 	if (skops->local_port != target_port) {
// 		return BPF_OK;
// 	}
// 	if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB && skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) { return BPF_OK; }
// 	struct sock_key key = {
// 		.dip = skops->remote_ip4,
// 		.sip = skops->local_ip4,
// 		/* convert to network byte order */
// 		.sport = skops->local_port,
// 		.dport = bpf_ntohl(skops->remote_port),
// 		.family = skops->family,
// 	};
// 	// TODO 记录连接关闭
// 	int v = 0;
// 	long err = 0;
// 	// long err = bpf_map_update_elem(&sock_xmit_map, &key, &v, BPF_ANY);
// 	if (err) {
// 		bpf_printk("update failed, lport: %d, dport:%d,err:%d", skops->local_port, bpf_ntohl(skops->remote_port),err);
// 		bpf_printk("failed op s:%d",skops->op );
// 	} else {
// 		bpf_printk("update, lip: %d, dip:%d", key.sip, key.dip);
// 		bpf_printk("update, lport: %d, dport:%d", key.sport, key.dport);
// 		bpf_printk("success op s:%d",skops->op );
// 	}
// 	return BPF_OK;
// }