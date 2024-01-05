#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcpstates.h"

#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

const volatile bool filter_by_sport = false;
const volatile bool filter_by_dport = false;
const volatile short target_family = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u16);
	__type(value, __u16);
} sports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u16);
	__type(value, __u16);
} dports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u64);
} timestamps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct event event = {};
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct sock *sk = (struct sock *)ctx->skaddr;
	__u16 family = ctx->family;
	__u16 sport = ctx->sport;
	__u16 dport = ctx->dport;
	__u64 *tsp, delta_us = 0, ts, *tspe;
	__u16 flag_submit = 0;
        __u16 flag_passive = 0;
	if (ctx->protocol != IPPROTO_TCP)
		return 0;

        int state = ctx->newstate;  
	int old_state = ctx->oldstate;
	if(state  == TCP_SYN_SENT){
		ts = bpf_ktime_get_ns();
	        bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);

        }

	if(old_state == TCP_LISTEN && state == TCP_SYN_RECV){
		flag_passive = 1;
		ts = bpf_ktime_get_ns();
                bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);

	 }
      
	if(state == TCP_ESTABLISHED)
	{
	   tspe = bpf_map_lookup_elem(&timestamps, &sk);
		if(!tspe)
			delta_us = 0;
	        else
		{
			__u64 tse = bpf_ktime_get_ns();
		        delta_us = (tse - *tspe) / 1000;
                        flag_submit = 1;
		}
	}

        if((ctx->newstate == TCP_SYN_SENT) || (ctx->newstate == TCP_CLOSE)) {
		event.skaddr = (__u64)sk;
               __u64 pid_tgid = bpf_get_current_pid_tgid();
		event.tid =(__u32) pid_tgid;
		event.pid = bpf_get_current_pid_tgid() >> 32;
		event.oldstate = ctx->oldstate;
		event.newstate = ctx->newstate;
		event.family = family;
		event.sport = sport;
		event.dport = dport;
		event.protocol = IPPROTO_TCP;
		bpf_get_current_comm(&event.task, sizeof(event.task));
	}

	if(old_state == TCP_SYN_RECV && state == TCP_ESTABLISHED){
		tspe = bpf_map_lookup_elem(&timestamps, &sk);
		if(tspe){
                __u64 pid_tgid = bpf_get_current_pid_tgid();
                event.tid =(__u32) pid_tgid;
                event.pid = bpf_get_current_pid_tgid() >> 32;
                event.oldstate = ctx->oldstate;
                event.newstate = ctx->newstate;
                event.family = family;
                event.sport = sport;
                event.dport = dport;
                event.protocol = IPPROTO_TCP;
		event.conn_passive = 1;
                bpf_get_current_comm(&event.task, sizeof(event.task));

		if (family == AF_INET) {
                bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
                bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
                } else { /* family == AF_INET6 */
                bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                }         
                bpf_printk(" passive src address %llu \n,", event.saddr);
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
		}
	}

	if (family == AF_INET) {
		bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
	} else { /* family == AF_INET6 */
		bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}
        if(flag_submit == 1) {
		event.delta_us = delta_us;
		event.newstate = ctx->newstate;
		event.sport = sport;
                event.dport = dport;

		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	}	
        if(state == TCP_CLOSE)
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	if (state == TCP_CLOSE)
		bpf_map_delete_elem(&timestamps, &sk);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
