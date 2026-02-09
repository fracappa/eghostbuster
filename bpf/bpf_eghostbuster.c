// go:build ignore
#include "include/common.h"
#include "include/types.h"
#include "include/maps.h"


SEC("fentry/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect, struct sock *sk) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    struct connection_info *meta = bpf_sk_storage_get(&sk_info_storage, sk, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    
    if (!meta) {
        return 0;
    }

    meta->pid = bpf_get_current_pid_tgid() >> 32;
    meta->start_time = BPF_CORE_READ(task, start_time);
    bpf_get_current_comm(&meta->comm, sizeof(meta->comm));

    return 0;
}

SEC("tp_btf/inet_sock_set_state")                                                                                                                           
int BPF_PROG(handle_set_state,const struct sock *sk,                                                                                                                                  
    const int oldstate, const int newstate) {
    if (newstate != TCP_ESTABLISHED) {
        return 0;
    }

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }

    struct connection_info *info = bpf_sk_storage_get(&sk_info_storage, (struct sock *)sk, NULL, 0);
    if (!info) {
        return 0;
    }

    struct connection_key key = {};
    key.src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key.proto = IPPROTO_TCP;

    bpf_map_update_elem(&conn_tracker, &key, info, BPF_ANY);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int bpf_reaper(struct trace_event_raw_sched_process_template *ctx) {
    __be32 pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __be64 exit_start_time = BPF_CORE_READ(task, start_time);
    
    struct connection_info *event;
    event = bpf_ringbuf_reserve(&zombie_events, sizeof(*event), 0);
    if (!event) return 0;

    event->pid = pid;
    event->start_time = exit_start_time;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

