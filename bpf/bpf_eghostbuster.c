// go:build ignore
#include "include/common.h"
#include "include/types.h"
#include "include/maps.h"

// client connections - capture PID at connect() time
SEC("fentry/tcp_v4_connect") 
int BPF_PROG(tcp_v4_connect, struct sock *sk) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_sk_storage_get(&sk_info_storage, sk, &pid, BPF_SK_STORAGE_GET_F_CREATE);
    return 0;
}

// server connections - capture PID at accept() return
SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept_exit, struct sock *sk, int flags, struct sock *ret) {
    if (ret) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_sk_storage_get(&sk_info_storage, ret, &pid, BPF_SK_STORAGE_GET_F_CREATE);
    }
    return 0;
}

// state changed - use stored PID
SEC("tp_btf/inet_sock_set_state")                                                                                                                           
int BPF_PROG(handle_set_state,const struct sock *sk,                                                                                                                                  
    const int oldstate, const int newstate) {

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }

    struct connection_key key = {};
    key.src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key.proto = IPPROTO_TCP;
    
    // track sockets in CLOSE_WAIT
    if(newstate == TCP_CLOSE_WAIT) {
        __u32 *owner_pid = bpf_sk_storage_get(&sk_info_storage, (struct sock *)sk, 0, 0);

        struct close_wait_info info = {};
        info.entered_at =  bpf_ktime_get_ns();
        info.pid = owner_pid? *owner_pid: 0;
        
        bpf_map_update_elem(&close_wait_tracker, &key, &info, BPF_ANY);
    }

    // if sockets exist form CLOSE_WAIT state, remove it form the map
    if(oldstate == TCP_CLOSE_WAIT && newstate != TCP_CLOSE_WAIT) {
        bpf_map_delete_elem(&close_wait_tracker, &key);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

