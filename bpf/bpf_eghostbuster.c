// go:build ignore
#include "include/common.h"
#include "include/types.h"
#include "include/maps.h"

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
    key.src_port = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_num));
    key.dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key.proto = IPPROTO_TCP;
    
    // track sockets in CLOSE_WAIT
    if(newstate == TCP_CLOSE_WAIT) {
        bpf_printk("handle_set_state: socket entering CLOSE_WAIT");                                                                                             
        struct close_wait_info info = {};
        info.entered_at =  bpf_ktime_get_ns();
        
        // Get netns inode from socket
        struct net *net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
        info.netns_ino = BPF_CORE_READ(net, ns.inum);

        
        bpf_map_update_elem(&close_wait_tracker, &key, &info, BPF_ANY);
    }

    // if sockets exist form CLOSE_WAIT state, remove it form the map
    if(oldstate == TCP_CLOSE_WAIT && newstate != TCP_CLOSE_WAIT) {
        bpf_map_delete_elem(&close_wait_tracker, &key);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

