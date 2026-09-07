// go:build ignore
#include "include/common.h"
#include "include/types.h"
#include "include/maps.h"

static long extension_callback(struct bpf_map *map, const void *key, void *value, void *ctx){
    struct file_extension *fe = (struct file_extension *)value;
   __u32 zero = 0;
    struct file_info *info = bpf_map_lookup_elem(&file_info_scratch, &zero);
    if (!info) 
        return 0;

    if(info->slen < fe->len || fe->len ==0)
        return 0;

    unsigned char match_found = 1;
    for(int i=0; i < fe->len && i < 15 && match_found; i++) {
        match_found = (info->filename[(info->slen - fe->len + i) & 0xFF] == fe->name[i]);
    }

    if(match_found) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_map_update_elem(&file_process_map, &pid, info, BPF_NOEXIST);
    }

    return match_found;
}


static __always_inline int track_lock_file(const void *filename_ptr) {

    __u32 zero = 0;
    struct file_info *info = bpf_map_lookup_elem(&file_info_scratch, &zero);

    if(!info) 
        return 0;

    int len = bpf_probe_read_user_str(info->filename,
         sizeof(info->filename), filename_ptr);

    if(len <= 1) 
        return 0;

    unsigned int slen = (unsigned int)(len - 1);
    if (slen > 255) slen = 255;
    info->slen = slen;

    bpf_for_each_map_elem(&file_extensions, extension_callback, NULL, 0);

    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int register_openat(struct trace_event_raw_sys_enter *ctx) {
    int flags = (int)ctx->args[2];

    if(!(flags & O_CREAT))
        return 0;
    
    return track_lock_file((const void *)ctx->args[1]);
}


SEC("tp/syscalls/sys_enter_openat2")
int register_openat2(struct trace_event_raw_sys_enter *ctx) {
    // openat2 args[2] is a pointer to a struct open_how { u64 flags; u64 mode; u64 resolve; }
    __u64 flags = 0;
    bpf_probe_read_user(&flags, sizeof(flags), (const void *)ctx->args[2]);

    if(!(flags & O_CREAT))
        return 0;
        
    return track_lock_file((const void *)ctx->args[1]);
}


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


SEC("fentry/nf_conntrack_destroy")
int BPF_PROG(handle_conntrack_destroy, struct nf_conn___local *ct) {
    __u16 family = BPF_CORE_READ(ct, tuplehash[0].tuple.src.l3num);
    if (family != AF_INET)
        return 0;

    struct conntrack_event event = {
        .last_seen_at = bpf_ktime_get_ns(),
    };

    // Reply source IP is the actual backend/pod IP in DNAT scenarios
    __be32 pod_ip = BPF_CORE_READ(ct, tuplehash[1].tuple.src.u3.ip);
    bpf_map_update_elem(&conntrack_destroy_tracker, &pod_ip, &event, BPF_ANY);

    return 0;
}

SEC("fentry/__nf_conntrack_hash_insert")
int BPF_PROG(handle_conntrack_new, struct nf_conn___local *ct) {
    __u16 family = BPF_CORE_READ(ct, tuplehash[0].tuple.src.l3num);
    if (family != AF_INET)
        return 0;

    __be32 pod_ip = BPF_CORE_READ(ct, tuplehash[1].tuple.src.u3.ip);
    bpf_map_delete_elem(&conntrack_destroy_tracker, &pod_ip);

    return 0;
}


SEC("tp/sched/sched_process_exit")
int process_exit_notifier(struct trace_event_raw_sched_process_template *ctx) {
    __be32 pid = bpf_get_current_pid_tgid() >> 32;

    struct file_info *info = bpf_map_lookup_elem(&file_process_map, &pid);
    if(!info) return 0;
    
    struct exit_event *event;
    event = bpf_ringbuf_reserve(&exit_events, sizeof(*event), 0);

    if (!event) return 0;

    event->pid = pid;
    __builtin_memcpy(event->filename, info->filename, sizeof(event->filename));

    bpf_map_delete_elem(&file_process_map, &pid);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

