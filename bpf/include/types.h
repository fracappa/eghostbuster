#ifndef __TYPES_H
#define __TYPES_H

#include "common.h"

struct connection_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
};
struct close_wait_info {
    __u64 entered_at;
    __u64 netns_ino;
};        

struct destroy_event {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u64 age_ns;
};

struct file_info {
    char  filename[256];
    unsigned int slen;
};
struct exit_event {
    __be32 pid;
    char  filename[256];
};

struct file_extension {
    char name[16];
    unsigned int len;
};

struct conntrack_event {
    __u64 last_seen_at;
};

// CO-RE compatible nf_conn definition.
// The ___local suffix avoids conflicts with vmlinux.h when nf_conntrack
// types are present. CO-RE strips the suffix at load time and matches
// against the kernel's nf_conn BTF.
union nf_inet_addr___local {
    __be32 ip;
    __be32 ip6[4];
} __attribute__((preserve_access_index));

struct nf_conn___local {
    struct {
        struct {
            struct {
                union nf_inet_addr___local u3;
                __u16 l3num;
            } src;
            struct {
                union nf_inet_addr___local u3;
            } dst;
        } tuple;
    } tuplehash[2];
} __attribute__((preserve_access_index));

#endif /* __TYPES_H */