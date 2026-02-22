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

#endif /* __TYPES_H */