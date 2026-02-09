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

struct connection_info {
    __be32 pid;           // The PID that opened the socket
    __be64 start_time;    // Kernel timestamp (ktime_get_ns)
    __u8 comm[16];       // Process name (e.g., "nginx")
};

#endif /* __TYPES_H */