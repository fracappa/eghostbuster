#ifndef __MAPS_H
#define __MAPS_H

#include "common.h"
#include "types.h"
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct connection_key);
    __type(value, struct close_wait_info);
} close_wait_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); // Required by API, but we use the sock pointer
    __type(value, __u32);
} sk_info_storage SEC(".maps");

#endif /* __MAPS_H */