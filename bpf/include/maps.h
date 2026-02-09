#ifndef __MAPS_H
#define __MAPS_H

#include "common.h"
#include "types.h"


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240); // Size based on your 2-node capacity
    __type(key, struct connection_key);
    __type(value, struct connection_info);
} conn_tracker SEC(".maps");

// temporary storage - deleted when socket dies
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); // Required by API, but we use the sock pointer
    __type(value, struct connection_info);
} sk_info_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} zombie_events SEC(".maps");


#endif /* __MAPS_H */