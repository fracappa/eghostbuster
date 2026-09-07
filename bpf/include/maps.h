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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct file_info);
} file_process_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, struct file_extension);
} file_extensions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} exit_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, struct file_info);
} file_info_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __be32);
    __type(value, struct conntrack_event);
} conntrack_destroy_tracker SEC(".maps");

#endif /* __MAPS_H */