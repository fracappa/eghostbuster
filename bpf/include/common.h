#ifndef __COMMON_H
#define __COMMON_H

 #include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 

#ifndef DEBUG
#define DEBUG 1
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define AF_INET 2

#define TCP_ESTABLISHED 1
#define TCP_CLOSE_WAIT  8
#define TCP_FIN_WAIT2   5


#define JHASH_INITVAL   0xdeadbeef
#define MAX_BACKENDS 3

#endif /* __COMMON_H */