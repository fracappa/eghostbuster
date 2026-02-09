<div align="center">                                                             
    <picture>                                                                  
      <source media="(prefers-color-scheme: dark)" srcset="docs/img/eghostbuster-dark.png">                                                                   
      <source media="(prefers-color-scheme: light)" srcset="docs/img/eghostbuster-dark.png">
      <img alt="eghostbuster" src="eghostbuster-light.png" width="400">
    </picture>
</div>


[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](/LICENSE)

An eBPF-based framework for detecting and cleaning up orphaned kernel resources left behind by dead processes.                                              

## Problem                                                                                                                                                  
                
When processes exit unexpectedly, they can leave behind various kernel resources that linger until timeout mechanisms or manual intervention clean them up:

- TCP/UDP sockets
- File locks
- Shared memory segments
- Semaphores
- Other kernel structures

These "ghost" resources consume memory, block other processes, and can cause subtle bugs in production systems.

## Solution

eghostbuster uses eBPF to:

1. **Track resource ownership** — Hooks into kernel functions to monitor resource allocation and associate them with processes
2. **Detect process exits** — Listens to `sched_process_exit` to detect when processes die
3. **Clean up orphaned resources** — Immediately releases resources belonging to dead processes

## Current Features

- **TCP connection cleanup** — Detects and destroys ghost TCP sockets via netlink `SOCK_DESTROY`

## Planned Features

- File lock cleanup
- Shared memory / IPC cleanup
- Custom resource handlers via plugin system

## Requirements

- Linux kernel 5.8+ (BTF and CO-RE support)
- BTF enabled (`/sys/kernel/btf/vmlinux`)
- Root privileges (or `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`)
- Go 1.21+
- Clang/LLVM
- bpftool

## Building

```bash
make generate  # Generate vmlinux.h (first time or after kernel update) and Go structs from BPF src
make build     # Build the binary
make run       # Build and run with sudo
```
## Usage
```
sudo ./eghostbuster
```