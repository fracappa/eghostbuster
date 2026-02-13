<div align="center">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/img/eghostbuster-dark.png">
      <source media="(prefers-color-scheme: light)" srcset="docs/img/eghostbuster-light.png">
      <img alt="eghostbuster" src="docs/img/eghostbuster-light.png" width="400">
    </picture>
    <br><br>
    <a href="/LICENSE">
        <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License">
    </a>
</div>

An eBPF-based tool for detecting and cleaning up stale kernel resources

## Problem                                                                                                                                                  
Kernel resources can become "stuck" or stale due to various conditions:

- Processes exiting unexpectedly without proper cleanup
- Applications that leak resources (don't close sockets, release locks, etc.)
- Network issues leaving connections in lingering states
- Bugs in resource lifecycle management

These "ghost" resources consume memory, block other processes, hold ports, and can cause subtle bugs in production systems. They often linger until timeout
mechanisms or manual intervention clean them up.

## Solution

eghostbuster uses eBPF to:

1. **Monitor resource state**: hooks into kernel functions to observe resource state transitions in real-time
2. **Detect stale resources**: identifies resources that have been in problematic states beyond configurable thresholds
3. **Clean up automatically**: releases stale resources before they cause issues


## Current Features

- **TCP CLOSE_WAIT cleanup**: detects TCP sockets stuck in `CLOSE_WAIT` state and destroys them after a configurable timeout

## Planned Features

- File lock cleanup
- Shared memory / IPC cleanup

## Requirements

- Linux kernel 5.8+ (BTF and CO-RE support)
- BTF enabled (`/sys/kernel/btf/vmlinux`)
- Root privileges (or `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`)
- Go 1.21+
- Clang/LLVM
- bpftool
- iproute2 (`ss` command, typically pre-installed)

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