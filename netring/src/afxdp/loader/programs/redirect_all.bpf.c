// SPDX-License-Identifier: GPL-2.0
//
// netring's built-in XDP program for AF_XDP capture.
//
// Single-purpose: redirect every packet on the bound queue to its
// AF_XDP socket via the `xsks_map` (BPF_MAP_TYPE_XSKMAP).
//
// Compilation (run from this directory; output is committed):
//
//     clang -O2 -g -target bpf -c \
//         -D__TARGET_ARCH_x86 \
//         redirect_all.bpf.c -o redirect_all.bpf.o
//
// On Fedora/RHEL the bpf headers come from `kernel-tools-libs-devel`
// or directly from the kernel source tree. If your distro ships
// libbpf-devel, `#include <bpf/bpf_helpers.h>` works; otherwise we
// declare what we need below.

#include <linux/bpf.h>

// Minimal stand-ins for `<bpf/bpf_helpers.h>` so this builds without
// libbpf-devel installed. Mirrors the upstream definitions.
#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif
#ifndef __uint
#define __uint(name, val) int(*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif

// `bpf_redirect_map` helper — kernel function ID 51.
static long (*bpf_redirect_map)(void *map, __u32 key, __u64 flags) =
    (void *)51;

// XSKMAP that the userspace loader registers AF_XDP socket fds onto,
// keyed by NIC queue index. Capacity 256 covers practical RSS queue
// counts; the userspace `XdpProgram::register` API checks bounds.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// The program. `XDP_PASS` is the miss action: if no socket is
// registered for `rx_queue_index`, the packet continues up the
// kernel network stack (i.e. AF_XDP isn't bound on this queue, so
// don't drop it).
SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
