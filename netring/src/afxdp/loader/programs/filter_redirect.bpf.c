// SPDX-License-Identifier: GPL-2.0
//
// netring's table-driven XDP filter+redirect program (0.25 W1a / S5).
//
// Unlike `redirect_all` (which redirects every frame), this program consults a
// `BPF_MAP_TYPE_HASH` keyed by `{proto, port}` to decide, in-kernel, whether a
// frame is interesting:
//   - hit  -> redirect the frame into the AF_XDP socket (capture it)
//   - miss -> XDP_PASS (let it continue up the normal kernel stack; "shed")
// Both the destination and source L4 port are probed, so a `{udp, 443}` entry
// matches traffic in either direction (mirrors the cBPF `port` predicate).
//
// Userspace populates `filter_map` from the subscription union's kernel-pushable
// `{proto, port}` atoms (see the Rust `XdpProgram::set_filter`). The key's
// `port` field is the **host-order** numeric value (e.g. 443), matching the
// `(hi<<8)|lo` reconstruction below; both sides use native endianness for the
// `u16`, so the bytewise HASH-key compare lines up. The 1-byte `pad` is zeroed
// on both sides so the 4-byte key has no uninitialised slack.
//
// Compilation (run from this directory; the .o is committed — needs BTF for
// aya >= 0.13, so keep the `-g` and the `llvm-strip -g`):
//
//     clang -O2 -g -target bpf -c -D__TARGET_ARCH_x86 \
//         filter_redirect.bpf.c -o filter_redirect.bpf.o
//     llvm-strip -g filter_redirect.bpf.o   # strip DWARF, keep .BTF
//
// Only `<linux/bpf.h>` is included (for `struct xdp_md` + the `xdp_action`
// enum); everything else is parsed from raw offsets so the build needs no
// libbpf-devel / kernel netproto headers (same constraint as redirect_all).

#include <linux/bpf.h>

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif
#ifndef __uint
#define __uint(name, val) int(*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif
#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Helper IDs (stable kernel ABI).
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_redirect_map)(void *map, __u32 key, __u64 flags) = (void *)51;

// 4-byte key: host-order L4 port + IP protocol + explicit zero pad.
struct filter_key {
    __u16 port;
    __u8 proto;
    __u8 pad;
};

// XSKMAP — userspace registers AF_XDP socket fds here, keyed by NIC queue.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// {proto,port} -> interesting? (value is a non-zero marker byte).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct filter_key);
    __type(value, __u8);
} filter_map SEC(".maps");

SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    unsigned char *p = data;

    // Ethernet header.
    if ((void *)(p + ETH_HLEN) > data_end)
        return XDP_PASS;
    __u16 h_proto = ((__u16)p[12] << 8) | p[13];
    if (h_proto != ETH_P_IP)
        return XDP_PASS;

    // IPv4 header (need at least the 20-byte fixed part).
    unsigned char *ip = p + ETH_HLEN;
    if ((void *)(ip + 20) > data_end)
        return XDP_PASS;
    __u8 ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20)
        return XDP_PASS;
    __u8 proto = ip[9];
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return XDP_PASS;

    // L4 header — TCP/UDP both carry sport at [0..2], dport at [2..4].
    unsigned char *l4 = ip + ihl;
    if ((void *)(l4 + 4) > data_end)
        return XDP_PASS;
    __u16 sport = ((__u16)l4[0] << 8) | l4[1];
    __u16 dport = ((__u16)l4[2] << 8) | l4[3];

    struct filter_key key;
    key.proto = proto;
    key.pad = 0;

    key.port = dport;
    if (bpf_map_lookup_elem(&filter_map, &key))
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

    key.port = sport;
    if (bpf_map_lookup_elem(&filter_map, &key))
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
