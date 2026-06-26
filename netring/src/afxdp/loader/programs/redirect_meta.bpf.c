// SPDX-License-Identifier: GPL-2.0
//
// netring's XDP program for AF_XDP capture *with RX hardware metadata*
// (issue #13). Same redirect behaviour as `redirect_all.bpf.c`, but before
// redirecting it reads the NIC's RX timestamp / RSS hash / VLAN tag via the
// kernel 6.3+ `bpf_xdp_metadata_*` kfuncs and writes a fixed-layout struct
// into the frame's metadata headroom. Userspace reads it back in
// `afxdp/metadata.rs` (`struct XdpRxMeta` — the two layouts MUST match).
//
// Compilation (run from this directory; output is committed):
//
//     clang -O2 -g -target bpf -c \
//         -D__TARGET_ARCH_x86 \
//         redirect_meta.bpf.c -o redirect_meta.bpf.o
//
// NOTE: this needs the kfunc declarations from a 6.3+ kernel's <linux/bpf.h>
// (or vmlinux.h) and CANNOT be exercised without a NIC/driver that implements
// the hints (ice/mlx5/gve); on loopback / generic XDP the kfuncs are absent
// and the program writes only `magic` with no field flags set — userspace
// then sees no metadata (the degrade path). Compile + validate on real
// hardware before committing the `.o`.

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
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif

// Mirrors `afxdp::metadata::XdpRxMeta`. Field order keeps every field
// naturally aligned; the struct is exactly 32 bytes on both sides.
#define NETRING_META_MAGIC 0x6E726D01u // "nrm" + version 1
#define NETRING_META_TIMESTAMP (1u << 0)
#define NETRING_META_HASH (1u << 1)
#define NETRING_META_VLAN (1u << 2)

struct netring_xdp_meta {
    __u32 magic;
    __u32 flags;
    __u64 rx_timestamp;
    __u32 rx_hash;
    __u32 rx_hash_type; // normalised code, see normalize_rss()
    __u32 vlan_tci;
    __u32 vlan_proto;
};
_Static_assert(sizeof(struct netring_xdp_meta) == 32, "metadata ABI mismatch");

// XDP-hints kfuncs (kernel 6.3+). `__weak` so the program still loads on
// drivers/kernels lacking them — the verifier relocates missing kfuncs to a
// call returning -EOPNOTSUPP, which we treat as "field absent".
extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
                                          __u64 *timestamp) __ksym __weak;
extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
                                    enum xdp_rss_hash_type *rss_type) __ksym __weak;
extern int bpf_xdp_metadata_rx_vlan_tag(const struct xdp_md *ctx,
                                        __be16 *vlan_proto,
                                        __u16 *vlan_tci) __ksym __weak;

static long (*bpf_xdp_adjust_meta)(struct xdp_md *ctx, int delta) = (void *)54;
static long (*bpf_redirect_map)(void *map, __u32 key, __u64 flags) = (void *)51;

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Collapse the kernel `xdp_rss_hash_type` bitfield to the flat code
// userspace expects (matches `RssHashType`'s declaration order). Keeping the
// kernel-version-specific bit logic here lets the Rust side stay a trivial
// match.
static __u32 normalize_rss(enum xdp_rss_hash_type t)
{
    int v6 = t & XDP_RSS_L3_IPV6;
    if (t & XDP_RSS_L4_TCP)
        return v6 ? 6 : 3;
    if (t & XDP_RSS_L4_UDP)
        return v6 ? 7 : 4;
    if (t & XDP_RSS_L4_SCTP)
        return v6 ? 8 : 5;
    if (t & XDP_RSS_L3_IPV4)
        return 1;
    if (v6)
        return 2;
    return 9; // Unknown
}

SEC("xdp")
int xdp_sock_meta_prog(struct xdp_md *ctx)
{
    // Reserve metadata headroom ahead of the frame. On failure, fall back to
    // a plain redirect (no metadata) rather than dropping the packet.
    if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct netring_xdp_meta)) < 0)
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

    void *data = (void *)(long)ctx->data;
    struct netring_xdp_meta *meta = (void *)(long)ctx->data_meta;
    if ((void *)(meta + 1) > data)
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

    meta->magic = NETRING_META_MAGIC;
    meta->flags = 0;

    __u64 ts;
    if (bpf_xdp_metadata_rx_timestamp(ctx, &ts) == 0) {
        meta->rx_timestamp = ts;
        meta->flags |= NETRING_META_TIMESTAMP;
    }

    __u32 hash;
    enum xdp_rss_hash_type rss_type;
    if (bpf_xdp_metadata_rx_hash(ctx, &hash, &rss_type) == 0) {
        meta->rx_hash = hash;
        meta->rx_hash_type = normalize_rss(rss_type);
        meta->flags |= NETRING_META_HASH;
    }

    __be16 vlan_proto;
    __u16 vlan_tci;
    if (bpf_xdp_metadata_rx_vlan_tag(ctx, &vlan_proto, &vlan_tci) == 0) {
        meta->vlan_tci = vlan_tci;
        meta->vlan_proto = __builtin_bswap16(vlan_proto); // be → host
        meta->flags |= NETRING_META_VLAN;
    }

    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
