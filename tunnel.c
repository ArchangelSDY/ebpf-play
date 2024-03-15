//go:build ignore

#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "lib/endian.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct in6_addr);
    __type(value, struct in6_addr);
} tunnel_remotes SEC(".maps");

static inline __attribute__((always_inline)) int parse_ip_dst_addr(struct __sk_buff *skb, struct in6_addr *dst) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return 0;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
        return 0;
    }

    struct ipv6hdr *ipv6_hdr = data + sizeof(*eth);
    if ((void *)ipv6_hdr + sizeof(*ipv6_hdr) > data_end) {
        return 0;
    }

    *dst = ipv6_hdr->daddr;

    return 1;
}

static inline __attribute__((always_inline)) void apply_mask_to_in6_addr(struct in6_addr *addr, int bits) {
    if (bits > 128 || bits < 0) {
        // Invalid number of bits, IPv6 addresses are 128 bits long.
        return;
    }

    int full_bytes = bits / 8; // Number of fully masked bytes
    int extra_bits = bits % 8; // Additional bits to mask in the next byte

    // Mask full bytes
    for (int i = 16; i > 16 - full_bytes; i--) {
        addr->s6_addr[i - 1] = 0x00;
    }

    // Mask extra bits if any
    if (extra_bits > 0) {
        // Calculate the mask for the remaining bits. For example, if extra_bits is 3, mask = 0xE0
        __u8 mask = (0xFF << (8 - extra_bits)) & 0xFF;
        addr->s6_addr[16 - full_bytes - 1] &= ~mask;
    }
}

SEC("tc")
int set_tunnel_remote(struct __sk_buff *skb) {
    struct in6_addr dst;

    if (!parse_ip_dst_addr(skb, &dst)) {
        return XDP_PASS;
    }

    apply_mask_to_in6_addr(&dst, 128 - 80);

    struct in6_addr *remote = bpf_map_lookup_elem(&tunnel_remotes, &dst);
    if (!remote) {
        return XDP_PASS;
    } else {
        struct bpf_tunnel_key key = {
            .tunnel_id = bpf_htonl(100),
            .tunnel_tos = 0,
            .tunnel_ttl = 64
        };
        __builtin_memcpy(key.remote_ipv6, remote->s6_addr32, sizeof(key.remote_ipv6));

        if (bpf_skb_set_tunnel_key(skb, &key, sizeof(key), BPF_F_TUNINFO_IPV6) != 0) {
            return XDP_PASS;
        }
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
