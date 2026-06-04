// Track D fail-secure XDP containment (ADR-0003 phase 4).
// supervisor_alive=0 after supervisor exit -> TCP XDP_DROP on attached NIC.
// Optional authorized_sockets_map for per-socket allow when enforcement is strict.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} supervisor_alive SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} containment_mode SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32);
} authorized_sockets_map SEC(".maps");

static __always_inline int packet_is_tcp(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
    return ip->protocol == IPPROTO_TCP;
}

SEC("xdp")
int containment_ingress_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 key = 0;
    __u32 *alive = bpf_map_lookup_elem(&supervisor_alive, &key);
    if (!alive || *alive == 0) {
        if (packet_is_tcp(data, data_end))
            return XDP_DROP;
        return XDP_PASS;
    }

    __u32 *mode = bpf_map_lookup_elem(&containment_mode, &key);
    if (!mode || *mode < 2)
        return XDP_PASS;

    if (!packet_is_tcp(data, data_end))
        return XDP_PASS;

    __u64 sk_cookie = bpf_get_socket_cookie(ctx);
    if (sk_cookie == 0)
        return XDP_PASS;

    __u32 *auth = bpf_map_lookup_elem(&authorized_sockets_map, &sk_cookie);
    if (!auth)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
