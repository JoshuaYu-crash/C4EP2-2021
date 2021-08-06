#include <uapi/linux/udp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>
struct udp4_data_struct {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 len;
};
BPF_HASH(udp4_data, struct udp4_data_struct);

struct udp6_data_struct {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 len;
};
BPF_HASH(udp6_data, struct udp6_data_struct);

static struct udphdr *skb_to_udphdr(const struct sk_buff *skb) {
    return (struct udphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
    return (struct iphdr *)(skb->head + skb->network_header);
}

int kprobe__udp_queue_rcv_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    u16 family = sk->__sk_common.skc_family;
    u16 sport = 0, dport = 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    sport = udp->source;
    dport = udp->dest;
    sport = ntohs(sport);
    dport = ntohs(dport);
    if (family == AF_INET) {
        struct udp4_data_struct data4 = {};
        data4.saddr = ip->saddr;
        data4.daddr = ip->daddr;
        data4.dport = dport;
        data4.sport = sport;
        data4.len = skb->len;
        udp4_data.increment(data4, 1);
    }
    else if (family == AF_INET6) {
        struct udp6_data_struct data6 = {};
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.dport = dport;
        data6.sport = sport;
        data6.len = skb->len;
        udp6_data.increment(data6, 1);
    }
    return 0;
}