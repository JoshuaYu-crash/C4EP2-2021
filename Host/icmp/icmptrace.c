#include <uapi/linux/icmp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>

struct icmp_data_struct {
    u32 saddr;
    u32 daddr;
    u32 len;
};
BPF_HASH(icmp_data, struct icmp_data_struct);

static struct icmphdr *skb_to_icmphdr(const struct sk_buff *skb) {
    return (struct icmphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
    return (struct iphdr *)(skb->head + skb->network_header);
}
int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    u16 sport = 0, dport = 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct icmphdr *icmp = skb_to_icmphdr(skb);
    struct icmp_data_struct data = {};
    data.saddr = ip->saddr;
    data.daddr = ip->daddr;
    data.len = ip->tot_len;
    icmp_data.increment(data, 1);
    return 0;
}