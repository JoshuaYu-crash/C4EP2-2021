from bcc import BPF
import ctypes as ct
import time
from socket import inet_ntop, AF_INET, AF_INET6, gethostname, gethostbyname
from struct import pack
import transinfo_client
def udptrace_compile():
    # define BPF program
    bpf_text = """
    #include <uapi/linux/udp.h>
    #include <uapi/linux/ip.h>
    #include <net/sock.h>
    struct ipv4_data_t {
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
        u32 rmem_alloc;
        u32 rcvbuf;
        u32 len;
    };
    BPF_PERF_OUTPUT(ipv4_events);
    struct ipv6_data_t {
        unsigned __int128 saddr;
        unsigned __int128 daddr;
        u16 sport;
        u16 dport;
        u32 rmem_alloc;
        u32 rcvbuf;
        u32 len;
    };
    BPF_PERF_OUTPUT(ipv6_events);
    static struct udphdr *skb_to_udphdr(const struct sk_buff *skb)
    {
        // unstable API. verify logic in udp_hdr() -> skb_transport_header().
        return (struct udphdr *)(skb->head + skb->transport_header);
    }
    static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
    {
        // unstable API. verify logic in ip_hdr() -> skb_network_header().
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
            struct ipv4_data_t data4 = {};
            data4.saddr = ip->saddr;
            data4.daddr = ip->daddr;
            data4.dport = dport;
            data4.sport = sport;
            data4.rmem_alloc = sk->sk_rmem_alloc.counter;
            data4.rcvbuf = sk->sk_rcvbuf;
            data4.len = skb->len;
            ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
        } else if (family == AF_INET6) {
            struct ipv6_data_t data6 = {};
            bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
                sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
                sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            data6.dport = dport;
            data6.sport = sport;
            data6.rmem_alloc = sk->sk_rmem_alloc.counter;
            data6.rcvbuf = sk->sk_rcvbuf;
            data6.len = skb->len;
            ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
        }
        return 0;
    }
    """
    b = BPF(text=bpf_text)
    return b

def udptrace_func(b, senddata):

    class Data_ipv4(ct.Structure):
        _fields_ = [
            ("saddr", ct.c_uint),
            ("daddr", ct.c_uint),
            ("sport", ct.c_ushort),
            ("dport", ct.c_ushort),
            ("rmem_alloc", ct.c_uint),
            ("rcvbuf", ct.c_uint),
            ("len", ct.c_uint),
        ]

    class Data_ipv6(ct.Structure):
        _fields_ = [
            ("saddr", (ct.c_ulonglong * 2)),
            ("daddr", (ct.c_ulonglong * 2)),
            ("sport", ct.c_ushort),
            ("dport", ct.c_ushort),
            ("rmem_alloc", ct.c_uint),
            ("rcvbuf", ct.c_uint),
            ("len", ct.c_uint),
        ]

    def print_ipv4_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
        ip4_data = {
            "time": time.time(),
            "saddr": inet_ntop(AF_INET, pack('I', event.saddr)),
            "sport": str(event.sport),
            "daddr": inet_ntop(AF_INET, pack('I', event.daddr)),
            "dport": str(event.dport),
            "len": int(event.len)
        }
        hostname = gethostname()
        ip = gethostbyname(hostname)
        senddata({
            "host": ip,
            "data": ip4_data,
            "type": "ip4",
            "protocol": "udp"
        })

    def print_ipv6_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
        ip6_data = {
            "time": time.time(),
            "saddr": inet_ntop(AF_INET6, pack('I', event.saddr)),
            "sport": str(event.sport),
            "daddr": inet_ntop(AF_INET6, pack('I', event.daddr)),
            "dport": str(event.dport),
            "len": int(event.len)
        }
        hostname = gethostname()
        ip = gethostbyname(hostname)
        senddata({
            "host": ip,
            "data": ip6_data,
            "type": "ip6",
            "protocol": "udp"
        })

    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)

# def senddata(data):
#     print(data)

if __name__ == '__main__':
    b = udptrace_compile()
    udptrace_func(b, transinfo_client.transinfo)
    while 1:
        b.perf_buffer_poll()
        time.sleep(1)