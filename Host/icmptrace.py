from bcc import BPF
import ctypes as ct
import time
from socket import inet_ntop, AF_INET, gethostname, gethostbyname
from struct import pack
import transinfo_client

def icmptrace_compile():
    # define BPF program
    bpf_text = """
    #include <uapi/linux/icmp.h>
    #include <uapi/linux/ip.h>
    #include <net/sock.h>
    struct ipv4_data_t {
        u32 saddr;
        u32 daddr;
        u32 len;
    };
    BPF_PERF_OUTPUT(ipv4_events);
    static struct icmphdr *skb_to_icmphdr(const struct sk_buff *skb)
    {
        // unstable API. verify logic in udp_hdr() -> skb_transport_header().
        return (struct icmphdr *)(skb->head + skb->transport_header);
    }
    static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
    {
        // unstable API. verify logic in ip_hdr() -> skb_network_header().
        return (struct iphdr *)(skb->head + skb->network_header);
    }
    int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
        u16 sport = 0, dport = 0;
        struct iphdr *ip = skb_to_iphdr(skb);
        struct icmphdr *icmp = skb_to_icmphdr(skb);
        struct ipv4_data_t data4 = {};
        data4.saddr = ip->saddr;
        data4.daddr = ip->daddr;
        data4.len = ip->tot_len;
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
        return 0;
    }
    """
    b = BPF(text=bpf_text)
    return b

def icmptrace_func(b, senddata):

    class Data_ipv4(ct.Structure):
        _fields_ = [
            ("saddr", ct.c_uint),
            ("daddr", ct.c_uint),
            ("len", ct.c_uint),
        ]

    def print_ipv4_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
        ip4_data = {
            "time": time.time(),
            "saddr": inet_ntop(AF_INET, pack('I', event.saddr)),
            "daddr": inet_ntop(AF_INET, pack('I', event.daddr)),
            "len": int(event.len)
        }
        hostname = gethostname()
        ip = gethostbyname(hostname)
        senddata({
            "host": ip,
            "data": ip4_data,
            "type": "ip4",
            "protocol": "icmp"
        })
    b["ipv4_events"].open_perf_buffer(print_ipv4_event)

# def senddata(data):
#     print(data)
if __name__ == '__main__':
    b = icmptrace_compile()
    icmptrace_func(b, transinfo_client.transinfo)
    while 1:
        b.perf_buffer_poll()
        time.sleep(1)