from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6, gethostname, gethostbyname
from struct import pack
import time
from collections import namedtuple, defaultdict
import transinfo_client
from dockerdata import getIPConfig


def tcptrace_compile():
    # BPF ????
    bpf_text = """
    #include <uapi/linux/ptrace.h>
    #include <net/sock.h>
    #include <bcc/proto.h>

    struct ipv4_key_t {
        u32 pid;
        u32 saddr;
        u32 daddr;
        u16 lport;
        u16 dport;
    };
    BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);// map<ipv4_key_t, int> ipv4_send_bytes   ipv4_send_bytes[...]
    BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

    struct ipv6_key_t {
        u32 pid;
        unsigned __int128 saddr;
        unsigned __int128 daddr;
        u16 lport;
        u16 dport;
    };
    BPF_HASH(ipv6_send_bytes, struct ipv6_key_t);
    BPF_HASH(ipv6_recv_bytes, struct ipv6_key_t);

    int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
        struct msghdr *msg, size_t size)
    {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        // FILTER
        u16 dport = 0, family = sk->__sk_common.skc_family;

        if (family == AF_INET) {
            struct ipv4_key_t ipv4_key = {.pid = pid};
            ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
            ipv4_key.daddr = sk->__sk_common.skc_daddr;
            ipv4_key.lport = sk->__sk_common.skc_num;
            dport = sk->__sk_common.skc_dport;
            ipv4_key.dport = ntohs(dport);
            ipv4_send_bytes.increment(ipv4_key, size);             //ipv4_send_bytes[ipv4_key]=size

        } else if (family == AF_INET6) {
            struct ipv6_key_t ipv6_key = {.pid = pid};
            __builtin_memcpy(&ipv6_key.saddr,
                sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32, sizeof(ipv6_key.saddr));
            __builtin_memcpy(&ipv6_key.daddr,
                sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32, sizeof(ipv6_key.daddr));
            ipv6_key.lport = sk->__sk_common.skc_num;
            dport = sk->__sk_common.skc_dport;
            ipv6_key.dport = ntohs(dport);
            ipv6_send_bytes.increment(ipv6_key, size);
        }
        // else drop

        return 0;
    }

    /*
    * tcp_recvmsg() would be obvious to trace, but is less suitable because:
    * - we'd need to trace both entry and return, to have both sock and size
    * - misses tcp_read_sock() traffic
    * we'd much prefer tracepoints once they are available.
    */
    int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
    {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        // FILTER
        u16 dport = 0, family = sk->__sk_common.skc_family;
        u64 *val, zero = 0;

        if (copied <= 0)
            return 0;

        if (family == AF_INET) {
            struct ipv4_key_t ipv4_key = {.pid = pid};
            ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
            ipv4_key.daddr = sk->__sk_common.skc_daddr;
            ipv4_key.lport = sk->__sk_common.skc_num;
            dport = sk->__sk_common.skc_dport;
            ipv4_key.dport = ntohs(dport);
            ipv4_recv_bytes.increment(ipv4_key, copied);

        } else if (family == AF_INET6) {
            struct ipv6_key_t ipv6_key = {.pid = pid};
            __builtin_memcpy(&ipv6_key.saddr,
                sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32, sizeof(ipv6_key.saddr));
            __builtin_memcpy(&ipv6_key.daddr,
                sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32, sizeof(ipv6_key.daddr));
            ipv6_key.lport = sk->__sk_common.skc_num;
            dport = sk->__sk_common.skc_dport;
            ipv6_key.dport = ntohs(dport);
            ipv6_recv_bytes.increment(ipv6_key, copied);
        }
        // else drop

        return 0;
    }
    """
    b = BPF(text=bpf_text)

    ipv4_send_bytes = b["ipv4_send_bytes"]
    ipv4_recv_bytes = b["ipv4_recv_bytes"]
    ipv6_send_bytes = b["ipv6_send_bytes"]
    ipv6_recv_bytes = b["ipv6_recv_bytes"]
    return (ipv4_send_bytes, ipv4_recv_bytes, ipv6_send_bytes, ipv6_recv_bytes)

# ??????????->tcptop
def tcptrace_func(ipv4_send_bytes, ipv4_recv_bytes, ipv6_send_bytes, ipv6_recv_bytes):
    TCPSessionKey = namedtuple('TCPSession', ['pid', 'laddr', 'lport', 'daddr', 'dport'])
    # ???????pid?????????????
    def pid_to_comm(pid):
        try:
            comm = open("/proc/%d/comm" % pid, "r").read().rstrip()
            return comm
        except IOError:
            return str(pid)

    # ????ipv4
    def get_ipv4_session_key(k):
        return TCPSessionKey(pid=k.pid,
                            laddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                            lport=k.lport,
                            daddr=inet_ntop(AF_INET, pack("I", k.daddr)),
                            dport=k.dport)

    # ????ipv6
    def get_ipv6_session_key(k):
        return TCPSessionKey(pid=k.pid,
                            laddr=inet_ntop(AF_INET6, k.saddr),
                            lport=k.lport,
                            daddr=inet_ntop(AF_INET6, k.daddr),
                            dport=k.dport)
    # IPv4: build dict of all seen keys
    ipv4_throughput = defaultdict(lambda: [0, 0])
    # ??????
    for k, v in ipv4_send_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][0] = v.value
    ipv4_send_bytes.clear()
    # ??????
    for k, v in ipv4_recv_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][1] = v.value
    ipv4_recv_bytes.clear()

    # ????ipv4????
    ipv4_data = [
        {
            "time": time.time(),
            "pid": int(k.pid),
            "com": pid_to_comm(k.pid),
            "saddr": k.laddr,
            "sport": str(k.lport),
            "daddr": k.daddr,
            "dport": str(k.dport),
            "recv_byte": int(recv_bytes),
            "send_byte": int(send_bytes)
        }
        for k, (send_bytes, recv_bytes) in ipv4_throughput.items()
    ]

    # IPv6: build dict of all seen keys
    ipv6_throughput = defaultdict(lambda: [0, 0])
    # ??????
    for k, v in ipv6_send_bytes.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][0] = v.value
    ipv6_send_bytes.clear()
    # ??????
    for k, v in ipv6_recv_bytes.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][1] = v.value
    ipv6_recv_bytes.clear()

    # ????ipv6????
    ipv6_data = [
        {
            "time": time.time(),
            "pid": int(k.pid),
            "com": pid_to_comm(k.pid),
            "saddr": k.laddr,
            "sport": str(k.lport),
            "daddr": k.daddr,
            "dport": str(k.dport),
            "recv_byte": int(recv_bytes),
            "send_byte": int(send_bytes)
        }
        for k, (send_bytes, recv_bytes) in ipv6_throughput.items()
    ]
    return (ipv4_data, ipv6_data)

if __name__ == '__main__':
    ip4s, ip4r, ip6s, ip6r = tcptrace_compile()
    hostname = gethostname()
    ip = gethostbyname(hostname)
    ryuIP = getIPConfig()
    while True:
        ip4, ip6 = tcptrace_func(ip4s, ip4r, ip6s, ip6r)
        for i in ip4:
            if i["daddr"] != ryuIP and i["com"] != "Xtightvnc":
                transinfo_client.transinfo({
                    "host": ip,
                    "data": i,
                    "type": "ip4",
                    "protocol": "tcp"
                })
        for i in ip6:
            if i["daddr"] != "::ffff:"+ryuIP:
                transinfo_client.transinfo({
                    "host": ip,
                    "data": i,
                    "type": "ip6",
                    "protocol": "tcp"
                })
        time.sleep(1)
