from bcc import BPF
from socket import inet_aton
import struct
import netifaces


# 获取网卡
def getNetIface():
    return [i for i in netifaces.interfaces() if i[0:4] == "veth"]


# 转换ip
def transIP(ip):
    return struct.unpack("=I", inet_aton(ip))[0]


# 生成控制代码
def generateCode(ip):
    code = """if(ip->saddr == %s || ip->daddr == %s) { return XDP_DROP; }
                    //#CODE#""" % (ip, ip)
    return code

# 生成XDP代码
def makeCode(ips):
    code_block = """
        #define KBUILD_MODNAME "filter"
        #include <linux/bpf.h>
        #include <linux/if_ether.h>
        #include <linux/ip.h>
        #include <linux/in.h>
        #include <linux/udp.h>
        #include <linux/tcp.h>
        #include <linux/icmp.h>

        int filter(struct xdp_md *ctx) {
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void*)eth + sizeof(*eth) <= data_end) {
                struct iphdr *ip = data + sizeof(*eth);
                if ((void*)ip + sizeof(*ip) <= data_end) {
                    //#CODE#
                }
            }
            return XDP_PASS;
        }
        """
    codeList = []
    for ip in ips:
        codeList.append(transIP(ip))
    for i in codeList:
        # print(generateCode(i))
        code_block = code_block.replace("//#CODE#", generateCode(i))
    return code_block


# xdp控制
def xdpcontrol(ips):
    text = makeCode(ips)
    # print(text)
    devices = getNetIface()
    b = BPF(text=text)
    fn = b.load_func("filter", BPF.XDP)
    for device in devices:
        b.attach_xdp(device, fn, 0)


def xdpstop():
    text = """
    #define KBUILD_MODNAME "filter"
    #include <linux/bpf.h>

    int filter(struct xdp_md *ctx) {
        return XDP_PASS;
    }
    """
    b = BPF(text=text)
    fn = b.load_func("filter", BPF.XDP)

    for i in getNetIface():
        b.remove_xdp(i, 0)

if __name__ == '__main__':
    xdpstop()
    import time
    time.sleep(19)
    xdpcontrol(["172.17.0.1"])
    time.sleep(6)
    xdpstop()