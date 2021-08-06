from bcc import BPF
import ctypes as ct
import time
from socket import inet_ntop, AF_INET, AF_INET6, gethostname, gethostbyname
from struct import pack


# compile the BPF program
def udptrace_compile():
    b = BPF(src_file="./udp/udptrace.c")
    return b.get_table("udp4_data"), b.get_table("udp6_data")


# get data from the compile func return's pointer
def udptrace_func(udp4_data, udp6_data):
    udp4_datas, udp6_datas = [], []
    for data, len in udp4_data.items():
        udp4_datas.append({
            "saddr": inet_ntop(AF_INET, pack('I', data.saddr)),
            "daddr": inet_ntop(AF_INET, pack('I', data.daddr)),
            "sport": data.sport,
            "dport": data.dport,
            "len": data.len,
            "time": time.time()
        })
    for data, len in udp6_data.items():
        udp6_datas.append({
            "saddr": inet_ntop(AF_INET6, pack('I', data.saddr)),
            "daddr": inet_ntop(AF_INET6, pack('I', data.daddr)),
            "sport": data.sport,
            "dport": data.dport,
            "len": data.len,
            "time": time.time()
        })
    udp4_data.clear()
    udp6_data.clear()
    return udp4_datas, udp6_datas

if __name__ == '__main__':
    udp4_data, udp6_data = udptrace_compile()
    while True:
        try:
            udp4_datas, udp6_datas = udptrace_func(udp4_data, udp6_data)
            for i in udp4_datas + udp6_datas:
                print(i)
            time.sleep(1)
        except KeyboardInterrupt:
            break