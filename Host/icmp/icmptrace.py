from bcc import BPF
import ctypes as ct
import time
from socket import inet_ntop, AF_INET, gethostname, gethostbyname
from struct import pack


# compile the icmptrace.c into the kernel
def icmptrace_compile():
    b = BPF(src_file="./icmp/icmptrace.c")
    return b.get_table("icmp_data")


# get data from the compile's return pointer
def icmptrace_func(icmp_data):
    icmp_datas = []
    for data, len in icmp_data.items():
        icmp_datas.append({
            "saddr": inet_ntop(AF_INET, pack('I', data.saddr)),
            "daddr": inet_ntop(AF_INET, pack('I', data.daddr)),
            "len": data.len,
            "time": time.time()
        })
    icmp_data.clear()
    return icmp_datas



if __name__ == '__main__':
    # get the pointer
    icmp_data = icmptrace_compile()
    while True:
        try:
            for i in icmptrace_func(icmp_data):
                print(i)
            time.sleep(1)
        except KeyboardInterrupt:
            break