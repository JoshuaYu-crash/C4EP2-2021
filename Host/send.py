import time

# BPF trace
from tcp.tcptrace import tcptrace_func, tcptrace_compile
from udp.udptrace import udptrace_func, udptrace_compile
from icmp.icmptrace import icmptrace_func, icmptrace_compile

# docker data
from docker.dockerdata import getDockerData

# utils to send data to Ryu
from socket import gethostname, gethostbyname
import requests
from transinfo_client import transinfo

# Config Object
from config import Config



# tcp special filter for the Ryu
def tcpFilter(datas):
    retData = []
    for data in datas:
        if True:
            retData.append(data)
    return retData


# send data function, send data to the Ryu
def sendDatas(datas, type, protocol):
    for i in datas:
        data = {
            "host": ip,
            "data": i,
            "type": type,
            "protocol": protocol
        }
        print(data)


def sendDockerData():
    host = "http://" + Config.RyuIP + ":5000/dockermsg"
    sendData = {
        "host": ip,
        "data": getDockerData()
    }
    po = requests.post(url=host, json=sendData)


if __name__ == '__main__':
    # compile block
    ip4s, ip4r, ip6s, ip6r = tcptrace_compile()
    udp4_data, udp6_data = udptrace_compile()
    icmp_data = icmptrace_compile()

    hostname = gethostname()
    ip = gethostbyname(hostname)

    while True:
        try:
            tcp4_datas, tcp6_datas = tcptrace_func(ip4s, ip4r, ip6s, ip6r)
            udp4_datas, udp6_datas = udptrace_func(udp4_data, udp6_data)
            icmp_datas = icmptrace_func(icmp_data)
            sendDatas(tcpFilter(tcp4_datas), "ip4", "tcp")
            sendDatas(tcpFilter(tcp6_datas), "ip6", "tcp")
            sendDatas(udp4_datas, "ip4", "udp")
            sendDatas(udp6_datas, "ip6", "udp")
            sendDatas(icmp_datas, "ip4", "icmp")
            # sendDockerData()
            time.sleep(1)
        except KeyboardInterrupt:
            break