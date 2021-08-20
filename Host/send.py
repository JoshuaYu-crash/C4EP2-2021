import time
import json

# BPF trace
from tcp.tcptrace import tcptrace_func, tcptrace_compile
from udp.udptrace import udptrace_func, udptrace_compile
from icmp.icmptrace import icmptrace_func, icmptrace_compile

# dockerdata get
from dockerdata.dockerdata import getDockerData, getDockerStats

# utils to send data to Ryu
from socket import gethostname, gethostbyname
from transinfo_client import transinfo

# Config Object
from config import Config

# redis
import redis

# xdp control
from xdpcontrol import xdpcontrol, xdpstop


# redis connect
class RedisHelper:
    def __init__(self):
        self.connect = redis.Redis(host=Config.RyuIP, port=6379)
        self.banIPChan = 'Banned IPs'
        self.containerChan = 'Container Msg'

    def subscribe(self):
        listen = self.connect.pubsub(ignore_subscribe_messages=True)
        listen.subscribe(self.banIPChan, self.containerChan)
        return listen


# tcp special filter for the Ryu
def tcpFilter(datas):
    retData = []
    for data in datas:
        if data["daddr"] != Config.RyuIP and data["com"] != "Xtightvnc" and data["daddr"] != "::ffff:" + Config.RyuIP:
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
        transinfo(data)


def redisSubscribeHandler():
    # receive control msg
    msg = listen.get_message()
    if msg:
        if str(msg["channel"], encoding="utf-8") == "Container Msg":
            containerID = str(msg["data"], encoding='utf-8')
            ret = getDockerStats(containerID)
            print(ret)
            rh.connect.set("containermsg", json.dumps(ret), ex=3)
        elif str(msg["channel"], encoding="utf-8") == "Banned IPs":
            data = json.loads(str(msg["data"], encoding='utf-8'))
            print(data)
            xdpstop()
            xdpcontrol(data)


if __name__ == '__main__':
    # compile block
    ip4s, ip4r, ip6s, ip6r = tcptrace_compile()
    udp4_data, udp6_data = udptrace_compile()
    icmp_data = icmptrace_compile()

    # get self IP
    hostname = gethostname()
    ip = gethostbyname(hostname)

    # get redis connect
    rh = RedisHelper()
    listen = rh.subscribe()

    while True:
        try:
            # net msg sends
            tcp4_datas, tcp6_datas = tcptrace_func(ip4s, ip4r, ip6s, ip6r)
            udp4_datas, udp6_datas = udptrace_func(udp4_data, udp6_data)
            icmp_datas = icmptrace_func(icmp_data)
            sendDatas(tcpFilter(tcp4_datas), "ip4", "tcp")
            sendDatas(tcpFilter(tcp6_datas), "ip6", "tcp")
            sendDatas(udp4_datas, "ip4", "udp")
            sendDatas(udp6_datas, "ip6", "udp")
            sendDatas(icmp_datas, "ip4", "icmp")

            # docker typology send
            rh.connect.hset("typology", ip, json.dumps(getDockerData()))

            # redis subscribe handler
            redisSubscribeHandler()
            # receive control msg
            # msg = listen.get_message()
            # if msg:
            #     data = json.loads(str(msg["data"], encoding='utf-8'))
            #     print(data)
            #     xdpstop()
            #     xdpcontrol(data)

            time.sleep(1)
        except KeyboardInterrupt:
            break
