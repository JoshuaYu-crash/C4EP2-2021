from sqlalchemy import Column, String, create_engine, Integer, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import transinfo_pb2_grpc
import transinfo_pb2
import logging
import grpc
import time
from concurrent import futures
import redis
from config import Config

r = redis.Redis(host="127.0.0.1", port=6379)
r["update_time"] = int(time.time())
session = None


def insert(req):
    # session = get_db_session()
    new_pkg = Pkg(Ty=req.type, protocol=req.protocol, saddr=req.saddr, sport=req.sport, send_byte=req.send_byte,
                  daddr=req.daddr, dport=req.dport, recv_byte=req.recv_byte, time=int(time.time()), pid=req.pid, com=req.com,
                  host=req.host)
    session.add(new_pkg)
    session.commit()


# >threshold1: warning(byte);  >threshold2: ban
def query(saddr, threshold1=Config.doubtThreshold, threshold2=Config.dangerThreshold):
    # session = get_db_session()
    now = int(time.time())
    pkg = session.query(Pkg).filter(Pkg.time > now - 60,
                                    Pkg.saddr == saddr).all()  # .all()
    send_sum = 0
    for e in pkg:
        send_sum += e.send_byte

    if send_sum > threshold2:
        ret = 2
    elif send_sum > threshold1:
        ret = 1
    else:
        ret = 0
    print(ret)
    return ret


def broadcast_to_clients():
    import json
    # session = get_db_session()
    banned_IPs = []
    IPs = session.query(BanIP).filter(BanIP.banned == True).all()  # .all()
    for ip in IPs:
        banned_IPs.append(ip.ban_ip)
    r.publish("Banned IPs", json.dumps(banned_IPs))


def ban(saddr, banned=True):  # True => banned, False => warning
    # session = get_db_session()
    item = session.query(BanIP).filter(BanIP.ban_ip == saddr).first()
    return_code = 0

    if item == None:
        new_ban_ip = BanIP(ban_ip=saddr, banned=banned)
        session.add(new_ban_ip)
        if banned:
            r["update_time"] = int(time.time())
        session.commit()
        # print(str(saddr) + " is added to the banned list.")
        broadcast_to_clients()
    elif item.banned != banned:
        item.banned = banned
        r["update_time"] = int(time.time())
        session.commit()
        broadcast_to_clients()
    else:
        print("Banned ip add failed. " + str(saddr) + " exists.")


def add_danger_ip(saddr):
    ban(saddr, banned=True)


def add_doubt_ip(saddr):
    ban(saddr, banned=False)


def get_db_session():
    engine = create_engine(
        'mysql+mysqldb://root:password@localhost:3306/package')
    Base.metadata.create_all(engine)
    DBSession = sessionmaker(bind=engine)
    Session = DBSession()
    return Session


def get_ban_list():
    # session = get_db_session()
    ips = session.query(BanIP).filter(BanIP.banned == True).all()
    ban_list = []
    for e in ips:
        ban_list.append(e.ban_ip)
    return ban_list


class TransInfo:

    def GetInfo(self, request, context):
        print(request)
        insert(req=request)
        isToBan = query(request.saddr, threshold1=Config.doubtThreshold,
                        threshold2=Config.dangerThreshold)
        if isToBan == 2:
            ban(request.saddr, banned=True)
        elif isToBan == 1:
            ban(request.saddr, banned=False)
        ban_list = get_ban_list()

        print(str(r["update_time"]) + " >= " + str(request.prev_time))
        # if int(r["update_time"]) >= request.prev_time and ban_list:
        #     # return transinfo_pb2.SuccessReply(reply_code=2, reply=str(ban_list))
        #     return transinfo_pb2.SuccessReply(reply_code=2, reply="")
        # else:
        return transinfo_pb2.SuccessReply(reply_code=1, reply="")


Base = declarative_base()


class Pkg(Base):
    __tablename__ = 'pkg'

    id = Column(Integer, primary_key=True)
    Ty = Column(String(8))  # type
    protocol = Column(String(10))
    daddr = Column(String(40))
    dport = Column(Integer)
    saddr = Column(String(40))
    sport = Column(Integer)
    send_byte = Column(Integer)
    recv_byte = Column(Integer)
    time = Column(Integer)
    pid = Column(Integer)
    com = Column(String(20))
    host = Column(String(40))

    def __init__(self, Ty, protocol, saddr, sport, send_byte, daddr, dport, recv_byte, time, pid, com, host):
        # {'type': 'ip4', 'data': {'daddr': '192.168.200.200', 'send_byte': 1400, 'sport': '22', 'recv_byte': 1160, 'time': 1623748639.296404, 'dport': '6989', 'com': '7432', 'saddr': '30.0.1.77', 'pid': 7432}, 'protocol': 'tcp'}
        self.Ty = Ty
        self.protocol = protocol
        self.saddr = saddr
        self.sport = sport
        self.send_byte = send_byte
        self.daddr = daddr
        self.dport = dport
        self.recv_byte = recv_byte
        self.time = time
        self.pid = pid
        self.com = com
        self.host = host


class BanIP(Base):
    __tablename__ = "banIP"

    id = Column(Integer, primary_key=True)
    ban_ip = Column(String(40))
    banned = Column(Boolean)

    def __init__(self, ban_ip, banned):
        self.ban_ip = ban_ip
        self.banned = banned


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    transinfo_pb2_grpc.add_TransInfoServicer_to_server(TransInfo(), server)
    server.add_insecure_port('[::]:11451')
    server.start()
    server.wait_for_termination()


def run():
    global session
    session = get_db_session()
    logging.basicConfig()
    serve()


if __name__ == '__main__':
    run()
