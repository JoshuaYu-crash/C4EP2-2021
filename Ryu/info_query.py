from sqlalchemy import Column, String, create_engine, Integer, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from transinfo_server import Pkg, BanIP, get_db_session
import json


def get_saddr_byte(daddr, session=get_db_session()):
    # return total saddr traffic flows(bytes) in json format
    import time
    now = time.time()
    pkgs = session.query(Pkg).filter(Pkg.daddr == daddr,
                                     Pkg.time >= now-2).all()  # .all()
    ret = 0
    last_time = 0
    try:
        last_time = pkgs[-1].time
    except:
        pass
    for pkg in pkgs:
        ret += pkg.send_byte + pkg.recv_byte
    return json.dumps({
        "byte": ret,
        "time": last_time
    })
    """
    {
    "byte": 1024,
    "time": 123325453422,
    }
    """


def get_ban_ips(session=get_db_session()):
    # return ban_ips in json format
    ret = {"danger": [], "doubt": []}
    IPs = session.query(BanIP).filter().all()  # .all()
    for ip in IPs:
        if ip.banned:
            ret["danger"].append(ip.ban_ip)
        else:
            ret["doubt"].append(ip.ban_ip)
    return json.dumps(ret)
    """
    {
        "danger": [
            "192.168.0.111",
            "192.168.0.222"
        ],
        "doubt": [
            "192.168.0.11",
            "192.169.0.22"
        ]
    }
    """


if __name__ == '__main__':
    get_saddr_byte('30.0.1.139', get_db_session())
    get_ban_ips(get_db_session())
