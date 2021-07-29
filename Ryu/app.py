from flask import Flask, render_template, request, jsonify
import redis
from flask_cors import *
import time
from sqlalchemy import Column, String, create_engine, Integer, Boolean
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from transinfo_server import Pkg, BanIP

r = redis.Redis(host="127.0.0.1", port=6379)

app = Flask(__name__)
CORS(app, supports_credentials=True)

session = None

def get_db_session():
    engine = create_engine(
        'mysql+mysqldb://root:password@localhost:3306/package')
    Base.metadata.create_all(engine)
    DBSession = sessionmaker(bind=engine)
    Session = DBSession()
    return Session

def latest(host,docker,Ty,seconds=10): # Ty: type
    now = int(time.time())
    pkg = session.query(Pkg).filter(Pkg.time >= now-seconds,Pkg.host==host,Pkg.daddr==docker,Pkg.Ty==Ty).all()
    ret = []
    for e in pkg:
        ret.append({
            {
                "time": e.time,
                "bytes": e.send_byte+e.recv_byte
            },
        })

    return ret # 返回前seconds秒的输入流量

session = get_db_session()


@app.route("/getnetdata")
def getNetData():
    # 前一秒的流量信息，时间戳和流量大小
    type = request.args.get("type")
    host = request.args.get("host")
    docker = request.args.get("docker")
    netdata = latest(host, docker, type)
    # print(netdata)
    return jsonify(netdata)


def modify(ip, ban):
    global session
    item = session.query(BanIP).filter(BanIP.ban_ip == ip).first()
    item.banned = ban
    session.commit()

@app.route("/setbanip", methods=["GET"])
def setBanIP():
    host = request.args.get("host")
    docker = request.args.get("docker")
    banIP = request.args.get("banip")
    isBan = request.args.get("isban")
    modify(banIP, isBan)
    return "ok"


def banIP_query():
    global session
    items = session.query(BanIP).all()
    ban_ips = []
    ips = []
    for item in items:
        ips.append(item)
        if item.banned == True: # True=>banned, False =>warning
            ban_ips.append(item)
     return item, ban_ips

@app.route("/getbanip", methods=["GET"])
def getBanIP():
    host = request.args.get("host")
    docker = request.args.get("docker")
    ips, banIP = banIP_query()
    return jsonify({
        "ips": ips,
        "banIP": banIP
    })


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5001,debug=True)

