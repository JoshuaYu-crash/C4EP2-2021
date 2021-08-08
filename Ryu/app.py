from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import redis
from flask_cors import *
import time

# /*----------------Flask and DB----------------*/

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+mysqldb://root:password@localhost:3306/package"
db = SQLAlchemy(app)
r = redis.Redis(host="127.0.0.1", port=6379)
CORS(app, supports_credentials=True)


# /*----------------DB Model----------------*/
# collected package
class Pkg(db.Model):
    __tablename__ = 'pkg'

    id = db.Column(db.Integer, primary_key=True)
    Ty = db.Column(db.String(8))  # type
    protocol = db.Column(db.String(10))
    daddr = db.Column(db.String(40))
    dport = db.Column(db.Integer)
    saddr = db.Column(db.String(40))
    sport = db.Column(db.Integer)
    send_byte = db.Column(db.Integer)
    recv_byte = db.Column(db.Integer)
    time = db.Column(db.Integer)
    pid = db.Column(db.Integer)
    com = db.Column(db.String(20))
    host = db.Column(db.String(40))


# doubt ips and

class BanIP(db.Model):
    __tablename__ = "banIP"

    id = db.Column(db.Integer, primary_key=True)
    ban_ip = db.Column(db.String(40))
    banned = db.Column(db.Boolean)

    def __init__(self, ban_ip, banned):
        self.ban_ip = ban_ip
        self.banned = banned


# /*----------------Helper Function----------------*/


def ban(saddr, banned=True):  # True => banned, False => warning
    item = BanIP.query.filter(BanIP.ban_ip == saddr).first()
    print(item)
    global update_time
    if item is None:
        new_ban_ip = BanIP(ban_ip=saddr, banned=banned)
        db.session.add(new_ban_ip)
        if banned:
            update_time = int(time.time())
        db.session.commit()
    elif item.banned != banned:
        item.banned = banned
        update_time = int(time.time())
        db.session.commit()
    else:
        print("Banned ip add failed. " + str(saddr) + " exists.")


def add_danger_ip(saddr):
    ban(saddr, banned=True)


def add_doubt_ip(saddr):
    ban(saddr, banned=False)


# /*----------------Interface----------------*/

# 前一秒的流量信息，时间戳和流量大小
@app.route("/getnetdata", methods=["GET"])
def getNetData():
    hostIP = request.args.get("hostip")
    dockerIP = request.args.get("dockerip")
    protocol = request.args.get("protocol")
    now = time.time()
    pkgs = Pkg.query.filter(Pkg.daddr == dockerIP, Pkg.protocol == protocol, Pkg.host == hostIP,
                            Pkg.time >= now - 2).all()
    ret = 0
    last_time = 0
    try:
        last_time = pkgs[-1].time
    except:
        pass
    for pkg in pkgs:
        ret += pkg.send_byte + pkg.recv_byte
    data = {
        "byte": ret,
        "time": last_time
    }
    return jsonify(data)


# 将IP变为可疑IP
@app.route("/setdoubtip", methods=["GET"])
def setDoubtIP():
    doubtIP = request.args.get("doubtip")
    add_danger_ip(doubtIP)
    return "OK"


# 将IP变为危险IP
@app.route("/setDangerip", methods=["GET"])
def setDangerIP():
    dangerIP = request.args.get("dangerip")
    add_danger_ip(dangerIP)
    return "OK"


# 获取所有的可疑IP和危险IP
@app.route("/getbanip", methods=["GET"])
def getBanIP():
    ret = {
        "danger": [],
        "doubt": []
    }
    IPs = BanIP.query.filter().all()
    for ip in IPs:
        if ip.banned:
            ret["danger"].append(ip.ban_ip)
        else:
            ret["doubt"].append(ip.ban_ip)
    return jsonify(ret)


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5001, debug=True)
