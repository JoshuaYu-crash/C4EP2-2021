from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import redis
from flask_cors import *
import time
import json
from pyecharts import options as opts
from pyecharts.charts import Graph

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


# doubt IP and danger IP

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
    if item is None:
        new_ban_ip = BanIP(ban_ip=saddr, banned=banned)
        db.session.add(new_ban_ip)
        if banned:
            r["update_time"] = int(time.time())
        db.session.commit()
    elif item.banned != banned:
        item.banned = banned
        r["update_time"] = int(time.time())
        db.session.commit()
    else:
        print("Banned ip add failed. " + str(saddr) + " exists.")


def add_danger_ip(saddr):
    ban(saddr, banned=True)


def add_doubt_ip(saddr):
    ban(saddr, banned=False)


# /*----------------IP Control Interface----------------*/

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
    add_doubt_ip(doubtIP)
    return "OK"


# 将IP变为危险IP
@app.route("/setdangerip", methods=["GET"])
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


# /*----------------Typology Show Interface----------------*/

# Receive Msg From Hosts
@app.route("/refreshdockermsg", methods=["POST"])
def dockerMsg():
    data = request.json
    host = data["host"]
    datalist = data["data"]
    # print(datalist)
    # r.set(host, json.dumps(datalist))
    r.hset("topology", host, datalist)
    return "ok"


@app.route("/getdockermsg", methods=["GET"])
def getDockerMsg():
    host = request.args.get("host")
    docker = request.args.get("dockerdata")
    dockers = json.loads(r.hget("topology", host))
    tar = None
    # print(dockers)
    for doc in dockers:
        print(doc["NetworkSettings"]["Networks"]["bridge"]["IPAddress"], docker)
        if docker == doc["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]:
            tar = doc
            break
    print(tar)
    return jsonify(tar)


def graph_base() -> Graph:
    nodes = []
    links = []
    categories = [
        {"symbol": "circle", 'name': 'ryu'},
        {"symbol": "diamond", 'name': 'host'},
        {"symbol": "roundRect", 'name': 'dockerdata'},
    ]
    ryu = opts.GraphNode(name="RYU", symbol_size=40, category=0)  # symbol='roundRect'
    nodes.append(ryu)
    doc_id = 1
    for key in r.keys():
        host = opts.GraphNode(name=key, symbol_size=30, category=1)  # symbol='diamond'
        nodes.append(host)
        ryuHostLink = opts.GraphLink(source="RYU", target=key)
        links.append(ryuHostLink)
        dockerlist = json.loads(r.get(key))
        for doc in dockerlist:
            docName = doc["Names"][0]
            docInfo = str(key, encoding='utf-8') + '/' + doc["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
            new_node = opts.GraphNode(name=str(doc_id) + docName, symbol_size=20, category=2, value=docInfo)
            nodes.append(new_node)
            hostDocLink = opts.GraphLink(source=key, target=str(doc_id) + docName)
            links.append(hostDocLink)
            doc_id += 1
    linestyle_opts = opts.LineStyleOpts(
        is_show=True,
        width=2,
        curve=0.1,
        type_="solid",
        color="orange",
    )
    g = (
        Graph()
            .add("", nodes, links, repulsion=1000, categories=categories,
                 label_opts=opts.LabelOpts(is_show=True, position="left", color='white'),
                 linestyle_opts=linestyle_opts)
            .set_global_opts(title_opts=opts.TitleOpts(title=""))
    )
    return g


@app.route("/graphchart", methods=["GET"])
def get_bar_chart():
    c = graph_base()
    return c.dump_options_with_quotes()


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5001, debug=True)
