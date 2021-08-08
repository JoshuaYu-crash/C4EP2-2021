from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import redis
from flask_cors import *
from info_query import *
from ip_ban import *


r = redis.Redis(host="127.0.0.1", port=6379)

app = Flask(__name__)
CORS(app, supports_credentials=True)


# 前一秒的流量信息，时间戳和流量大小
@app.route("/getnetdata")
def getNetData():
    hostIP = request.args.get("hostip")
    dockerIP = request.args.get("dockerip")
    protocol = request.args.get("protocol")
    print(hostIP)
    print(dockerIP)
    print(protocol)
    data = get_saddr_byte(dockerIP, hostIP, protocol)
    return jsonify(data)


# 将IP变为可疑IP
@app.route("/setdoubtip", methods=["GET"])
def setDoubtIP():
    doubtIP = request.args.get("doubtip")
    add_doubt_ip(doubtIP)
    return "OK"


# 将IP变为危险IP
@app.route("/setDangerip", methods=["GET"])
def setDangerIP():
    dangerIP = request.args.get("dangerip")
    add_doubt_ip(dangerIP)
    return "OK"


# 获取所有的可疑IP和危险IP
@app.route("/getbanip", methods=["GET"])
def getBanIP():
    data = getBanIP()
    return jsonify(data)


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5001,debug=True)

