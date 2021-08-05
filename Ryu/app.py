from flask import Flask, render_template, request, jsonify
import redis
from flask_cors import *
import info_query
from transinfo_server import get_db_session
session = get_db_session()


r = redis.Redis(host="127.0.0.1", port=6379)

app = Flask(__name__)
CORS(app, supports_credentials=True)


@app.route("/getnetdata")
def getNetData():
    # 前一秒的流量信息，时间戳和流量大小
    dockerName = request.form.get("dockername")
    pass


# 将IP变为可疑IP
@app.route("/setdoubtip", methods=["POST"])
def setDoubtIP():
    pass


# 将IP变为危险IP
@app.route("/setDangerip", methods=["POST"])
def setDangerIP():
    pass


@app.route("/getbanip", methods=["GET"])
def getBanIP():
    pass


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=5001,debug=True)

