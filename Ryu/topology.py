from flask import Flask, render_template, request, jsonify
from pyecharts import options as opts
from pyecharts.charts import Graph
import json
import redis
from flask_cors import *

r = redis.Redis(host="127.0.0.1", port=6379)
app = Flask(__name__)
CORS(app, supports_credentials=True)


@app.route("/dockermsg", methods=["POST"])
def dockerMsg():
    data = request.json
    host = data["host"]
    datalist = data["data"]
    # print(datalist)
    r.set(host, json.dumps(datalist))
    return "ok"


@app.route("/getdockermsg", methods=["GET"])
def getDockerMsg():
    host = request.args.get("host")
    docker = request.args.get("docker")
    dockers = json.loads(r.get(host))
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
        {"symbol": "roundRect", 'name': 'docker'},
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
    linestyle_opts = opts.LineStyleOpts(is_show=True,
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
    app.run(host="127.0.0.1", port=5000, debug=True)
