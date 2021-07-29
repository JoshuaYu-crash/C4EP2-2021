import json
import requests
from socket import gethostbyname, gethostname
import docker
import time

def getdata():
    cli = docker.from_env()
    client = docker.APIClient(base_url='unix://var/run/docker.sock')
    datalist = client.containers()
    retdata = []
    for i in datalist:
        container = cli.containers.get(i["Id"])
        i["stats"] = container.stats(stream=False)
        retdata.append(i)
    return retdata

def getIPConfig():
    with open("./config.json", "r") as f:
        configs = json.load(f)
        return configs["ryu"]


host="http://" + getIPConfig() + ":5000/dockermsg"
hostname = gethostname()
ip = gethostbyname(hostname)
while True:

    senddata = {
        "host": ip,
        "data": getdata()
    }

    po = requests.post(url=host, json=senddata)
    time.sleep(2)
print(po.text)

getIPConfig()