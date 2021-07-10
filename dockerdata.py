import requests
from socket import gethostbyname, gethostname
import docker

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

host="http://127.0.0.1:5000/dockermsg"
hostname = gethostname()
ip = gethostbyname(hostname)
senddata = {
    "host": ip,
    "data": getdata()
}

po = requests.post(url=host, json=senddata)
print(po.text)