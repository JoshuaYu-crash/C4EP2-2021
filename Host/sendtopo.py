import time
import redis
from config import Config
from socket import gethostname, gethostbyname
import json

from dockerdata import dockerdata

r = redis.Redis(host=Config.RyuIP, port=6379)
hostname = gethostname()
ip = gethostbyname(hostname)

while True:

    r.hset("typology", ip, json.dumps(dockerdata.getDockerData()))

    time.sleep(5)