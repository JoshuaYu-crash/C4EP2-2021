import docker


cli = docker.APIClient(base_url='unix://var/run/docker.sock')

def getDockerData():
    datalist = cli.containers()
    retData = []
    for i in cli.containers():
        i["stats"] = cli.stats(i["Id"], stream=False)
        retData.append(i)
    return retData

def getDockerStats(containID):
    return cli.stats(containID, stream=False)


if __name__ == '__main__':
    getDockerData()
