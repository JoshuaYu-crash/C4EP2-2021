import docker


cli = docker.APIClient(base_url='unix://var/run/docker.sock')

def getDockerData():
    return cli.containers()

def getDockerStats(containID):
    return cli.stats(containID, stream=False)


if __name__ == '__main__':
    getDockerData()
