import docker

def getDockerData():
    cli = docker.APIClient(base_url='unix://var/run/docker.sock')
    return cli.containers()

if __name__ == '__main__':
    print(getDockerData())