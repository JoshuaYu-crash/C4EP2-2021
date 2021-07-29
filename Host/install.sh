sudo apt update

sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys D4284CDD

echo "deb https://repo.iovisor.org/apt/bionic bionic main" | sudo tee /etc/apt/sources.list.d/iovisor.list

sudo apt-get update

sudo apt-get install libbcc

sudo apt-get install python-bcc

pip install docker

pip install requests

