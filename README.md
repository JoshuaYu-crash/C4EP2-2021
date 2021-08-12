# 部署

## Host端

安装环境

```shell
git clone https://gitee.com/Joshua-Yu/C4EP2file.git
cd C4EP2file/Host
sh install.sh
vim config.py
# 配置Ryu的IP，保存退出
```

启动

```shell
python3 send.py
```

## Ryu端

安装环境

```shell
git clone https://gitee.com/Joshua-Yu/C4EP2file.git
cd C4EP2file/Ryu
sh install.sh
```

配置`Redis`

```shell
vim /etc/redis/redis.conf
# 将bind 127.0.0.1 修改为 Ryu 的IP，保存退出

systemctl restart redis
ufw allow 6379

# 测试redis
redis-cli -h <Ryu IP> -p 6379
```

启动

```shell
python3 transinfo_server.py
```

