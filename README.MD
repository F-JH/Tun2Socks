# Tun2Socks

### 编译

Cmake V3.24:

```shell
cmake -B build 
cmake --build build --target Tun2Socks -j 6
# 运行，注意运行前一定要先启动socks5代理，并且关闭时一定要用Ctrl+C停止进程，因为处理了此信号，用于恢复路由表，参考socksify_darwin.cpp: void signal_handler(int sig)
sudo build/Tun2Socks <addr_ip> <local_port>
```

g++直接编译：

```shell
mkdir build && cd build
g++ -c ../src/conntrack.cpp ../src/socksify_darwin.cpp
g++ ./*.o -o Tun2Socks
# 运行，注意运行前一定要先启动socks5代理，并且关闭时一定要用Ctrl+C停止进程，因为处理了此信号，用于恢复路由表，参考socksify_darwin.cpp: void signal_handler(int sig)
sudo ./Tun2Socks <addr_ip> <local_port>
```

<addr_ip>: 需要向外转发数据包的ip地址，通常是远程代理服务的ip  
<local_port>: 本地开启的socks client

### 数据流向
[数据包] -> [虚拟网卡] -> [NAT转发至本地port监听的socks client服务] -> [远端socks服务]
