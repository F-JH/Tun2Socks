# Tun2Socks

### 编译

Cmake V3.24:

```shell
cmake -B build 
cmake --build build --target Tun2Socks -j 6
# 运行，注意运行前一定要先启动socks5代理，并且关闭时一定要用Ctrl+C停止进程，因为处理了此信号，用于恢复路由表，参考socksify_darwin.cpp: void signal_handler(int sig)
sudo build/Tun2Socks
```

g++直接编译：

```shell
mkdir build && cd build
g++ -c ../src/conntrack.cpp ../src/socksify_darwin.cpp
g++ ./*.o -o Tun2Socks
# 运行，注意运行前一定要先启动socks5代理，并且关闭时一定要用Ctrl+C停止进程，因为处理了此信号，用于恢复路由表，参考socksify_darwin.cpp: void signal_handler(int sig)
sudo ./Tun2Socks
```
