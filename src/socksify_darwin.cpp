#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <errno.h>
#include <list>
#include <signal.h>

#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#include <netinet/ip.h>
#include <sys/uio.h>

#define err(fmt) fprintf(stderr, fmt)
#define errf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define tun_read(...) utun_read(__VA_ARGS__)
#define tun_write(...) utun_write(__VA_ARGS__)
#define TCP_FLAG 0x06
#define UDP_FLAG 0x11

class NetAdapterUtil {
public:
    int getIpv4(std::list<std::string> &out_list_ip4);
    int getIpv6(std::list<std::string> &out_list_ip6);
private:
    int getIp(int ipv4_6, std::list<std::string> &out_list_ip);
};

static struct utun{
    int fd;
    char* ifname;
} utunx;

static char gateway[15] = {0};
static char vpn_server[15];
std::list<std::string> dns_servers;

int check_fd_fine(int fd);

static inline int utun_modified_len(int len)
{
	if (len > 0)
		return (len > sizeof (u_int32_t)) ? len - sizeof (u_int32_t) : 0;
	else
		return len;
}

static int utun_write(int fd, void *buf, size_t len)
{
	u_int32_t type;
	struct iovec iv[2];
	struct ip *iph;

	iph = (struct ip *) buf;

	if (iph->ip_v == 6)
		type = htonl(AF_INET6);
	else
		type = htonl(AF_INET);

	iv[0].iov_base = &type;
	iv[0].iov_len = sizeof(type);
	iv[1].iov_base = buf;
	iv[1].iov_len = len;

	return utun_modified_len(writev(fd, iv, 2));
}

static int utun_read(int fd, void *buf, size_t len)
{
	u_int32_t type;
	struct iovec iv[2];

	iv[0].iov_base = &type;
	iv[0].iov_len = sizeof(type);
	iv[1].iov_base = buf;
	iv[1].iov_len = len;

	return utun_modified_len(readv(fd, iv, 2));
}

void vpn_tun_alloc(struct utun* utunx)
{
	struct ctl_info ctlInfo;
	struct sockaddr_ctl sc;
    socklen_t ifname_len = sizeof(utunx->ifname);

//	if (dev == NULL) {
//		errf("utun device name cannot be null");
//        exit(-1);
//	}
//	if (sscanf(dev, "utun%d", &utunnum) != 1) {
//		errf("invalid utun device name: %s", dev);
//		return -1;
//	}

	memset(&ctlInfo, 0, sizeof(ctlInfo));
	if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >=
			sizeof(ctlInfo.ctl_name)) {
		errf("can not setup utun device: UTUN_CONTROL_NAME too long");
        exit(-1);
	}

    utunx->fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

	if (utunx->fd == -1) {
		err("socket[SYSPROTO_CONTROL]");
        exit(-1);
	}

	if (ioctl(utunx->fd, CTLIOCGINFO, &ctlInfo) == -1) {
		close(utunx->fd);
		err("ioctl[CTLIOCGINFO]");
        exit(-1);
	}

	sc.sc_id = ctlInfo.ctl_id;
	sc.sc_len = sizeof(sc);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_unit = 0;

	if (connect(utunx->fd, (struct sockaddr *) &sc, sizeof(sc)) == -1) {
		close(utunx->fd);
		err("connect[AF_SYS_CONTROL]");
        exit(-1);
	}
    if(getsockopt(utunx->fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, utunx->ifname, &ifname_len) == -1){
        err("getsockopt[UTUN_OPT_IFNAME]");
        exit(-1);
    }

    printf("create utunX on %s\n", utunx->ifname);
    fflush(stdout);
}

void module_init(uint16_t port);
ssize_t tcp_frag_nat(void *packet, size_t len, size_t limit);
ssize_t udp_frag_nat(void *packet, size_t len, size_t limit);
void print_packet(char* packet, int len);

static void signal_handler(int sig){
    close(utunx.fd);
    char buf[1024] = {0};
    if (sig == SIGINT || sig == SIGTERM){
        printf("关闭VPN，等待重置route...");
        snprintf(buf, 1024, "route -v delete -net %s", vpn_server);
        system(buf);
        system("route -v delete -net 0.0.0.0");

        memset(buf, 0, 1024);
        snprintf(buf, 1024, "route add -net 0.0.0.0 %s", gateway);
        system(buf);

        for (auto item : dns_servers){
            memset(buf, 0, 1024);
            snprintf(buf, 1024, "route -v delete -net %s", item.c_str());
            system(buf);
        }
        close(utunx.fd);
        exit(0);
    }
}

static void init_route(char* buf, int len){
    FILE *fp_gateway, *fp_dns;
    // 获取网关
    if ((fp_gateway = popen("netstat -rn | grep default | awk '{print $2}'", "r")) != NULL){
        if (fgets(gateway, sizeof(gateway), fp_gateway) == NULL){
            err("get gateway error!");
            exit(-1);
        }
    }
    pclose(fp_gateway);
    // 获取dns
    if ((fp_dns = popen("cat /etc/resolv.conf | grep nameserver | awk '{print $2}'", "r")) != NULL){
        char dns[15] = {0};
        while (fgets(dns, sizeof(dns), fp_dns) != NULL){
            std::string tmp_dns(dns);
            dns_servers.push_back(tmp_dns.substr(0, tmp_dns.size()-1));
            memset(dns, 0, sizeof(dns));
        }
    }
    pclose(fp_dns);

    // 删除已有default路由
    system("route -v delete -net 0.0.0.0");

    // 添加v2ray server
    memset(buf, 0, len);
    snprintf(buf, len, "route add -net %s %s", vpn_server, gateway);
    system(buf);

    // 添加default路由
    system("route add -net 0.0.0.0 10.2.0.1");
    system("route add -net 10.2.0.26/32 10.2.0.1");

    // 添加dns server路由
    for (auto item : dns_servers) {
        memset(buf, 0, len);
        snprintf(buf, len, "route add -net %s %s", item.c_str(), gateway);
        system(buf);
    }
}

int main(int argc, char *argv[])
{
    uint16_t port = 1080;
    if (argc < 3){
        err("required socks5 server ip addr and port");
    } else{
        strcpy(vpn_server, argv[1]);
        if (INADDR_NONE == inet_addr(vpn_server)){
            err("socks server ip is invalid!");
            exit(-1);
        }
        if ((atoi(argv[2]) & 0xffff) != atoi(argv[2]) || atoi(argv[2]) == 0){
            err("socks server port is invaild!");
            exit(-1);
        }
        port = atoi(argv[2]);
    }
    //ctrl+c信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

	char buf[2048] = {0};
    char ifname[20];
	int len;
//    struct utun utunx;
    utunx.ifname = ifname;

	vpn_tun_alloc(&utunx);
	if (utunx.fd == -1) {
		return -1;
	}

	module_init(port);

    snprintf(buf, sizeof(buf), "ifconfig %s 10.2.0.26/24 10.2.0.1 up", utunx.ifname);
	system(buf);

    init_route(buf, sizeof(buf));

    // 经试验不能直接添加default，因为这个项目不能转发udp，设置default后无法进行dns，还需要进行改造

	for (; ; ) {
		char *packet = (buf + 60);
		len = tun_read(utunx.fd, packet, 1500);
//        print_packet(packet, len);
		if (len < 0) {
			fprintf(stderr, "read tun failure\n");
            perror("open error");
            continue;
		}

        if ((int8_t)*(packet + 9) == UDP_FLAG){
            len = udp_frag_nat(packet, len, 1500);
        }else{
            len = tcp_frag_nat(packet, len, 1500);
        }

		if (len <= 0) {
			fprintf(stderr, "nat failure\n");
			continue;
		}

		len = tun_write(utunx.fd, packet, len);
		if (len <= 0) {
			fprintf(stderr, "write tun failure: %d\n", errno);
			continue;
		}
	}

	return 0;
}

