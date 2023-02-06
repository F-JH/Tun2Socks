//
// Created by Xiaoandi Fu on 2022/12/27.
//
#include <iostream>
#include <sys/wait.h>
#include <sys/types.h>
#include <list>
#include <unistd.h>

void sigint_handler(int sig){
//    std::cout << "in handler" << std::endl;
    if (sig == SIGINT || sig == SIGTERM){
        std::cout << "结束进程..." << std::endl;
    } else{
        std::cout << "异常！" << std::endl;
    }
}

int main(){
    signal(SIGTERM, sigint_handler);

    char gateway[15];

    FILE *fp_gateway, *fp_dns;
    std::list<std::string> dns_servers;
    if ((fp_dns = popen("cat /etc/resolv.conf | grep nameserver | awk '{print $2}'", "r")) != NULL){
        char dns[30];
        while (fgets(dns, sizeof(dns), fp_dns) != NULL){
            std::string tmp_dns(dns);
            dns_servers.push_back(tmp_dns.substr(0, tmp_dns.size()-1));
            memset(dns, 0, sizeof(dns));
        }
    }
//    fclose(fp_gateway);
    pclose(fp_dns);

    if ((fp_gateway = popen("netstat -rn | grep default | awk '{print $2}'", "r")) != NULL){
        if (fgets(gateway, sizeof(gateway), fp_gateway) == NULL){
            exit(-1);
        }
    }
    pclose(fp_gateway);

    std::cout << dns_servers.size() << std::endl;
    while (1){
        std::cout << "running..." << std::endl;
        sleep(1);
    }
    return 0;
}