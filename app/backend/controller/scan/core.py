import nmap
import masscan
import re


# 你是API的定制者，是你来设置端口参数的格式，让别人去匹配！
class Scan(object):
    def __init__(self, ip, ports=None, scan_argument=None, script_argument=None, sacn_rate=None):
        """
        param ip 我们要扫描的ip
        type: ip string

        param ports 扫描的目的端口
        type: ports string

        param scan_argument 扫描参数
        type: argument string

        paran script_name 扫描脚本
        type：script_name string   exc:"banner.nse"
        """
        self.ip = ip
        self.ports = ports
        self.scan_argument = scan_argument  # 扫描参数：例如-sU，-sT
        self.script_argument = script_argument  # 使用哪种脚本
        self.nm = nmap.PortScanner()  # 创建nmap的Scanner类
        self.ms = masscan.PortScanner()  # 创建masscan的Scanner类
        self.results = []
        self.scan_rate = "--max-rate " + str(sacn_rate)

    # 工具函数
    def get_ip(self, result):
        ips = list(result["scan"].keys())  # 将扫描的到的出来的ip地址赋值给self.ip
        return ips

    # 使用masscan检测开放的端口
    def port_decetion(self):
        """
        Method which uses masscan to dectect the open ports if ports=None

        param result masscan扫描的结果
        type result dict

        :param hosts: string for hosts as masscan use it "scanme.masscan.org" or "198.116.0-255.1-127" or "216.163.128.20/20"
        :param ports: string for ports as masscan use it "22,53,110,143-4564"
        """
        # 如果扫描参数里有-sU 则使用udp扫
        try:
            if re.search("-sU", self.scan_argument):
                ports = "U:1-65535"
                result = self.ms.scan(hosts=self.ip, ports=ports, arguments=self.scan_rate)
                ips = list(result["scan"].keys())
                for ip in ips:
                    port = list(result["scan"][ip]["udp"].keys())

            # tcp 扫描
            ports = "T:1-65535"
            result = self.ms.scan(hosts=self.ip, ports=ports, arguments=self.scan_rate)
            # 将扫描的ip列表化
            ips = list(result["scan"].keys())
            for ip in ips:
                port = port + list(result["scan"][ip]["tcp"])
            open_ports = [str(i) for i in port]
            ports = ",".join(open_ports)
            return ports  # 这里ports要转换成字符串，后面basic_dection 还要用
        except:
            print("network is unreachable.")
            return None

    # 基本检测 无论什么扫描都会调用一次
    def basic_detection(self):
        """
        Method which detect the service
        """

        print("star nmap_scan")

        if self.ports is None:
            ports = self.port_decetion()  # 如果用户没有提供端口，则需要用masscan扫描出来
        else:
            ports = self.ports
        result = self.nm.scan(hosts=self.ip, ports=ports,
                              arguments=self.scan_argument + " " + self.script_argument)
        print(result)
        return result

    # 为每个ip设一个字典
    def init_result(self, result):
        ips = self.get_ip(result)

        for i in range(len(ips)):
            self.results.append({})  # 往result里添加一个字典
            # 与端口无关的信息，请插入到这里
            self.results[i][ips[i]] = {}
            self.results[i][ips[i]]["OS"] = ""
            self.results[i][ips[i]]["vendor"] = ""
            self.results[i][ips[i]]["model_name"] = ""
            self.results[i][ips[i]]["firmware_version"] = ""
            self.results[i][ips[i]]["is_discontinued"] = ""
            self.results[i][ips[i]]["cve_list"] = {"cve_id": "", "cvss": ""}
            self.results[i][ips[i]]["decive_type"] = ""
            self.results[i][ips[i]]["firmware_infor"] = {"name": "", "version": "", "shar2": ""}

            # 与端口有关的信息，请插入到这里
            self.results[i][ips[i]]["tcp"] = []
            self.results[i][ips[i]]["udp"] = []

            tcp_ports = list(result["scan"][ips[i]]["tcp"].keys()) if "tcp" in result["scan"][ips[i]] else []

            udp_ports = list(result["scan"][ips[i]]["udp"].keys()) if "udp" in result["scan"][ips[i]] else []

            for j in range(len(tcp_ports)):
                self.results[i][ips[i]]["tcp"].append({})
                self.results[i][ips[i]]["tcp"][j]["port"] = tcp_ports[j]
            for j in range(len(udp_ports)):
                self.results[i][ips[i]]["udp"].append({})
                self.results[i][ips[i]]["udp"][j]["port"] = udp_ports[j]
        return self.results

    # 获取hostnames
    def get_hostnames(self, result):
        ips = self.get_ip(result)
        for i in range(len(ips)):
            self.results[i][ips[i]]["hostnames"] = result["scan"][ips[i]]["hostnames"]
            # 获取厂商信息

    def get_vender(self, result):
        ips = list(result["scan"].keys())
        for i in range(len(ips)):
            self.results[i][ips[i]]["vendor"] = result["scan"][ips[i]]["vendor"]

    # 端口服务探测信息获取
    def service(self, result):
        ips = self.get_ip(result)
        for i in range(len(ips)):
            if "tcp" in result["scan"][ips[i]].keys():
                tcp_ports = list(result["scan"][ips[i]]["tcp"].keys())
                for j in range(len(tcp_ports)):
                    self.results[i][ips[i]]["tcp"][j]["service"] = result["scan"][ips[i]]["tcp"][int(tcp_ports[j])][
                        "name"]
            if "udp" in result["scan"][ips[i]].keys():
                udp_ports = list(result["scan"][ips[i]]["udp"].keys())
                for j in range(len(udp_ports)):
                    self.results[i][ips[i]]["udp"][j]["service"] = result["scan"][ips[i]]["udp"][int(udp_ports[j])][
                        "name"]

    # 脆弱性信息获取
    # 这里要做字符串处理，挺麻烦的，到时候再弄吧
    def vul_detection(self, result):
        cve = {}  # 存储cve的字典，key是端口 value是该端口的cve信息
        ips = self.get_ip(result)
        for i in range(len(ips)):
            if "tcp" in result["scan"][ips[i]].keys():
                tcp_ports = list(result["scan"][ips[i]]["tcp"].keys()) if "tcp" in result["scan"][ips[i]] else []
                for t_port in tcp_ports:
                    if "vulscan" in result["scan"][ips[i]]["tcp"][int(t_port)]["script"]:
                        self.results[i][ips[i]][t_port][t_port]["cve"] = \
                        result["scan"][ips[i]]["tcp"][int(t_port)]["script"][
                            "vulscan"]
            if "udp" in result["scan"][ips[i]].keys():
                udp_ports = list(result["scan"][ips[i]]["udp"].keys()) if "udp" in result["scan"][ips[i]] else []
                for u_port in udp_ports:
                    if "vulscan" in result["scan"][ips[i]]["tcp"][int(u_port)]["script"]:
                        self.results[i][ips[i]][u_port]["cve"] = result["scan"][ips[i]]["tcp"][int(u_port)]["script"][
                            "vulscan"]

    # snmp信息获取，只在161端口
    def snmp_info(self, result):
        ips = self.get_ip(result)
        for i in range(len(ips)):
            u_ports = list(result["scan"][ips[i]]["udp"].keys()) if "udp" in result["scan"][ips[i]] else []
            for j in range(len(u_ports)):
                # 如果扫描的结果里有161端口，而且nmap扫描的结果里有snmp-sysdescr的结果则赋值
                if self.results[i][ips[i]]["udp"][j]["port"] == 161 and "snmp-sysdescr" in \
                        result["scan"][ips[i]]["udp"][161]["script"]:
                    self.results[i][ips[i]]["udp"][j]["snmp-sysdescr"] = result["scan"][ips[i]]["udp"][161]["script"][
                        "snmp-sysdescr"]
                else:
                    self.results[i][ips[i]]["udp"][j]["snmp-sysdescr"] = ""

                    # banner 获取

    def get_banner(self, result):
        ips = self.get_ip(result)

        for i in range(len(ips)):
            t_ports = list(result["scan"][ips[i]]["tcp"].keys())
            for j in range(len(t_ports)):
                # 获取ftp_banner
                if self.results[i][ips[i]]["tcp"][j]["port"] == 21 and "banner" in result["scan"][ips[i]]["tcp"][21][
                    "script"]:
                    self.results[i][ips[i]]["tcp"][j]["port"]["ftp_banner"] = \
                    result["scan"][ips[i]]["tcp"][21]["script"]["banner"]
                else:
                    self.results[i][ips[i]]["tcp"][j]["port"]["ftp_banner"] = ""
                # 获取telnet_banner
                if self.results[i][ips[i]]["tcp"][j]["port"] == 23 and "banner" in result["scan"][ips[i]]["tcp"][23][
                    "script"]:
                    self.results[i][ips[i]]["tcp"][j]["port"]["telnet_banner"] = \
                    result["scan"][ips[i]]["tcp"][23]["script"]["banner"]
                else:
                    self.results[i][ips[i]]["tcp"][j]["port"]["telnet_banner"] = ""

    def get_result(self):
        return self.results

# [{
#    "198.53.49.46":
#
#    {
#       "os": "string",
#       "vendor": "manufacturer",
#       "model_name": "string",
#       "firmware_version": "string",
#       "is_discontinued": "boolean",
#       "cve_list": {
#          "cve_id": "int",
#          "cvss": "int"
#       },
#       "device_type": "string",
#       "firmware_infor": {
#          "name": "string",
#          "version": "string",
#          "sha2": "string"
#       },
#
#       "tcp": [{
#             "port": 21,
#             "service": "tcpwrapped"
#          },
#          {
#             "port": 23,
#             "service": "tcpwrapped"
#          }
#       ],
#       "udp": [{
#             "port": 17,
#             "service": "tcpwrapped"
#          },
#          {
#             "port": 19,
#             "service": "tcpwrapped"
#          }
#       ]
#
#    }
# }]
